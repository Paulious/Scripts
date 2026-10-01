"""End-to-end analysis. Everything lives in memory for the length of one request.

`run_analysis` is an async generator that yields progress events (dicts) and,
last, either a `result` or an `error` event. The API layer streams these to the
browser as newline-delimited JSON, so no job store or database is needed.
"""
from __future__ import annotations

import asyncio
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator

from typing import Any

from pydantic import ValidationError

from app.config import Settings
from app.core import scoring
from app.core.archive import ArchiveLimitError, Limits
from app.core.walk import Member, walk_upload
from app.core.case import Case
from app.core.decoding import NotTextError, decode_bytes, looks_binary, split_lines
from app.core.heuristic import build_heuristic
from app.core.report import build_report
from app.core.scanner import FileScan, build_findings, link_by_mentions, mentioned_files, scan_entries
from app.llm import LLMError, LLMProvider, build_provider, resolve_provider_id
from app.llm.output import LLMOutput, parse_output
from app.llm.prompts import SYSTEM_PROMPT, build_case_file
from app.models import (
    Analysis, AnalysisResult, Confidence, Finding, LogFileInfo, RemediationStep, Role, RootCause, SkippedFile, SkippedGroup,
    Stats, SuppressedNoise,
)
from app.parsers import detect_parser
from app.patterns import get_library
from app.patterns.triage import TIER_ORDER, Decision, classify

STAGES = [
    ("extract", "Extracting archives"),
    ("detect", "Detecting log types"),
    ("scan", "Scanning for errors"),
    ("evidence", "Collecting evidence"),
    ("analyze", "Root cause analysis"),
    ("report", "Building report"),
]


def _progress(stage: str, status: str, message: str = "", percent: int | None = None) -> dict:
    ev = {"type": "progress", "stage": stage, "status": status, "message": message}
    if percent is not None:
        ev["percent"] = percent
    return ev


def _prepare(path: str, data: bytes, settings: Settings, max_lines: int | None = None) -> FileScan | SkippedFile:
    try:
        text, encoding = decode_bytes(data)
    except NotTextError:
        return SkippedFile(path=path, reason="binary file")
    if looks_binary(text):
        return SkippedFile(path=path, reason="binary file")
    lines = split_lines(text)
    del text
    if not any(ln.strip() for ln in lines):
        return SkippedFile(path=path, reason="empty file")
    # A triage rule can set its own limit for a kind of file; everything else uses the global one.
    limit = max_lines if max_lines is not None else settings.max_lines_per_file
    total = len(lines)
    offset = 0
    if total > limit:
        # Recent events matter most, so keep the end of the file.
        offset = total - limit
        lines = lines[offset:]
    parser, confidence = detect_parser(path, lines)
    parsed = parser.parse(lines)
    if offset:
        for e in parsed.entries:
            e.line_no += offset
            e.end_line += offset
    scan = FileScan(path=path, log_type=parser.id, lines=lines, entries=parsed.entries, parser=parser)
    scan.encoding, scan.size_bytes, scan.detection_confidence = encoding, len(data), confidence
    scan.truncated, scan.offset = bool(offset), offset
    scan.facts = dict(parsed.facts)
    if offset:
        scan.facts["Note"] = f"Only the last {len(lines):,} of {total:,} lines were analysed (lines {offset + 1:,} to {total:,})"
    return scan


def _file_info(scan: FileScan) -> LogFileInfo:
    stamps = [e.timestamp for e in scan.entries if e.timestamp]
    facts = dict(scan.facts)
    return LogFileInfo(
        path=scan.path, size_bytes=scan.size_bytes, line_count=len(scan.lines) + scan.offset, encoding=scan.encoding,
        log_type=scan.log_type, log_type_label=scan.parser.label, detection_confidence=scan.detection_confidence,
        error_count=scan.errors, warning_count=scan.warnings,
        first_timestamp=min(stamps).strftime("%Y-%m-%d %H:%M:%S") if stamps else None,
        last_timestamp=max(stamps).strftime("%Y-%m-%d %H:%M:%S") if stamps else None,
        facts=facts,
    )


@dataclass
class PlanItem:
    member: Member
    decision: Decision

    @property
    def path(self) -> str:
        return self.member.path


@dataclass
class FileResult:
    info: LogFileInfo
    findings: list[Finding]
    suppressed: Counter
    suppressed_example: dict[str, str]
    mentions: set[str]
    lines: int
    size: int


def build_plan(members: list[Member]) -> tuple[list[PlanItem], list[SkippedFile]]:
    """Decide from names and sizes alone what to read, and in what order."""
    skipped: list[SkippedFile] = []
    items: list[PlanItem] = []
    for m in members:
        d = classify(m.path)
        if d.tier == "skip":
            skipped.append(SkippedFile(path=m.path, reason=d.reason or "not a useful log"))
        else:
            items.append(PlanItem(m, d))

    # Some groups (for example 77 rotated agent logs) only need their newest files.
    by_rule: dict[str, list[PlanItem]] = defaultdict(list)
    for it in items:
        if it.decision.max_files:
            by_rule[it.decision.rule_id].append(it)
    dropped: set[int] = set()
    for group in by_rule.values():
        limit = group[0].decision.max_files or 0
        for it in sorted(group, key=lambda i: i.path, reverse=True)[limit:]:
            dropped.add(id(it))
            skipped.append(SkippedFile(path=it.path, reason=f"older file in a large group; the newest {limit} were read"))
    items = [it for it in items if id(it) not in dropped]
    items.sort(key=lambda i: (TIER_ORDER[i.decision.tier], i.path))
    return items, skipped


def process_member(item: PlanItem, lib, settings: Settings) -> FileResult | SkippedFile:
    """Read, scan and summarise one file, then let its text go."""
    data = item.member.read()
    scan = _prepare(item.path, data, settings, item.decision.max_lines)
    del data
    if isinstance(scan, SkippedFile):
        return scan
    scan_entries(scan, lib)
    findings = build_findings(scan, lib, settings)
    return FileResult(
        info=_file_info(scan), findings=findings, suppressed=scan.suppressed,
        suppressed_example=scan.suppressed_example, mentions=mentioned_files(scan.lines),
        lines=len(scan.lines), size=scan.size_bytes,
    )


def _group_skipped(skipped: list[SkippedFile]) -> list[SkippedGroup]:
    groups: dict[str, list[str]] = defaultdict(list)
    for s in skipped:
        groups[s.reason].append(s.path)
    return [SkippedGroup(reason=r, count=len(p), examples=[re.sub(r"^\(\d+\)\s+", "", x.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]) for x in p[:3]])
            for r, p in sorted(groups.items(), key=lambda kv: -len(kv[1]))]


def _suppressed_summary(counts: Counter, examples: dict[str, str], lib) -> list[SuppressedNoise]:
    reasons = {s.id: s.reason for s in lib.suppressions}
    return [SuppressedNoise(id=k, reason=reasons.get(k, ""), count=n, example=examples.get(k, "")) for k, n in counts.most_common()]


def _weight_of(case: Case, finding: Finding) -> float:
    p = case.library.get(finding.pattern_id)
    return p.weight if p else 0.25


def _to_analysis(out: LLMOutput, case: Case, provider: LLMProvider) -> Analysis:
    heur = build_heuristic(case, provider=provider.name)
    root: RootCause | None = None
    if out.root_cause or case.top:
        ids = [i for i in (out.root_cause.finding_ids if out.root_cause else []) if case.finding(i)]
        chosen = case.finding(ids[0]) if ids else case.top
        if chosen:
            base = scoring.compute_confidence(chosen, case.findings, case.links, _weight_of(case, chosen))
            conf = scoring.blend_with_llm(base, out.root_cause.confidence if out.root_cause else None)
            if out.root_cause:
                root = RootCause(
                    title=out.root_cause.title, category=out.root_cause.category or chosen.category,
                    explanation=out.root_cause.explanation or chosen.explanation, reasoning=out.root_cause.reasoning,
                    finding_ids=ids or [chosen.id], confidence=conf,
                    tied_to_failure=heur.root_cause.tied_to_failure if heur.root_cause else True,
                )
            else:
                root = heur.root_cause
    steps = [
        RemediationStep(order=i, action=r.action, detail=r.detail, command=(r.command or None))
        for i, r in enumerate(out.remediation, start=1)
    ] or heur.remediation
    return Analysis(
        summary=out.summary, root_cause=root, contributing_factors=out.contributing_factors,
        ruled_out=out.ruled_out or heur.ruled_out, remediation=steps,
        verification=out.verification or heur.verification, further_data=out.further_data or heur.further_data,
        provider=provider.name, model=provider.model,
    )


async def _ask_llm(provider: LLMProvider, case: Case, settings: Settings, redact: bool) -> LLMOutput:
    prompt = build_case_file(case, evidence_budget=settings.llm_evidence_char_budget, redact_text=redact)
    last_err: Exception | None = None
    for attempt in range(2):
        suffix = "" if attempt == 0 else "\n\nYour previous reply was not valid JSON for the required shape. Reply with the JSON object only."
        text = await asyncio.wait_for(
            provider.complete(SYSTEM_PROMPT, prompt + suffix, max_tokens=settings.llm_max_output_tokens),
            timeout=settings.llm_timeout_seconds + 30,
        )
        try:
            return parse_output(text)
        except (ValueError, ValidationError) as exc:
            last_err = exc
    raise LLMError(f"The model did not return usable JSON ({last_err.__class__.__name__})")


async def run_analysis(
    uploads: list[tuple[str, bytes]],
    *,
    settings: Settings,
    context: str | None = None,
    provider_id: str | None = None,
    redact: bool | None = None,
    http_client: Any | None = None,
) -> AsyncIterator[dict]:
    started = time.monotonic()
    lib = get_library()
    redact = settings.redact_for_llm if redact is None else redact

    try:
        provider = build_provider(resolve_provider_id(provider_id, settings), settings, http_client)
    except ValueError as exc:
        yield {"type": "error", "message": str(exc)}
        return

    # ---- 1. extract: list what is in the upload, decide what is worth reading -----------
    yield _progress("extract", "running", "Reading uploaded files")
    limits = Limits(
        max_total_bytes=settings.max_extracted_mb * 1024 * 1024, max_file_bytes=settings.max_file_mb * 1024 * 1024,
        max_files=settings.max_files, max_depth=settings.max_archive_depth,
    )
    try:
        listed: list = []
        for name, data in uploads:
            listed.extend(await asyncio.to_thread(lambda n=name, d=data: list(walk_upload(n, d, limits))))
    except ArchiveLimitError as exc:
        yield {"type": "error", "message": f"Upload rejected: {exc}"}
        return
    skipped: list[SkippedFile] = [m for m in listed if isinstance(m, SkippedFile)]
    plan, plan_skipped = build_plan([m for m in listed if isinstance(m, Member)])
    skipped += plan_skipped
    del listed
    if not plan:
        reasons = "; ".join(f"{s.path}: {s.reason}" for s in skipped[:5])
        yield {"type": "error", "message": "No readable log files found in the upload." + (f" ({reasons})" if reasons else "")}
        return
    note = f"{len(plan)} to read" + (f", {len(skipped)} skipped" if skipped else "")
    yield _progress("extract", "done", note, 100)
    yield _progress("detect", "running", "Prioritising logs")
    yield _progress("detect", "done", f"{sum(1 for p in plan if p.decision.tier == 'high')} high-priority logs", 100)

    # ---- 2-4. read, detect, scan and collect evidence one file at a time -----------------
    yield _progress("scan", "running", "Matching error patterns", 0)
    infos: list[LogFileInfo] = []
    all_findings: list[Finding] = []
    suppressed_counts: Counter = Counter()
    suppressed_examples: dict[str, str] = {}
    mentions: dict[str, set[str]] = {}
    total_lines = total_bytes = 0
    read_started = time.monotonic()
    n = len(plan)
    for i, item in enumerate(plan, start=1):
        over_time = time.monotonic() - read_started > settings.time_budget_seconds
        over_lines = total_lines >= settings.max_total_lines
        over_bytes = total_bytes >= limits.max_total_bytes
        if over_time or over_lines or over_bytes:
            skipped.append(SkippedFile(path=item.path, reason="analysis budget reached on a large package; higher-priority files were read first"))
        else:
            res = await asyncio.to_thread(process_member, item, lib, settings)
            if isinstance(res, SkippedFile):
                skipped.append(res)
            else:
                infos.append(res.info)
                all_findings += res.findings
                suppressed_counts.update(res.suppressed)
                for k, v in res.suppressed_example.items():
                    suppressed_examples.setdefault(k, v)
                mentions[item.path] = res.mentions
                total_lines += res.lines
                total_bytes += res.size
        if i == n or i % 3 == 0:
            yield _progress("scan", "running", item.path.rsplit("/", 1)[-1][:60], int(100 * i / n))
    plan.clear()
    uploads.clear()
    if not infos:
        yield {"type": "error", "message": "None of the uploaded files could be read as text logs."}
        return
    hits = sum(f.match_count for f in all_findings)
    yield _progress("scan", "done", f"{len(infos)} logs scanned, {hits} pattern hit(s)", 100)

    yield _progress("evidence", "running", "Ranking and linking findings", 50)
    links = link_by_mentions(mentions)
    ranked = scoring.rank(all_findings)
    for idx, f in enumerate(ranked):
        f.related_files = sorted(links.get(f.file, set()))[:5]
        if idx >= settings.max_findings_with_evidence:
            f.evidence, f.evidence_trimmed = [], True
    case = Case(context=context, files=infos, skipped=skipped[:200], findings=ranked,
                suppressed=_suppressed_summary(suppressed_counts, suppressed_examples, lib), links=links, library=lib,
                top=ranked[0] if ranked else None)
    yield _progress("evidence", "done", f"{len(ranked)} finding(s)", 100)

    # ---- 5. root cause analysis ---------------------------------------
    label = "Pattern library" if provider is None else f"{provider.name} / {provider.model}"
    yield _progress("analyze", "running", label)
    if provider is None or case.top is None:
        analysis = build_heuristic(case, provider="none")
    else:
        try:
            out = await _ask_llm(provider, case, settings, redact)
            analysis = _to_analysis(out, case, provider)
        except (LLMError, asyncio.TimeoutError) as exc:
            reason = str(exc) or "the request timed out"
            analysis = build_heuristic(
                case, provider="none", degraded=True,
                note=f"The {provider.name} analysis failed ({reason}), so this is the pattern-library result.",
            )
        except Exception as exc:  # noqa: BLE001 - never lose the deterministic result to a provider bug
            analysis = build_heuristic(
                case, provider="none", degraded=True,
                note=f"The {provider.name} analysis failed unexpectedly ({exc.__class__.__name__}), so this is the pattern-library result.",
            )
    yield _progress("analyze", "done", "Analysis complete", 100)

    # ---- 6. report ----------------------------------------------------
    yield _progress("report", "running", "Writing Markdown report")
    result = AnalysisResult(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        context=context,
        stats=Stats(
            files_analyzed=len(infos), files_skipped=len(skipped), total_lines=total_lines, total_bytes=total_bytes,
            findings=len(ranked), errors=sum(i.error_count for i in infos),
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
        files=infos, skipped=skipped[:200], skipped_groups=_group_skipped(skipped), findings=ranked, suppressed=case.suppressed, analysis=analysis,
        report_markdown="",
    )
    result.report_markdown = build_report(result)
    yield _progress("report", "done", "Done", 100)
    yield {"type": "result", "data": result.model_dump(mode="json")}


# ---------------------------------------------------------------------------
# Second step: add an LLM analysis to a result the pattern pass already produced.
# The browser sends the pattern result back, so the server still keeps nothing.
# ---------------------------------------------------------------------------
def case_from_result(result: AnalysisResult) -> Case:
    links: dict[str, set[str]] = defaultdict(set)
    for f in result.findings:
        for other in f.related_files:
            links[f.file].add(other)
            links[other].add(f.file)
    return Case(
        context=result.context, files=result.files, skipped=result.skipped, findings=result.findings,
        suppressed=result.suppressed, links=dict(links), library=get_library(),
        top=result.findings[0] if result.findings else None,
    )


async def run_enhance(
    result: AnalysisResult,
    *,
    settings: Settings,
    provider_id: str,
    redact: bool | None = None,
    http_client: Any | None = None,
) -> AsyncIterator[dict]:
    redact = settings.redact_for_llm if redact is None else redact
    pid = resolve_provider_id(provider_id, settings)
    if pid == "none":
        yield {"type": "error", "message": "No AI provider is selected or configured on the server."}
        return
    try:
        provider = build_provider(pid, settings, http_client)
    except ValueError as exc:
        yield {"type": "error", "message": str(exc)}
        return

    case = case_from_result(result)
    if case.top is None:
        yield {"type": "error", "message": "The pattern pass found nothing to analyse, so there is nothing to send to the AI."}
        return

    yield _progress("analyze", "running", f"{provider.name} / {provider.model}")
    try:
        out = await _ask_llm(provider, case, settings, redact)
        analysis = _to_analysis(out, case, provider)
    except (LLMError, asyncio.TimeoutError) as exc:
        yield {"type": "error", "message": f"The {provider.name} analysis failed: {str(exc) or 'the request timed out'}"}
        return
    except Exception as exc:  # noqa: BLE001
        yield {"type": "error", "message": f"The {provider.name} analysis failed unexpectedly ({exc.__class__.__name__})"}
        return
    yield _progress("analyze", "done", "Analysis complete", 100)

    yield _progress("report", "running", "Writing Markdown report")
    enhanced = result.model_copy(update={"analysis": analysis})
    enhanced.report_markdown = build_report(enhanced)
    yield _progress("report", "done", "Done", 100)
    yield {"type": "result", "data": enhanced.model_dump(mode="json")}
