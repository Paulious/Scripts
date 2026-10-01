"""Regex scanning: parsed entries -> matches -> grouped findings with evidence."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from app.config import Settings
from app.models import EvidenceLine, EvidenceWindow, Finding, Role, Severity, SuppressedNoise
from app.parsers.base import ERROR, WARNING, LogEntry, LogParser
from app.patterns import PatternDef, PatternLibrary

SEVERITY_FACTOR = {
    Severity.critical: 1.0, Severity.high: 0.95, Severity.medium: 0.8, Severity.low: 0.6, Severity.info: 0.4,
}
_NUM = re.compile(r"\d+")
_HEXNUM = re.compile(r"0x[0-9a-fA-F]+")
_LEAD_NUM = re.compile(r"^\d+:\s+")
_GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")


@dataclass
class Match:
    entry_index: int
    detail: str | None


@dataclass
class FileScan:
    path: str
    log_type: str
    lines: list[str]
    entries: list[LogEntry]
    parser: LogParser
    matches: dict[str, list[Match]] = field(default_factory=dict)
    suppressed: Counter = field(default_factory=Counter)
    suppressed_example: dict[str, str] = field(default_factory=dict)
    unclassified: list[int] = field(default_factory=list)  # entry indexes of error-level lines no pattern claimed
    errors: int = 0
    warnings: int = 0
    encoding: str = ""
    size_bytes: int = 0
    detection_confidence: float = 0.0
    truncated: bool = False
    facts: dict = field(default_factory=dict)
    offset: int = 0  # lines dropped from the top; displayed line numbers stay those of the original file


# Output of a diagnostic command or an exported registry key: words like "error" or "Failed" there are data, not log levels.
_DATA_FILE = re.compile(r"\)\s*(?:Command|RegistryKey)\s|windows_defender_support|mpsupportfiles|msinfo32|\.(?:html?|xml|reg|json|csv)$", re.IGNORECASE)


def scan_entries(scan: FileScan, lib: PatternLibrary) -> None:
    data_file = bool(_DATA_FILE.search(scan.path))
    table, residual = lib.prefilter(scan.log_type)
    order = {p.id: i for i, p in enumerate(lib.for_log_type(scan.log_type))}
    any_noise = lib.suppress_any.search
    claimed: set[tuple[int, Role, str]] = set()
    for idx, entry in enumerate(scan.entries):
        text = entry.text
        if not text.strip():
            continue
        # Almost every line is routine, so the cheap checks come first.
        if any_noise(text):
            sup = lib.suppression_for(text)
            if sup:
                scan.suppressed[sup.id] += 1
                scan.suppressed_example.setdefault(sup.id, text.strip()[:200])
                continue
        if entry.level == ERROR:
            scan.errors += 1
        elif entry.level == WARNING:
            scan.warnings += 1

        low = text.lower()
        candidates: dict[str, PatternDef] = {}
        for lit, pats in table:
            if lit in low:
                for p in pats:
                    candidates[p.id] = p
        for p in residual:
            candidates[p.id] = p

        hit_any = False
        for p in sorted(candidates.values(), key=lambda p: order[p.id]):
            key = (idx, p.role, p.category)
            if key in claimed:
                continue
            ok, detail = p.match(text)
            if ok:
                claimed.add(key)
                scan.matches.setdefault(p.id, []).append(Match(idx, detail))
                hit_any = True
        if not hit_any and entry.level == ERROR and not data_file:
            scan.unclassified.append(idx)


def _fmt(ts: datetime | None) -> str | None:
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else None


def _cluster(lines: list[int], gap: int) -> list[list[int]]:
    groups: list[list[int]] = []
    for ln in lines:
        if groups and ln - groups[-1][-1] <= gap:
            groups[-1].append(ln)
        else:
            groups.append([ln])
    return groups


def _trim(text: str, limit: int) -> str:
    text = text.rstrip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_window(scan: FileScan, match_lines: set[int], anchor: int, settings: Settings) -> EvidenceWindow:
    ctx = settings.evidence_context_lines
    first = scan.offset + 1
    last = scan.offset + len(scan.lines)
    start = max(first, anchor - ctx)
    end = min(last, anchor + ctx)
    lines: list[EvidenceLine] = []
    for n in range(start, end + 1):
        raw = scan.lines[n - scan.offset - 1]
        lines.append(EvidenceLine(
            n=n,
            # A matched line keeps much more text: the useful part of a long JSON or script-output line is often deep inside it.
            text=_trim(raw, settings.max_line_chars * 4 if n in match_lines else settings.max_line_chars),
            match=n in match_lines,
            anchor=n == anchor,
            noise=scan.parser.is_noise(raw),
        ))
    return EvidenceWindow(file=scan.path, start_line=start, end_line=end, anchor_line=anchor, lines=lines)


def _normalise(msg: str) -> str:
    msg = _GUID.sub("<guid>", msg)
    msg = _HEXNUM.sub("<hex>", msg)
    return _NUM.sub("#", msg).strip()[:200]


def build_findings(scan: FileScan, lib: PatternLibrary, settings: Settings) -> list[Finding]:
    findings: list[Finding] = []
    gap = settings.evidence_context_lines * 2
    for pattern_id, matches in scan.matches.items():
        p: PatternDef = lib.get(pattern_id)  # type: ignore[assignment]
        entries = [scan.entries[m.entry_index] for m in matches]
        line_nos = sorted({e.line_no for e in entries})
        clusters = _cluster(line_nos, gap)
        details: list[str] = []
        for m in matches:
            d = _LEAD_NUM.sub("", m.detail) if m.detail else None  # MSI logs prefix messages with "1: "
            if d and d not in details:
                details.append(d)
        codes: dict[str, str] = {}
        for e in entries[:50]:
            codes.update(lib.explain_codes(e.text))
        stamps = [e.timestamp for e in entries if e.timestamp]
        explanation = p.render_summary(details)
        if codes:
            explanation += " Code meaning: " + "; ".join(f"{c} = {m}" for c, m in list(codes.items())[:3]) + "."

        attempts = len(clusters)
        recurrence = 1 + 0.08 * min(attempts - 1, 3)
        role_factor = 1.0 if p.role == Role.cause else 0.6
        # Event logs on a healthy machine are full of errors that mean little on their own, so they never rank as high.
        severity = Severity.medium if (scan.log_type == "windows_event_log" and p.severity == Severity.high) else p.severity
        score = round(p.weight * SEVERITY_FACTOR[severity] * recurrence * role_factor, 3)

        match_lines: set[int] = set()
        for e in entries:
            match_lines.update(range(e.line_no, e.end_line + 1))
        windows: list[EvidenceWindow] = []
        picks = [clusters[0]] if attempts == 1 else [clusters[0], clusters[-1]]
        for cl in picks[: settings.max_evidence_windows_per_finding]:
            windows.append(build_window(scan, match_lines, cl[0], settings))

        findings.append(Finding(
            id="", pattern_id=p.id, title=p.title, category=p.category, severity=severity, role=p.role,
            file=scan.path, log_type=scan.log_type, match_count=len(matches), attempts=attempts,
            first_line=line_nos[0], last_line=line_nos[-1],
            first_timestamp=_fmt(min(stamps)) if stamps else None,
            last_timestamp=_fmt(max(stamps)) if stamps else None,
            details=details[:6], error_codes=list(codes.keys())[:6],
            sample=_trim(entries[0].text.strip().replace("\n", " "), 300),
            score=score, explanation=explanation, evidence=windows,
        ))

    if scan.unclassified:
        findings.append(_unclassified_finding(scan, settings, gap))
    return findings


def _unclassified_finding(scan: FileScan, settings: Settings, gap: int) -> Finding:
    entries = [scan.entries[i] for i in scan.unclassified]
    line_nos = sorted({e.line_no for e in entries})
    clusters = _cluster(line_nos, gap)
    counts = Counter(_normalise(e.text) for e in entries)
    top = [f"{msg} (x{n})" if n > 1 else msg for msg, n in counts.most_common(5)]
    stamps = [e.timestamp for e in entries if e.timestamp]
    match_lines = {ln for e in entries for ln in range(e.line_no, e.end_line + 1)}
    window = build_window(scan, match_lines, line_nos[0], settings)
    return Finding(
        id="", pattern_id="unclassified-errors", title="Error-level messages not covered by the pattern library",
        category="other", severity=Severity.medium, role=Role.cause, file=scan.path, log_type=scan.log_type,
        match_count=len(entries), attempts=len(clusters), first_line=line_nos[0], last_line=line_nos[-1],
        first_timestamp=_fmt(min(stamps)) if stamps else None, last_timestamp=_fmt(max(stamps)) if stamps else None,
        details=top, sample=_trim(entries[0].text.strip().replace("\n", " "), 300),
        score=round(0.25 * SEVERITY_FACTOR[Severity.medium], 3),
        explanation="The log marks these lines as errors but no known pattern matches them. Treat the most frequent or earliest message as the lead.",
        evidence=[window],
    )


def collect_suppressed(scans: list[FileScan], lib: PatternLibrary) -> list[SuppressedNoise]:
    total: Counter = Counter()
    example: dict[str, str] = {}
    for s in scans:
        total.update(s.suppressed)
        for k, v in s.suppressed_example.items():
            example.setdefault(k, v)
    reasons = {s.id: s.reason for s in lib.suppressions}
    return [
        SuppressedNoise(id=k, reason=reasons.get(k, ""), count=n, example=example.get(k, ""))
        for k, n in total.most_common()
    ]


_HOT = re.compile(r"\.(?:log|txt|xml|json|csv|etl|evtx|cab|reg|html?)\b", re.IGNORECASE)
_TOKEN = re.compile(r"[\w\-. ]{6,120}?\.(?:log|txt|xml|json|csv|etl|evtx|cab|reg|html?)\b", re.IGNORECASE)


def mentioned_files(lines: list[str], limit: int = 300) -> set[str]:
    """File names a log refers to (ScriptRunner names the installer log it launched).
    Computed while the file is in memory so the lines can be dropped afterwards."""
    found: set[str] = set()
    hot = _HOT.search
    for ln in lines:
        if not hot(ln):
            continue
        for m in _TOKEN.findall(ln):
            found.add(m.strip().rsplit("\\", 1)[-1].lower())
            if len(found) >= limit:
                return found
    return found


def link_by_mentions(mentions: dict[str, set[str]]) -> dict[str, set[str]]:
    """Symmetric links between logs where one names the other."""
    names = {path: path.replace("\\", "/").rsplit("/", 1)[-1].lower() for path in mentions}
    links: dict[str, set[str]] = defaultdict(set)
    for path, tokens in mentions.items():
        for other, base in names.items():
            if other != path and len(base) >= 6 and any(base == t or base in t for t in tokens):
                links[path].add(other)
                links[other].add(path)
    return links


def link_files(scans: list[FileScan]) -> dict[str, set[str]]:
    """Find logs that reference each other by file name (ScriptRunner names the
    installer log it asked for). Links are symmetric."""
    names = {s.path: s.path.rsplit("/", 1)[-1].lower() for s in scans}
    links: dict[str, set[str]] = defaultdict(set)
    for s in scans:
        mentions = "\n".join(ln for ln in s.lines if ".log" in ln.lower() or "\\" in ln).lower()
        if not mentions:
            continue
        for other, base in names.items():
            if other != s.path and len(base) >= 6 and base in mentions:
                links[s.path].add(other)
                links[other].add(s.path)
    return links


MAX_UNCLASSIFIED = 10
MAX_OTHER_FILES = 12


def merge_across_files(findings: list[Finding]) -> tuple[list[Finding], int]:
    """The same pattern matching in ten rotated logs is one problem, not ten.

    Each pattern keeps its strongest finding; the others are folded into it (their hits and attempts are
    added, their file names are listed). "Error-level messages not covered by the pattern library" is
    per file by nature, so only the busiest few files are kept and the rest are counted.
    Returns the merged findings and how many unclassified findings were left out."""
    by_pattern: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_pattern[f.pattern_id].append(f)
    out: list[Finding] = []
    left_out = 0
    for pattern_id, group in by_pattern.items():
        if pattern_id == "unclassified-errors":
            group.sort(key=lambda f: -f.match_count)
            out += group[:MAX_UNCLASSIFIED]
            left_out += len(group[MAX_UNCLASSIFIED:])
            continue
        group.sort(key=lambda f: (-f.score, -f.match_count, f.file))
        primary, rest = group[0], group[1:]
        if rest:
            primary.other_files = [f.file for f in rest][:MAX_OTHER_FILES]
            primary.match_count += sum(f.match_count for f in rest)
            primary.attempts += sum(f.attempts for f in rest)
            # Settings dumps carry dates that are not when anything happened, so only real logs set the time range.
            stamps = [t for f in group if not f.file.lower().endswith((".reg", ".xml", ".json", ".html", ".htm", ".txt")) for t in (f.first_timestamp, f.last_timestamp) if t]
            if stamps:
                primary.first_timestamp, primary.last_timestamp = min(stamps), max(stamps)
            for f in rest:
                for d in f.details:
                    if d not in primary.details and len(primary.details) < 6:
                        primary.details.append(d)
                for c in f.error_codes:
                    if c not in primary.error_codes and len(primary.error_codes) < 6:
                        primary.error_codes.append(c)
        out.append(primary)
    return out, left_out
