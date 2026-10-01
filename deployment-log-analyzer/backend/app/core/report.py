"""Markdown report export."""
from __future__ import annotations

from app.models import AnalysisResult, EvidenceWindow, Finding

FULL_EVIDENCE_FOR = 3     # top findings get a wide window (the app itself shows the full +/-100 lines)
FULL_CONTEXT = 40
SHORT_CONTEXT = 6         # everything else gets a few lines around the match


def _fence(lines: list[str]) -> str:
    body = "\n".join(lines)
    ticks = "````" if "```" in body else "```"
    return f"{ticks}text\n{body}\n{ticks}"


def _window_text(w: EvidenceWindow, radius: int | None) -> str:
    out: list[str] = []
    hidden = 0
    for ln in w.lines:
        if radius is not None and abs(ln.n - w.anchor_line) > radius:
            continue
        if ln.noise and not ln.match:
            hidden += 1
            continue
        if hidden:
            out.append(f"      ... {hidden} routine lines hidden ...")
            hidden = 0
        mark = ">>" if ln.anchor else "> " if ln.match else "  "
        out.append(f"{mark} {ln.n:>6} | {ln.text}")
    if hidden:
        out.append(f"      ... {hidden} routine lines hidden ...")
    return _fence(out)


def _evidence(f: Finding, full: bool, shown: dict[str, list[tuple[int, int, str]]] | None = None) -> str:
    parts: list[str] = []
    shown = shown if shown is not None else {}
    for w in f.evidence:
        prior = next((fid for a, b, fid in shown.get(w.file, []) if a <= w.anchor_line <= b), None)
        if prior:
            parts.append(f"`{w.file}` around line {w.anchor_line}: same region as {prior} above.")
            continue
        shown.setdefault(w.file, []).append((w.start_line, w.end_line, f.id))
        lo = max(w.start_line, w.anchor_line - FULL_CONTEXT) if full else w.start_line
        hi = min(w.end_line, w.anchor_line + FULL_CONTEXT) if full else w.end_line
        label = f"`{w.file}` lines {lo}-{hi}" if full else f"`{w.file}` around line {w.anchor_line}"
        parts.append(f"{label}\n\n{_window_text(w, FULL_CONTEXT if full else SHORT_CONTEXT)}")
    return "\n\n".join(parts)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def build_report(r: AnalysisResult) -> str:
    a = r.analysis
    md: list[str] = []
    md.append("# Deployment Log Analysis")
    md.append("")
    meta = [f"Generated: {r.generated_at}", f"Files analysed: {r.stats.files_analyzed}", f"Lines read: {r.stats.total_lines:,}"]
    if a.provider != "none":
        meta.append(f"Analysis by: {a.provider}" + (f" ({a.model})" if a.model else ""))
    else:
        meta.append("Analysis by: pattern library (no LLM)")
    md.append(" | ".join(meta))
    if r.context:
        md += ["", f"Case note: {r.context.strip()}"]
    for n in a.notes:
        md += ["", f"> Note: {n}"]

    md += ["", "## Summary", "", a.summary]

    rc = a.root_cause
    if rc:
        md += ["", "## Most likely root cause" if rc.tied_to_failure else "## Most notable problem", "", f"**{rc.title}**  ", f"Confidence: {rc.confidence.score}% ({rc.confidence.label})", "", rc.explanation]
        if rc.reasoning:
            md += ["", "Why we think so:", "", rc.reasoning]

    if a.remediation:
        md += ["", "## What to do", ""]
        for step in a.remediation:
            line = f"{step.order}. **{step.action}**"
            if step.detail:
                line += f" - {step.detail}"
            md.append(line)
            if step.command:
                body = [f"   {ln}" for ln in step.command.splitlines()]
                md += ["", "   ```powershell", *body, "   ```", ""]
    if a.verification:
        md += ["", "## How to confirm it is fixed", ""] + [f"- {v}" for v in a.verification]

    findings = {f.id: f for f in r.findings}
    printed: dict[str, list[tuple[int, int, str]]] = {}
    if rc:
        shown = [findings[i] for i in rc.finding_ids if i in findings]
        if shown:
            md += ["", "## Supporting evidence", ""]
            for f in shown:
                md += [f"### {f.id}: {f.title}", "", f"{f.file}, first seen at line {f.first_line}"
                       + (f", {f.first_timestamp}" if f.first_timestamp else "")
                       + (f". {f.attempts} separate attempts." if f.attempts > 1 else "."), "", _evidence(f, True, printed), ""]

    if a.contributing_factors:
        md += ["", "## Other things worth knowing", ""] + [f"- {c}" for c in a.contributing_factors]
    if a.ruled_out:
        md += ["", "## Checked and ruled out", ""] + [f"- {c}" for c in a.ruled_out]

    if r.findings:
        md += ["", "## All findings", "", "| ID | Severity | Type | Finding | File | Line | Hits |", "|---|---|---|---|---|---|---|"]
        for f in r.findings:
            md.append(f"| {f.id} | {f.severity.value} | {f.role.value} | {_cell(f.title)} | {_cell(f.file)} | {f.first_line} | {f.match_count} |")
        extra = [f for f in r.findings[:FULL_EVIDENCE_FOR] if not rc or f.id not in rc.finding_ids]
        if extra:
            md += ["", "### Evidence for the next findings", ""]
            for f in extra:
                md += [f"#### {f.id}: {f.title}", "", _evidence(f, False, printed), ""]

    md += ["", "## Files analysed", "", "| File | Detected as | Lines | Errors | Warnings |", "|---|---|---|---|---|"]
    for f in r.files:
        md.append(f"| {_cell(f.path)} | {f.log_type_label} | {f.line_count:,} | {f.error_count} | {f.warning_count} |")
    if r.skipped_groups:
        md += ["", "Not read:", ""]
        for g in r.skipped_groups:
            names = ", ".join(g.examples) + (", ..." if g.count > len(g.examples) else "")
            md.append(f"- {g.count} file{'s' if g.count != 1 else ''}: {g.reason}" + (f" ({names})" if names else ""))

    if a.further_data:
        md += ["", "## Data that would help", ""] + [f"- {x}" for x in a.further_data]

    if rc:
        md += ["", "## How the confidence score was worked out", "", "| Factor | Score | Weight | Reason |", "|---|---|---|---|"]
        for fa in rc.confidence.factors:
            md.append(f"| {fa.name} | {int(fa.score * 100)}% | {int(fa.weight * 100)}% | {_cell(fa.detail)} |")
        if rc.confidence.llm_reported is not None:
            md += ["", f"The model reported {rc.confidence.llm_reported}%. The final figure blends it with the evidence score and cannot exceed it by more than 10 points."]

    md += ["", "---", "Nothing from this analysis is stored on the server. This file is the only copy."]
    return "\n".join(md) + "\n"
