"""Pattern-only analysis. Used when no LLM is configured, when the user picks
"pattern library only", and as the fallback when a provider call fails.

It is not as good at joining the dots as a model, but it is deterministic and
every sentence comes straight from the pattern library.
"""
from __future__ import annotations

from app.core.case import Case
from app.models import Analysis, Finding, RemediationStep, Role, RootCause
from app.core.scoring import compute_confidence

_GENERIC_REMEDIATION = [
    ("Find the first real error", "Open the evidence for the top finding and read upwards from it; the cause is almost always logged before the failure."),
    ("Reproduce on one test device", "Run the same install in the same context (SYSTEM) with verbose logging turned on."),
    ("Collect more logs", "See 'Further data' below."),
]


def _further_data(case: Case) -> list[str]:
    types = {f.log_type for f in case.files}
    out: list[str] = []
    if not types & {"intune_ime"}:
        out.append(r"Intune logs from C:\ProgramData\Microsoft\IntuneManagementExtension\Logs (IntuneManagementExtension.log and AppWorkload.log) covering the failure time.")
    if types & {"patchmypc_scriptrunner"} and not types & {"msi_verbose", "dell_dup"}:
        out.append(r"The installer's own log from C:\ProgramData\PatchMyPCInstallLogs for the failing app.")
    if not types & {"msi_verbose", "dell_dup", "psadt"} and not types & {"patchmypc_scriptrunner"}:
        out.append(r"A verbose MSI log (msiexec /i <package> /l*v C:\Temp\install.log) from a failing device.")
    out.append("The exact app name, version, assignment type and install context (System or User) from the Intune portal.")
    return out


def _step_list(top: Finding | None, case: Case) -> list[RemediationStep]:
    steps: list[RemediationStep] = []
    pattern = case.library.get(top.pattern_id) if top else None
    if pattern and pattern.remediation:
        for i, r in enumerate(pattern.remediation, start=1):
            steps.append(RemediationStep(order=i, action=r.action, detail=r.detail, command=r.command))
    else:
        for i, (a, d) in enumerate(_GENERIC_REMEDIATION, start=1):
            steps.append(RemediationStep(order=i, action=a, detail=d))
    return steps


def _ruled_out(case: Case) -> list[str]:
    return [f"{s.reason} ({s.count} line{'s' if s.count != 1 else ''})" for s in case.suppressed[:6]]


def build_heuristic(case: Case, *, provider: str = "none", note: str | None = None, degraded: bool = False) -> Analysis:
    notes = [note] if note else []
    n_files = len(case.files)
    top = case.top
    if top is None:
        return Analysis(
            summary=(f"{n_files} log file{'s' if n_files != 1 else ''} analysed. No known failure signature and no error-level "
                     "messages were found, so there is nothing to point at yet."),
            root_cause=None, ruled_out=_ruled_out(case), further_data=_further_data(case),
            remediation=_step_list(None, case)[:0], provider=provider, degraded=degraded, notes=notes,
        )

    pattern = case.library.get(top.pattern_id)
    base = compute_confidence(top, case.findings, case.links, pattern.weight if pattern else 0.25)

    near = [f for f in case.findings if f.id != top.id and f.file == top.file and abs(f.first_line - top.first_line) <= 60]
    outcomes = [f for f in case.findings if f.role == Role.symptom and f.id != top.id]
    contributing = [f"{f.title} ({f.file}:{f.first_line})" for f in near if f.role == Role.cause][:5]

    where = f"{top.file}:{top.first_line}"
    reasoning = [f"The strongest signal is '{top.title}' at {where}."]
    if not outcomes:
        reasoning.append("No failed install or failing exit code was recorded, so this is a problem worth fixing rather than proof of a failed deployment.")
    if outcomes:
        o = outcomes[0]
        reasoning.append(f"The outcome matches: {o.title} at {o.file}:{o.first_line}.")
    if top.attempts > 1:
        reasoning.append(f"It appears in {top.attempts} separate attempts, so it is repeatable rather than a one-off.")
    if top.related_files:
        reasoning.append("Related logs: " + ", ".join(top.related_files[:3]) + ".")

    when = f" between {top.first_timestamp} and {top.last_timestamp}" if top.first_timestamp and top.last_timestamp and top.first_timestamp != top.last_timestamp else ""
    if outcomes:
        summary = (
            f"{n_files} log file{'s' if n_files != 1 else ''} analysed. Most likely cause: {top.title}. "
            f"{top.explanation} "
            f"It shows up in {top.attempts} separate attempt{'s' if top.attempts != 1 else ''}{when}."
        )
    else:
        # Nothing in the logs says a deployment actually failed, so don't present this as a failure.
        summary = (
            f"{n_files} log file{'s' if n_files != 1 else ''} analysed. No failed install, failing exit code or failed "
            f"deployment outcome was found, so these logs may show a healthy deployment. The most notable problem in them is: "
            f"{top.title}. {top.explanation}"
        )

    verification = list(pattern.verification) if pattern and pattern.verification else [
        "Re-run the deployment on one test device and confirm the installer exits with 0 and the detection rule passes."
    ]

    return Analysis(
        summary=summary,
        root_cause=RootCause(
            title=top.title, category=top.category, explanation=top.explanation,
            reasoning=" ".join(reasoning), finding_ids=[top.id], confidence=base,
        ),
        contributing_factors=contributing,
        ruled_out=_ruled_out(case),
        remediation=_step_list(top, case),
        verification=verification,
        further_data=_further_data(case),
        provider=provider, degraded=degraded, notes=notes,
    )
