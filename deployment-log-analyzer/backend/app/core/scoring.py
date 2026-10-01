"""Ranking and confidence scoring.

The LLM explains; this module decides how much the evidence actually supports
the conclusion. The confidence number is deliberately explainable: five
factors, each with a plain-English reason, so an engineer can disagree with a
specific one instead of arguing with a black box.
"""
from __future__ import annotations

from app.models import Confidence, ConfidenceFactor, Finding, Role

ADJACENT_LINES = 60       # findings this close in the same file are one story, not rivals
SEQUENCE_LINES = 400      # cause should precede the failure within this many lines

WEIGHTS = {
    "signature": 0.30,
    "failure": 0.20,
    "corroboration": 0.20,
    "sequence": 0.15,
    "competition": 0.15,
}


def rank(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(findings, key=lambda f: (f.role != Role.cause, -f.score, f.file, f.first_line))
    for i, f in enumerate(ordered, start=1):
        f.id = f"F{i}"
    return ordered


def _adjacent(a: Finding, b: Finding) -> bool:
    return a.file == b.file and (
        abs(a.first_line - b.first_line) <= ADJACENT_LINES or abs(a.last_line - b.last_line) <= ADJACENT_LINES
    )


def label_for(score: int) -> str:
    return "High" if score >= 80 else "Medium" if score >= 55 else "Low"


def compute_confidence(
    top: Finding,
    findings: list[Finding],
    links: dict[str, set[str]],
    pattern_weight: float,
) -> Confidence:
    others = [f for f in findings if f.id != top.id]
    linked = links.get(top.file, set())
    symptoms = [f for f in others if f.role == Role.symptom and f.file == top.file]
    linked_symptoms = [f for f in others if f.role == Role.symptom and f.file in linked]
    any_symptom = [f for f in others if f.role == Role.symptom]

    # 1. How specific is the signature?
    signature = pattern_weight
    sig_detail = (
        "Matches a specific, well-known failure signature." if pattern_weight >= 0.8
        else "Matches a known pattern, but one that can have several underlying causes." if pattern_weight >= 0.5
        else "Only a generic indicator - the log does not name a specific cause."
    )

    # 2. Is there proof the deployment actually failed?
    if top.role == Role.symptom:
        failure, fail_detail = 0.6, "The top finding is itself an outcome (exit code / failure message), not a cause."
    elif symptoms or linked_symptoms:
        src = "the same log" if symptoms else "a linked log"
        failure, fail_detail = 1.0, f"A failing exit code or 'install failed' outcome is recorded in {src}."
    elif any_symptom:
        failure, fail_detail = 0.6, "A failure outcome exists in another log, but nothing ties it to this one."
    else:
        failure, fail_detail = 0.35, "No failing exit code or failure outcome was found, so this may be a warning that did not break anything."

    # 3. Is it corroborated by more than one place?
    supporting_files = {top.file} | {f.file for f in linked_symptoms}
    same_family = [f for f in others if f.category == top.category and (f.file == top.file or f.file in linked)]
    recurring = top.attempts >= 2
    if len(supporting_files) >= 2:
        corroboration = 1.0 if recurring else 0.9
        corr_detail = f"Seen across {len(supporting_files)} related logs" + (f" and in {top.attempts} separate attempts." if recurring else ".")
    elif recurring or same_family:
        corroboration = 0.75 if recurring else 0.6
        corr_detail = f"Repeated in {top.attempts} separate attempts." if recurring else "Other findings in the same log point the same way."
    else:
        corroboration, corr_detail = 0.45, "Supported by a single occurrence in a single log."

    # 4. Does the cause come before the failure?
    if symptoms:
        after = [s for s in symptoms if 0 <= s.first_line - top.first_line <= SEQUENCE_LINES]
        if after:
            sequence, seq_detail = 1.0, "The cause is logged shortly before the failure, which is the order you would expect."
        else:
            sequence, seq_detail = 0.6, "The cause and the failure are in the same log but not close together."
    elif linked_symptoms:
        sequence, seq_detail = 0.8, "The failure is recorded in a linked log that references this one."
    else:
        sequence, seq_detail = 0.3, "No failure event to order against."

    # 5. Are there credible rival explanations?
    in_scope = {top.file} | linked
    rivals = [
        f for f in others
        if f.role == Role.cause and f.file in in_scope and f.category != top.category
        and not _adjacent(f, top) and f.score >= 0.35 * top.score
    ]
    if rivals:
        best = max(r.score for r in rivals)
        competition = max(0.2, min(1.0, 1 - best / max(top.score, 0.01)))
        comp_detail = f"{len(rivals)} other independent cause(s) are plausible, the strongest being '{rivals[0].title}'."
    else:
        competition, comp_detail = 1.0, "No credible competing explanation found in the logs."

    factors = [
        ConfidenceFactor(name="Signature specificity", score=round(signature, 2), weight=WEIGHTS["signature"], detail=sig_detail),
        ConfidenceFactor(name="Failure confirmed", score=round(failure, 2), weight=WEIGHTS["failure"], detail=fail_detail),
        ConfidenceFactor(name="Corroboration", score=round(corroboration, 2), weight=WEIGHTS["corroboration"], detail=corr_detail),
        ConfidenceFactor(name="Cause precedes failure", score=round(sequence, 2), weight=WEIGHTS["sequence"], detail=seq_detail),
        ConfidenceFactor(name="No rival explanation", score=round(competition, 2), weight=WEIGHTS["competition"], detail=comp_detail),
    ]
    # Logs alone never prove a cause beyond doubt, so the evidence score tops out at 95.
    score = min(95, round(100 * sum(f.score * f.weight for f in factors)))
    return Confidence(score=score, label=label_for(score), factors=factors)


def blend_with_llm(base: Confidence, llm_score: int | None) -> Confidence:
    """The model can nudge the number, but it cannot claim more certainty than the
    evidence supports: the result is capped at base + 10."""
    if llm_score is None:
        return base
    llm_score = max(0, min(100, int(llm_score)))
    blended = round(0.6 * base.score + 0.4 * llm_score)
    final = min(blended, base.score + 10)
    return Confidence(score=final, label=label_for(final), factors=base.factors, llm_reported=llm_score)
