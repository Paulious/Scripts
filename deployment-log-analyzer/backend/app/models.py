"""Public data contracts. The frontend mirrors these in frontend/lib/types.ts."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_serializer


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Role(str, Enum):
    cause = "cause"      # explains *why* something broke
    symptom = "symptom"  # shows *that* something broke (exit codes, "install failed")


class LogFileInfo(BaseModel):
    path: str
    size_bytes: int
    line_count: int
    encoding: str
    log_type: str
    log_type_label: str
    detection_confidence: float
    error_count: int = 0
    warning_count: int = 0
    first_timestamp: str | None = None
    last_timestamp: str | None = None
    facts: dict[str, str] = Field(default_factory=dict)


class SkippedFile(BaseModel):
    path: str
    reason: str


class SkippedGroup(BaseModel):
    reason: str
    count: int
    examples: list[str] = Field(default_factory=list)


class EvidenceLine(BaseModel):
    n: int
    text: str
    match: bool = False
    anchor: bool = False
    noise: bool = False

    @model_serializer(mode="wrap")
    def _compact(self, handler):
        # Thousands of lines are sent per result, and most flags are false: leave them out.
        d = handler(self)
        for key in ("match", "anchor", "noise"):
            if d.get(key) is False:
                d.pop(key)
        return d


class EvidenceWindow(BaseModel):
    file: str
    start_line: int
    end_line: int
    anchor_line: int
    lines: list[EvidenceLine]


class Finding(BaseModel):
    id: str
    pattern_id: str
    title: str
    category: str
    severity: Severity
    role: Role
    file: str
    log_type: str
    match_count: int
    attempts: int = 1
    first_line: int
    last_line: int
    first_timestamp: str | None = None
    last_timestamp: str | None = None
    details: list[str] = Field(default_factory=list)
    error_codes: list[str] = Field(default_factory=list)
    sample: str
    score: float
    explanation: str
    related_files: list[str] = Field(default_factory=list)
    evidence: list[EvidenceWindow] = Field(default_factory=list)
    evidence_trimmed: bool = False


class SuppressedNoise(BaseModel):
    id: str
    reason: str
    count: int
    example: str


class ConfidenceFactor(BaseModel):
    name: str
    score: float  # 0..1
    weight: float
    detail: str


class Confidence(BaseModel):
    score: int  # 0..100
    label: str
    factors: list[ConfidenceFactor]
    llm_reported: int | None = None


class RemediationStep(BaseModel):
    order: int
    action: str
    detail: str = ""
    command: str | None = None


class RootCause(BaseModel):
    title: str
    category: str
    explanation: str
    reasoning: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    confidence: Confidence
    # False when no failed install or failing exit code in the same log goes with it: a problem to fix, not a proven cause.
    tied_to_failure: bool = True


class Analysis(BaseModel):
    summary: str
    root_cause: RootCause | None
    contributing_factors: list[str] = Field(default_factory=list)
    ruled_out: list[str] = Field(default_factory=list)
    remediation: list[RemediationStep] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    further_data: list[str] = Field(default_factory=list)
    provider: str
    model: str | None = None
    degraded: bool = False
    notes: list[str] = Field(default_factory=list)


class Stats(BaseModel):
    files_analyzed: int
    files_skipped: int
    total_lines: int
    total_bytes: int
    findings: int
    errors: int
    duration_ms: int


class AnalysisResult(BaseModel):
    generated_at: str
    context: str | None = None
    stats: Stats
    files: list[LogFileInfo]
    skipped: list[SkippedFile]
    skipped_groups: list[SkippedGroup] = Field(default_factory=list)
    findings: list[Finding]
    suppressed: list[SuppressedNoise]
    analysis: Analysis
    report_markdown: str
