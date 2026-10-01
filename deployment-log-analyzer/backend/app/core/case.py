"""The 'case file' that every later stage works from."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.models import Finding, LogFileInfo, SkippedFile, SuppressedNoise
from app.patterns import PatternLibrary


@dataclass
class Case:
    context: str | None
    files: list[LogFileInfo]
    skipped: list[SkippedFile]
    findings: list[Finding]          # already ranked, ids assigned
    suppressed: list[SuppressedNoise]
    links: dict[str, set[str]]
    library: PatternLibrary
    top: Finding | None = None
    window_lines: dict[str, dict[int, str]] = field(default_factory=dict)

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.id == finding_id), None)
