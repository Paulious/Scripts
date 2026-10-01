"""Parser registry and log-type detection.

Order matters only for ties: more specific parsers come first.
"""
from __future__ import annotations

from .base import LogEntry, LogParser, ParsedLog
from .cmtrace import CMTraceParser
from .dsregcmd import DsregcmdParser
from .generic import GenericTextParser, PsadtParser
from .intune import IntuneImeParser
from .msi import DellDupParser, MsiVerboseParser
from .patchmypc import PatchMyPCDetectionParser, PatchMyPCScriptRunnerParser

PARSERS: list[type[LogParser]] = [
    PatchMyPCScriptRunnerParser,
    PatchMyPCDetectionParser,
    DsregcmdParser,
    IntuneImeParser,
    DellDupParser,
    MsiVerboseParser,
    PsadtParser,
    CMTraceParser,
    GenericTextParser,
]

_BY_ID = {p.id: p for p in PARSERS}
SAMPLE_LINES = 300


def get_parser(parser_id: str) -> LogParser:
    return _BY_ID.get(parser_id, GenericTextParser)()


def detect_parser(filename: str, lines: list[str]) -> tuple[LogParser, float]:
    """Pick the parser with the highest detection score. Returns a fresh instance
    (parsers keep per-file state) and its confidence."""
    sample = lines[:SAMPLE_LINES]
    best_cls: type[LogParser] = GenericTextParser
    best = -1.0
    for cls in PARSERS:
        score = cls.detect(filename, sample)
        if score > best:
            best_cls, best = cls, score
    return best_cls(), round(max(best, 0.0), 2)


__all__ = ["PARSERS", "LogEntry", "LogParser", "ParsedLog", "detect_parser", "get_parser"]
