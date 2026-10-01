"""Parser framework.

A parser turns the physical lines of one log file into logical `LogEntry`
objects (a CMTrace record can span several lines) and says how sure it is that
a file is "its" format. To add a format: subclass `LogParser`, implement
`detect` and `parse`, then add the class to `PARSERS` in `parsers/__init__.py`.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar

ERROR, WARNING, INFO = "error", "warning", "info"


@dataclass
class LogEntry:
    line_no: int          # 1-based, first physical line of the entry
    end_line: int         # last physical line (same as line_no for single-line formats)
    text: str             # the logical message (what patterns run against)
    level: str = INFO
    timestamp: datetime | None = None
    component: str = ""


@dataclass
class ParsedLog:
    entries: list[LogEntry]
    facts: dict[str, str] = field(default_factory=dict)


class LogParser(ABC):
    id: ClassVar[str]
    label: ClassVar[str]
    description: ClassVar[str] = ""

    @classmethod
    @abstractmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        """Return 0..1: how likely it is that this file is our format.
        `sample` is the first few hundred lines of the file."""

    @abstractmethod
    def parse(self, lines: list[str]) -> ParsedLog:
        ...

    # Lines that carry no diagnostic value. Used to shrink evidence for the LLM
    # and to let the UI hide chatter. Never used to hide matches.
    def is_noise(self, line: str) -> bool:
        return False


# ---- shared helpers ----------------------------------------------------------

_LEVEL_WORDS = [
    (re.compile(r"\b(fatal|critical|exception|failed|failure|error)\b", re.I), ERROR),
    (re.compile(r"\b(warn|warning)\b", re.I), WARNING),
]


_EXPLICIT_LEVEL = re.compile(r"^\s*(?:\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d+)?[,\s]+)(info|information|debug|trace|warning|warn|error|fatal)\b", re.I)


def explicit_level(text: str) -> str | None:
    """CBS, setupact and many other logs print the level right after the timestamp. When it is there,
    trust it: an Info line that says "Failed to ..." is the log describing something it handled."""
    m = _EXPLICIT_LEVEL.match(text)
    if not m:
        return None
    word = m.group(1).lower()
    return ERROR if word in ("error", "fatal") else WARNING if word in ("warning", "warn") else INFO


def guess_level(text: str) -> str:
    if (lvl := explicit_level(text)) is not None:
        return lvl
    for rx, level in _LEVEL_WORDS:
        if rx.search(text):
            return level
    return INFO


_DATE_FORMATS = (
    "%m-%d-%Y", "%m/%d/%Y", "%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y",
)


def parse_date(value: str) -> datetime | None:
    value = value.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


_TIME_RX = re.compile(r"^(\d{1,2}):(\d{2}):(\d{2})(?:[.:](\d{1,6}))?")


def combine(date: datetime | None, time_text: str) -> datetime | None:
    """Join a date with an 'HH:MM:SS[.ffffff]' string. Missing date -> None."""
    if date is None:
        return None
    m = _TIME_RX.match(time_text.strip())
    if not m:
        return date
    h, mi, s, frac = m.groups()
    micro = int((frac or "0").ljust(6, "0")[:6])
    try:
        return date.replace(hour=int(h), minute=int(mi), second=int(s), microsecond=micro)
    except ValueError:
        return date
