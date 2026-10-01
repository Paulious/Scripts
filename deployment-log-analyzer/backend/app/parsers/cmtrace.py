"""CMTrace-style logs: <![LOG[message]LOG]!><time=".." date=".." component=".." type="1">.

This is the format used by the Intune Management Extension, Patch My PC's
ScriptRunner, ConfigMgr and a lot of vendor tooling. The Intune and Patch My PC
parsers are thin subclasses that only change detection and the facts we pull out.
"""
from __future__ import annotations

import re

from .base import ERROR, INFO, WARNING, LogEntry, LogParser, ParsedLog, combine, parse_date

_START = "<![LOG["
_END = "]LOG]!>"
_TAIL = re.compile(
    r'time="(?P<time>[^"]*)"\s+date="(?P<date>[^"]*)"\s+component="(?P<comp>[^"]*)"'
    r'(?:\s+context="[^"]*")?\s+type="(?P<type>\d)"',
)
_LEVELS = {"1": INFO, "2": WARNING, "3": ERROR}


class CMTraceParser(LogParser):
    id = "cmtrace"
    label = "CMTrace log"
    description = "Configuration Manager / generic CMTrace formatted log"

    @classmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        hits = sum(1 for line in sample[:40] if _START in line)
        if hits >= 3:
            return 0.8
        return 0.5 if hits else 0.0

    def parse(self, lines: list[str]) -> ParsedLog:
        entries: list[LogEntry] = []
        buf: list[str] = []
        start_no = 0
        for i, line in enumerate(lines, start=1):
            if not buf:
                if _START not in line:
                    # Stray line outside a record: keep it so nothing is invisible.
                    if line.strip():
                        entries.append(LogEntry(i, i, line, INFO))
                    continue
                start_no = i
            buf.append(line)
            if _END in line:
                entries.append(self._entry("\n".join(buf), start_no, i))
                buf = []
        if buf:  # unterminated record at EOF
            entries.append(LogEntry(start_no, len(lines), "\n".join(buf), INFO))
        return ParsedLog(entries=entries, facts=self.facts(entries))

    @staticmethod
    def _entry(raw: str, start: int, end: int) -> LogEntry:
        s = raw.index(_START) + len(_START)
        e = raw.rindex(_END)
        message = raw[s:e]
        m = _TAIL.search(raw[e:])
        if not m:
            return LogEntry(start, end, message, INFO)
        ts = combine(parse_date(m["date"]), m["time"])
        return LogEntry(start, end, message, _LEVELS.get(m["type"], INFO), ts, m["comp"])

    def facts(self, entries: list[LogEntry]) -> dict[str, str]:
        return {}
