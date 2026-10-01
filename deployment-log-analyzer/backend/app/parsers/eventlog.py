"""Windows event logs after conversion to text (see app/core/evtx.py)."""
from __future__ import annotations

import re
from datetime import datetime

from .base import ERROR, INFO, WARNING, LogEntry, LogParser, ParsedLog, explicit_level

_LINE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s+(?P<level>\w+)\s+(?P<rest>.*)$")


class EventLogParser(LogParser):
    id = "windows_event_log"
    label = "Windows event log"
    description = "Windows .evtx event log, one line per event"

    @classmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        return 0.99 if sample and sample[0].startswith("#EVTX") else 0.0

    def parse(self, lines: list[str]) -> ParsedLog:
        entries: list[LogEntry] = []
        counts = {ERROR: 0, WARNING: 0}
        for i, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            m = _LINE.match(line)
            ts = None
            level = INFO
            if m:
                try:
                    ts = datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    ts = None
                level = explicit_level(line) or INFO
            counts[level] = counts.get(level, 0) + 1
            entries.append(LogEntry(i, i, line, level, ts))
        facts = {"Channel": lines[0][6:].split("|")[0].strip()} if lines and lines[0].startswith("#EVTX") else {}
        if lines and "|" in lines[0]:
            facts["Events"] = lines[0].split("|", 1)[1].strip()
        return ParsedLog(entries=entries, facts=facts)
