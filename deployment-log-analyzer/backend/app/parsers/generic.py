"""PSADT and a generic fallback for anything we don't recognise."""
from __future__ import annotations

import re
from datetime import datetime

from .base import ERROR, INFO, WARNING, LogEntry, LogParser, ParsedLog, explicit_level, guess_level

_TS_PATTERNS = [
    (re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})"), "%Y-%m-%d %H:%M:%S"),
    (re.compile(r"(\d{1,2}/\d{1,2}/\d{4}),?\s+(\d{1,2}:\d{2}:\d{2})"), "%m/%d/%Y %H:%M:%S"),
    (re.compile(r"(\d{1,2}-\d{1,2}-\d{4})\s+(\d{1,2}:\d{2}:\d{2})"), "%m-%d-%Y %H:%M:%S"),
]


def sniff_timestamp(line: str) -> datetime | None:
    head = line[:60]
    for rx, fmt in _TS_PATTERNS:
        if m := rx.search(head):
            try:
                return datetime.strptime(f"{m.group(1)} {m.group(2)}", fmt)
            except ValueError:
                continue
    return None


class PsadtParser(LogParser):
    """PowerShell App Deployment Toolkit (v3 and v4) logs."""

    id = "psadt"
    label = "PSAppDeployToolkit log"
    description = "PowerShell App Deployment Toolkit install log"

    _RX = re.compile(r"^\[(?P<ts>[^\]]+)\]\s*(?P<tags>(?:\[[^\]]*\]\s*)+)(?:::?)?\s*(?P<msg>.*)$")

    @classmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        name = filename.lower()
        hits = 0
        for ln in sample[:60]:
            if cls._RX.match(ln) and ("::" in ln):
                hits += 1
        text = "\n".join(sample[:120])
        marker = "PSAppDeployToolkit" in text or "Deploy-Application" in text or "Invoke-AppDeployToolkit" in text
        if hits >= 5 and marker:
            return 0.97
        if hits >= 8:
            return 0.85
        if marker and ("psadt" in name or "deploy" in name):
            return 0.8
        return 0.0

    def parse(self, lines: list[str]) -> ParsedLog:
        entries: list[LogEntry] = []
        for i, line in enumerate(lines, start=1):
            m = self._RX.match(line)
            if not m:
                if line.strip():
                    entries.append(LogEntry(i, i, line, guess_level(line)))
                continue
            tags = [t.strip(" []") for t in re.findall(r"\[[^\]]*\]", m["tags"])]
            sev = next((t.lower() for t in tags if t.lower() in {"error", "warning", "info", "success", "debug"}), "info")
            level = ERROR if sev == "error" else WARNING if sev == "warning" else INFO
            ts = None
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%m-%d-%Y %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m-%d-%Y %H:%M:%S"):
                try:
                    ts = datetime.strptime(m["ts"].strip(), fmt)
                    break
                except ValueError:
                    continue
            entries.append(LogEntry(i, i, line, level, ts, tags[0] if tags else ""))
        return ParsedLog(entries=entries)


_ERR = re.compile(r"\b(error|fatal|exception|failed|failure)\b", re.I)
_BENIGN = re.compile(r"\b(0|no|zero) (errors?|failures?|warnings?)\b|\bsucceeded\b|\bwithout errors?\b", re.I)


class GenericTextParser(LogParser):
    id = "generic"
    label = "Generic text log"
    description = "Unrecognised text log - timestamps and severity are inferred"

    @classmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        return 0.2  # always available as the fallback

    def parse(self, lines: list[str]) -> ParsedLog:
        entries: list[LogEntry] = []
        last_ts: datetime | None = None
        for i, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            ts = sniff_timestamp(line) or last_ts
            last_ts = ts
            level = explicit_level(line)
            if level is not None:
                pass
            elif _ERR.search(line) and not _BENIGN.search(line):
                level = ERROR
            elif re.search(r"\bwarn(ing)?\b", line, re.I):
                level = WARNING
            else:
                level = INFO
            entries.append(LogEntry(i, i, line, level, ts))
        return ParsedLog(entries=entries)
