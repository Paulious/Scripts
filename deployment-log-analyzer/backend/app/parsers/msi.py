"""Windows Installer verbose logs (msiexec /l*v) and Dell Update Package logs.

A verbose MSI log is mostly chatter. The signal is a handful of lines:
`Return value 3`, `Product: X -- Installation failed`, `Error 1603`, and the
final `Installation success or error status: N`. The parser flags those as
errors and tags the chatter as noise so the evidence stays readable.

Dell DUP logs embed the MSI log, so the DUP parser is the MSI parser plus an
extra line format.
"""
from __future__ import annotations

import re
from datetime import datetime

from .base import ERROR, INFO, WARNING, LogEntry, LogParser, ParsedLog, combine, parse_date

_PREFIX = re.compile(r"^MSI \([sc]\) \([0-9A-Fa-f:!]+\) \[(?P<time>\d\d:\d\d:\d\d:\d{3})\]: (?P<msg>.*)$")
_VERBOSE_START = re.compile(r"Verbose logging started:\s*(?P<date>\d{1,2}/\d{1,2}/\d{4})\s+(?P<time>\d{1,2}:\d{2}:\d{2})")
_ACTION_TIME = re.compile(r"^Action (?:start|ended) (?P<time>\d{1,2}:\d{2}:\d{2})")

_ERROR_RX = [
    re.compile(r"Return value 3\b"),
    re.compile(r"-- (?:Installation|Removal|Configuration) (?:operation )?failed", re.I),
    re.compile(r"-- Error \d+"),
    re.compile(r"^Error \d{4}\."),
    re.compile(r"returned actual error code \d+"),
    re.compile(r"Installation success or error status: (?!0\b)\d+"),
    re.compile(r"MainEngineThread is returning (?!0\b)\d+"),
    re.compile(r"\bERROR:", re.I),
    re.compile(r"\bError 0x[0-9A-Fa-f]{8}"),
]
_NOISE_RX = re.compile(
    r"MSIHANDLE|Note: 1: 22(?:05|28|62|27)|^Property\([SCN]\):|PROPERTY CHANGE|SHELL32::SHGetFolderPath"
    r"|APPCOMPAT:|Note: 1: 2727|Resetting cached policy|Machine policy value|User policy value|Entering CMsiConfigurationManager"
    r"|Setting cached product context|Using cached product context|Running as a service|Closing MSIHANDLE"
    r"|Grabbed execution mutex|Releasing (?:execution )?mutex|^\s*$"
)


class MsiVerboseParser(LogParser):
    id = "msi_verbose"
    label = "Windows Installer (MSI) verbose log"
    description = "msiexec /l*v output"

    @classmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        text = "\n".join(sample[:250])
        prefixed = sum(1 for ln in sample[:250] if ln.startswith("MSI (s)") or ln.startswith("MSI (c)"))
        if "Verbose logging started" in text and prefixed:
            return 0.98
        if prefixed >= 10:
            return 0.92
        if "Action start" in text and "Property(S)" in text:
            return 0.85
        return 0.0

    def __init__(self) -> None:
        self._date: datetime | None = None
        self._last_ts: datetime | None = None

    # -- per-line --------------------------------------------------------
    def _classify(self, text: str) -> str:
        if _NOISE_RX.search(text):
            return INFO
        if any(rx.search(text) for rx in _ERROR_RX):
            return ERROR
        if re.search(r"\bwarning\b", text, re.I):
            return WARNING
        return INFO

    def parse_line(self, line_no: int, line: str) -> LogEntry:
        m = _VERBOSE_START.search(line)
        if m:
            self._date = parse_date(m["date"])
            self._last_ts = combine(self._date, m["time"])
            return LogEntry(line_no, line_no, line, INFO, self._last_ts, "msi")
        if m := _PREFIX.match(line):
            msg = m["msg"]
            # "18:02:01:406" -> hh:mm:ss.fff
            h, mi, s, ms = m["time"].split(":")
            ts = combine(self._date, f"{h}:{mi}:{s}.{ms}") if self._date else None
            self._last_ts = ts or self._last_ts
            return LogEntry(line_no, line_no, line, self._classify(msg), ts, "msi")
        if m := _ACTION_TIME.match(line):
            ts = combine(self._date, m["time"]) if self._date else None
            self._last_ts = ts or self._last_ts
            return LogEntry(line_no, line_no, line, self._classify(line), ts, "msi")
        return LogEntry(line_no, line_no, line, self._classify(line), self._last_ts, "msi")

    def parse(self, lines: list[str]) -> ParsedLog:
        self._date = self._last_ts = None
        entries = [self.parse_line(i, ln) for i, ln in enumerate(lines, start=1)]
        self._downgrade_continue_marked(entries)
        return ParsedLog(entries=entries, facts=self.facts(entries))

    @staticmethod
    def _downgrade_continue_marked(entries: list[LogEntry]) -> None:
        """WiX custom actions marked 'continue' log scary errors and then report
        'translated to success'. Those errors did not fail the install."""
        for idx, e in enumerate(entries):
            if "translated to success" not in e.text:
                continue
            e.level = WARNING
            j = idx - 1
            while j >= 0 and idx - j <= 12:
                prev = entries[j]
                if prev.level == ERROR and (prev.text.startswith("Wix") or "Error 0x" in prev.text or "ERROR:" in prev.text):
                    prev.level = WARNING
                j -= 1

    def is_noise(self, line: str) -> bool:
        body = line
        m = _PREFIX.match(line)
        if m:
            body = m["msg"]
        return bool(_NOISE_RX.search(body))

    # -- facts -----------------------------------------------------------
    _FACT_RX = {
        "Product name": re.compile(r"^Property\(S\): ProductName = (.+)$"),
        "Product version": re.compile(r"^Property\(S\): ProductVersion = (.+)$"),
        "Product code": re.compile(r"^Property\(S\): ProductCode = (.+)$"),
        "Manufacturer": re.compile(r"^Property\(S\): Manufacturer = (.+)$"),
    }
    _STATUS = re.compile(r"Installation success or error status: (-?\d+)")
    _ENGINE = re.compile(r"MainEngineThread is returning (-?\d+)")
    _PACKAGE = re.compile(r"Product: (.+?) -- (Installation|Removal|Configuration) (?:operation )?(completed successfully|failed)", re.I)

    def facts(self, entries: list[LogEntry]) -> dict[str, str]:
        out: dict[str, str] = {}
        statuses: list[str] = []
        for e in entries:
            line = e.text
            body = _PREFIX.match(line)["msg"] if _PREFIX.match(line) else line
            for key, rx in self._FACT_RX.items():
                if key not in out and (m := rx.match(body)):
                    out[key] = m.group(1).strip()
            if m := self._PACKAGE.search(body):
                out["Installer outcome"] = f"{m.group(2)} {m.group(3)}"
                out.setdefault("Product name", m.group(1).strip())
            if m := self._STATUS.search(body):
                statuses.append(m.group(1))
            if m := self._ENGINE.search(body):
                out["MSI exit code"] = m.group(1)
        if statuses:
            out["MSI install status"] = statuses[-1]
        return out


_DUP_LINE = re.compile(r"^\[(?P<dt>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d \d{4})\]\s+(?P<msg>.*)$")


class DellDupParser(MsiVerboseParser):
    id = "dell_dup"
    label = "Dell Update Package (DUP) log"
    description = "Dell Update Package / Command Update installer log with embedded MSI output"

    @classmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        text = "\n".join(sample[:60])
        if "DUP Framework" in text or "Update Package Execution Started" in text:
            return 0.99
        return 0.0

    def parse_line(self, line_no: int, line: str) -> LogEntry:
        m = _DUP_LINE.match(line)
        if not m:
            return super().parse_line(line_no, line)
        try:
            ts = datetime.strptime(" ".join(m["dt"].split()), "%a %b %d %H:%M:%S %Y")
        except ValueError:
            ts = None
        if ts:
            self._date = ts.replace(hour=0, minute=0, second=0)
            self._last_ts = ts
        msg = m["msg"]
        level = INFO
        if re.search(r"Result: FAILURE|Name of Exit Code: (?!SUCCESS|REBOOT)\w+|Exit Code set to: (?!0\b)\d+", msg):
            level = ERROR
        elif self._classify(msg) == ERROR:
            level = ERROR
        return LogEntry(line_no, line_no, line, level, ts, "dup")

    _DUP_FACTS = {
        "DUP framework": re.compile(r"DUP Framework EXE Version:\s*(.+)"),
        "DUP release": re.compile(r"DUP Release:\s*(.+)"),
        "Dell exit code name": re.compile(r"Name of Exit Code:\s*(\S+)"),
        "Dell exit code": re.compile(r"Exit Code set to:\s*(-?\d+)"),
        "Dell result": re.compile(r"Result:\s*(\w+)"),
        "Command line": re.compile(r"Original command line:\s*(.+)"),
    }

    def facts(self, entries: list[LogEntry]) -> dict[str, str]:
        out = super().facts(entries)
        for e in entries:
            m = _DUP_LINE.match(e.text)
            if not m:
                continue
            for key, rx in self._DUP_FACTS.items():
                if hit := rx.search(m["msg"]):
                    out[key] = hit.group(1).strip()  # keep the last one: that's the final outcome
        return out
