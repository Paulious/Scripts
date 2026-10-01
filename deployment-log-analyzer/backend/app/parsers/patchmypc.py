"""Patch My PC logs: ScriptRunner (CMTrace format) and the detection script log."""
from __future__ import annotations

import re

from .base import ERROR, INFO, LogEntry, LogParser, ParsedLog, combine, parse_date
from .cmtrace import CMTraceParser

_PMPC_COMPONENTS = {"ScriptRunner", "InstallationDriver", "AutomaticInstaller", "Arguments"}


class PatchMyPCScriptRunnerParser(CMTraceParser):
    id = "patchmypc_scriptrunner"
    label = "Patch My PC ScriptRunner"
    description = "Patch My PC Publisher ScriptRunner log (install/uninstall driver)"

    @classmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        base = super().detect(filename, sample)
        if not base:
            return 0.0
        text = "\n".join(sample[:60])
        name = filename.lower()
        if "starting scriptrunner" in text.lower() or 'component="ScriptRunner"' in text:
            return 0.97
        if "patchmypc" in name and "scriptrunner" in name:
            return 0.95
        comps = sum(1 for c in _PMPC_COMPONENTS if f'component="{c}"' in text)
        return 0.9 if comps >= 2 else 0.0

    _RX = {
        "ScriptRunner version": re.compile(r"Starting ScriptRunner \(V([\d.]+)\)"),
        "Device name": re.compile(r"Device name:\s*(\S+)"),
        "Operating system": re.compile(r"Operating System:\s*(.+)"),
        "Running as": re.compile(r"Running as\s+(.+)"),
    }
    _APP_RX = re.compile(r"Argument #\d+ is: \"?/ApplicationName=(.+?)\"?$")
    _VENDOR_RX = re.compile(r"Vendor Name: (.*?), Version: ([\w.\-]+), Product Name: (.+)")
    _EXIT_RX = re.compile(r"End of Script Runner\. Exit code is:\s*(-?\d+)")

    def facts(self, entries: list[LogEntry]) -> dict[str, str]:
        out: dict[str, str] = {}
        apps: list[str] = []
        exits: list[str] = []
        for e in entries:
            t = e.text
            for key, rx in self._RX.items():
                if key not in out and (m := rx.search(t)):
                    out[key] = m.group(1).strip()
            if m := self._APP_RX.search(t):
                apps.append(m.group(1).strip())
            elif m := self._VENDOR_RX.search(t):
                apps.append(f"{m.group(3).strip()} {m.group(2)}")
            if m := self._EXIT_RX.search(t):
                exits.append(m.group(1))
        if apps:
            out["Applications"] = "; ".join(dict.fromkeys(apps))
        if exits:
            out["Run exit codes"] = ", ".join(exits)
            out["Runs"] = str(len(exits))
        return out

    def is_noise(self, line: str) -> bool:
        return "Argument #" in line or "Removing registryHooks" in line or line.rstrip().endswith("= ")


class PatchMyPCDetectionParser(LogParser):
    """MM/DD/YYYY HH:MM:SS~[App version]~[Found:True|False]~[Purpose:Detection]~[Context:..]~[Hive:..]"""

    id = "patchmypc_detection"
    label = "Patch My PC detection script"
    description = "Software detection results written by the Patch My PC detection script"

    _RX = re.compile(
        r"^\s*(?P<date>\d{1,2}/\d{1,2}/\d{4})\s+(?P<time>\d{1,2}:\d{2}:\d{2})~\[(?P<app>.*?)\]~\[Found:(?P<found>True|False)\]"
        r"(?:~\[Purpose:(?P<purpose>[^\]]*)\])?"
    )

    @classmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        hits = sum(1 for line in sample[:20] if cls._RX.match(line))
        if hits >= 2:
            return 0.97
        return 0.85 if hits else 0.0

    def parse(self, lines: list[str]) -> ParsedLog:
        entries: list[LogEntry] = []
        last: dict[str, tuple[str, str]] = {}
        for i, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            m = self._RX.match(line)
            if not m:
                entries.append(LogEntry(i, i, line, INFO))
                continue
            ts = combine(parse_date(m["date"]), m["time"])
            # "Found:False" is normal before an install, so it stays at info level;
            # the engine looks at the *final* state per app instead.
            entries.append(LogEntry(i, i, line, INFO, ts, "Detection"))
            app = re.sub(r"\s+\{[0-9a-f-]{36}\}", "", m["app"]).strip()
            last[app] = (m["found"], f"{m['date']} {m['time']}")
        facts = {f"Last detection: {app}": f"{'FOUND' if found == 'True' else 'NOT FOUND'} at {ts}"
                 for app, (found, ts) in last.items()}
        return ParsedLog(entries=entries, facts=facts)
