"""Intune Management Extension logs.

IME writes CMTrace-format files such as IntuneManagementExtension.log,
AppWorkload.log, AppActionProcessor.log, AgentExecutor.log, ClientHealth.log
and Win32AppInventory.log, normally under
C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs.
"""
from __future__ import annotations

import re

from .base import LogEntry
from .cmtrace import CMTraceParser

_NAMES = (
    "intunemanagementextension", "appworkload", "appactionprocessor", "agentexecutor",
    "clienthealth", "healthscripts", "win32appinventory", "sensor", "devicehealthmonitoring",
)


class IntuneImeParser(CMTraceParser):
    id = "intune_ime"
    label = "Intune Management Extension"
    description = "Intune Management Extension (IME) / Win32 app workload log"

    @classmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        base = super().detect(filename, sample)
        if not base:
            return 0.0
        name = filename.lower().rsplit("/", 1)[-1]
        if any(name.startswith(n) for n in _NAMES):
            return 0.97
        text = "\n".join(sample[:80])
        if re.search(r"\[Win32App\]|IntuneManagementExtension|\[PowerShell\]|AgentExecutor", text):
            return 0.9
        return 0.0

    _RX = {
        "Intune device ID": re.compile(r"(?:DeviceId|device id)[\s:=\"]+([0-9a-fA-F-]{36})", re.I),
        "IME version": re.compile(r"Intune Management Extension (?:version|Version)[\s:]+([\d.]+)"),
    }
    _APP_RX = re.compile(r"\[Win32App\].{0,80}?(?:app(?:lication)? (?:name|id)|Id)[\s:=\"]+([0-9a-fA-F-]{36})", re.I)

    def facts(self, entries: list[LogEntry]) -> dict[str, str]:
        out: dict[str, str] = {}
        apps: list[str] = []
        for e in entries:
            for key, rx in self._RX.items():
                if key not in out and (m := rx.search(e.text)):
                    out[key] = m.group(1)
            if (m := self._APP_RX.search(e.text)) and m.group(1) not in apps and len(apps) < 10:
                apps.append(m.group(1))
        if apps:
            out["Win32 app IDs seen"] = ", ".join(apps)
        return out
