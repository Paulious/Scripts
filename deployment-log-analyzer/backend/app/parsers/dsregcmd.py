"""`dsregcmd /status` output (Entra ID / hybrid join state), as collected in Intune diagnostics."""
from __future__ import annotations

import re

from .base import INFO, LogEntry, LogParser, ParsedLog

_KV = re.compile(r"^\s*([A-Za-z][\w ]{1,40}?)\s*:\s*(.*?)\s*$")
_FACTS = (
    "AzureAdJoined", "EnterpriseJoined", "DomainJoined", "DeviceName", "TenantName", "TenantId", "DeviceId",
    "DeviceAuthStatus", "MdmUrl", "TpmProtected", "Executing Account Name", "Attempt Status", "Server Error Code",
)


class DsregcmdParser(LogParser):
    id = "dsregcmd"
    label = "dsregcmd /status output"
    description = "Device registration / join state from dsregcmd"

    @classmethod
    def detect(cls, filename: str, sample: list[str]) -> float:
        text = "\n".join(sample[:80])
        if "| Device State" in text and "AzureAdJoined" in text:
            return 0.97
        if "dsregcmd" in filename.lower() and "AzureAdJoined" in text:
            return 0.95
        return 0.0

    def parse(self, lines: list[str]) -> ParsedLog:
        entries = [LogEntry(i, i, ln, INFO) for i, ln in enumerate(lines, start=1) if ln.strip()]
        facts: dict[str, str] = {}
        for e in entries:
            m = _KV.match(e.text)
            if m and m.group(1).strip() in _FACTS and m.group(2) and m.group(1).strip() not in facts:
                facts[m.group(1).strip()] = m.group(2)
        return ParsedLog(entries=entries, facts=facts)

    def is_noise(self, line: str) -> bool:
        return line.startswith("+---") or not line.strip()
