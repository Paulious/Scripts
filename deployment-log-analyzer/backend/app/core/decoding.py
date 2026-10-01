"""Turn raw bytes into text lines.

Windows installers love UTF-16. MSI verbose logs, Dell DUP logs and plenty of
PowerShell output are UTF-16 LE with a BOM, and some have no BOM at all. Reading
them as UTF-8 gives you a wall of NUL characters, so we sniff first.
"""
from __future__ import annotations

import codecs

_BOMS: list[tuple[bytes, str, str]] = [
    (codecs.BOM_UTF32_LE, "utf-32", "UTF-32 LE"),
    (codecs.BOM_UTF32_BE, "utf-32", "UTF-32 BE"),
    (codecs.BOM_UTF8, "utf-8-sig", "UTF-8 (BOM)"),
    (codecs.BOM_UTF16_LE, "utf-16", "UTF-16 LE"),
    (codecs.BOM_UTF16_BE, "utf-16", "UTF-16 BE"),
]


class NotTextError(Exception):
    """Raised when the bytes look like a binary file rather than a log."""


def decode_bytes(data: bytes) -> tuple[str, str]:
    """Return (text, encoding_label). Raises NotTextError for binary content."""
    if not data:
        return "", "empty"

    for bom, codec, label in _BOMS:
        if data.startswith(bom):
            return data.decode(codec, errors="replace"), label

    head = data[:8192]
    nul = head.count(0)
    if nul and nul / len(head) > 0.25:
        # BOM-less UTF-16: NULs sit in the high byte of each character.
        even = head[0::2].count(0)
        odd = head[1::2].count(0)
        if odd >= even:
            text, label = data.decode("utf-16-le", errors="replace"), "UTF-16 LE (no BOM)"
        else:
            text, label = data.decode("utf-16-be", errors="replace"), "UTF-16 BE (no BOM)"
        # A real UTF-16 log decodes to mostly plain characters; a renamed .exe decodes to junk.
        sample = text[:4000]
        plain = sum(1 for ch in sample if ch in "\t\r\n" or 32 <= ord(ch) < 0x250)
        if sample and plain / len(sample) < 0.7:
            raise NotTextError("contains binary data")
        return text, label
    if nul:
        raise NotTextError("contains binary data")

    try:
        return data.decode("utf-8"), "UTF-8"
    except UnicodeDecodeError:
        text = data.decode("cp1252", errors="replace")
        return text, "Windows-1252"


def looks_binary(text: str) -> bool:
    sample = text[:20000]
    if not sample:
        return False
    bad = sum(1 for ch in sample if ord(ch) < 32 and ch not in "\t\r\n\f\x1b" or ch == "�")
    return bad / len(sample) > 0.05


def split_lines(text: str) -> list[str]:
    """Split on CR/LF/CRLF only. str.splitlines() also splits on form feeds and
    unicode separators, which would shift line numbers away from what the user
    sees in Notepad++ or CMTrace."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines
