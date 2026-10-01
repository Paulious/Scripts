"""Scrub secrets and personal data before text leaves for an LLM provider.

This only touches what is sent to the model. The on-screen evidence and the
exported report keep the original text.
"""
from __future__ import annotations

import re

_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?key|token|sas|sig|signature)\b(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s;&,\"']+)"), r"\1\2<redacted>"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{16,}"), "Bearer <redacted>"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"), "<jwt>"),
    (re.compile(r"(?i)([?&](?:sig|sv|se|sp|spr|st|sr|skoid|sktid|skt|ske|sks|skv|sas|code|access_token|token)=)[^&\s\"']+"), r"\1<redacted>"),
    (re.compile(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b"), "<email>"),
    (re.compile(r"(?i)(C:\\Users\\)([^\\\s\"']+)"), r"\1<user>"),
    (re.compile(r"(?i)(/Users/|/home/)([^/\s\"']+)"), r"\1<user>"),
]


def redact(text: str) -> str:
    for rx, repl in _RULES:
        text = rx.sub(repl, text)
    return text
