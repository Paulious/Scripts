"""Loads the JSON pattern library.

Each file in `library/` looks like:

    {"domain": "...", "patterns": [ {id, title, category, severity, role, weight,
                                     regex[], summary, remediation[], ...} ]}

`suppressions.json` lists known-harmless noise and `error_codes.json` maps
numeric codes to plain-English meanings. Point PATTERN_DIR at a folder of extra
*.json files to add your own patterns without touching the code.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from app.config import get_settings
from app.models import Role, Severity
from app.patterns.literals import required_literals

LIBRARY_DIR = Path(__file__).parent / "library"
_HEX = re.compile(r"\b0x[0-9A-Fa-f]{8}\b")
_AADSTS = re.compile(r"AADSTS(\d{4,7})")
_MSI_CODE = re.compile(r"(?:Error |status: |error code |returning |code )(\d{4})\b")


class RemediationDef(BaseModel):
    action: str
    detail: str = ""
    command: str | None = None


class PatternDef(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    role: Role
    weight: float = Field(ge=0, le=1)
    regex: list[str] = Field(min_length=1)
    summary: str
    remediation: list[RemediationDef] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    applies_to: list[str] = Field(default_factory=list)
    ignore_details: list[str] = Field(default_factory=list)
    likely_causes: list[str] = Field(default_factory=list)

    _compiled: list[re.Pattern] = []
    _ignore: list[re.Pattern] = []

    @field_validator("regex")
    @classmethod
    def _valid_regex(cls, value: list[str]) -> list[str]:
        for rx in value:
            re.compile(rx, re.IGNORECASE)
        return value

    def model_post_init(self, __context) -> None:
        self._compiled = [re.compile(rx, re.IGNORECASE) for rx in self.regex]
        self._ignore = [re.compile(rx, re.IGNORECASE) for rx in self.ignore_details]

    def match(self, text: str) -> tuple[bool, str | None]:
        """Return (matched, detail). A match whose detail is on the ignore list does not count."""
        for rx in self._compiled:
            m = rx.search(text)
            if not m:
                continue
            detail = None
            if "detail" in rx.groupindex:
                detail = (m.group("detail") or "").strip() or None
            if detail and any(ig.search(detail) for ig in self._ignore):
                continue
            return True, detail
        return False, None

    def render_summary(self, details: list[str]) -> str:
        shown = ", ".join(details[:3]) if details else "see evidence"
        return self.summary.replace("{detail}", shown)


class SuppressionDef(BaseModel):
    id: str
    regex: str
    reason: str

    _compiled: re.Pattern | None = None

    def model_post_init(self, __context) -> None:
        self._compiled = re.compile(self.regex, re.IGNORECASE)

    def hits(self, text: str) -> bool:
        return bool(self._compiled.search(text))


class PatternLibrary:
    def __init__(self, patterns: list[PatternDef], suppressions: list[SuppressionDef], codes: dict[str, dict[str, str]]):
        ids = [p.id for p in patterns]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate pattern ids: {sorted(dupes)}")
        # Strongest signatures first so a line is claimed by its most specific pattern.
        self.patterns = sorted(patterns, key=lambda p: (-p.weight, p.id))
        self.suppressions = suppressions
        self.codes = codes
        self._by_id = {p.id: p for p in patterns}
        self._by_type: dict[str, list[PatternDef]] = {}

    def get(self, pattern_id: str) -> PatternDef | None:
        return self._by_id.get(pattern_id)

    def for_log_type(self, log_type: str) -> list[PatternDef]:
        if log_type not in self._by_type:
            self._by_type[log_type] = [p for p in self.patterns if not p.applies_to or log_type in p.applies_to]
        return self._by_type[log_type]

    def any_hit(self, log_type: str) -> re.Pattern:
        """One regex that matches if *any* pattern for this log type could match.

        Most log lines match nothing, so testing one combined regex first is far cheaper than
        trying every pattern on every line. Named groups are stripped because a name can only
        appear once in a regex."""
        cache = self.__dict__.setdefault("_any", {})
        if log_type not in cache:
            parts = [f"(?:{rx.replace('(?P<detail>', '(?:')})" for pat in self.for_log_type(log_type) for rx in pat.regex]
            cache[log_type] = re.compile("|".join(parts), re.IGNORECASE)
        return cache[log_type]

    def prefilter(self, log_type: str) -> tuple[tuple[tuple[str, tuple["PatternDef", ...]], ...], tuple["PatternDef", ...]]:
        """((literal, patterns that need it), ...) plus the patterns with no safe literal.

        A line can only match a pattern if its lower-cased text contains one of that pattern's
        literals. The scanner checks the literals with plain substring tests and then runs only
        the patterns attached to the literals it found."""
        cache = self.__dict__.setdefault("_pre", {})
        if log_type not in cache:
            by_lit: dict[str, list[PatternDef]] = {}
            residual: list[PatternDef] = []
            for pat in self.for_log_type(log_type):
                needs_full = False
                for rx in pat.regex:
                    got = required_literals(rx)
                    if got is None:
                        needs_full = True
                    else:
                        for lit in got:
                            if pat not in by_lit.setdefault(lit, []):
                                by_lit[lit].append(pat)
                if needs_full and pat not in residual:
                    residual.append(pat)
            table = tuple((lit, tuple(pats)) for lit, pats in sorted(by_lit.items(), key=lambda kv: -len(kv[0])))
            cache[log_type] = (table, tuple(residual))
        return cache[log_type]

    @property
    def suppress_any(self) -> re.Pattern:
        cache = self.__dict__.setdefault("_sup_any", [])
        if not cache:
            cache.append(re.compile("|".join(f"(?:{s.regex})" for s in self.suppressions), re.IGNORECASE))
        return cache[0]

    def suppression_for(self, text: str) -> SuppressionDef | None:
        for s in self.suppressions:
            if s.hits(text):
                return s
        return None

    def explain_codes(self, text: str) -> dict[str, str]:
        """Find known error codes in a line and return {code: meaning}."""
        found: dict[str, str] = {}
        for hx in _HEX.findall(text):
            meaning = self.codes.get("hresult", {}).get(hx.upper().replace("0X", "0x"))
            if meaning:
                found[hx.upper().replace("0X", "0x")] = meaning
        for num in _AADSTS.findall(text):
            meaning = self.codes.get("aadsts", {}).get(num)
            if meaning:
                found[f"AADSTS{num}"] = meaning
        for num in _MSI_CODE.findall(text):
            meaning = self.codes.get("msi", {}).get(num)
            if meaning:
                found[num] = meaning
        return found


def _read(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _load_dir(directory: Path) -> tuple[list[PatternDef], list[SuppressionDef], dict[str, dict[str, str]]]:
    patterns: list[PatternDef] = []
    sups: list[SuppressionDef] = []
    codes: dict[str, dict[str, str]] = {}
    for path in sorted(directory.glob("*.json")):
        data = _read(path)
        for raw in data.get("patterns", []):
            patterns.append(PatternDef(**raw))
        for raw in data.get("suppressions", []):
            sups.append(SuppressionDef(**raw))
        for kind, table in (data if path.name == "error_codes.json" else {}).items():
            codes.setdefault(kind, {}).update(table)
    return patterns, sups, codes


@lru_cache
def get_library() -> PatternLibrary:
    patterns, sups, codes = _load_dir(LIBRARY_DIR)
    extra = get_settings().pattern_dir
    if extra and Path(extra).is_dir():
        p2, s2, c2 = _load_dir(Path(extra))
        patterns += p2
        sups += s2
        for kind, table in c2.items():
            codes.setdefault(kind, {}).update(table)
    return PatternLibrary(patterns, sups, codes)
