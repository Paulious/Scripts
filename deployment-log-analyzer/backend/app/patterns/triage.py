"""Decides which files in a big package are worth reading, and how much of each.

Rules live in library/triage.json. Tiers, in reading order:
  high    read first, generous line limit (the logs that usually explain a failure)
  normal  everything not matched by a rule
  low     read last, tail-only and capped (large, noisy, rarely the cause)
  skip    not read at all, with a reason shown to the user
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from app.config import get_settings

LIBRARY = Path(__file__).parent / "library" / "triage.json"
TIER_ORDER = {"high": 0, "normal": 1, "low": 2}


class Rule(BaseModel):
    id: str
    match: str
    tier: Literal["skip", "low", "normal", "high"]
    reason: str = ""
    max_lines: int | None = None
    max_files: int | None = None


@dataclass(frozen=True)
class Decision:
    tier: str
    rule_id: str
    reason: str
    max_lines: int | None
    max_files: int | None


NORMAL = Decision("normal", "", "", None, None)


@lru_cache
def _rules() -> list[tuple[re.Pattern, Rule]]:
    raw = json.loads(LIBRARY.read_text(encoding="utf-8"))["rules"]
    rules = [Rule(**r) for r in raw]
    extra = get_settings().pattern_dir
    if extra and (Path(extra) / "triage.json").is_file():
        rules += [Rule(**r) for r in json.loads((Path(extra) / "triage.json").read_text(encoding="utf-8"))["rules"]]
    return [(re.compile(r.match, re.IGNORECASE), r) for r in rules]


def classify(path: str) -> Decision:
    """First matching rule wins, so more specific rules go first in the file."""
    for rx, rule in _rules():
        if rx.search(path):
            return Decision(rule.tier, rule.id, rule.reason, rule.max_lines, rule.max_files)
    return NORMAL
