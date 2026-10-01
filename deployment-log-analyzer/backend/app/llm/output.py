"""Parse and validate what the model sends back."""
from __future__ import annotations

import json
import re

from pydantic import BaseModel, Field, field_validator

_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.I)


class LLMRemediation(BaseModel):
    action: str
    detail: str = ""
    command: str | None = None


class LLMRootCause(BaseModel):
    title: str
    category: str = "other"
    explanation: str = ""
    reasoning: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    confidence: int | None = None

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce(cls, v):
        if v is None or v == "":
            return None
        try:
            v = float(str(v).strip("% "))
        except ValueError:
            return None
        if 0 < v <= 1:  # model answered 0.85 instead of 85
            v *= 100
        return max(0, min(100, int(round(v))))


class LLMOutput(BaseModel):
    summary: str
    root_cause: LLMRootCause | None = None
    contributing_factors: list[str] = Field(default_factory=list)
    ruled_out: list[str] = Field(default_factory=list)
    remediation: list[LLMRemediation] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    further_data: list[str] = Field(default_factory=list)

    @field_validator("contributing_factors", "ruled_out", "verification", "further_data", mode="before")
    @classmethod
    def _strings(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return [x if isinstance(x, str) else json.dumps(x) for x in v]


def extract_json(text: str) -> dict:
    text = _FENCE.sub("", text.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in reply")
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : i + 1])
    raise ValueError("unterminated JSON object in reply")


def parse_output(text: str) -> LLMOutput:
    return LLMOutput.model_validate(extract_json(text))
