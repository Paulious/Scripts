from __future__ import annotations

from abc import ABC, abstractmethod


class LLMError(Exception):
    """Raised for any provider failure the pipeline should survive."""


class LLMProvider(ABC):
    name: str
    model: str

    @abstractmethod
    async def complete(self, system: str, user: str, *, max_tokens: int) -> str:
        """Return the model's text reply. Must raise LLMError on refusal, truncation or API failure."""
