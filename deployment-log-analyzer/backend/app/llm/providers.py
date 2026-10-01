"""Provider implementations. Each wraps the vendor's official async SDK."""
from __future__ import annotations

from typing import Any

from .base import LLMError, LLMProvider


def _reason(exc: Exception) -> str:
    """The provider's own error text (for example 'credit balance is too low'). It describes the
    request, never the log content, so it is safe to show."""
    msg = str(getattr(exc, "message", "") or exc).strip().replace("\n", " ")
    return msg[:300]


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str, *, effort: str = "", timeout: float = 180.0,
                 http_client: Any | None = None):
        from anthropic import AsyncAnthropic

        self.model = model
        self._effort = effort.strip()
        self._client = AsyncAnthropic(api_key=api_key, timeout=timeout, max_retries=2, http_client=http_client)

    async def complete(self, system: str, user: str, *, max_tokens: int) -> str:
        import anthropic

        kwargs: dict = {}
        if self._effort:
            kwargs["output_config"] = {"effort": self._effort}
        try:
            resp = await self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                **kwargs,
            )
        except anthropic.APIStatusError as exc:
            raise LLMError(f"Anthropic API returned {exc.status_code}: {_reason(exc)}") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMError("Could not reach the Anthropic API") from exc

        if resp.stop_reason == "refusal":
            raise LLMError("The model declined to answer this request")
        if resp.stop_reason == "max_tokens":
            raise LLMError("The model ran out of output tokens before finishing")
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        if not text.strip():
            raise LLMError("The model returned no text")
        return text


class _ChatCompletionsProvider(LLMProvider):
    """Shared logic for OpenAI and Azure OpenAI (same chat-completions surface)."""

    _client = None

    async def complete(self, system: str, user: str, *, max_tokens: int) -> str:
        import openai

        try:
            resp = await self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                max_completion_tokens=max_tokens,
                response_format={"type": "json_object"},
            )
        except openai.APIStatusError as exc:
            raise LLMError(f"{self.name} API returned {exc.status_code}: {_reason(exc)}") from exc
        except openai.APIConnectionError as exc:
            raise LLMError(f"Could not reach the {self.name} API") from exc

        choice = resp.choices[0]
        if choice.finish_reason == "length":
            raise LLMError("The model ran out of output tokens before finishing")
        if choice.finish_reason == "content_filter":
            raise LLMError("The response was blocked by the provider's content filter")
        text = choice.message.content or ""
        if not text.strip():
            raise LLMError("The model returned no text")
        return text


class OpenAIProvider(_ChatCompletionsProvider):
    name = "openai"

    def __init__(self, api_key: str, model: str, *, base_url: str | None = None, timeout: float = 180.0,
                 http_client: Any | None = None):
        from openai import AsyncOpenAI

        self.model = model
        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url, timeout=timeout, max_retries=2, http_client=http_client)


class AzureOpenAIProvider(_ChatCompletionsProvider):
    name = "azure_openai"

    def __init__(self, endpoint: str, deployment: str, api_version: str, *, api_key: str | None = None,
                 timeout: float = 180.0, http_client: Any | None = None):
        from openai import AsyncAzureOpenAI

        self.model = deployment  # Azure routes by deployment name
        kwargs: dict = {}
        if api_key:
            kwargs["api_key"] = api_key
        else:
            # Keyless: use the managed identity / developer login available to the host.
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider

            kwargs["azure_ad_token_provider"] = get_bearer_token_provider(
                DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
            )
        self._client = AsyncAzureOpenAI(
            azure_endpoint=endpoint, api_version=api_version, timeout=timeout, max_retries=2,
            http_client=http_client, **kwargs,
        )
