from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.config import Settings

from .base import LLMProvider
from .providers import AnthropicProvider, AzureOpenAIProvider, OpenAIProvider

AUTO_ORDER = ["anthropic", "azure_openai", "openai"]


class ProviderInfo(BaseModel):
    id: str
    label: str
    model: str | None = None
    configured: bool


def _configured(settings: Settings) -> dict[str, bool]:
    return {
        "anthropic": bool(settings.anthropic_api_key),
        "azure_openai": bool(settings.azure_openai_endpoint and settings.azure_openai_deployment),
        "openai": bool(settings.openai_api_key),
    }


def list_providers(settings: Settings) -> list[ProviderInfo]:
    ok = _configured(settings)
    return [
        ProviderInfo(id="anthropic", label="Anthropic Claude", model=settings.anthropic_model, configured=ok["anthropic"]),
        ProviderInfo(id="azure_openai", label="Azure OpenAI", model=settings.azure_openai_deployment, configured=ok["azure_openai"]),
        ProviderInfo(id="openai", label="OpenAI", model=settings.openai_model, configured=ok["openai"]),
        ProviderInfo(id="none", label="Pattern library only (no LLM)", model=None, configured=True),
    ]


def resolve_provider_id(requested: str | None, settings: Settings) -> str:
    choice = (requested or settings.llm_provider or "auto").lower()
    if choice == "auto":
        ok = _configured(settings)
        return next((p for p in AUTO_ORDER if ok[p]), "none")
    return choice


def build_provider(provider_id: str, settings: Settings, http_client: Any | None = None) -> LLMProvider | None:
    """Return a provider instance, or None for pattern-only analysis. Raises ValueError if the
    provider is unknown or not configured."""
    if provider_id == "none":
        return None
    ok = _configured(settings)
    if provider_id not in ok:
        raise ValueError(f"Unknown provider '{provider_id}'")
    if not ok[provider_id]:
        raise ValueError(f"Provider '{provider_id}' is not configured on the server")
    t = settings.llm_timeout_seconds
    if provider_id == "anthropic":
        return AnthropicProvider(settings.anthropic_api_key, settings.anthropic_model,
                                 effort=settings.anthropic_effort, timeout=t, http_client=http_client)
    if provider_id == "openai":
        return OpenAIProvider(settings.openai_api_key, settings.openai_model,
                              base_url=settings.openai_base_url, timeout=t, http_client=http_client)
    return AzureOpenAIProvider(settings.azure_openai_endpoint, settings.azure_openai_deployment,
                               settings.azure_openai_api_version, api_key=settings.azure_openai_api_key,
                               timeout=t, http_client=http_client)
