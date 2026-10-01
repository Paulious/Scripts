"""Runtime settings. Everything comes from environment variables (or a local .env file).

Nothing in here is ever sent to the browser except the list of provider *names*
that are configured.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- LLM providers -------------------------------------------------
    # "auto" picks the first configured provider, "none" forces pattern-only analysis.
    llm_provider: str = "auto"
    llm_timeout_seconds: float = 180.0
    # Includes thinking tokens on models that think, so keep it generous.
    llm_max_output_tokens: int = 16000
    # Rough character budget for evidence sent to the model (about 4 chars per token).
    llm_evidence_char_budget: int = 70_000

    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-opus-5-5"
    # Thinking depth for models that support the effort setting. Leave empty to omit it.
    anthropic_effort: str = "high"

    openai_api_key: str | None = None
    openai_model: str = "gpt-5"
    openai_base_url: str | None = None

    azure_openai_endpoint: str | None = None
    azure_openai_api_key: str | None = None  # leave empty to use Entra ID (DefaultAzureCredential)
    azure_openai_deployment: str | None = None
    azure_openai_api_version: str = "2024-10-21"

    # --- Upload / extraction limits -----------------------------------
    max_upload_mb: int = 200
    max_extracted_mb: int = 600
    max_file_mb: int = 100
    max_files: int = 1000
    max_archive_depth: int = 3
    max_lines_per_file: int = 400_000
    # Big diagnostics packages: read the important files first, then stop at these limits.
    max_total_lines: int = 1_500_000
    time_budget_seconds: float = 150.0

    # --- Analysis ------------------------------------------------------
    evidence_context_lines: int = 100
    max_evidence_windows_per_finding: int = 2
    max_findings_with_evidence: int = 15
    max_line_chars: int = 600
    redact_for_llm: bool = True
    # Optional extra folder of *.json pattern files that is loaded on top of the built-in library.
    pattern_dir: str | None = None

    # --- Web -----------------------------------------------------------
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])


@lru_cache
def get_settings() -> Settings:
    return Settings()
