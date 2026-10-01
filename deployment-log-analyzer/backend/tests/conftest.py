import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, llm_provider="none", anthropic_api_key=None, openai_api_key=None,
                    azure_openai_endpoint=None, azure_openai_deployment=None, azure_openai_api_key=None)
