import json

import httpx
import httpx2  # the Anthropic SDK 1.x uses httpx2; OpenAI still uses httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.pipeline import run_analysis
from app.llm import LLMError, build_provider, list_providers, resolve_provider_id
from app.llm.base import LLMProvider
from app.llm.output import extract_json, parse_output

from .fixtures import dup_failure_log, make_zip, scriptrunner_log

LLM_REPLY = {
    "summary": "Dell Command Update failed because the .NET Desktop Runtime 10 is not installed.",
    "root_cause": {
        "title": ".NET Desktop Runtime 10 missing", "category": "prerequisite",
        "explanation": "The installer checks for the runtime first and aborts.",
        "reasoning": "Dell.EXE.log:%LINE% states the requirement and setup aborts straight after.",
        "finding_ids": ["F1"], "confidence": "98%",
    },
    "contributing_factors": ["No dependency is configured on the app"],
    "ruled_out": ["MSI Error 2205 notes are normal"],
    "remediation": [{"action": "Deploy .NET Desktop Runtime 10", "detail": "as a dependency", "command": "dotnet --list-runtimes"}],
    "verification": ["dotnet --list-runtimes shows Microsoft.WindowsDesktop.App 10.x"],
    "further_data": [],
}


def _uploads():
    dup, _ = dup_failure_log()
    name = "Dell-Command-Update.EXE.log"
    return [("Logs.zip", make_zip({f"PatchMyPCInstallLogs/{name}": dup, "PatchMyPCIntuneLogs/PatchMyPC-ScriptRunner.log": scriptrunner_log(name)}))]


class FakeProvider(LLMProvider):
    name, model = "fake", "fake-1"

    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    async def complete(self, system, user, *, max_tokens):
        self.calls.append((system, user))
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r if isinstance(r, str) else json.dumps(r)


async def _run(settings, provider, **kw):
    import app.core.pipeline as pl
    orig = pl.build_provider
    pl.build_provider = lambda *_a, **_k: provider
    try:
        events = [e async for e in run_analysis(_uploads(), settings=settings, provider_id="x", **kw)]
    finally:
        pl.build_provider = orig
    return events


# ---- output parsing -----------------------------------------------------------
def test_extract_json_handles_fences_and_chatter():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure! Here you go: {"a": {"b": "}"}} thanks') == {"a": {"b": "}"}}
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_parse_output_coerces_confidence_and_strings():
    out = parse_output(json.dumps({"summary": "s", "root_cause": {"title": "t", "confidence": 0.85}, "ruled_out": "one thing"}))
    assert out.root_cause.confidence == 85 and out.ruled_out == ["one thing"]


# ---- pipeline with a model -----------------------------------------------------
@pytest.mark.asyncio
async def test_pipeline_with_llm_blends_confidence_and_redacts(settings):
    provider = FakeProvider([LLM_REPLY])
    events = await _run(settings, provider)
    result = events[-1]["data"]
    a = result["analysis"]
    assert a["provider"] == "fake" and not a["degraded"]
    rc = a["root_cause"]
    assert rc["title"].startswith(".NET Desktop Runtime 10") and rc["finding_ids"] == ["F1"]
    assert rc["confidence"]["llm_reported"] == 98 and rc["confidence"]["score"] <= 95 + 10
    assert [s["order"] for s in a["remediation"]] == [1]
    stages = [e["stage"] for e in events if e["type"] == "progress" and e["status"] == "done"]
    assert stages == ["extract", "detect", "scan", "evidence", "analyze", "report"]
    # the prompt contained the case, chatter-free evidence, and the injection guard
    system, user = provider.calls[0]
    assert "untrusted data" in system and "Desktop Runtime" in user and "MSIHANDLE" not in user
    assert "# Deployment Log Analysis" in result["report_markdown"]


@pytest.mark.asyncio
async def test_provider_failure_falls_back_to_pattern_result(settings):
    events = await _run(settings, FakeProvider([LLMError("API returned 429")]))
    a = events[-1]["data"]["analysis"]
    assert a["degraded"] and "429" in a["notes"][0]
    assert a["root_cause"]["title"] == ".NET runtime prerequisite is not installed"


@pytest.mark.asyncio
async def test_invalid_json_twice_falls_back(settings):
    provider = FakeProvider(["not json", "still not json"])
    a = (await _run(settings, provider))[-1]["data"]["analysis"]
    assert a["degraded"] and len(provider.calls) == 2


@pytest.mark.asyncio
async def test_hallucinated_finding_id_is_ignored(settings):
    reply = json.loads(json.dumps(LLM_REPLY))
    reply["root_cause"]["finding_ids"] = ["F99"]
    a = (await _run(settings, FakeProvider([reply])))[-1]["data"]["analysis"]
    assert a["root_cause"]["finding_ids"] == ["F1"]


@pytest.mark.asyncio
async def test_pattern_only_mode_needs_no_provider(settings):
    events = [e async for e in run_analysis(_uploads(), settings=settings, provider_id="none")]
    a = events[-1]["data"]["analysis"]
    assert a["provider"] == "none" and a["root_cause"]["confidence"]["label"] == "High"
    assert a["remediation"] and a["further_data"]


@pytest.mark.asyncio
async def test_empty_or_binary_upload_gives_clear_error(settings):
    events = [e async for e in run_analysis([("x.zip", make_zip({"a.exe": b"MZ"}))], settings=settings, provider_id="none")]
    assert events[-1]["type"] == "error" and "No readable log files" in events[-1]["message"]


# ---- report ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_markdown_report_has_evidence_and_no_ai_fluff(settings):
    md = [e async for e in run_analysis(_uploads(), settings=settings, provider_id="none")][-1]["data"]["report_markdown"]
    for heading in ("## Summary", "## Most likely root cause", "## What to do", "## Supporting evidence", "## All findings", "## Files analysed"):
        assert heading in md
    assert "Desktop Runtime 10.0" in md and ">>" in md
    assert "MSIHANDLE" not in md  # routine chatter is collapsed in the report
    assert "routine lines hidden" in md


# ---- providers (real SDKs, mocked HTTP) --------------------------------------------
def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _aclient(handler):
    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


@pytest.mark.asyncio
async def test_anthropic_provider_request_and_response():
    seen = {}

    def handler(req: httpx2.Request):
        seen["url"], seen["key"], seen["body"] = str(req.url), req.headers.get("x-api-key"), json.loads(req.content)
        return httpx2.Response(200, json={"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
                                         "content": [{"type": "text", "text": "{\"ok\": true}"}], "stop_reason": "end_turn",
                                         "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}})

    s = Settings(_env_file=None, anthropic_api_key="sk-test")
    p = build_provider("anthropic", s, _aclient(handler))
    assert await p.complete("sys", "usr", max_tokens=1000) == '{"ok": true}'
    b = seen["body"]
    assert seen["url"].endswith("/v1/messages") and seen["key"] == "sk-test"
    assert b["model"] == "claude-opus-5-5" and b["system"] == "sys" and b["output_config"] == {"effort": "high"}
    assert "temperature" not in b and "thinking" not in b and b["messages"] == [{"role": "user", "content": "usr"}]


@pytest.mark.asyncio
@pytest.mark.parametrize("stop,msg", [("refusal", "declined"), ("max_tokens", "output tokens")])
async def test_anthropic_refusal_and_truncation_raise(stop, msg):
    def handler(req):
        return httpx2.Response(200, json={"id": "m", "type": "message", "role": "assistant", "model": "x",
                                         "content": [{"type": "text", "text": "partial"}], "stop_reason": stop,
                                         "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}})
    p = build_provider("anthropic", Settings(_env_file=None, anthropic_api_key="k"), _aclient(handler))
    with pytest.raises(LLMError, match=msg):
        await p.complete("s", "u", max_tokens=10)


@pytest.mark.asyncio
async def test_anthropic_http_error_becomes_llm_error():
    p = build_provider("anthropic", Settings(_env_file=None, anthropic_api_key="k"),
                       _aclient(lambda r: httpx2.Response(401, json={"type": "error", "error": {"type": "authentication_error", "message": "bad"}})))
    with pytest.raises(LLMError, match="401: .*bad"):
        await p.complete("s", "u", max_tokens=10)


def _chat_reply():
    return {"id": "c1", "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "{\"ok\": 1}"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


@pytest.mark.asyncio
async def test_openai_provider_request_and_response():
    seen = {}

    def handler(req):
        seen.update(url=str(req.url), auth=req.headers.get("authorization"), body=json.loads(req.content))
        return httpx.Response(200, json=_chat_reply())

    p = build_provider("openai", Settings(_env_file=None, openai_api_key="sk-o", openai_model="gpt-x"), _client(handler))
    assert await p.complete("sys", "usr", max_tokens=500) == '{"ok": 1}'
    assert seen["url"].endswith("/chat/completions") and seen["auth"] == "Bearer sk-o"
    assert seen["body"]["model"] == "gpt-x" and seen["body"]["max_completion_tokens"] == 500
    assert seen["body"]["response_format"] == {"type": "json_object"}
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]


@pytest.mark.asyncio
async def test_azure_openai_provider_uses_deployment_and_api_key():
    seen = {}

    def handler(req):
        seen.update(url=str(req.url), key=req.headers.get("api-key"))
        return httpx.Response(200, json=_chat_reply())

    s = Settings(_env_file=None, azure_openai_endpoint="https://example.openai.azure.com", azure_openai_deployment="dep1",
                 azure_openai_api_key="az-key", azure_openai_api_version="2024-10-21")
    p = build_provider("azure_openai", s, _client(handler))
    await p.complete("s", "u", max_tokens=10)
    assert "/openai/deployments/dep1/chat/completions" in seen["url"] and "api-version=2024-10-21" in seen["url"]
    assert seen["key"] == "az-key"


def test_provider_selection_rules():
    none = Settings(_env_file=None)
    assert resolve_provider_id(None, none) == "none"
    both = Settings(_env_file=None, openai_api_key="a", anthropic_api_key="b")
    assert resolve_provider_id(None, both) == "anthropic"
    assert resolve_provider_id("openai", both) == "openai"
    with pytest.raises(ValueError, match="not configured"):
        build_provider("azure_openai", both)
    with pytest.raises(ValueError, match="Unknown"):
        build_provider("bogus", both)
    assert build_provider("none", both) is None
    assert {p.id: p.configured for p in list_providers(both)} == {"anthropic": True, "azure_openai": False, "openai": True, "none": True}


# ---- HTTP API ----------------------------------------------------------------------
@pytest.fixture
def client(monkeypatch, settings):
    import app.api.routes as routes
    from app.main import create_app
    monkeypatch.setattr(routes, "get_settings", lambda: settings)
    return TestClient(create_app())


def test_health_and_config_do_not_leak_secrets(client, settings, monkeypatch):
    import app.api.routes as routes
    leaky = Settings(_env_file=None, anthropic_api_key="sk-ant-SECRET", openai_api_key="sk-openai-SECRET")
    monkeypatch.setattr(routes, "get_settings", lambda: leaky)
    assert client.get("/api/health").json()["status"] == "ok"
    r = client.get("/api/config")
    assert "SECRET" not in r.text and r.headers["cache-control"] == "no-store"
    assert r.json()["default_provider"] == "anthropic"


def test_analyze_streams_progress_then_result(client):
    dup, _ = dup_failure_log()
    zipped = make_zip({"a/Dell.EXE.log": dup})
    r = client.post("/api/analyze", files=[("files", ("Logs.zip", zipped, "application/zip"))],
                    data={"provider": "none", "context": "Dell Command Update via Patch My PC"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson")
    assert r.headers["cache-control"] == "no-store"
    events = [json.loads(line) for line in r.text.splitlines() if line]
    assert events[0]["type"] == "progress" and events[-1]["type"] == "result"
    data = events[-1]["data"]
    assert data["context"] == "Dell Command Update via Patch My PC"
    assert data["findings"][0]["pattern_id"] == "dep-dotnet-missing"


def test_upload_limit_returns_413(monkeypatch, settings):
    import app.api.routes as routes
    from app.main import create_app
    tiny = settings.model_copy(update={"max_upload_mb": 1})
    monkeypatch.setattr(routes, "get_settings", lambda: tiny)
    c = TestClient(create_app())
    r = c.post("/api/analyze", files=[("files", ("big.log", b"x" * (2 * 1024 * 1024), "text/plain"))])
    assert r.status_code == 413


def test_unconfigured_provider_is_reported_as_error_event(client):
    r = client.post("/api/analyze", files=[("files", ("a.log", b"ERROR boom\n", "text/plain"))], data={"provider": "openai"})
    last = json.loads(r.text.splitlines()[-1])
    assert last["type"] == "error" and "not configured" in last["message"]


def test_nothing_is_written_to_disk_or_kept_in_memory(client, tmp_path):
    import app.core.pipeline as pl
    before = set(vars(pl))
    client.post("/api/analyze", files=[("files", ("a.log", b"ERROR boom\n", "text/plain"))], data={"provider": "none"})
    after = set(vars(pl))
    assert before == after  # no module-level state grew


@pytest.mark.asyncio
async def test_provider_error_message_is_surfaced():
    body = {"type": "error", "error": {"type": "invalid_request_error", "message": "Your credit balance is too low to access the API."}}
    p = build_provider("anthropic", Settings(_env_file=None, anthropic_api_key="k"), _aclient(lambda r: httpx2.Response(400, json=body)))
    with pytest.raises(LLMError, match="400: .*credit balance is too low"):
        await p.complete("s", "u", max_tokens=10)
