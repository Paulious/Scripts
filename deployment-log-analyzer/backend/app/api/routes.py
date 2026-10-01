from __future__ import annotations

import asyncio
import json
import logging
import resource
import secrets
import time
from typing import AsyncIterator

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from app.config import get_settings
from app.core.pipeline import STAGES, run_analysis, run_enhance
from app.llm import list_providers, resolve_provider_id
from app.models import AnalysisResult
from app.patterns import get_library

router = APIRouter(prefix="/api")
# uvicorn's own logger, so these lines show up in the container log. Sizes and timings only, never file names or contents.
log = logging.getLogger("uvicorn.error")

CHUNK = 1024 * 1024
PING_SECONDS = 15


@router.get("/health")
async def health() -> dict:
    lib = get_library()
    return {"status": "ok", "patterns": len(lib.patterns), "suppressions": len(lib.suppressions)}


@router.get("/selftest")
async def selftest(kb: int = 900, chunk_kb: int = 4, seconds: float = 0):
    """Sends kb KB of filler in chunk_kb pieces, optionally spread over some seconds. Open it in the browser
    to check that a reply of that size gets through the whole hosting path. Carries no data."""
    kb, chunk_kb, seconds = max(1, min(kb, 20000)), max(1, min(chunk_kb, 1024)), max(0.0, min(seconds, 120.0))
    pieces = max(1, kb // chunk_kb)

    async def gen() -> AsyncIterator[bytes]:
        for i in range(pieces):
            yield (json.dumps({"n": i, "pad": "x" * (chunk_kb * 1024 - 40)}) + "\n").encode()
            if seconds:
                await asyncio.sleep(seconds / pieces)
        yield (json.dumps({"done": True, "kb": kb, "chunk_kb": chunk_kb}) + "\n").encode()

    return StreamingResponse(gen(), media_type="text/plain", headers={"Cache-Control": "no-store"})


@router.get("/config")
async def config() -> dict:
    """Everything the UI needs to know. No secrets, only which providers exist."""
    s = get_settings()
    default = resolve_provider_id(None, s)
    return {
        "providers": [p.model_dump() for p in list_providers(s)],
        "default_provider": default,
        # The website runs the pattern pass first and offers AI as an optional second step.
        "ai_available": default != "none",
        "ai_default_provider": default if default != "none" else None,
        "stages": [{"id": i, "label": label} for i, label in STAGES],
        "limits": {"max_upload_mb": s.max_upload_mb, "evidence_context_lines": s.evidence_context_lines},
        "redact_default": s.redact_for_llm,
    }


async def _read_all(files: list[UploadFile], limit_bytes: int) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    total = 0
    for f in files:
        buf = bytearray()
        while chunk := await f.read(CHUNK):
            total += len(chunk)
            if total > limit_bytes:
                raise HTTPException(413, f"Upload is larger than the {limit_bytes // (1024 * 1024)} MB limit")
            buf += chunk
        await f.close()
        out.append((f.filename or "upload.log", bytes(buf)))
    return out


def _line(ev: dict) -> bytes:
    return (json.dumps(ev, separators=(",", ":")) + "\n").encode()


# Azure's ingress cuts a single reply somewhere between 200 and 400 KB. A finished result is often bigger
# than that, so the stream only announces it and the browser fetches it in small pieces.
PART_CHARS = 50_000
RESULT_TTL = 600
MAX_HELD = 20
_held: dict[str, tuple[float, list[str]]] = {}


def _sweep() -> None:
    now = time.monotonic()
    for key in [k for k, (exp, _) in _held.items() if exp < now]:
        del _held[key]
    while len(_held) > MAX_HELD:
        del _held[min(_held, key=lambda k: _held[k][0])]


def hold_result(data: dict) -> dict:
    """Keep a finished result in memory for a few minutes so the browser can collect it in pieces.
    Nothing touches disk, and it is dropped as soon as the browser says it has it."""
    _sweep()
    text = json.dumps(data, separators=(",", ":"))
    parts = [text[i:i + PART_CHARS] for i in range(0, len(text), PART_CHARS)] or [""]
    rid = secrets.token_urlsafe(16)
    _held[rid] = (time.monotonic() + RESULT_TTL, parts)
    return {"type": "result_ready", "id": rid, "parts": len(parts)}


@router.get("/result/{rid}/{index}")
async def result_part(rid: str, index: int):
    _sweep()
    entry = _held.get(rid)
    if not entry or not 0 <= index < len(entry[1]):
        raise HTTPException(404, "That result has expired. Run the analysis again.")
    return PlainTextResponse(entry[1][index], headers={"Cache-Control": "no-store"})


@router.delete("/result/{rid}")
async def result_done(rid: str):
    _held.pop(rid, None)
    return {"ok": True}


def _encode(ev: dict) -> list[bytes]:
    if ev.get("type") == "result":
        return [_line(hold_result(ev["data"]))]
    return [_line(ev)]


async def _stream(events: AsyncIterator[dict]) -> AsyncIterator[bytes]:
    """Yield NDJSON, with a ping every few seconds so proxies don't drop a quiet connection
    during a long LLM call."""
    queue: asyncio.Queue = asyncio.Queue()
    started = time.monotonic()
    sent = 0
    outcome = "client went away"

    async def pump() -> None:
        try:
            async for ev in events:
                await queue.put(ev)
        except Exception as exc:  # noqa: BLE001
            log.exception("analysis crashed")
            await queue.put({"type": "error", "message": f"Analysis failed unexpectedly ({exc.__class__.__name__})"})
        finally:
            await queue.put(None)

    task = asyncio.create_task(pump())
    try:
        while True:
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=PING_SECONDS)
            except asyncio.TimeoutError:
                yield b'{"type":"ping"}\n'
                continue
            if ev is None:
                break
            for chunk in _encode(ev):
                sent += len(chunk)
                yield chunk
        outcome = "finished"
    finally:
        task.cancel()
        peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024
        log.info("analysis %s after %.1fs, %d KB sent, peak memory %d MB", outcome, time.monotonic() - started, sent // 1024, peak_mb)


@router.post("/analyze")
async def analyze(
    request: Request,
    files: list[UploadFile] = File(...),
    context: str = Form(""),
    provider: str = Form(""),
    redact: bool | None = Form(None),
):
    s = get_settings()
    limit = s.max_upload_mb * 1024 * 1024
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit + 1024 * 1024:
        raise HTTPException(413, f"Upload is larger than the {s.max_upload_mb} MB limit")
    if not files:
        raise HTTPException(400, "No files uploaded")

    uploads = await _read_all(files, limit)
    log.info("analysis started: %d file(s), %.1f MB", len(uploads), sum(len(d) for _, d in uploads) / 1048576)
    events = run_analysis(
        uploads, settings=s, context=context.strip()[:2000] or None,
        provider_id=provider or None, redact=redact,
    )
    return StreamingResponse(
        _stream(events),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


class EnhanceRequest(BaseModel):
    result: AnalysisResult
    provider: str = ""
    redact: bool | None = None


MAX_ENHANCE_BYTES = 25 * 1024 * 1024


@router.post("/enhance")
async def enhance(request: Request, body: EnhanceRequest):
    """Add an AI-written analysis to a pattern result the client already holds.

    The server keeps nothing between the two calls: the browser sends its own result back.
    The result is treated as untrusted input, like the log text it came from.
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_ENHANCE_BYTES:
        raise HTTPException(413, "Result is too large to send for AI analysis")
    s = get_settings()
    if resolve_provider_id(body.provider or None, s) == "none":
        raise HTTPException(400, "No AI provider is selected or configured on the server")
    events = run_enhance(body.result, settings=s, provider_id=body.provider, redact=body.redact)
    return StreamingResponse(
        _stream(events),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
