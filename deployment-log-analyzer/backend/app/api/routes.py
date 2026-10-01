from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse

from app.config import get_settings
from app.core.pipeline import STAGES, run_analysis
from app.llm import list_providers, resolve_provider_id
from app.patterns import get_library

router = APIRouter(prefix="/api")

CHUNK = 1024 * 1024
PING_SECONDS = 15


@router.get("/health")
async def health() -> dict:
    lib = get_library()
    return {"status": "ok", "patterns": len(lib.patterns), "suppressions": len(lib.suppressions)}


@router.get("/config")
async def config() -> dict:
    """Everything the UI needs to know. No secrets, only which providers exist."""
    s = get_settings()
    return {
        "providers": [p.model_dump() for p in list_providers(s)],
        "default_provider": resolve_provider_id(None, s),
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


async def _stream(events: AsyncIterator[dict]) -> AsyncIterator[bytes]:
    """Yield NDJSON, with a ping every few seconds so proxies don't drop a quiet connection
    during a long LLM call."""
    queue: asyncio.Queue = asyncio.Queue()

    async def pump() -> None:
        try:
            async for ev in events:
                await queue.put(ev)
        except Exception as exc:  # noqa: BLE001
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
            yield (json.dumps(ev, separators=(",", ":")) + "\n").encode()
    finally:
        task.cancel()


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
    events = run_analysis(
        uploads, settings=s, context=context.strip()[:2000] or None,
        provider_id=provider or None, redact=redact,
    )
    return StreamingResponse(
        _stream(events),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
