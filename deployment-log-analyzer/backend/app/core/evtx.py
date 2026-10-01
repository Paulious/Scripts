"""Windows event logs (.evtx) as plain text lines.

An event log is binary, so it is turned into one text line per event and then goes through the
same pattern scan as every other log. The line starts with a timestamp and a level word, which is
what the parsers look for:

    2026-10-01 12:10:51 Error   Service Control Manager [7000] The Foo service failed to start ...

Errors and warnings are always kept. Information events are kept only when the log is small,
because a busy Application or System log holds tens of thousands of them and they bury the signal.
"""
from __future__ import annotations

import io
import json
from typing import Any

try:  # a compiled library; the app still runs without it and just skips event logs
    from evtx import PyEvtxParser
except ImportError:  # pragma: no cover
    PyEvtxParser = None  # type: ignore[assignment,misc]

MAX_LINES = 60_000
KEEP_INFO_BELOW = 4_000
MAX_TEXT = 700
HEADER = "#EVTX"
_LEVELS = {1: "Fatal", 2: "Error", 3: "Warning", 4: "Info", 5: "Debug", 0: "Info"}


class EvtxError(Exception):
    pass


def available() -> bool:
    return PyEvtxParser is not None


def _text(node: Any, out: list[str], depth: int = 0) -> None:
    """Flatten whatever the event carries (EventData, UserData) into readable words."""
    if node is None or depth > 6:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("#attributes", "Binary", "xmlns"):
                continue
            if isinstance(value, (dict, list)):
                _text(value, out, depth + 1)
            elif value not in (None, ""):
                out.append(str(value) if key in ("#text", "Data") else f"{key}={value}")
    elif isinstance(node, list):
        for item in node:
            _text(item, out, depth + 1)
    elif node != "":
        out.append(str(node))


def _field(node: Any) -> Any:
    return node.get("#text") if isinstance(node, dict) else node


def _event_line(rec: dict) -> tuple[int, str, str] | None:
    event = rec.get("Event", rec)
    system = event.get("System", {})
    level = _field(system.get("Level"))
    try:
        level = int(level)
    except (TypeError, ValueError):
        level = 4
    stamp = str(((system.get("TimeCreated") or {}).get("#attributes") or {}).get("SystemTime", ""))
    stamp = stamp.replace("T", " ")[:19]
    provider = ((system.get("Provider") or {}).get("#attributes") or {}).get("Name", "?")
    eid = _field(system.get("EventID"))
    words: list[str] = []
    _text(event.get("EventData"), words)
    _text(event.get("UserData"), words)
    body = " ".join(w.strip() for w in words if w.strip())
    body = " ".join(body.split())[:MAX_TEXT]
    word = _LEVELS.get(level, "Info")
    return level, str(system.get("Channel", "")), f"{stamp} {word:<7} {provider} [{eid}] {body}".rstrip()


def evtx_to_text(data: bytes) -> bytes:
    if PyEvtxParser is None:
        raise EvtxError("the event log reader is not installed")
    lines: list[tuple[int, str]] = []
    channel, total = "", 0
    try:
        parser = PyEvtxParser(io.BytesIO(data))
        for record in parser.records_json():
            total += 1
            parsed = _event_line(json.loads(record["data"]))
            if parsed is None:
                continue
            level, chan, line = parsed
            channel = channel or chan
            lines.append((level, line))
    except EvtxError:
        raise
    except Exception as exc:  # noqa: BLE001 - corrupt or truncated file
        if not lines:
            raise EvtxError(f"could not read event log ({exc.__class__.__name__})") from exc
    keep_info = total <= KEEP_INFO_BELOW
    kept = [line for level, line in lines if level <= 3 or keep_info]
    kept = kept[-MAX_LINES:]
    head = f"{HEADER} {channel or 'event log'} | {total:,} events, {len(kept):,} shown" + ("" if keep_info else " (errors and warnings only)")
    return ("\n".join([head, *kept]) + "\n").encode("utf-8")
