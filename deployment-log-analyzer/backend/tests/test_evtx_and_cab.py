import json
import shutil

import pytest

from app.core import cab as cabmod
from app.core import evtx as evtxmod
from app.core.archive import Limits, sniff_archive
from app.core.evtx import EvtxError, evtx_to_text
from app.core.walk import Member, walk_upload
from app.parsers import detect_parser
from app.patterns import get_library

from .fixtures import make_zip


def _rec(level, provider, eid, channel="System", data=None, ts="2026-10-01T12:00:00.000000Z"):
    return {"data": json.dumps({"Event": {
        "System": {"Provider": {"#attributes": {"Name": provider}}, "EventID": {"#attributes": {"Qualifiers": 0}, "#text": eid},
                   "Level": level, "TimeCreated": {"#attributes": {"SystemTime": ts}}, "Channel": channel},
        "EventData": data or {"Data": {"#text": ["x"]}}}})}


class FakeParser:
    def __init__(self, _):
        pass

    def records_json(self):
        yield _rec(2, "Service Control Manager", 7000, data={"param1": "Spooler", "param2": "%%2"})
        yield _rec(4, "EventLog", 6005)
        yield _rec(3, "Microsoft-Windows-DistributedCOM", 10016)
        yield _rec(2, "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider", 404)


def test_evtx_becomes_text_lines_with_time_and_level(monkeypatch):
    monkeypatch.setattr(evtxmod, "PyEvtxParser", FakeParser)
    text = evtx_to_text(b"x").decode()
    first, *rest = text.splitlines()
    assert first.startswith("#EVTX System")
    assert "2026-10-01 12:00:00 Error   Service Control Manager [7000] param1=Spooler" in rest[0]
    parser, conf = detect_parser("System.evtx", text.splitlines())
    assert parser.id == "windows_event_log" and conf > 0.9


def test_busy_logs_keep_only_errors_and_warnings(monkeypatch):
    class Busy(FakeParser):
        def records_json(self):
            for _ in range(evtxmod.KEEP_INFO_BELOW + 10):
                yield _rec(4, "Noisy", 1)
            yield _rec(2, "Service Control Manager", 7031)
    monkeypatch.setattr(evtxmod, "PyEvtxParser", Busy)
    lines = evtx_to_text(b"x").decode().splitlines()
    assert len(lines) == 2 and "errors and warnings only" in lines[0]


def test_unreadable_event_log_is_reported(monkeypatch):
    class Broken:
        def __init__(self, _):
            raise ValueError("bad header")
    monkeypatch.setattr(evtxmod, "PyEvtxParser", Broken)
    with pytest.raises(EvtxError):
        evtx_to_text(b"x")


def test_event_patterns_match_and_dcom_is_ruled_out():
    lib = get_library()
    line = "2026-10-01 12:00:00 Error   Service Control Manager [7000] param1=Spooler param2=%%2"
    hits = [p.id for p in lib.for_log_type("windows_event_log") if p.match(line)[0]]
    assert "evt-service-failed" in hits
    assert lib.suppression_for("2026-10-01 12:00:00 Warning Microsoft-Windows-DistributedCOM [10016] x")
    mdm = "2026-10-01 12:00:00 Error   Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider [404] x"
    assert "evt-mdm-error" in [p.id for p in lib.for_log_type("windows_event_log") if p.match(mdm)[0]]


@pytest.fixture
def small_cab():
    if cabmod.CabArchive is None:
        pytest.skip("cabarchive missing")
    from cabarchive import CabArchive, CabFile
    arc = CabArchive()
    arc["Logs/a.log"] = CabFile(b"hello\nERROR: it broke\n")
    arc["b.txt"] = CabFile(b"second file\n")
    return arc.save(compress=True)


def test_cab_members_are_listed_inside_a_zip(small_cab):
    assert sniff_archive(small_cab) == "cab"
    zipped = make_zip({"outer/pack.cab": small_cab, "x.log": b"y"})
    items = list(walk_upload("d.zip", zipped, Limits(max_total_bytes=10**7, max_file_bytes=10**7, max_files=100, max_depth=3)))
    paths = {i.path for i in items if isinstance(i, Member)}
    assert any(p.endswith("pack.cab/Logs/a.log") for p in paths) and any(p.endswith("b.txt") for p in paths)
    member = next(i for i in items if isinstance(i, Member) and i.path.endswith("a.log"))
    assert b"it broke" in member.read()


@pytest.mark.skipif(not shutil.which("cabextract"), reason="cabextract not installed")
def test_lzx_style_cabs_fall_back_to_cabextract(small_cab, monkeypatch):
    def unsupported(*a, **k):
        raise cabmod.NotSupportedError("LZX compression not supported")
    monkeypatch.setattr(cabmod, "_with_python", unsupported)
    files = dict(cabmod.read_cab(small_cab, Limits(max_total_bytes=10**7, max_file_bytes=10**7, max_files=100, max_depth=3)))
    assert files["Logs/a.log"].startswith(b"hello") and "b.txt" in files


def test_cab_without_a_usable_reader_is_skipped_with_a_reason(small_cab, monkeypatch):
    monkeypatch.setattr(cabmod, "_with_python", lambda *a, **k: (_ for _ in ()).throw(cabmod.NotSupportedError("LZX")))
    monkeypatch.setattr(cabmod.shutil, "which", lambda _: None)
    items = list(walk_upload("pack.cab", small_cab, Limits(max_total_bytes=10**7, max_file_bytes=10**7, max_files=100, max_depth=3)))
    assert len(items) == 1 and "LZX" in items[0].reason
