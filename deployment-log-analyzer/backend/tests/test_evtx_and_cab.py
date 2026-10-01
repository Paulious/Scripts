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


ENTRA = ("2026-09-30 10:00:00 ERROR script failed: AADSTS700016: Application with identifier "
         "'1659b7df-78bd-4907-81bc-717b5890bd10' was not found in the directory 'x'\n")


@pytest.mark.asyncio
async def test_same_problem_in_many_logs_is_one_finding_and_cabinet_copies_are_skipped(settings):
    from cabarchive import CabArchive, CabFile
    from app.core.pipeline import run_analysis
    body = ("noise line\n" * 20 + ENTRA + "noise line\n" * 20).encode()
    cab = CabArchive()
    cab["healthscripts.log"] = CabFile(body)           # a copy of the loose file
    zipped = make_zip({
        "logs/healthscripts.log": body,
        "logs/healthscripts-20260928.log": body + body,   # a rotated log with the same problem twice
        "mdm/mdmlogs.cab": cab.save(compress=True),
    })
    events = [e async for e in run_analysis([("Diag.zip", zipped)], settings=settings, provider_id="none")]
    result = next(e for e in events if e["type"] == "result")["data"]
    entra = [f for f in result["findings"] if f["pattern_id"] == "entra-app-not-found"]
    assert len(entra) == 1
    assert entra[0]["other_files"] and entra[0]["match_count"] == 3
    reasons = [s["reason"] for s in result["skipped"]]
    assert any("copy of a log" in r for r in reasons)
    assert all(".cab/" not in f["path"] for f in result["files"])


def test_hash_mismatch_is_not_reported_for_unrelated_logs():
    p = get_library().get("intune-hash-mismatch")
    line = "Defender MOF hash mismatch. Current: febff51d, Stored: (null). Re-registering..."
    assert p.applies_to and "generic" not in p.applies_to
    assert "intune_ime" in p.applies_to


def test_defender_bundle_is_read_last_and_briefly():
    from app.patterns.triage import classify
    d = classify("(65) FoldersFiles ProgramData_Microsoft_Windows_Defender_Support_MpSupportFiles_cab/mpsupportfiles.cab/C_/x/MPLog.log")
    assert d.tier == "low" and d.max_lines == 15000
    assert classify("(62) Events System Events.evtx").tier == "normal"


def test_defender_bundle_keeps_its_logs_and_skips_its_data_files():
    from app.patterns.triage import classify
    base = "(65) FoldersFiles ProgramData_Microsoft_Windows_Defender_Support_MpSupportFiles_cab/mpsupportfiles.cab/C_/ProgramData/Microsoft/Windows Defender/Support/"
    assert classify(base + "MpCmdRun-SystemTemp.log").tier == "low"
    assert classify(base + "topTraffic").tier == "skip"
    assert classify(base + "system.evtx").tier == "skip"


def test_settings_dumps_do_not_produce_unclassified_error_findings():
    from app.core.scanner import _DATA_FILE
    for name in ("x/MDMDiagReport.xml", "x/energy-report.html", "x/dump.reg", "(5) RegistryKey HKLM_x export.reg"):
        assert _DATA_FILE.search(name)
    assert not _DATA_FILE.search("x/healthscripts.log")
