"""Behaviour for big Intune diagnostics packages: triage, budgets, tail reading, fast scanning."""
import pytest

from app.core.archive import Limits
from app.core.pipeline import build_plan, run_analysis
from app.core.walk import Member, walk_upload
from app.patterns import get_library
from app.patterns.literals import required_literals
from app.patterns.triage import classify
from app.models import SkippedFile

from .fixtures import dup_failure_log, healthy_msi_log, make_zip, scriptrunner_log

LIMITS = Limits(max_total_bytes=500_000_000, max_file_bytes=100_000_000, max_files=2000, max_depth=3)

IME = "(40) FoldersFiles ProgramData_Microsoft_IntuneManagementExtension_Logs\\IntuneManagementExtension.log"
DSREG = "(12) Command windir_system32_Dsregcmd_exe_status output.log"
DSREG_TEXT = "\r\n".join([
    "+---------------------------------------------+", "| Device State                                |", "+---------------------------------------------+", "",
    "             AzureAdJoined : YES", "          EnterpriseJoined : NO", "              DomainJoined : NO", "                DeviceName : CLE-1", "",
    "+---------------------------------------------+", "| Device Details                              |", "+---------------------------------------------+", "",
    "              DeviceId : 11111111-2222-3333-4444-555555555555",
    "        DeviceAuthStatus : FAILED. Device is either disabled or deleted", "",
]).encode()


def cm(msg, t="10:00:00.000000", typ=1):
    return f'<![LOG[{msg}]LOG]!><time="{t}" date="10-01-2026" component="W" context="" type="{typ}" thread="1" file="">'


def ime_log(lines=300, fail_at=None):
    body = [cm(f"Heartbeat {i}") for i in range(lines)]
    if fail_at is not None:
        body[fail_at] = cm("[Win32App] The application was not detected after installation (0x87D1041C)", typ=3)
    return "\r\n".join(body).encode()


def package():
    files = {
        IME: ime_log(300, fail_at=250),
        DSREG: DSREG_TEXT,
        "(62) Events System Events.evtx": b"ElfFile\x00" + b"\x01" * 100,
        "(74) FoldersFiles temp_MDMDiagnostics_mdmlogs_cab\\mdmlogs.cab": b"MSCF\x00\x00\x00\x00" + b"\x01" * 100,
        "(70) FoldersFiles windir_Logs_WindowsUpdate_etl\\WindowsUpdate.1.etl": b"\x01" * 100,
        "(11) No Results - Error [0x80070002] FoldersFiles windir_ccmsetup_logs_log\\x.log": b"nothing",
    }
    for i in range(8):
        files[f"(69) FoldersFiles ProgramFiles_Microsoft_EPM_Agent_Logs\\epm-2026093{i}.log"] = ime_log(50)
    return make_zip(files)


async def run(settings, data, **kw):
    return [e async for e in run_analysis([("Diag.zip", data)], settings=settings, provider_id="none", **kw)]


# ---- triage ----------------------------------------------------------------------------------
def test_triage_classifies_real_package_names():
    assert classify("(62) Events System Events.evtx").tier == "skip"
    assert classify("x\\mpsupportfiles.cab").tier == "skip"
    assert classify("(72) FoldersFiles windir_Logs_WindowsUpdate_etl\\a.etl").tier == "skip"
    assert classify("(11) No Results - Error [0x80070002] FoldersFiles windir_ccmsetup_logs_log\\x").tier == "skip"
    assert classify(IME).tier == "high"
    assert classify(DSREG).tier == "high"
    assert classify("(5) FoldersFiles windir_SoftwareDistribution_ReportingEvents_log\\ReportingEvents.log").tier == "high"
    assert classify("(69) FoldersFiles ProgramFiles_Microsoft_EPM_Agent_Logs\\epmservicejobs-1.log").tier == "low"
    assert classify("(33) Command windir_system32_ipconfig_exe_all output.log").tier == "normal"


def test_plan_reads_important_files_first_and_keeps_only_newest_of_big_groups():
    members = [Member(f"(69) FoldersFiles ProgramFiles_Microsoft_EPM_Agent_Logs\\epm-{i}.log", 10, lambda: b"x") for i in range(10)]
    members += [Member(IME, 10, lambda: b"x"), Member("(33) Command ipconfig output.log", 10, lambda: b"x")]
    plan, skipped = build_plan(members)
    tiers = [p.decision.tier for p in plan]
    assert tiers == sorted(tiers, key={"high": 0, "normal": 1, "low": 2}.get)
    epm_read = [p.path for p in plan if "EPM" in p.path]
    assert len(epm_read) == 6 and all(f"epm-{i}.log" in " ".join(epm_read) for i in (9, 8, 7, 6, 5, 4))  # newest by name
    assert sum("older file in a large group" in s.reason for s in skipped) == 4


# ---- end to end -------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_package_is_triaged_and_the_real_failure_is_found(settings):
    events = await run(settings, package())
    data = events[-1]["data"]
    paths = [f["path"] for f in data["files"]]
    assert all("EPM_Agent_Logs" not in p for p in paths[:2])                                  # high priority files come first
    assert paths[-1].endswith(".log") and "EPM_Agent_Logs" in paths[-1]                        # low priority files come last
    reasons = {g["reason"]: g["count"] for g in data["skipped_groups"]}
    assert any("trace log" in r for r in reasons) and any("event logs" in r for r in reasons) and any("CAB" in r for r in reasons)
    assert any("not present on the device" in r for r in reasons)
    ids = [f["pattern_id"] for f in data["findings"]]
    assert "intune-not-detected" in ids and "dsreg-device-auth-failed" in ids
    kinds = {f["path"].rsplit("/", 1)[-1]: f["log_type"] for f in data["files"]}   # backslashes in zip names become '/'
    assert kinds["IntuneManagementExtension.log"] == "intune_ime"
    assert kinds["(12) Command windir_system32_Dsregcmd_exe_status output.log"] == "dsregcmd"
    dsreg = next(f for f in data["files"] if f["log_type"] == "dsregcmd")
    assert dsreg["facts"]["AzureAdJoined"] == "YES" and dsreg["facts"]["DeviceName"] == "CLE-1"


@pytest.mark.asyncio
async def test_tail_reading_keeps_original_line_numbers(settings):
    small = settings.model_copy(update={"max_lines_per_file": 100})
    lines = [f"2026-10-01 10:00:{i % 60:02d} INFO heartbeat {i}" for i in range(500)]
    lines[480] = "2026-10-01 10:08:00 ERROR installer reported: another installation is already in progress (Error 1618)"
    data = make_zip({"(33) Command app output.log": "\r\n".join(lines).encode()})
    d = (await run(small, data))[-1]["data"]
    f = next(x for x in d["findings"] if x["pattern_id"] == "msi-another-install")
    assert f["first_line"] == 481                                   # the line number in the real file, not in the tail
    w = f["evidence"][0]
    assert w["start_line"] == 401 and w["end_line"] == 500           # only the tail exists; window is clamped to it
    anchor = next(l for l in w["lines"] if l.get("anchor"))
    assert anchor["n"] == 481 and "Error 1618" in anchor["text"]
    note = d["files"][0]["facts"]["Note"]
    assert "last 100 of 500" in note and "401" in note


@pytest.mark.asyncio
async def test_budget_stops_low_priority_files_but_keeps_high_priority(settings):
    tight = settings.model_copy(update={"max_total_lines": 300})
    d = (await run(tight, package()))[-1]["data"]
    read = [f["path"] for f in d["files"]]
    assert any(p.endswith("IntuneManagementExtension.log") for p in read)
    assert not any("EPM_Agent_Logs" in p for p in read)
    assert any("budget reached" in g["reason"] for g in d["skipped_groups"])
    assert any(f["pattern_id"] == "intune-not-detected" for f in d["findings"])


@pytest.mark.asyncio
async def test_files_are_read_lazily(settings):
    reads = []
    members = list(walk_upload("Diag.zip", package(), LIMITS))
    # Nothing has been decompressed just by listing the archive: the reader is a callable.
    assert all(callable(m.read) for m in members if isinstance(m, Member))
    assert any(isinstance(m, SkippedFile) for m in members) or any(isinstance(m, Member) for m in members)
    del reads


# ---- fast scanning ---------------------------------------------------------------------------
def test_required_literals_are_sound_and_useful():
    assert required_literals(r"Error 1618") == ["error 1618"]
    assert required_literals(r"(?P<detail>[^\r\n]{0,120}\.NET (?:Desktop )?Runtime[^\r\n]{0,120}needs to be installed[^\r\n]{0,60})") == ["needs to be installed"]
    assert required_literals(r"(?:not supported|unsupported)[^\r\n]{0,30}(?:on|for)") == ["not supported", "unsupported"]
    assert required_literals(r"\d+") is None


def test_fast_path_never_misses_a_pattern_the_full_regexes_find():
    lib = get_library()
    lines = [
        "Installation finished. Exit code: 4", "Error 1618", "0x87D1041C", "Defender blocked the file", "TpmProtected : NO",
        "The term 'Get-Foo' is not recognized as the name of a cmdlet, function", "DeviceAuthStatus : FAILED. Device is either disabled or deleted",
        "Windows failed to install the following update with error 0x800f0922", "exit code 5", "with code 3", "install timed out",
        "Microsoft .NET Desktop Runtime 10.0 needs to be installed for this installation to continue.", "Name of Exit Code: DEP_HARD_ERROR",
        "Product: X -- Error 1920. Service 'Foo' failed to start.", "Attempt Status : Client error 0x801c03f2", "HRESULT = 0x800f081f",
        "Action ended 17:40:03: LaunchConditions. Return value 3.", "Access to the path 'C:\\x' is denied.", "plain boring heartbeat line",
    ] + healthy_msi_log().decode("utf-16-le", "ignore").splitlines() + scriptrunner_log("x.log").decode().splitlines() + dup_failure_log()[0].decode("utf-16-le", "ignore").splitlines()
    for log_type in ("generic", "msi_verbose", "intune_ime", "dsregcmd", "patchmypc_scriptrunner", "dell_dup"):
        table, residual = lib.prefilter(log_type)
        for line in lines:
            low = line.lower()
            cands = {p.id for lit, pats in table if lit in low for p in pats} | {p.id for p in residual}
            for p in lib.for_log_type(log_type):
                if any(rx.search(line) for rx in p._compiled):
                    assert p.id in cands, (log_type, p.id, line)


def test_walker_skips_unreadable_junk_but_lists_triage_candidates():
    zipped = make_zip({"a.log": b"x", "setup.exe": b"MZ", "System.evtx": b"ElfFile\x00", "t.etl": b"\x01"})
    out = list(walk_upload("z.zip", zipped, LIMITS))
    members = {m.path for m in out if isinstance(m, Member)}
    skipped = {m.path: m.reason for m in out if isinstance(m, SkippedFile)}
    assert members == {"a.log", "System.evtx", "t.etl"} and "setup.exe" in skipped
