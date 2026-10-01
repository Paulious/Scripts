import json
import re
from pathlib import Path

from app.core import scoring
from app.core.decoding import decode_bytes, split_lines
from app.core.pipeline import _prepare
from app.core.scanner import build_findings, collect_suppressed, link_files, scan_entries
from app.patterns import get_library
from app.patterns.loader import LIBRARY_DIR

from .fixtures import NET_LINE, dup_failure_log, healthy_msi_log, scriptrunner_log


def test_library_is_valid_and_complete():
    lib = get_library()
    assert len(lib.patterns) >= 50
    for p in lib.patterns:
        assert p.remediation, f"{p.id} has no remediation"
        assert 0 < p.weight <= 1
        for rx in p.regex:
            re.compile(rx, re.I)
    # every file on disk is valid JSON
    for f in Path(LIBRARY_DIR).glob("*.json"):
        json.loads(f.read_text())


def test_library_patterns_do_not_fire_on_benign_lines():
    lib = get_library()
    benign = [
        "MSI installation timeout is set to infinite.",
        "SOFTWARE RESTRICTION POLICY: Verifying package --> 'C:\\x.msi' against software restriction policy",
        "Exiting With code: 0", "Installation finished. Exit code: 0", "Exit Code set to: 0 (0x0)",
        "Name of Exit Code: SUCCESS", "Executing op: RollbackInfo(,RollbackAction=Rollback,RollbackDescription=Rolling back action: [1],",
        "Looking if application installation process need to be aborted due to running process",
        "No need to abort due to the running processes", "Installation success or error status: 0.",
        "Installation success or error status: 3010.",
    ]
    for line in benign:
        hits = [p.id for p in lib.patterns if p.role.value == "cause" and p.match(line)[0]]
        hits += [p.id for p in lib.patterns if p.role.value == "symptom" and p.id not in ("msi-reboot-required",) and p.match(line)[0]]
        assert not hits, (line, hits)


def test_known_failure_lines_match():
    lib = get_library()
    cases = {
        "Installation finished. Exit code: 4": "pmpc-nonzero-exit",
        NET_LINE: "dep-dotnet-missing",
        "Action ended 17:40:03: LaunchConditions. Return value 3.": "msi-launch-condition",
        "Product: X -- Error 1920. Service 'Foo' failed to start.": "msi-error-dialog",
        "The term 'Get-Foo' is not recognized as the name of a cmdlet, function": "ps-command-not-found",
        "Error 0x87D1041C: app not detected": "intune-not-detected",
    }
    for line, expected in cases.items():
        assert any(p.id == expected and p.match(line)[0] for p in lib.patterns), (line, expected)


def _scan(name: str, data: bytes, settings):
    prepared = _prepare(name, data, settings)
    scan_entries(prepared, get_library())
    return prepared


def test_evidence_is_100_lines_each_side_and_marks_the_match(settings):
    data, net_line = dup_failure_log(noise_before=150, noise_after=150)
    scan = _scan("Dell.EXE.log", data, settings)
    findings = build_findings(scan, get_library(), settings)
    f = next(x for x in findings if x.pattern_id == "dep-dotnet-missing")
    w = f.evidence[0]
    assert w.anchor_line == net_line
    assert w.start_line == net_line - 100 and w.end_line == net_line + 100
    assert len(w.lines) == 201
    anchor = next(l for l in w.lines if l.anchor)
    assert anchor.match and "Desktop Runtime" in anchor.text
    assert sum(1 for l in w.lines if l.noise) > 100  # MSIHANDLE chatter is flagged


def test_evidence_window_clamps_at_start_of_file(settings):
    data, net_line = dup_failure_log(noise_before=5, noise_after=5)
    scan = _scan("Dell.EXE.log", data, settings)
    f = next(x for x in build_findings(scan, get_library(), settings) if x.pattern_id == "dep-dotnet-missing")
    assert f.evidence[0].start_line == 1


def test_healthy_log_produces_no_findings_and_counts_noise(settings):
    scan = _scan("ok.msi.log", healthy_msi_log(), settings)
    assert build_findings(scan, get_library(), settings) == []
    counts = {s.id: s.count for s in collect_suppressed([scan], get_library())}
    assert counts["msi-internal-notes"] == 2 and counts["wix-continue-marked"] == 1 and counts["msi-srp-check"] == 1


def test_cross_file_link_and_confidence(settings):
    dup, _ = dup_failure_log()
    name = "Dell-Command-Update.EXE.log"
    scans = [_scan(f"PatchMyPCInstallLogs/{name}", dup, settings), _scan("PatchMyPC-ScriptRunner.log", scriptrunner_log(name), settings)]
    links = link_files(scans)
    assert links["PatchMyPC-ScriptRunner.log"] == {f"PatchMyPCInstallLogs/{name}"}

    findings = scoring.rank([f for s in scans for f in build_findings(s, get_library(), settings)])
    top = findings[0]
    assert top.pattern_id == "dep-dotnet-missing" and top.role.value == "cause"
    conf = scoring.compute_confidence(top, findings, links, get_library().get(top.pattern_id).weight)
    assert conf.score >= 80 and conf.label == "High" and len(conf.factors) == 5
    assert abs(sum(f.weight for f in conf.factors) - 1.0) < 1e-9


def test_confidence_is_low_for_a_lone_generic_error(settings):
    text = "2026-09-25 10:00:00 ERROR something odd happened\n2026-09-25 10:00:01 INFO done\n"
    scan = _scan("odd.log", text.encode(), settings)
    findings = scoring.rank(build_findings(scan, get_library(), settings))
    assert findings[0].pattern_id == "unclassified-errors"
    conf = scoring.compute_confidence(findings[0], findings, {}, 0.25)
    assert conf.label == "Low"


def test_llm_cannot_inflate_confidence_beyond_cap():
    from app.models import Confidence
    base = Confidence(score=50, label="Low", factors=[])
    assert scoring.blend_with_llm(base, 100).score == 60
    assert scoring.blend_with_llm(base, None).score == 50
    assert scoring.blend_with_llm(base, 10).score == 34


def _hits(pattern_id, line):
    p = next(p for p in get_library().patterns if p.id == pattern_id)
    return [m for rx in p.regex if (m := re.search(rx, line, re.I))]


def test_real_intune_lines_entra_app_and_script_error_stream():
    line = "Application with identifier '1659b7df-78bd-4907-81bc-717b5890bd10' was not found in the directory"
    hit = _hits("entra-app-not-found", line)
    assert hit and "1659b7df" in (hit[0].groupdict().get("detail") or "")
    err = "[HS] Detect error even if exit code is 0, error = Get-ItemProperty : Cannot find path 'HKCU:\\SOFTWARE\\x'"
    assert _hits("hs-detect-error-stream", err)


def test_real_intune_routine_lines_are_not_flagged():
    assert not _hits("intune-timeout", "script exceeded the max run count 1, skipping")
    assert not _hits("cbs-hresult", "2024-01-01 10:00:00, Info                  CBS    Failed to x [HRESULT = 0x800f0805]")
    assert _hits("cbs-hresult", "2024-01-01 10:00:00, Error                 CBS    Failed to x [HRESULT = 0x800f0805]")


def test_aadsts_code_is_explained():
    notes = get_library().explain_codes("AADSTS700016: Application not found")
    assert notes
