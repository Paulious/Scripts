import gzip
import io
import tarfile

import pytest

from app.core.archive import ArchiveLimitError, Limits, clean_path, expand_upload, sniff_archive
from app.core.decoding import NotTextError, decode_bytes, split_lines
from app.core.redact import redact
from app.parsers import detect_parser

from .fixtures import dup_failure_log, healthy_msi_log, make_zip, scriptrunner_log, utf16

LIMITS = Limits(max_total_bytes=50_000_000, max_file_bytes=10_000_000, max_files=100, max_depth=3)


# ---- decoding ---------------------------------------------------------------
def test_decodes_utf16_with_bom():
    text, enc = decode_bytes(utf16("hello\nworld"))
    assert split_lines(text) == ["hello", "world"] and "UTF-16" in enc


def test_decodes_utf16_without_bom():
    text, enc = decode_bytes(utf16("MSI (s) test line", bom=False))
    assert text == "MSI (s) test line" and "no BOM" in enc


def test_decodes_utf8_bom_and_cp1252():
    assert decode_bytes(b"\xef\xbb\xbfabc")[0] == "abc"
    text, enc = decode_bytes("caf\xe9".encode("cp1252"))
    assert text == "café" and enc == "Windows-1252"


def test_binary_is_rejected():
    with pytest.raises(NotTextError):
        decode_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00" + b"\x00" * 100 + b"abc")


def test_line_numbers_match_notepad():
    # form feed and unicode separators must not create extra lines
    assert split_lines("a\fb\r\nc\u2028d\n") == ["a\fb", "c\u2028d"]


# ---- archives ---------------------------------------------------------------
def test_zip_is_expanded_and_nested_zip_too():
    inner = make_zip({"inner/a.log": b"line"})
    outer = make_zip({"top.log": b"x", "nested.zip": inner})
    ex = expand_upload("Logs.zip", outer, LIMITS)
    assert sorted(f.path for f in ex.files) == ["nested.zip/inner/a.log", "top.log"]


def test_archive_detected_by_magic_not_extension():
    ex = expand_upload("renamed.txt", make_zip({"a.log": b"hi"}), LIMITS)
    assert [f.path for f in ex.files] == ["a.log"]


def test_plain_log_passes_through():
    ex = expand_upload("single.log", b"just a log", LIMITS)
    assert [f.path for f in ex.files] == ["single.log"]


def test_gz_and_tgz():
    assert expand_upload("a.log.gz", gzip.compress(b"hello"), LIMITS).files[0].path == "a.log"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("dir/x.log")
        info.size = 3
        tf.addfile(info, io.BytesIO(b"abc"))
    assert [f.path for f in expand_upload("logs.tgz", buf.getvalue(), LIMITS).files] == ["dir/x.log"]


def test_zip_slip_names_are_neutralised():
    assert clean_path("../../etc/passwd") == "etc/passwd"
    assert clean_path("C:\\Windows\\..\\x.log") == "C:/x.log"
    ex = expand_upload("evil.zip", make_zip({"../../evil.log": b"x"}), LIMITS)
    assert ex.files[0].path == "evil.log"


def test_total_size_limit_stops_a_zip_bomb():
    bomb = make_zip({f"f{i}.log": b"A" * 2_000_000 for i in range(6)})
    with pytest.raises(ArchiveLimitError):
        expand_upload("bomb.zip", bomb, Limits(max_total_bytes=5_000_000, max_file_bytes=10_000_000, max_files=100, max_depth=3))


def test_oversized_file_and_unsupported_archive_are_skipped_not_fatal():
    ex = expand_upload("a.zip", make_zip({"big.log": b"A" * 3000, "ok.log": b"ok"}),
                       Limits(max_total_bytes=10_000_000, max_file_bytes=1000, max_files=10, max_depth=3))
    assert [f.path for f in ex.files] == ["ok.log"] and ex.skipped[0].reason == "file too large"
    seven = expand_upload("x.7z", b"7z\xbc\xaf\x27\x1c" + b"0" * 50, LIMITS)
    assert not seven.files and "7-Zip" in seven.skipped[0].reason


def test_binary_extensions_are_skipped():
    ex = expand_upload("pack.zip", make_zip({"setup.exe": b"MZ", "a.log": b"x"}), LIMITS)
    assert [f.path for f in ex.files] == ["a.log"]
    assert sniff_archive(b"plain text") is None


# ---- log type detection -----------------------------------------------------
def test_detects_each_supported_type():
    dup, _ = dup_failure_log()
    cases = [
        ("Dell.EXE.log", decode_bytes(dup)[0], "dell_dup"),
        ("PatchMyPC-ScriptRunner.log", scriptrunner_log("x.log").decode(), "patchmypc_scriptrunner"),
        ("Webex.msi.log", decode_bytes(healthy_msi_log())[0], "msi_verbose"),
        ("AppWorkload.log", scriptrunner_log("x.log").decode().replace("ScriptRunner", "AppWorkload"), "intune_ime"),
        ("anything.log", "random text\nmore text", "generic"),
    ]
    for name, text, expected in cases:
        parser, conf = detect_parser(name, text.splitlines())
        assert parser.id == expected, (name, parser.id)
        assert 0 <= conf <= 1


def test_detects_detection_script_log():
    line = "09/25/2026 17:34:43~[Webex {ab51c413-48bd-5707-a269-49ee0d1fcd4b} 46.9]~[Found:False]~[Purpose:Detection]~[Context:PC$)]~[Hive:HKLM]"
    parser, _ = detect_parser("PatchMyPC-SoftwareDetectionScript.log", [line, line])
    assert parser.id == "patchmypc_detection"


def test_cmtrace_multiline_record_and_levels():
    lines = ['<![LOG[first line', 'second line]LOG]!><time="10:00:00.000" date="09-25-2026" component="X" context="" type="3" thread="1" file="">']
    parser, _ = detect_parser("a.log", lines * 3)
    parsed = parser.parse(lines)
    assert len(parsed.entries) == 1
    e = parsed.entries[0]
    assert (e.line_no, e.end_line, e.level) == (1, 2, "error") and "second line" in e.text
    assert e.timestamp.year == 2026


def test_msi_continue_marked_errors_are_downgraded():
    parser, _ = detect_parser("x.msi.log", decode_bytes(healthy_msi_log())[0].splitlines())
    parsed = parser.parse(decode_bytes(healthy_msi_log())[0].splitlines())
    assert not [e for e in parsed.entries if e.level == "error"]


# ---- redaction ----------------------------------------------------------------
def test_redaction_masks_secrets_but_keeps_diagnostics():
    text = r"password=Hunter2 Bearer abcdefghijklmnopqrstuvwxyz0123 user bob@contoso.com C:\Users\jsmith\AppData exit code 1603"
    out = redact(text)
    assert "Hunter2" not in out and "abcdefghijkl" not in out and "bob@contoso.com" not in out and "jsmith" not in out
    assert "exit code 1603" in out


def test_stray_bom_and_misaligned_crlf_are_removed():
    assert split_lines("a\n਍਍﻿b\n") == ["a", "b"]
