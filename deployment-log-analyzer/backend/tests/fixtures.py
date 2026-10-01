"""Synthetic log builders. They mimic real formats (Patch My PC, Dell DUP, MSI) without
containing any customer data."""
from __future__ import annotations

import io
import zipfile

NET_LINE = ("1: Microsoft .NET Desktop Runtime 10.0 with version greater than 10.0.7 (x64) "
            "needs to be installed for this installation to continue.")
PKG = "DellCommandUpdate-Test"


def utf16(text: str, bom: bool = True) -> bytes:
    raw = text.replace("\n", "\r\n").encode("utf-16-le")
    return (b"\xff\xfe" + raw) if bom else raw


def msi_noise(n: int, start: int = 0) -> list[str]:
    out = []
    for i in range(n):
        out.append(f"MSI (s) (74:7C) [17:39:{(start + i) % 60:02d}:100]: Creating MSIHANDLE ({i}) of type 790531 for thread 1")
    return out


def dup_failure_log(noise_before: int = 150, noise_after: int = 150) -> tuple[bytes, int]:
    """Returns (utf16 bytes, 1-based line number of the .NET message)."""
    lines = [
        "[Fri Sep 25 17:39:41 2026]\tUpdate Package Execution Started",
        "[Fri Sep 25 17:39:41 2026]\tDUP Framework EXE Version: 5.9.1.90",
        "=== Verbose logging started: 9/25/2026  17:39:49  Build type: SHIP UNICODE 5.00.10011.00  Calling process: C:\\WINDOWS\\system32\\MsiExec.exe ===",
    ]
    lines += msi_noise(noise_before)
    lines += ["MSI (s) (74:7C) [17:39:53:596]: Note: 1: 2205 2:  3: Error "]
    net_line_no = len(lines) + 1
    lines.append(NET_LINE)
    lines += [
        "InstallShield 17:40:03: Setup aborted",
        "CustomAction CheckFrameworkSupported returned actual error code 1602 (note this may not be 100% accurate if translation happened inside sandbox)",
        "Action ended 17:40:03: CheckFrameworkSupported. Return value 2.",
        f"MSI (s) (74:7C) [17:40:03:101]: Product: {PKG} -- Installation operation failed.",
        "MSI (s) (74:7C) [17:40:03:106]: Windows Installer installed the product. Product Name: Test. Installation success or error status: 1602.",
    ]
    lines += msi_noise(noise_after)
    lines += [
        "[Fri Sep 25 17:40:06 2026]\tName of Exit Code: DEP_HARD_ERROR",
        "[Fri Sep 25 17:40:06 2026]\tExit Code set to: 4 (0x4)",
        "[Fri Sep 25 17:40:06 2026]\tResult: FAILURE",
    ]
    return utf16("\n".join(lines)), net_line_no


def _cm(msg: str, t: str, comp: str = "ScriptRunner", typ: int = 1) -> str:
    return f'<![LOG[{msg}]LOG]!><time="{t}" date="09-25-2026" component="{comp}" context="" type="{typ}" thread="1" file="">'


def scriptrunner_log(installer_log: str, exit_code: int = 4) -> bytes:
    lines = [
        _cm("Starting ScriptRunner (V2.2.96.0) with 1 argument(s)", "17:39:37.000000"),
        _cm("Device name: TEST-PC\tDomain name: WORKGROUP", "17:39:37.100000"),
        _cm("Operating System: Microsoft Windows 11 Pro 10.0.26100", "17:39:37.200000"),
        _cm(f"Running EXE File. With arguments: /s /l=C:\\ProgramData\\PatchMyPCInstallLogs\\{installer_log}", "17:39:39.964563", "AutomaticInstaller"),
        _cm(f"Exiting With code: {exit_code}", "17:40:06.289986", "AutomaticInstaller"),
        _cm(f"Installation finished. Exit code: {exit_code}", "17:40:08.307909", "AutomaticInstaller"),
        _cm(f"End of installation. Exit code is: {exit_code}", "17:40:08.317967", "InstallationDriver"),
        _cm(f"End of Script Runner. Exit code is: {exit_code}", "17:40:08.327764"),
    ]
    return "\n".join(lines).encode("utf-8")


def healthy_msi_log() -> bytes:
    lines = [
        "=== Verbose logging started: 9/25/2026  18:02:00  Build type: SHIP UNICODE 5.00.10011.00  Calling process: C:\\WINDOWS\\system32\\MsiExec.exe ===",
        "MSI (s) (2C:20) [18:02:01:406]: Note: 1: 2205 2:  3: Error ",
        "MSI (s) (2C:20) [18:02:01:500]: Note: 1: 2228 2:  3: Error 4: SELECT `Message` FROM `Error` WHERE `Error` = 22 ",
        "MSI (s) (2C:20) [18:02:01:501]: SOFTWARE RESTRICTION POLICY: Verifying package --> 'C:\\x.msi' against software restriction policy",
        "MSI (s) (2C:20) [18:02:01:502]: Skipping action: NewerVersionError (condition is false)",
        "WixQuietExec:  ERROR: The process \"Webex.exe\" not found.",
        "WixQuietExec:  Error 0x80070080: Command line returned an error.",
        "CustomAction KillSpark returned actual error code 1603 but will be translated to success due to continue marking",
        "MSI (s) (2C:20) [18:02:04:100]: Product: Test App -- Installation completed successfully.",
        "MSI (s) (2C:20) [18:02:04:101]: Windows Installer installed the product. Product Name: Test App. Installation success or error status: 0.",
    ]
    return utf16("\n".join(lines))


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()
