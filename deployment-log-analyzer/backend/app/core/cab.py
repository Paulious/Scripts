"""Windows cabinet (.cab) files. MDM diagnostics and Defender support bundles arrive as CABs.

The pure-Python reader handles uncompressed and MSZIP cabinets in memory. Windows often uses LZX,
which it cannot read, so those fall back to the `cabextract` program when the host has it
(the container image does). Extraction happens in a temporary folder that is removed straight away.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterator

from app.core.archive import ArchiveLimitError, Limits

try:
    from cabarchive import CabArchive
    from cabarchive.errors import NotSupportedError
except ImportError:  # pragma: no cover
    CabArchive = None  # type: ignore[assignment,misc]

    class NotSupportedError(Exception):  # type: ignore[no-redef]
        pass

MAGIC = b"MSCF"


class CabError(Exception):
    pass


def _check_size(total: int, limits: Limits) -> None:
    if total > limits.max_total_bytes:
        raise ArchiveLimitError("cabinet expands to more than the allowed size")


def _with_python(data: bytes, limits: Limits) -> list[tuple[str, bytes]]:
    cab = CabArchive(data)
    out: list[tuple[str, bytes]] = []
    total = 0
    for name, f in cab.items():
        total += len(f.buf)
        _check_size(total, limits)
        out.append((name.replace("\\", "/"), bytes(f.buf)))
    return out


def _with_cabextract(data: bytes, limits: Limits) -> list[tuple[str, bytes]]:
    exe = shutil.which("cabextract")
    if not exe:
        raise CabError("compressed with LZX, which needs the cabextract tool (not installed on this host)")
    with tempfile.TemporaryDirectory(prefix="dla-cab-") as tmp:
        src = Path(tmp) / "in.cab"
        src.write_bytes(data)
        dest = Path(tmp) / "out"
        dest.mkdir()
        try:
            proc = subprocess.run([exe, "-q", "-d", str(dest), str(src)], capture_output=True, timeout=60, check=False)
        except subprocess.TimeoutExpired as exc:
            raise CabError("cabinet took too long to unpack") from exc
        if proc.returncode != 0 and not any(dest.rglob("*")):
            raise CabError("could not unpack cabinet")
        out: list[tuple[str, bytes]] = []
        total = 0
        for f in sorted(p for p in dest.rglob("*") if p.is_file() and not p.is_symlink()):
            total += f.stat().st_size
            _check_size(total, limits)
            out.append((f.relative_to(dest).as_posix(), f.read_bytes()))
        return out


def read_cab(data: bytes, limits: Limits) -> Iterator[tuple[str, bytes]]:
    """Yield (name, bytes) for each file in a cabinet. Raises CabError with a reason a person can read."""
    if len(data) > limits.max_file_bytes:
        raise CabError("cabinet too large")
    files: list[tuple[str, bytes]] | None = None
    if CabArchive is not None:
        try:
            files = _with_python(data, limits)
        except NotSupportedError:
            files = None
        except ArchiveLimitError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise CabError(f"could not read cabinet ({exc.__class__.__name__})") from exc
    if files is None:
        files = _with_cabextract(data, limits)
    if len(files) > limits.max_files:
        raise ArchiveLimitError(f"more than {limits.max_files} files in cabinet")
    yield from files
