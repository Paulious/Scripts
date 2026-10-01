"""Safe, in-memory archive expansion.

Nothing is written to disk. Every limit is enforced while reading so that a
zip bomb is stopped early instead of after it has eaten the container's RAM.
Archives are recognised by magic bytes, not by extension, because people
rename things.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import posixpath
import tarfile
import zipfile
from dataclasses import dataclass, field

from app.models import SkippedFile

ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
GZIP_MAGIC = b"\x1f\x8b"
BZ2_MAGIC = b"BZh"
XZ_MAGIC = b"\xfd7zXZ\x00"
UNSUPPORTED = {
    b"7z\xbc\xaf\x27\x1c": "7-Zip archives are not supported - re-zip as .zip first",
    b"Rar!\x1a\x07": "RAR archives are not supported - re-zip as .zip first",
    b"MSCF\x00\x00\x00\x00": "CAB archives are not supported - extract them and upload the logs",
}
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".msi", ".msp", ".msu", ".cab", ".png", ".jpg", ".jpeg", ".gif",
    ".bmp", ".ico", ".pdf", ".docx", ".xlsx", ".pptx", ".etl", ".evtx", ".dmp", ".mdmp",
    ".vhd", ".vhdx", ".iso", ".wim", ".nupkg", ".appx", ".msix", ".mp4", ".mov", ".so",
}


class ArchiveLimitError(Exception):
    pass


@dataclass
class Limits:
    max_total_bytes: int
    max_file_bytes: int
    max_files: int
    max_depth: int


@dataclass
class Extracted:
    path: str
    data: bytes


@dataclass
class Expansion:
    files: list[Extracted] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    total_bytes: int = 0


def clean_path(name: str) -> str:
    """Normalise to a forward-slash relative path with no traversal. Display only."""
    name = name.replace("\\", "/")
    parts = [p for p in posixpath.normpath(name).split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "file"


def sniff_archive(data: bytes) -> str | None:
    head = data[:512]
    if head.startswith(ZIP_MAGIC):
        return "zip"
    if head.startswith(GZIP_MAGIC):
        return "gzip"
    if head.startswith(BZ2_MAGIC) and len(head) > 4 and head[3:4] in b"123456789":
        return "bz2"
    if head.startswith(XZ_MAGIC):
        return "xz"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    for magic in UNSUPPORTED:
        if head.startswith(magic):
            return "unsupported"
    return None


def unsupported_reason(data: bytes) -> str:
    for magic, reason in UNSUPPORTED.items():
        if data.startswith(magic):
            return reason
    return "unsupported archive type"


def _read_limited(stream, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ArchiveLimitError(f"larger than the {limit // (1024 * 1024)} MB per-file limit")
    return data


class _Expander:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.out = Expansion()

    # ---- bookkeeping ---------------------------------------------------
    def _account(self, size: int) -> None:
        self.out.total_bytes += size
        if self.out.total_bytes > self.limits.max_total_bytes:
            raise ArchiveLimitError(
                f"extracted content exceeds {self.limits.max_total_bytes // (1024 * 1024)} MB - "
                "upload fewer logs or a smaller archive"
            )

    def _add(self, path: str, data: bytes, depth: int) -> None:
        if len(self.out.files) >= self.limits.max_files:
            raise ArchiveLimitError(f"more than {self.limits.max_files} files in the upload")
        kind = sniff_archive(data)
        if kind == "unsupported":
            self.out.skipped.append(SkippedFile(path=path, reason=unsupported_reason(data)))
            return
        if kind:
            if depth >= self.limits.max_depth:
                self.out.skipped.append(SkippedFile(path=path, reason="archives nested too deeply"))
                return
            self.expand(path, data, depth + 1)
            return
        ext = posixpath.splitext(path.lower())[1]
        if ext in BINARY_EXTENSIONS:
            self.out.skipped.append(SkippedFile(path=path, reason=f"{ext} is not a text log"))
            return
        self._account(len(data))
        self.out.files.append(Extracted(path=path, data=data))

    # ---- format handlers -----------------------------------------------
    def expand(self, name: str, data: bytes, depth: int = 0) -> None:
        kind = sniff_archive(data)
        base = clean_path(name)
        try:
            if kind == "zip":
                self._zip(base, data, depth)
            elif kind == "tar":
                self._tar(base, data, depth)
            elif kind in ("gzip", "bz2", "xz"):
                self._compressed(base, data, kind, depth)
            elif kind == "unsupported":
                self.out.skipped.append(SkippedFile(path=base, reason=unsupported_reason(data)))
            else:
                self._add(base, data, depth)
        except ArchiveLimitError:
            raise
        except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, lzma.LZMAError) as exc:
            self.out.skipped.append(SkippedFile(path=base, reason=f"could not read archive ({exc.__class__.__name__})"))

    def _zip(self, base: str, data: bytes, depth: int) -> None:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            if len(infos) > self.limits.max_files:
                raise ArchiveLimitError(f"more than {self.limits.max_files} files in {base}")
            for info in infos:
                path = clean_path(f"{base}/{info.filename}" if depth else info.filename)
                if info.flag_bits & 0x1:
                    self.out.skipped.append(SkippedFile(path=path, reason="password protected"))
                    continue
                if info.file_size > self.limits.max_file_bytes:
                    self.out.skipped.append(SkippedFile(path=path, reason="file too large"))
                    continue
                if info.compress_size and info.file_size / max(info.compress_size, 1) > 1000 and info.file_size > 10_000_000:
                    self.out.skipped.append(SkippedFile(path=path, reason="suspicious compression ratio"))
                    continue
                try:
                    with zf.open(info) as fh:
                        payload = _read_limited(fh, self.limits.max_file_bytes)
                except ArchiveLimitError:
                    self.out.skipped.append(SkippedFile(path=path, reason="file too large"))
                    continue
                except (RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
                    self.out.skipped.append(SkippedFile(path=path, reason=f"unreadable ({exc.__class__.__name__})"))
                    continue
                self._add(path, payload, depth)

    def _tar(self, base: str, data: bytes, depth: int) -> None:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for member in tf:
                if not member.isfile():
                    continue
                path = clean_path(f"{base}/{member.name}" if depth else member.name)
                if member.size > self.limits.max_file_bytes:
                    self.out.skipped.append(SkippedFile(path=path, reason="file too large"))
                    continue
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                self._add(path, _read_limited(fh, self.limits.max_file_bytes), depth)

    def _compressed(self, base: str, data: bytes, kind: str, depth: int) -> None:
        opener = {"gzip": gzip.GzipFile, "bz2": bz2.BZ2File, "xz": lzma.LZMAFile}[kind]
        try:
            with opener(fileobj=io.BytesIO(data)) as fh:
                payload = _read_limited(fh, self.limits.max_file_bytes)
        except ArchiveLimitError:
            self.out.skipped.append(SkippedFile(path=base, reason="file too large"))
            return
        inner = posixpath.splitext(base)[0] if base.lower().endswith((".gz", ".bz2", ".xz")) else base
        # A .tar.gz is one logical archive, not a nested one, so don't count it as a level.
        if sniff_archive(payload) not in (None, "unsupported"):
            self.expand(inner, payload, depth)
        else:
            self._add(inner, payload, depth)


def expand_upload(name: str, data: bytes, limits: Limits) -> Expansion:
    """Expand one uploaded file (archive or plain log) into text candidates."""
    ex = _Expander(limits)
    ex.expand(name, data, 0)
    return ex.out


def merge(expansions: list[Expansion]) -> Expansion:
    merged = Expansion()
    seen: dict[str, int] = {}
    for ex in expansions:
        for f in ex.files:
            # Avoid collisions when two uploads contain the same relative path.
            n = seen.get(f.path, 0)
            seen[f.path] = n + 1
            path = f.path if n == 0 else f"{f.path} ({n + 1})"
            merged.files.append(Extracted(path=path, data=f.data))
        merged.skipped.extend(ex.skipped)
        merged.total_bytes += ex.total_bytes
    return merged
