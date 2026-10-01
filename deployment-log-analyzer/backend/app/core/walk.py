"""Lazy archive walking.

`walk_upload` lists what is inside an upload without reading every file. Each `Member` carries a
`read()` callable, so the pipeline can decide from the name and size alone what is worth reading
and then read one file at a time. That keeps a 600 MB diagnostics package from sitting in memory.
"""
from __future__ import annotations

import io
import posixpath
import zipfile
from dataclasses import dataclass
from typing import Callable, Iterator

from app.core.archive import (
    BINARY_EXTENSIONS, ArchiveLimitError, Limits, _Expander, _read_limited, clean_path, sniff_archive, unsupported_reason,
)
from app.models import SkippedFile

# Binary formats the triage rules explain themselves (so the user sees a useful reason).
KEEP_FOR_TRIAGE = {".etl", ".evtx", ".cab", ".dmp", ".mdmp"}
NESTED_EXT = {".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz"}


@dataclass
class Member:
    path: str
    size: int                     # uncompressed size from the archive index
    read: Callable[[], bytes]


def walk_upload(name: str, data: bytes, limits: Limits, depth: int = 0) -> Iterator[Member | SkippedFile]:
    kind = sniff_archive(data)
    base = clean_path(name)
    if kind == "zip":
        yield from _walk_zip(base, data, limits, depth)
    elif kind in ("tar", "gzip", "bz2", "xz"):
        ex = _Expander(limits)
        ex.expand(name, data, depth)
        for f in ex.out.files:
            yield Member(f.path, len(f.data), lambda d=f.data: d)
        yield from ex.out.skipped
    elif kind == "unsupported":
        yield SkippedFile(path=base, reason=unsupported_reason(data))
    else:
        yield Member(base, len(data), lambda: data)


def _walk_zip(base: str, data: bytes, limits: Limits, depth: int) -> Iterator[Member | SkippedFile]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        yield SkippedFile(path=base, reason="could not read archive (BadZipFile)")
        return
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > limits.max_files:
        raise ArchiveLimitError(f"more than {limits.max_files} files in {base}")
    for info in infos:
        path = clean_path(f"{base}/{info.filename}" if depth else info.filename)
        ext = posixpath.splitext(path.lower())[1]
        if info.flag_bits & 0x1:
            yield SkippedFile(path=path, reason="password protected")
            continue
        if info.file_size > limits.max_file_bytes:
            yield SkippedFile(path=path, reason="file too large")
            continue
        if info.compress_size and info.file_size / max(info.compress_size, 1) > 1000 and info.file_size > 10_000_000:
            yield SkippedFile(path=path, reason="suspicious compression ratio")
            continue
        if ext in BINARY_EXTENSIONS and ext not in KEEP_FOR_TRIAGE:
            yield SkippedFile(path=path, reason=f"{ext} is not a text log")
            continue
        if ext in NESTED_EXT:
            if depth >= limits.max_depth:
                yield SkippedFile(path=path, reason="archives nested too deeply")
                continue
            try:
                with zf.open(info) as fh:
                    payload = _read_limited(fh, limits.max_file_bytes)
            except (ArchiveLimitError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
                yield SkippedFile(path=path, reason="could not read nested archive")
                continue
            yield from walk_upload(path, payload, limits, depth + 1)
            continue

        def reader(i=info) -> bytes:
            with zf.open(i) as fh:
                return _read_limited(fh, limits.max_file_bytes)

        yield Member(path, info.file_size, reader)
