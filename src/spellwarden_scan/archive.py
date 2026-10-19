"""Zip unpacking with the safety rules of spec 5.6. The archive is bytes in
memory; nothing touches the file system."""
from __future__ import annotations

import io
import lzma
import posixpath
import re
import stat
import zipfile
import zlib
from dataclasses import dataclass

_DRIVE = re.compile(r"^[A-Za-z]:")
_CHUNK = 65536


@dataclass(frozen=True)
class ArchiveLimits:
    max_compressed: int = 20 * 2**20
    max_uncompressed: int = 50 * 2**20
    max_files: int = 2000
    max_file: int = 10 * 2**20
    max_path: int = 255


DEFAULT_LIMITS = ArchiveLimits()


class ArchiveError(ValueError):
    """`code` is one of `too_large`, `too_many_files`, `unsafe_path`, `symlink`, `bad_zip`, `empty`."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _unsafe(name: str, limits: ArchiveLimits) -> bool:
    if not name or "\x00" in name or "\\" in name or _DRIVE.match(name) or name.startswith("/"):
        return True
    if len(name) > limits.max_path:
        return True
    parts = name.split("/")
    # `.` and `..` anywhere, and empty parts (`a//b`): every consumer must read the same path the scan read.
    return any(part in ("..", ".", "") for part in parts[:-1]) or parts[-1] in ("..", ".")


def _is_special(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)


def _is_executable(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return bool(mode & stat.S_IXUSR)


def _strip_common_top(names: list[str]) -> str:
    """The single top-level directory every entry shares, or an empty string."""
    tops = {name.split("/", 1)[0] for name in names}
    if len(tops) != 1:
        return ""
    top = tops.pop()
    return top if all("/" in name for name in names) else ""


def unpack_zip(data: bytes, limits: ArchiveLimits = DEFAULT_LIMITS, *, with_modes: bool = False):
    """`{path: bytes}` of a zip held in memory; with `with_modes=True`,
    `(files, executable_paths)`. Raises `ArchiveError` (spec 5.6)."""
    if len(data) > limits.max_compressed:
        raise ArchiveError("too_large", "compressed size over the limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, ValueError, EOFError, RuntimeError, OSError) as exc:
        # `NotImplementedError` (a `RuntimeError`) for an unsupported "version needed to extract" in the central directory.
        raise ArchiveError("bad_zip", str(exc)) from exc
    entries = [info for info in infos if not info.is_dir()]
    if not entries:
        raise ArchiveError("empty")
    if len(entries) > limits.max_files:
        raise ArchiveError("too_many_files", str(len(entries)))
    for info in entries:
        if _unsafe(info.filename, limits):
            raise ArchiveError("unsafe_path", info.filename)
        if _is_special(info):
            raise ArchiveError("symlink", info.filename)
    _check_declared(entries, limits)
    top = _strip_common_top([info.filename for info in entries])
    files: dict[str, bytes] = {}
    executable: set[str] = set()
    folded: set[str] = set()
    total = 0
    for info in entries:
        name = info.filename[len(top) + 1:] if top else info.filename
        if _unsafe(name, limits) or posixpath.normpath(name) != name:
            raise ArchiveError("unsafe_path", info.filename)
        # A repeated name (or one that differs only in case) would let an extractor install a file the scan never read.
        if name.casefold() in folded:
            raise ArchiveError("unsafe_path", f"duplicate {info.filename}")
        folded.add(name.casefold())
        content, total = _read_entry(archive, info, limits, total)
        files[name] = content
        if _is_executable(info):
            executable.add(name)
    _check_file_directory_clash(files)
    if with_modes:
        return files, frozenset(executable)
    return files


def _check_file_directory_clash(files: dict[str, bytes]) -> None:
    """`a/b` as a file and `a/b/c` as another: no file system holds both, so an extractor keeps one of them."""
    names = {name.casefold() for name in files}
    for name in files:
        parts = name.casefold().split("/")
        for depth in range(1, len(parts)):
            if "/".join(parts[:depth]) in names:
                raise ArchiveError("unsafe_path", f"file and directory {name}")


def _check_declared(entries: list[zipfile.ZipInfo], limits: ArchiveLimits) -> None:
    """The sizes the headers declare (`file_size`, `compress_size`), checked before any entry is
    opened: a declared size over a limit is `too_large` without reading a byte. The declared
    sizes are not trusted for the opposite case; `_read_entry` counts the real bytes."""
    declared = 0
    for info in entries:
        if info.file_size > limits.max_file or info.compress_size > limits.max_compressed:
            raise ArchiveError("too_large", info.filename)
        declared += info.file_size
        if declared > limits.max_uncompressed:
            raise ArchiveError("too_large", "declared uncompressed size over the limit")


def _read_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limits: ArchiveLimits, total: int) -> tuple[bytes, int]:
    """Reads one entry in chunks and counts the real decompressed bytes: `too_large` is raised the
    moment the entry or the running total exceeds its limit, before `zipfile` reaches the CRC check.
    `zipfile` never yields more than the declared size, so a header that understates the size ends
    in a size or CRC mismatch, which is `bad_zip`."""
    chunks: list[bytes] = []
    size = 0
    try:
        with archive.open(info) as handle:
            while True:
                chunk = handle.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                total += len(chunk)
                if size > limits.max_file or total > limits.max_uncompressed:
                    raise ArchiveError("too_large", info.filename)
                chunks.append(chunk)
    except ArchiveError:
        raise  # an `ArchiveError` is a `ValueError`: keep `too_large` out of the corrupt-stream clause below
    except (zipfile.BadZipFile, RuntimeError, EOFError, ValueError, OSError, zlib.error, lzma.LZMAError) as exc:
        # A corrupt stream surfaces as `zlib.error` (deflate), `OSError` (bzip2) or `LZMAError`, and an
        # unsupported method as `NotImplementedError` (a `RuntimeError`): all are `bad_zip`, the one code callers catch.
        raise ArchiveError("bad_zip", info.filename) from exc
    return b"".join(chunks), total
