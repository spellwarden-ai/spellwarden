"""Zip unpacking with the safety rules of spec 5.6. The archive is bytes in
memory; nothing touches the file system."""
from __future__ import annotations

import io
import lzma
import posixpath
import re
import stat
import unicodedata
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


def _platform_unsafe(name: str) -> bool:
    """A part ending in a dot or a space, or holding `:`, is renamed or refused by Windows extractors (`run.sh.`
    becomes `run.sh`): checked only under the scanned root (a repository may hold `docs/10:00.md` elsewhere)."""
    return any(part.endswith((".", " ")) or ":" in part for part in name.split("/"))


def _folded(name: str) -> str:
    """The key two names collide on in a case-insensitive, normalising file system (Windows, macOS): NFC and
    `lower()` (not `casefold()`, which maps `ß` to `ss` where NTFS and APFS do not)."""
    return unicodedata.normalize("NFC", name).lower()


def _platform_key(name: str) -> str:
    """The path as a case-insensitive, normalising Windows or macOS extractor writes it: each segment without its
    trailing dots and spaces, NFC, lower-cased."""
    return "/".join(_folded(part.rstrip(". ")) for part in name.split("/"))


def _under(name: str, root: str | None) -> bool:
    """Whether `name` lands under the scanned root on some file system: decided on the platform key, so
    `Skill/SKILL.md` or `skill./x` is under `skill` too (a macOS or Windows extractor merges them)."""
    if root is None:
        return False
    if not root:
        return True
    key, scope = _platform_key(name), _platform_key(root)
    return key == scope or key.startswith(scope + "/")


def _is_special(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)


def _is_executable(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return bool(mode & stat.S_IXUSR)


def _is_junk(name: str) -> bool:
    """What macOS adds to a hand-made zip of a directory: a `__MACOSX/` tree beside it and `.DS_Store` files."""
    return name.startswith("__MACOSX/") or name.rpartition("/")[2] == ".DS_Store"


def _strip_common_top(names: list[str]) -> str:
    """The single top-level directory every entry shares, or an empty string. `__MACOSX/` entries and `.DS_Store` files
    are not looked at, so a hand-made zip of one skill directory strips like a forge archive."""
    names = [name for name in names if not _is_junk(name)]
    tops = {name.split("/", 1)[0] for name in names}
    if len(tops) != 1:
        return ""
    top = tops.pop()
    return top if all("/" in name for name in names) else ""


def unpack_zip(data: bytes, limits: ArchiveLimits = DEFAULT_LIMITS, *, with_modes: bool = False, root: str | None = ""):
    """`{path: bytes}` of a zip held in memory; with `with_modes=True`,
    `(files, executable_paths)`. Raises `ArchiveError` (spec 5.6).

    Everywhere in the archive, a repeated name, a `.`, `..` or empty segment and a file that is also a
    directory are `unsafe_path` (every extractor reads them differently). Under `root` (the directory
    that will be scanned, relative to the stripped top; `""` is the whole archive, `None` none of it),
    two names equal after NFC normalisation and lower-casing and a segment Windows renames or refuses
    are `unsafe_path` as well: outside it they belong to another directory of a repository."""
    scope = None if root is None else root.strip("/")
    if len(data) > limits.max_compressed:
        raise ArchiveError("too_large", "compressed size over the limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, ValueError, EOFError, RuntimeError, OSError) as exc:
        # `NotImplementedError` (a `RuntimeError`) for an unsupported "version needed to extract" in the central directory.
        raise ArchiveError("bad_zip", str(exc)) from exc
    for info in infos:
        if info.is_dir() and _unsafe(info.filename.rstrip("/"), limits):
            raise ArchiveError("unsafe_path", info.filename)
    directories = [info.filename.rstrip("/") for info in infos if info.is_dir()]
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
        name = info.filename[len(top) + 1:] if top and info.filename.startswith(top + "/") else info.filename
        if _unsafe(name, limits) or posixpath.normpath(name) != name or name in files:
            raise ArchiveError("unsafe_path", info.filename)
        if _under(name, scope):
            # Under the scanned root, a name that differs only in case or normalisation, or that Windows renames,
            # would let an extractor install a file the scan never read; so would a name an extractor merges into the
            # root that is not under it byte for byte (`Skill/run.sh` for `skill`: the scan reads `skill/` only).
            exact = not scope or name == scope or name.startswith(scope + "/")
            if not exact or _platform_unsafe(name) or _platform_key(name) in folded:
                raise ArchiveError("unsafe_path", f"colliding {info.filename}")
            folded.add(_platform_key(name))
        content, total = _read_entry(archive, info, limits, total)
        files[name] = content
        if _is_executable(info):
            executable.add(name)
    _check_file_directory_clash(files, [d[len(top) + 1:] if top and d.startswith(top + "/") else d for d in directories], scope)
    if with_modes:
        return files, frozenset(executable)
    return files


def _check_file_directory_clash(files: dict[str, bytes], directories: list[str], scope: str | None) -> None:
    """`a/b` as a file and `a/b/c` (or a directory entry `a/b/`) as another: no file system holds both, so an
    extractor keeps one of them. Exact names everywhere; under the scanned root also case- and NFC-folded."""
    exact = set(files)
    folded = {_platform_key(name) for name in files if _under(name, scope)}
    directory_set = set(directories)
    for name in list(files) + directories:
        parts = name.split("/")
        for depth in range(1, len(parts) + (name in directory_set)):
            prefix = "/".join(parts[:depth])
            if prefix in exact or (_under(prefix, scope) and _platform_key(prefix) in folded):
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
