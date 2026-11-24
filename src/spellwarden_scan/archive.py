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
# P6-10 spec 7.4.1, D10 (1.23.0): the four bytes that open a central directory header; `zipfile` builds one entry per header
_CENTRAL_HEADER = b"PK\x01\x02"
# P6-10 spec 7.2.2, D8 (1.23.0): the most bytes a symbolic link entry's target text may hold, declared and real
LINK_MAX = 4096


@dataclass(frozen=True)
class ArchiveLimits:
    max_compressed: int = 20 * 2**20
    max_uncompressed: int = 50 * 2**20
    max_files: int = 2000
    max_file: int = 10 * 2**20
    max_path: int = 255
    # P6-10 spec 7.4.1, D10 (1.23.0): the most central directory headers the whole archive may hold, whatever `root` is
    max_entries: int = 100_000


DEFAULT_LIMITS = ArchiveLimits()
# P6-10 spec 7.4.2, D11 (1.23.0): a repository's archive read under a named root (the hosted git source); every other field
# is the default, and `DEFAULT_LIMITS` keeps 20 MiB
REPOSITORY_LIMITS = ArchiveLimits(max_compressed=50 * 2**20)


class ArchiveError(ValueError):
    """`code` is one of `too_large`, `too_many_files`, `unsafe_path`, `symlink`, `bad_zip`, `empty`. `why` (1.23.0, P6-10
    spec 7.6) names the case: for `symlink` one of `special`, `unsafe_target`, `outside`, `dangling`, `chain`, `directory`,
    `through_link`; for `too_many_files` `archive_entries` (the whole archive's headers) or `""` (`max_files`); `""` for
    every other code."""

    def __init__(self, code: str, detail: str = "", why: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.why = why


def _unsafe(name: str, limits: ArchiveLimits, *, length: bool = True) -> bool:
    """`length=False` (1.23.0, P6-10 spec 7.3, D9) for a raw entry name, which may hold the forge's top directory: the
    255-character bound is measured on the stripped name, the path inside the repository."""
    if not name or "\x00" in name or "\\" in name or _DRIVE.match(name) or name.startswith("/"):
        return True
    if length and len(name) > limits.max_path:
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


def _in_scope(name: str, scope: str) -> bool:
    """Whether an entry's stripped `name` is under the non-empty `scope`, decided conservatively: it is under if the
    name itself, its `normpath` (`other/../skill/x`) or its platform key (`Skill/x`, `skill./x`) equals the scope or
    starts with `scope/`, and so does the name as a Windows extractor reads it (`\\` as `/`, no leading `/`, no drive:
    `skill\\x`, `/skill/x`, `C:skill/x`). A name that might land under the scope on any reading keeps every rule."""
    scope_key = _platform_key(scope)
    extracted = _DRIVE.sub("", name.replace("\\", "/").lstrip("/")).lstrip("/")
    candidates = []
    for variant in (name, posixpath.normpath(name), extracted, posixpath.normpath(extracted)):
        candidates.append((variant, scope))
        candidates.append((_platform_key(variant), scope_key))
    return any(candidate == wanted or candidate.startswith(wanted + "/") for candidate, wanted in candidates)


def _suspicious(raw: str) -> bool:
    """A raw entry name that some extractor reads differently from the scan: a backslash, a NUL, a leading `/` or `//`
    (UNC), a drive, or a `.`, `..` or empty segment anywhere. Python's `zipfile` and Info-ZIP drop `..`, `.` and empty
    segments, Windows tools read `\\` as `/` and strip drives and UNC prefixes, so such a name may land under the scanned
    root wherever it seems to point (`repo-main/../skill/x` is written as `repo-main/skill/x`). With a non-empty root
    such an entry is treated as under it, fail closed, and refused by the unsafe-name rule; a forge archive never
    holds one."""
    name = raw.rstrip("/")
    if not name or "\x00" in name or "\\" in name or name.startswith("/") or _DRIVE.match(name):
        return True
    return any(part in ("..", ".", "") for part in name.split("/"))


def _is_special(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)


def _is_link(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


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


def _open(data: bytes, limits: ArchiveLimits) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    """The archive and its central directory, after the two whole-archive bounds: the compressed size, then the number of
    central directory headers its bytes hold (P6-10 spec 7.4.1, D10), counted before `zipfile` parses one. `zipfile`
    ignores the count the end record declares and builds one entry per header it finds, and it refuses a header without
    the signature, so the count bounds what it builds; it can only be higher than the real number of entries (the same
    four bytes stored in file data), which fails closed."""
    if len(data) > limits.max_compressed:
        raise ArchiveError("too_large", "compressed size over the limit")
    if data.count(_CENTRAL_HEADER) > limits.max_entries:
        raise ArchiveError("too_many_files", f"more than {limits.max_entries} entries in the archive", why="archive_entries")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, ValueError, EOFError, RuntimeError, OSError) as exc:
        # `NotImplementedError` (a `RuntimeError`) for an unsupported "version needed to extract" in the central directory.
        raise ArchiveError("bad_zip", str(exc)) from exc
    return archive, infos


def unpack_zip(data: bytes, limits: ArchiveLimits = DEFAULT_LIMITS, *, with_modes: bool = False, root: str | None = ""):
    """`{path: bytes}` of a zip held in memory; with `with_modes=True`,
    `(files, executable_paths)`. Raises `ArchiveError` (spec 5.6).

    The whole-archive compressed limit is checked first, then the number of central directory headers (`max_entries`,
    1.23.0). Everywhere in the archive, a repeated name, a `.`, `..` or empty segment, a file that is also a directory
    and an entry whose path passes through a symbolic link or shares its name are `unsafe_path` (every extractor reads
    them differently). Under `root` (the directory that will be scanned, relative to the stripped top; `""` is the whole
    archive, `None` none of it), two names equal after NFC normalisation and lower-casing and a segment Windows renames or
    refuses are `unsafe_path` as well: outside it they belong to another directory of a repository. The 255-character
    path bound is measured on the stripped name, the path inside the repository (1.23.0).

    With a non-empty `root`, every limit and rule above applies to the entries under it only (`max_files`, the
    declared and real sizes, links and special files, unsafe names, collisions). An entry outside it is skipped:
    never opened, never returned, never reported as executable. An entry counts as under the root when its stripped
    name, its `normpath` or its platform key equals the root or starts with `root/`, so `other/../skill/x` and
    `Skill/run.sh` for `skill` keep every rule, and so does a name read the way a Windows extractor does (`skill\\x`,
    `/skill/x`, `C:skill/x`). Fail closed, any raw name with a backslash, a leading `/`, a drive or a `.`, `..` or
    empty segment counts as under the root (`_suspicious`) and is refused as `unsafe_path`. No file under the root is
    `empty`. `root=""` and `root=None` read the whole archive as before.

    A symbolic link under the root (1.23.0, P6-10 spec 7.2) is read when its target, judged from its text alone, is a
    regular file of the tree (the root's directory, the whole stripped archive for `""` and `None`) reached through
    directories of the tree only: the link's path then holds the target's bytes, executable when the target is, and the
    target's size counts again toward `max_uncompressed`. Every other link is `symlink`, with `why` saying which case; a
    device, FIFO or socket is `symlink` with `why="special"`."""
    scope = None if root is None else root.strip("/")
    archive, infos = _open(data, limits)
    all_files = [info for info in infos if not info.is_dir()]
    top = _strip_common_top([info.filename for info in all_files])

    def stripped(name: str) -> str:
        return name[len(top) + 1:] if top and name.startswith(top + "/") else name

    _check_symlink_paths(infos, stripped)  # every root (1.23.0, P6-10 spec 7.2.6): a link may now be followed anywhere
    directory_infos = [info for info in infos if info.is_dir()]
    entries = all_files
    if scope:  # a non-empty root: only what is under it is read, counted and checked
        def under(raw: str) -> bool:
            return _suspicious(raw) or _in_scope(stripped(raw.rstrip("/")), scope)

        directory_infos = [info for info in directory_infos if under(info.filename)]
        entries = [info for info in all_files if under(info.filename)]
        if not entries:
            raise ArchiveError("empty", f"nothing under {scope}")
    for info in directory_infos:
        raw = info.filename.rstrip("/")
        if _unsafe(raw, limits, length=False) or len(stripped(raw)) > limits.max_path:
            raise ArchiveError("unsafe_path", info.filename)
    if not entries:  # no file at all: checked after the directory names, as it always was
        raise ArchiveError("empty")
    directories = [stripped(info.filename.rstrip("/")) for info in directory_infos]
    if len(entries) > limits.max_files:
        raise ArchiveError("too_many_files", str(len(entries)))
    for info in entries:
        if _unsafe(info.filename, limits, length=False):
            raise ArchiveError("unsafe_path", info.filename)
        if _is_special(info) and not _is_link(info):
            raise ArchiveError("symlink", info.filename, why="special")
    _check_declared(entries, limits)
    files: dict[str, bytes] = {}
    links: dict[str, zipfile.ZipInfo] = {}
    executable: set[str] = set()
    folded: set[str] = set()
    total = 0
    for info in entries:
        name = stripped(info.filename)
        if _unsafe(name, limits) or posixpath.normpath(name) != name or name in files or name in links:
            raise ArchiveError("unsafe_path", info.filename)
        if _under(name, scope):
            # Under the scanned root, a name that differs only in case or normalisation, or that Windows renames,
            # would let an extractor install a file the scan never read; so would a name an extractor merges into the
            # root that is not under it byte for byte (`Skill/run.sh` for `skill`: the scan reads `skill/` only).
            exact = not scope or name == scope or name.startswith(scope + "/")
            if not exact or _platform_unsafe(name) or _platform_key(name) in folded:
                raise ArchiveError("unsafe_path", f"colliding {info.filename}")
            folded.add(_platform_key(name))
        if _is_link(info):
            links[name] = info  # resolved below, once every regular file of the tree is read (7.2.7)
            continue
        content, total = _read_entry(archive, info, limits, total)
        files[name] = content
        if _is_executable(info):
            executable.add(name)
    _follow_links(archive, links, files, executable, directories, scope or "", limits, total)
    _check_file_directory_clash(files, directories, scope)
    if with_modes:
        return files, frozenset(executable)
    return files


def _follow_links(archive: zipfile.ZipFile, links: dict[str, zipfile.ZipInfo], files: dict[str, bytes], executable: set[str],
                  directories: list[str], tree: str, limits: ArchiveLimits, total: int) -> None:
    """P6-10 spec 7.1.2, 7.2.3 to 7.2.5 (1.23.0): each link of the tree, in sorted order of its stripped name, is followed
    into `files` (and `executable`) or refused with the first case that applies: a target through a link, a target whose
    text walks through a name that is no directory of the tree (`dangling`: a file, or nothing, so no file system reaches
    the target), then a regular file (followed), a link (`chain`), a directory, nothing (`dangling`). A followed link's
    target size counts again toward `max_uncompressed` (D5), so links never multiply the bytes the engine judges past the
    limit."""
    regular = frozenset(files)
    named = frozenset(links)
    held = {"", *directories}  # every directory of the tree: directory entries and every proper prefix of a name
    for name in (*regular, *named, *directories):
        parts = name.split("/")
        held.update("/".join(parts[:depth]) for depth in range(1, len(parts)))
    for name in sorted(links):
        info = links[name]
        target, passed, total = _link_target(archive, info, name, tree, limits, total)
        parts = target.split("/")
        if not named.isdisjoint((*passed, *("/".join(parts[:depth]) for depth in range(1, len(parts))))):
            why = "through_link"
        elif not held.issuperset(passed):
            # 7.1.2: a target is reached through real directories only (`missing/../x.md`, `file/../x.md`, `file/.`)
            why = "dangling"
        elif target in regular:
            content = files[target]
            total += len(content)
            if total > limits.max_uncompressed:
                raise ArchiveError("too_large", info.filename)
            files[name] = content
            if target in executable:
                executable.add(name)
            continue
        elif target in named:
            why = "chain"
        elif target in held:
            why = "directory"
        else:
            why = "dangling"
        raise ArchiveError("symlink", info.filename, why=why)


def _link_target(archive: zipfile.ZipFile, info: zipfile.ZipInfo, name: str, tree: str, limits: ArchiveLimits,
                 total: int) -> tuple[str, list[str], int]:
    """The stripped name a link entry's text names, resolved lexically against the link's directory (P6-10 spec 7.2.2,
    7.2.3, D4, D8), the names the text walks through on the way (each must be a real directory of the tree, which
    `_follow_links` judges: spec 7.1.2), and the running total of real bytes. The text is at most `LINK_MAX` bytes,
    UTF-8, not empty, with no NUL and no backslash, not absolute and with no drive, no empty segment and no segment of
    only dots and spaces other than `.` and `..`, after one leading `./` and one trailing `/` are dropped: otherwise
    `unsafe_target`. A walk that leaves `tree` at any step, even when a later segment comes back in, is `outside`."""
    if info.file_size > LINK_MAX:
        raise ArchiveError("symlink", info.filename, why="unsafe_target")
    raw, total = _read_entry(archive, info, limits, total)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ArchiveError("symlink", info.filename, why="unsafe_target") from None
    if text.startswith("./"):
        text = text[2:]
    if text.endswith("/"):
        text = text[:-1]
    segments = text.split("/")
    if (len(raw) > LINK_MAX or not text or "\x00" in text or "\\" in text or text.startswith("/") or _DRIVE.match(text)
            or any(not segment.strip(". ") and segment not in (".", "..") for segment in segments)):
        raise ArchiveError("symlink", info.filename, why="unsafe_target")
    floor = len(tree.split("/")) if tree else 0
    walk = name.split("/")[:-1]
    passed: list[str] = []  # every name the text enters before its last segment: a file system reads each as a directory
    for index, segment in enumerate(segments):
        if segment == "..":
            if len(walk) <= floor:
                raise ArchiveError("symlink", info.filename, why="outside")
            walk.pop()
        elif segment != ".":
            walk.append(segment)
            if index < len(segments) - 1:
                passed.append("/".join(walk))
    return "/".join(walk), passed, total


def list_zip(data: bytes, limits: ArchiveLimits = REPOSITORY_LIMITS) -> frozenset[str]:
    """The stripped names of every file and symbolic link entry of a zip held in memory (no directory entry), read from the
    central directory only: no entry is opened (1.23.0, P6-10 spec 7.5, D13). It applies the checks `unpack_zip` applies to
    the whole archive when a root is named, and no other: `max_compressed`, `max_entries`, `bad_zip`, a suspicious raw name
    (`unsafe_path`) and an entry through a link or sharing its name (`unsafe_path`). Each name is read later, if at all, by
    `unpack_zip` with its own root, where every rule applies. No file at all is `empty`. Devices, FIFOs and sockets are not
    listed."""
    _archive, infos = _open(data, limits)
    for info in infos:
        if _suspicious(info.filename):
            raise ArchiveError("unsafe_path", info.filename)
    all_files = [info for info in infos if not info.is_dir()]
    top = _strip_common_top([info.filename for info in all_files])

    def stripped(name: str) -> str:
        return name[len(top) + 1:] if top and name.startswith(top + "/") else name

    _check_symlink_paths(infos, stripped)
    names = frozenset(stripped(info.filename) for info in all_files if _is_link(info) or not _is_special(info))
    if not names:
        raise ArchiveError("empty")
    return names


def _check_symlink_paths(infos: list[zipfile.ZipInfo], stripped) -> None:
    """A symbolic link (or other special entry) is allowed, but not one that another entry's path passes through
    (`link` -> `skill` and `link/evil.sh`, also `Link` and `link/evil.sh`) or that another entry shares its name with
    (`link` written again as a file): an extractor that follows the link it has just written puts that file under the
    root unscanned. Checked over the whole archive for every root since 1.23.0 (P6-10 spec 7.2.6). Header metadata only;
    nothing is opened."""
    special = [info for info in infos if not info.is_dir() and _is_special(info)]
    if not special:
        return
    # Compared on the platform key, so `Link` and `link/evil.sh` meet as a case-insensitive extractor merges them.
    links = {_platform_key(stripped(info.filename.rstrip("/"))) for info in special}
    # By identity, in one step (1.23.0): the guard runs for every root and for `list_zip`, on up to `max_entries` entries, so
    # it must not compare every entry with every special entry (20,000 links beside 20,000 files took 9 seconds that way).
    own_entries = {id(info) for info in special}
    for info in infos:
        parts = _platform_key(stripped(info.filename.rstrip("/"))).split("/")
        # Every proper prefix; and the entry's own path unless it is the symlink itself: a file written after a link
        # of the same name is written through it, and a directory entry `link/` is the link's own path.
        own = 0 if id(info) in own_entries else 1
        for depth in range(1, len(parts) + own):
            if "/".join(parts[:depth]) in links:
                raise ArchiveError("unsafe_path", f"through a symlink {info.filename}")


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
