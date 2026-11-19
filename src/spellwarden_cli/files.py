"""The scan root and the file set (spec 6.4). Git first (tracked files with
their index modes, then untracked unignored files), a directory walk
otherwise. Listing reads metadata only, never file content (plan P12).
`StagedIndex` (1.19.0, `scan --staged`) is the other file set: the git index
alone, every file read from its staged blob."""
from __future__ import annotations

import errno
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import unicodedata
import weakref
from collections.abc import Mapping
from dataclasses import dataclass, field

from spellwarden_scan import identity

from spellwarden_cli import paths
from spellwarden_cli.report import Notice
from spellwarden_cli.settings import Settings, glob_match

FILE_MAX = 10 * 2**20
LINK_MAX = 4096  # the longest symbolic link target read (PATH_MAX on Linux)
SKIP_DIRS = (".git", *identity.SKIP_DIRS)
_GIT_TIMEOUT = 120


@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    executable: bool
    tracked: bool


@dataclass(frozen=True)
class LinkEntry:
    """A listed symbolic link: index mode `120000`, or a link in the working tree (a linked directory too). Never read
    as a file; discovery follows one at an agent-content path or inside a skill package or local plugin directory
    (spec 6.4, 6.5) and reports every other as `symlink_skipped`."""
    path: str
    tracked: bool


@dataclass(frozen=True)
class FileSet:
    root: str
    entries: tuple[FileEntry, ...]
    repo_prefix: str | None  # `git rev-parse --show-prefix`: "" at the top, "sub/dir/" below it, None outside git
    notices: tuple[Notice, ...]
    errors: tuple[Notice, ...]
    links: tuple[LinkEntry, ...] = ()
    # O3 spec 6.6, P48: what the connected gate needs to say that a skill's package cannot be hashed as a forge archive
    # holds it. `skipped_dirs`: the SKIP_DIRS directories the walk did not enter (git mode lists them through the index,
    # so it records none); `deselected`: every path `include` or `exclude` dropped. Scan-root paths, sorted.
    skipped_dirs: tuple[str, ...] = ()
    deselected: tuple[str, ...] = ()
    # 1.16.1: the regular files over `FILE_MAX` that `include` and `exclude` keep, sorted. They are not read and not
    # entries; discovery decides what each one is: agent content left unread is the error `unreadable` (an incomplete
    # scan, README "Limits"), any other file the notice `file_too_large`.
    too_large: tuple[str, ...] = ()
    # 1.19.0: the git index this file set was read from under `scan --staged` (`StagedIndex.fileset`), else None. With it, `read`
    # and `link_target` return the staged blobs, never the working tree's files.
    index: StagedIndex | None = field(default=None, compare=False, repr=False)

    def paths(self) -> frozenset[str]:
        return frozenset(entry.path for entry in self.entries)

    def read(self, path: str) -> bytes:
        if self.index is not None:
            return self.index.blob(path, FILE_MAX)
        return paths.read_contained(self.root, path, max_bytes=FILE_MAX)[0]

    def link_target(self, path: str) -> bytes:
        """The target text of the listed link `path`, at most `LINK_MAX` bytes (`paths.read_link`, or the staged blob)."""
        if self.index is not None:
            return self.index.link_text(path, LINK_MAX)
        return paths.read_link(self.root, path, max_bytes=LINK_MAX)


class _GitFailed(Exception):
    pass


def work_tree_top(root: str) -> str | None:
    """The first directory at or above `root` holding `.git` (a directory, or a file starting `gitdir:`).
    Runs no git: the answer feeds `safe.directory`, which must be known before git is trusted."""
    current = os.path.abspath(root)
    while True:
        marker = os.path.join(current, ".git")
        if os.path.isdir(marker):
            return current
        if os.path.isfile(marker):
            try:
                with open(marker, "rb") as handle:
                    if handle.read(8) == b"gitdir: ":
                        return current
            except OSError:
                pass
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def list_files(root: str, settings: Settings, *, git: str | None = None, platform: str = sys.platform,
               env: Mapping[str, str] | None = None) -> FileSet:
    """`git=None` looks git up on `PATH`; `git=""` disables it (the walk). Entries are sorted by path. Git runs with
    the explicit environment `env` (else a copy of ours; O3 invariant 2)."""
    root = os.path.abspath(root)
    notices: list[Notice] = []
    errors: list[Notice] = []
    top = work_tree_top(root)
    executable = shutil.which("git") if git is None else git
    listed: list[tuple[str, str | None]] | None = None  # (path, index mode or None when untracked)
    prefix: str | None = None
    if top is not None and executable:
        try:
            prefix, listed = _git_listing(executable, top, root, notices, env)
        except _GitFailed as exc:
            notices.append(Notice("git_unavailable", "", f"git could not list the files ({exc}); the directory was walked"))
    skipped: list[str] = []
    if listed is None:
        listed = _walk(root, notices, skipped)
        if top is not None:
            relative = os.path.relpath(root, top).replace(os.sep, "/")
            prefix = "" if relative == "." else relative + "/"
    if prefix is None:
        notices.append(Notice("upload_paths_scan_root", ".", "not inside a git repository: SARIF and Code Quality "
                                                             "paths are relative to the scan root, and code scanning or "
                                                             "Code Quality uploads need a scan inside a repository"))
    entries, links, large = _entries(root, listed, platform, notices, errors)
    return _narrowed(root, prefix, entries, links, large, notices, errors, settings, platform=platform, skipped=skipped)


def _narrowed(root: str, prefix: str | None, entries: list[FileEntry], links: list[LinkEntry], large: list[str],
              notices: list[Notice], errors: list[Notice], settings: Settings, *, platform: str,
              skipped: list[str] | None = None, index: StagedIndex | None = None) -> FileSet:
    """The `FileSet` of what `include` and `exclude` keep, every path they dropped in `deselected` (both file sets)."""
    deselected = sorted({*(item.path for item in (*entries, *links) if not _selected(item.path, settings)),
                         *(path for path in large if not _selected(path, settings))})
    entries = [e for e in entries if _selected(e.path, settings)]
    links = [link for link in links if _selected(link.path, settings)]
    large = [path for path in large if _selected(path, settings)]
    if platform == "win32" and any(not entry.tracked for entry in entries):
        notices.append(Notice("exec_bits_unknown", "", "Windows records no executable bit; untracked files were "
                                                       "judged not executable"))
    return FileSet(root, tuple(sorted(entries, key=lambda e: e.path)), prefix, tuple(notices), tuple(errors),
                   tuple(sorted(links, key=lambda link: link.path)), tuple(sorted(skipped or ())), tuple(deselected),
                   tuple(sorted(large)), index)


def _selected(path: str, settings: Settings) -> bool:
    if settings.include and not any(glob_match(path, pattern) for pattern in settings.include):
        return False
    return not any(glob_match(path, pattern) for pattern in settings.exclude)


def _git_command(executable: str, top: str, root: str, *args: str) -> list[str]:
    return [executable, "-c", f"safe.directory={top.replace(os.sep, '/')}", "-c", "core.fsmonitor=false", "-C", root, *args]


def _git(executable: str, top: str, root: str, *args: str, env: Mapping[str, str] | None = None,
         stdin: bytes | None = None) -> bytes:
    command = _git_command(executable, top, root, *args)
    feed = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}
    try:
        done = subprocess.run(command, capture_output=True, check=False, timeout=_GIT_TIMEOUT,
                              env=dict(os.environ) if env is None else dict(env), **feed)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _GitFailed(type(exc).__name__) from exc
    if done.returncode != 0:
        first = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise _GitFailed(first[0] if first else f"exit {done.returncode}")
    return done.stdout


def _decode(raw: bytes, notices: list[Notice]) -> str | None:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        notices.append(Notice("non_utf8_path", raw.decode("utf-8", "backslashreplace"), "path is not valid UTF-8; skipped"))
        return None


def _git_listing(executable: str, top: str, root: str, notices: list[Notice],
                 env: Mapping[str, str] | None = None) -> tuple[str, list[tuple[str, str | None]]]:
    prefix = _git(executable, top, root, "rev-parse", "--show-prefix", env=env).decode("utf-8", "replace").strip()
    staged = _git(executable, top, root, "ls-files", "-z", "--stage", "--full-name", env=env)
    others = _git(executable, top, root, "ls-files", "-z", "--others", "--exclude-standard", "--full-name", env=env)
    listed: dict[str, str | None] = {}
    for record in staged.split(b"\0"):
        if not record:
            continue
        meta, _, raw = record.partition(b"\t")
        mode = meta.split(b" ", 1)[0].decode("ascii", "replace")
        path = _decode(raw, notices)
        if path is None or not path.startswith(prefix):
            continue
        relative = path[len(prefix):]
        if mode == "160000":  # a submodule is not entered
            continue
        listed.setdefault(relative, mode)
    for raw in others.split(b"\0"):
        if not raw or raw.endswith(b"/"):  # an untracked nested repository is listed as a directory
            continue
        path = _decode(raw, notices)
        if path is not None and path.startswith(prefix):
            listed.setdefault(path[len(prefix):], None)
    return prefix, sorted(listed.items())


def _walk(root: str, notices: list[Notice], skipped: list[str]) -> list[tuple[str, str | None]]:
    found: list[tuple[str, str | None]] = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        base = os.path.relpath(directory, root).replace(os.sep, "/")
        base = "" if base == "." else base + "/"
        kept = []
        for name in sorted(dirnames):
            if name in SKIP_DIRS:
                if name != ".git":  # a repository's own metadata is no package content
                    skipped.append(base + name)
                continue
            if os.path.islink(os.path.join(directory, name)):
                found.append((base + name, None))  # a linked directory is a listed link, never entered (r2:F6)
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            try:
                name.encode("utf-8")
            except UnicodeEncodeError:
                raw = os.fsencode(name)
                notices.append(Notice("non_utf8_path", base + raw.decode("utf-8", "backslashreplace"),
                                      "path is not valid UTF-8; skipped"))
                continue
            found.append((base + name, None))
    return found


def _colliding(listed_paths: list[str], errors: list[Notice]) -> set[str]:
    """The paths that differ from another only in case or Unicode form, each the error `case_collision` (both file sets)."""
    folded: dict[str, list[str]] = {}
    for path in listed_paths:
        folded.setdefault(unicodedata.normalize("NFC", path).casefold(), []).append(path)
    colliding = {path for group in folded.values() if len(group) > 1 for path in group}
    for path in sorted(colliding):
        errors.append(Notice("case_collision", path, "another path differs only in case or Unicode form; "
                                                     "a macOS or Windows checkout holds only one of them"))
    return colliding


def _entries(root: str, listed: list[tuple[str, str | None]], platform: str, notices: list[Notice],
             errors: list[Notice]) -> tuple[list[FileEntry], list[LinkEntry], list[str]]:
    colliding = _colliding([path for path, _ in listed], errors)
    entries: list[FileEntry] = []
    links: list[LinkEntry] = []
    large: list[str] = []
    for path, mode in listed:
        if path in colliding:
            continue
        try:
            info = os.lstat(os.path.join(root, *path.split("/")))
        except FileNotFoundError:
            notices.append(Notice("file_missing", path, "listed by git but missing from the working tree; skipped"))
            continue
        except OSError as exc:
            errors.append(Notice("unreadable", path, f"cannot be read ({exc.strerror})"))
            continue
        # The index decides a tracked link; a checkout without symlink support holds a plain file of the target text.
        if mode == "120000" or stat.S_ISLNK(info.st_mode):
            links.append(LinkEntry(path, mode is not None))
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        if info.st_size > FILE_MAX:  # not read; discovery says whether it is agent content (1.16.1)
            large.append(path)
            continue
        if mode is not None:
            executable = mode == "100755"  # the index decides for tracked files, on every OS
        else:
            executable = platform != "win32" and bool(info.st_mode & 0o111)
        entries.append(FileEntry(path, info.st_size, executable, mode is not None))
    return entries, links, large


# --- 1.19.0: `scan --staged`, the git index as the file set -------------------------------------------------------------

_REGULAR_MODES = ("100644", "100755")
_LINK_MODE = "120000"
_GITLINK_MODE = "160000"
_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
CONFLICT_MESSAGE = ("the index holds an unresolved merge conflict for this path, so it was not read: resolve the conflict and "
                    "stage the file")


class StagedUnavailable(Exception):
    """`scan --staged` cannot read the index (1.19.0): the scan root is not inside a git work tree, git is not found, or a git
    call failed. The message says which; the command reports it as the error `staged_unavailable` (exit 2)."""


@dataclass(frozen=True)
class IndexEntry:
    """One path of the index at stage 0 (1.19.0): its mode (`100644`, `100755` or `120000`), its blob's object id and size."""
    mode: str
    oid: str
    size: int


def _stop_batch(process: subprocess.Popen) -> None:
    """Ends a `git cat-file --batch` process: its input closed (git then exits), killed if it has not exited soon after."""
    for pipe in (process.stdin, process.stdout):
        try:
            if pipe is not None:
                pipe.close()
        except OSError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


class StagedIndex:
    """The git index of the work tree holding a scan root, read once (1.19.0, `scan --staged`): every path at stage 0 under the
    scan root with its mode, object id and size (`git ls-files -z --stage --full-name`, then one `git cat-file --batch-check`),
    and each blob read when it is asked for, through one `git cat-file --batch` process kept for the index's life (started at
    the first read, ended by `close`), as stored: no filter and no line-ending conversion, so the bytes are the same on every
    system. A staged scan so reads what would be committed whatever the working tree holds: no untracked file and no unstaged
    change, and a path removed from the index is not listed. Raises `StagedUnavailable`."""

    def __init__(self, root: str, *, git: str | None = None, env: Mapping[str, str] | None = None) -> None:
        self.root = os.path.abspath(root)
        self.env = dict(os.environ) if env is None else dict(env)
        top = work_tree_top(self.root)
        if top is None:
            raise StagedUnavailable("--staged needs a git repository.")
        executable = shutil.which("git") if git is None else git
        if not executable:
            raise StagedUnavailable("--staged needs git, and git was not found on PATH.")
        self.top = top
        self.executable = executable
        self.notices: list[Notice] = []
        try:
            self.prefix = self._git("rev-parse", "--show-prefix").decode("utf-8", "replace").strip()
            listed, self.conflicted = self._listing(self._git("ls-files", "-z", "--stage", "--full-name"))
            sizes = self._sizes(sorted({oid for _, oid in listed.values()}))
        except _GitFailed as exc:
            raise StagedUnavailable(f"--staged could not read the git index ({exc}).") from exc
        self.entries: dict[str, IndexEntry] = {path: IndexEntry(mode, oid, sizes[oid])
                                               for path, (mode, oid) in sorted(listed.items())}
        self._batch: subprocess.Popen | None = None
        self._batch_end: weakref.finalize | None = None  # ends the process if the index is dropped without `close`
        self._lock = threading.Lock()

    def close(self) -> None:
        """Ends the `git cat-file --batch` process, if one was started; a later read starts another."""
        with self._lock:
            self._end_batch()

    def __enter__(self) -> StagedIndex:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _end_batch(self) -> None:
        if self._batch_end is not None:
            self._batch_end()  # calls `_stop_batch` once
        self._batch = self._batch_end = None

    def _git(self, *args: str, stdin: bytes | None = None) -> bytes:
        return _git(self.executable, self.top, self.root, *args, env=self.env, stdin=stdin)

    def _listing(self, raw: bytes) -> tuple[dict[str, tuple[str, str]], tuple[str, ...]]:
        """The stage-0 paths under the scan root, scan-root-relative, with `(mode, object id)`; and the paths that have conflict
        stages only (an unresolved merge). A submodule (`160000`) is not entered, as in a working-tree scan."""
        staged: dict[str, tuple[str, str]] = {}
        unmerged: set[str] = set()
        for record in raw.split(b"\0"):
            if not record:
                continue
            meta, _, name = record.partition(b"\t")
            fields = meta.decode("ascii", "replace").split(" ")
            path = _decode(name, self.notices)
            if path is None or len(fields) != 3 or not path.startswith(self.prefix):
                continue
            mode, oid, stage = fields
            if _OBJECT_ID.fullmatch(oid) is None:
                raise _GitFailed("the index lists an object id git did not write")
            relative = path[len(self.prefix):]
            if stage != "0":
                unmerged.add(relative)
            elif mode != _GITLINK_MODE:
                staged[relative] = (mode, oid)
        return staged, tuple(sorted(unmerged - staged.keys()))

    def _sizes(self, oids: list[str]) -> dict[str, int]:
        """The size of each blob, from one `git cat-file --batch-check`."""
        if not oids:
            return {}
        answer = self._git("cat-file", "--batch-check", stdin="".join(f"{oid}\n" for oid in oids).encode("ascii"))
        sizes: dict[str, int] = {}
        for line in answer.decode("ascii", "replace").splitlines():
            fields = line.split(" ")
            if len(fields) == 3 and fields[2].isdigit():
                sizes[fields[0]] = int(fields[2])
        missing = [oid for oid in oids if oid not in sizes]
        if missing:
            raise _GitFailed(f"git cannot read {len(missing)} of the objects the index names")
        return sizes

    def _blob(self, entry: IndexEntry, shown: str) -> bytes:
        """The bytes of `entry`'s blob, from the index's one `git cat-file --batch` process (binary pipes, no shell). Raises
        `OSError` when git cannot give them; the process is then ended, since its output may be out of step, and the next read
        starts another. A read that takes longer than git's time limit ends the process too."""
        with self._lock:
            if self._batch is None:
                try:
                    self._batch = subprocess.Popen(_git_command(self.executable, self.top, self.root, "cat-file", "--batch"),
                                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                                   env=self.env)
                except (OSError, subprocess.SubprocessError) as exc:
                    raise OSError(errno.EIO, f"git cannot read the staged {shown} ({type(exc).__name__})") from exc
                self._batch_end = weakref.finalize(self, _stop_batch, self._batch)
            process = self._batch
            timer = threading.Timer(_GIT_TIMEOUT, process.kill)
            timer.start()
            try:
                process.stdin.write(f"{entry.oid}\n".encode("ascii"))
                process.stdin.flush()
                header = process.stdout.readline(256)
                fields = header.decode("ascii", "replace").rstrip("\n").split(" ")
                if len(fields) != 3 or fields[1] != "blob" or fields[2] != str(entry.size):
                    raise OSError(errno.EIO, f"git did not return the staged {shown}")
                content = process.stdout.read(entry.size)
                if len(content) != entry.size or process.stdout.read(1) != b"\n":
                    raise OSError(errno.EIO, f"git did not return the staged {shown}")
                return content
            except OSError as exc:
                self._end_batch()
                if exc.errno == errno.EIO:
                    raise
                raise OSError(errno.EIO, f"git cannot read the staged {shown} ({type(exc).__name__})") from exc
            finally:
                timer.cancel()

    def blob(self, path: str, max_bytes: int) -> bytes:
        """The staged bytes of the regular file `path` (scan-root-relative), what `FileSet.read` returns under `--staged`:
        `FileNotFoundError` when the index holds no such file, `paths.TooLarge` past `max_bytes`, `OSError` when git cannot
        give the blob."""
        entry = self.entries.get(path)
        if entry is None or entry.mode not in _REGULAR_MODES:
            raise FileNotFoundError(errno.ENOENT, "not a file of the index", path)
        if entry.size > max_bytes:
            raise paths.TooLarge(f"{path}: more than {max_bytes} bytes")
        return self._blob(entry, path)

    def link_text(self, path: str, max_bytes: int) -> bytes:
        """The target text of the staged symbolic link `path` (index mode `120000`), at most `max_bytes` bytes."""
        entry = self.entries.get(path)
        if entry is None or entry.mode != _LINK_MODE:
            raise paths.UnsafePath(f"{path}: not a symbolic link of the index")
        if entry.size > max_bytes:
            raise paths.TooLarge(f"{path}: link target longer than {max_bytes} bytes")
        return self._blob(entry, path)

    def read(self, relative: str, max_bytes: int) -> bytes:
        """The staged settings file, baseline or lock file `relative` (scan-root-relative), with the contract of
        `ci.RevisionSource.read`: `FileNotFoundError` when the index does not hold it, `paths.TooLarge` past `max_bytes`,
        `paths.UnsafePath` for a link, anything but a regular file, or a file of the index where a directory of the path is."""
        contained = paths.contain("", relative)
        parts = contained.split("/")
        for depth in range(1, len(parts)):
            above = "/".join(parts[:depth])
            if above in self.entries:
                raise paths.UnsafePath(f"{contained}: {above} is not a directory in the index")
        entry = self.entries.get(contained)
        if entry is None:
            raise FileNotFoundError(errno.ENOENT, "not in the index", contained)
        if entry.mode not in _REGULAR_MODES:
            raise paths.UnsafePath(f"{contained}: not a regular file in the index")
        if entry.size > max_bytes:
            raise paths.TooLarge(f"{contained}: more than {max_bytes} bytes")
        return self._blob(entry, contained)

    def fileset(self, settings: Settings) -> FileSet:
        """The file set of a staged scan: every regular file and link of the index under the scan root, the executable bit
        the index mode's, narrowed by `include` and `exclude`; a file over `FILE_MAX` is in `too_large` as in a working-tree
        scan, and a path with an unresolved merge conflict is the error `unreadable`."""
        notices = list(self.notices)
        errors = [Notice("unreadable", path, CONFLICT_MESSAGE) for path in self.conflicted]
        colliding = _colliding(list(self.entries), errors)
        entries: list[FileEntry] = []
        links: list[LinkEntry] = []
        large: list[str] = []
        for path, entry in self.entries.items():
            if path in colliding:
                continue
            if entry.mode == _LINK_MODE:
                links.append(LinkEntry(path, True))
            elif entry.mode in _REGULAR_MODES:
                if entry.size > FILE_MAX:
                    large.append(path)
                else:
                    entries.append(FileEntry(path, entry.size, entry.mode == "100755", True))
        return _narrowed(self.root, self.prefix, entries, links, large, notices, errors, settings, platform=sys.platform,
                         index=self)


__all__ = ["CONFLICT_MESSAGE", "FILE_MAX", "LINK_MAX", "SKIP_DIRS", "FileEntry", "FileSet", "IndexEntry", "LinkEntry",
           "StagedIndex", "StagedUnavailable", "list_files", "work_tree_top"]
