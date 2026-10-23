"""The scan root and the file set (spec 6.4). Git first (tracked files with
their index modes, then untracked unignored files), a directory walk
otherwise. Listing reads metadata only, never file content (plan P12)."""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass

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

    def paths(self) -> frozenset[str]:
        return frozenset(entry.path for entry in self.entries)

    def read(self, path: str) -> bytes:
        return paths.read_contained(self.root, path, max_bytes=FILE_MAX)[0]

    def link_target(self, path: str) -> bytes:
        """The target text of the listed link `path`, at most `LINK_MAX` bytes (`paths.read_link`)."""
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
    if listed is None:
        listed = _walk(root, notices)
        if top is not None:
            relative = os.path.relpath(root, top).replace(os.sep, "/")
            prefix = "" if relative == "." else relative + "/"
    if prefix is None:
        notices.append(Notice("upload_paths_scan_root", ".", "not inside a git repository: SARIF and Code Quality "
                                                             "paths are relative to the scan root, and code scanning or "
                                                             "Code Quality uploads need a scan inside a repository"))
    entries, links = _entries(root, listed, platform, notices, errors)
    entries = [e for e in entries if _selected(e.path, settings)]
    links = [link for link in links if _selected(link.path, settings)]
    if platform == "win32" and any(not entry.tracked for entry in entries):
        notices.append(Notice("exec_bits_unknown", "", "Windows records no executable bit; untracked files were "
                                                       "judged not executable"))
    return FileSet(root, tuple(sorted(entries, key=lambda e: e.path)), prefix, tuple(notices), tuple(errors),
                   tuple(sorted(links, key=lambda link: link.path)))


def _selected(path: str, settings: Settings) -> bool:
    if settings.include and not any(glob_match(path, pattern) for pattern in settings.include):
        return False
    return not any(glob_match(path, pattern) for pattern in settings.exclude)


def _git(executable: str, top: str, root: str, *args: str, env: Mapping[str, str] | None = None) -> bytes:
    command = [executable, "-c", f"safe.directory={top.replace(os.sep, '/')}", "-c", "core.fsmonitor=false",
               "-C", root, *args]
    try:
        done = subprocess.run(command, capture_output=True, check=False, timeout=_GIT_TIMEOUT, stdin=subprocess.DEVNULL,
                              env=dict(os.environ) if env is None else dict(env))
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


def _walk(root: str, notices: list[Notice]) -> list[tuple[str, str | None]]:
    found: list[tuple[str, str | None]] = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        base = os.path.relpath(directory, root).replace(os.sep, "/")
        base = "" if base == "." else base + "/"
        kept = []
        for name in sorted(dirnames):
            if name in SKIP_DIRS:
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


def _entries(root: str, listed: list[tuple[str, str | None]], platform: str, notices: list[Notice],
             errors: list[Notice]) -> tuple[list[FileEntry], list[LinkEntry]]:
    folded: dict[str, list[str]] = {}
    for path, _ in listed:
        folded.setdefault(unicodedata.normalize("NFC", path).casefold(), []).append(path)
    colliding = {path for group in folded.values() if len(group) > 1 for path in group}
    for path in sorted(colliding):
        errors.append(Notice("case_collision", path, "another path differs only in case or Unicode form; "
                                                     "a macOS or Windows checkout holds only one of them"))
    entries: list[FileEntry] = []
    links: list[LinkEntry] = []
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
        if info.st_size > FILE_MAX:
            notices.append(Notice("file_too_large", path, f"larger than {FILE_MAX // 2**20} MiB; skipped"))
            continue
        if mode is not None:
            executable = mode == "100755"  # the index decides for tracked files, on every OS
        else:
            executable = platform != "win32" and bool(info.st_mode & 0o111)
        entries.append(FileEntry(path, info.st_size, executable, mode is not None))
    return entries, links


__all__ = ["FILE_MAX", "LINK_MAX", "SKIP_DIRS", "FileEntry", "FileSet", "LinkEntry", "list_files", "work_tree_top"]
