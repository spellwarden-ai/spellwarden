"""Containment and safe opening (spec 6.13). `contain` is the engine's pure
rule (plan decision P2); `read_contained` opens a scan-root-relative path one
component at a time without following a symbolic link anywhere, and returns
the bytes and the mode of the handle it actually read."""
from __future__ import annotations

import os
import stat
from collections.abc import Callable

from spellwarden_scan.relpath import UnsafePath, contain

_HAS_DIR_FD: bool = os.open in os.supports_dir_fd
_BEFORE_OPEN: Callable[[str], None] | None = None  # test hook: called with the relative path just before opening
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_BINARY = getattr(os, "O_BINARY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)  # a FIFO planted in a checkout must not block the open
_CHUNK = 65536


class TooLarge(ValueError):
    """The file holds more than `max_bytes`."""


def read_contained(root: str, relative: str, *, max_bytes: int) -> tuple[bytes, int]:
    """`(content, st_mode)` of the regular file `relative` under `root`. Raises `UnsafePath` for a path the
    containment rule refuses, a symbolic link at any component ("symlink") or anything but a regular file,
    `TooLarge` past `max_bytes`, and `OSError` when the file cannot be opened or read."""
    contained = contain("", relative)
    if _BEFORE_OPEN is not None:
        _BEFORE_OPEN(contained)
    fd = _open_walk(root, contained) if _HAS_DIR_FD else _open_checked(root, contained)
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode):
            raise UnsafePath(f"{contained}: not a regular file")
        return _read(fd, max_bytes, contained), mode
    finally:
        os.close(fd)


def _is_link(name: str, dir_fd: int) -> bool:
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def _open_walk(root: str, relative: str) -> int:
    """Linux and macOS: each directory is opened relative to its parent's descriptor with `O_NOFOLLOW`, so a
    component swapped for a link after listing is refused, never followed (no stat-then-open)."""
    parts = relative.split("/")
    dir_fd = os.open(root, os.O_RDONLY | _DIRECTORY)
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=dir_fd)
            except OSError as exc:
                if _is_link(part, dir_fd):
                    raise UnsafePath(f"{relative}: symlink") from exc
                raise
            os.close(dir_fd)
            dir_fd = next_fd
        try:
            return os.open(parts[-1], os.O_RDONLY | _NOFOLLOW | _NONBLOCK | _BINARY, dir_fd=dir_fd)
        except OSError as exc:
            if _is_link(parts[-1], dir_fd):
                raise UnsafePath(f"{relative}: symlink") from exc
            raise
    finally:
        os.close(dir_fd)


def _open_checked(root: str, relative: str) -> int:
    """Windows (no `dir_fd`): open, then require that the real path of what was opened is the expected path
    and that the handle and that path are one file; a link anywhere makes the real path differ."""
    base = os.path.realpath(root)
    expected = os.path.join(base, *relative.split("/"))
    fd = os.open(expected, os.O_RDONLY | _BINARY)
    try:
        actual = os.path.realpath(expected)
        if os.path.normcase(actual) != os.path.normcase(expected):
            raise UnsafePath(f"{relative}: symlink")
        opened, named = os.fstat(fd), os.stat(actual, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise UnsafePath(f"{relative}: symlink")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read(fd: int, max_bytes: int, relative: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(_CHUNK, max_bytes + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise TooLarge(f"{relative}: more than {max_bytes} bytes")


__all__ = ["TooLarge", "UnsafePath", "contain", "read_contained"]
