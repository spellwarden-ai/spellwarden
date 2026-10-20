"""Spec 6.13 containment and safe opening (claim C13). Every test runs the
`dir_fd` walk where the platform has it and the Windows real-path branch
(forced with `_HAS_DIR_FD = False`) on every platform."""
from __future__ import annotations

import os

import pytest

from spellwarden_cli import paths
from spellwarden_cli.paths import TooLarge, UnsafePath, read_contained

BRANCHES = [pytest.param(True, id="dir_fd"), pytest.param(False, id="realpath")]


@pytest.fixture(params=BRANCHES)
def branch(request, monkeypatch):
    if request.param and os.open not in os.supports_dir_fd:
        pytest.skip("this platform has no dir_fd")
    monkeypatch.setattr(paths, "_HAS_DIR_FD", request.param)
    return request.param


def _symlink(target, link, *, directory=False):
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")


@pytest.mark.usefixtures("branch")
def test_reads_a_contained_file_and_its_mode(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "c.txt").write_bytes(b"hello")
    data, mode = read_contained(str(tmp_path), "a/b/c.txt", max_bytes=10)
    assert data == b"hello"
    assert mode & 0o444


@pytest.mark.parametrize("relative", ["/etc/passwd", "..\\x", "C:\\x", "C:x", "\\\\server\\share", "../x", "a/../../x",
                                      "", "a\x00b", "a/./b"])
@pytest.mark.usefixtures("branch")
def test_refuses_unsafe_paths(tmp_path, relative):
    with pytest.raises(UnsafePath):
        read_contained(str(tmp_path), relative, max_bytes=10)


@pytest.mark.usefixtures("branch")
def test_refuses_a_symlinked_file(tmp_path):
    (tmp_path / "secret").write_bytes(b"s")
    _symlink(tmp_path / "secret", tmp_path / "link")
    with pytest.raises(UnsafePath):
        read_contained(str(tmp_path), "link", max_bytes=10)


@pytest.mark.usefixtures("branch")
def test_refuses_a_symlinked_directory_component(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "f").write_bytes(b"x")
    root = tmp_path / "root"
    root.mkdir()
    _symlink(outside, root / "d", directory=True)
    with pytest.raises(UnsafePath):
        read_contained(str(root), "d/f", max_bytes=10)


@pytest.mark.usefixtures("branch")
def test_a_file_swapped_for_a_symlink_after_listing_is_refused(tmp_path, monkeypatch):
    (tmp_path / "secret").write_bytes(b"secret")
    (tmp_path / "plain").write_bytes(b"plain")

    def swap(relative):
        os.unlink(tmp_path / relative)
        _symlink(tmp_path / "secret", tmp_path / relative)

    monkeypatch.setattr(paths, "_BEFORE_OPEN", swap)
    with pytest.raises(UnsafePath):
        read_contained(str(tmp_path), "plain", max_bytes=100)


@pytest.mark.usefixtures("branch")
def test_too_large_and_missing(tmp_path):
    (tmp_path / "big").write_bytes(b"x" * 11)
    with pytest.raises(TooLarge):
        read_contained(str(tmp_path), "big", max_bytes=10)
    with pytest.raises(FileNotFoundError):
        read_contained(str(tmp_path), "missing", max_bytes=10)


@pytest.mark.skipif(not hasattr(os, "mkfifo") or os.open not in os.supports_dir_fd, reason="no FIFOs here")
def test_a_fifo_is_refused_without_blocking(tmp_path):
    # Only the dir_fd walk: the real-path branch is Windows', which has no FIFOs.
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(UnsafePath):
        read_contained(str(tmp_path), "pipe", max_bytes=10)


@pytest.mark.usefixtures("branch")
def test_a_scan_below_the_repository_root_reads_relative_to_it(tmp_path):
    (tmp_path / "services" / "agent").mkdir(parents=True)
    (tmp_path / "services" / "agent" / "x").write_bytes(b"1")
    (tmp_path / "top").write_bytes(b"2")
    assert read_contained(str(tmp_path / "services" / "agent"), "x", max_bytes=1)[0] == b"1"
    with pytest.raises(UnsafePath):
        read_contained(str(tmp_path / "services" / "agent"), "../../top", max_bytes=1)
