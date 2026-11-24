"""P6-10 spec 7.5 (1.23.0; claim T11): `list_zip` returns the stripped names of every file and link entry from the central
directory alone, with the whole-archive checks `unpack_zip` applies when a root is named, and opens no entry."""
from __future__ import annotations

import io
import os
import random
import stat
import time
import warnings
import zipfile

import pytest

import spellwarden_scan
from spellwarden_scan.archive import REPOSITORY_LIMITS, ArchiveError, ArchiveLimits, list_zip, unpack_zip

LINK = (stat.S_IFLNK | 0o777) << 16
# A wall-clock budget, as in tests/test_linear_time.py: it scales with SPELLWARDEN_SPEED_FACTOR when that is set (CI sets 3).
BUDGET_SECONDS = 3.0 * float(os.environ.get("SPELLWARDEN_SPEED_FACTOR", "1"))


def _zip(entries: list[tuple[str, bytes]], links: list[tuple[str, bytes]] = ()) -> bytes:
    buffer = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        warnings.simplefilter("ignore")
        for name, content in entries:
            archive.writestr(name, content)
        for name, target in links:
            info = zipfile.ZipInfo(name)
            info.external_attr = LINK
            archive.writestr(info, target)
    return buffer.getvalue()


def _refused(data: bytes, **kwargs) -> ArchiveError:
    with pytest.raises(ArchiveError) as caught:
        list_zip(data, **kwargs)
    return caught.value


def test_the_names_of_files_and_links_are_listed_stripped_without_directories():
    data = _zip([("repo-main/", b""), ("repo-main/skills/a/", b""), ("repo-main/skills/a/SKILL.md", b"a"),
                 ("repo-main/README.md", b"r")], [("repo-main/CLAUDE.md", b"AGENTS.md")])
    assert list_zip(data) == frozenset({"skills/a/SKILL.md", "README.md", "CLAUDE.md"})
    assert spellwarden_scan.list_zip is list_zip


def test_no_entry_is_opened_and_a_corrupt_entry_still_lists(monkeypatch):
    data = bytearray(_zip([("repo-main/skills/a/SKILL.md", b"x" * 4000), ("repo-main/README.md", b"r")]))
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
        info = archive.getinfo("repo-main/skills/a/SKILL.md")
    start = info.header_offset + 30 + len(info.filename.encode()) + 2
    for offset in range(start, start + 20):
        data[offset] ^= 0xFF
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(bytes(data))
    assert caught.value.code == "bad_zip"

    def never(*_args, **_kwargs):
        raise AssertionError("list_zip opened an entry")

    monkeypatch.setattr(zipfile.ZipFile, "open", never)
    assert list_zip(bytes(data)) == frozenset({"skills/a/SKILL.md", "README.md"})


def test_what_is_refused_only_under_a_root_is_listed():
    """Thousands of files, a dangling link, a long name and two names that differ only in case are for `unpack_zip` under
    the root that reads them, not for the listing."""
    entries = [(f"repo-main/vendor/f{index}", b"") for index in range(2500)]
    entries += [("repo-main/skills/a/SKILL.md", b"a"), ("repo-main/" + "x" * 300, b"l"), ("repo-main/Makefile", b"m"),
                ("repo-main/makefile", b"m")]
    names = list_zip(_zip(entries, [("repo-main/dangling", b"nothing")]))
    assert len(names) == 2505 and "dangling" in names


@pytest.mark.parametrize("name", ["repo-main/../x", "repo-main/./x", "repo-main//x", "/x", "C:x",
                                  pytest.param("a\\b", marks=pytest.mark.skipif(
                                      os.sep == "\\", reason="zipfile reads a backslash as `/` on Windows"))])
def test_a_suspicious_name_is_unsafe_path(name):
    assert _refused(_zip([("repo-main/SKILL.md", b"a"), (name, b"x")])).code == "unsafe_path"


def test_a_name_through_a_link_is_unsafe_path():
    data = _zip([("repo-main/SKILL.md", b"a"), ("repo-main/l/evil.sh", b"x")], [("repo-main/l", b"skills")])
    error = _refused(data)
    assert error.code == "unsafe_path" and "through a symlink" in error.detail


def test_the_compressed_and_entry_bounds_apply():
    data = _zip([("repo-main/SKILL.md", random.Random(1).randbytes(4000)), ("repo-main/a", b""), ("repo-main/b", b"")])
    assert _refused(data, limits=ArchiveLimits(max_compressed=1000)).code == "too_large"
    error = _refused(data, limits=ArchiveLimits(max_entries=2))
    assert (error.code, error.why) == ("too_many_files", "archive_entries")
    assert REPOSITORY_LIMITS.max_entries == 100_000


def test_an_archive_with_no_file_is_empty_and_a_broken_one_is_bad_zip():
    assert _refused(_zip([("repo-main/", b""), ("repo-main/skills/", b"")])).code == "empty"
    assert _refused(b"not a zip").code == "bad_zip"


def test_thirty_thousand_link_entries_are_listed_in_linear_time():
    """Plan decision P16 (review round 1, F1): the listing runs the through-link guard on archives of up to `max_entries`
    entries. With 30,000 links beside 30,000 files, the guard that compared each entry with each link took about 20 seconds
    here on the reviewer's laptop; the linear one of Task 2 takes about 0.3."""
    data = _zip([("repo-main/skills/a/SKILL.md", b"a")] + [(f"repo-main/vendor/f{index}", b"") for index in range(30_000)],
                [(f"repo-main/links/l{index}", b"x") for index in range(30_000)])
    started = time.perf_counter()
    assert len(list_zip(data)) == 60_001
    assert time.perf_counter() - started < BUDGET_SECONDS


def test_deep_names_beside_a_link_are_listed_in_linear_time():
    """Review r0:F2: the through-link guard walked every prefix of every name by joining the segments again, so the work
    grew with the square of a name's depth. One link and forty names of 16,000 segments took about 30 seconds here before
    the guard walked a trie of the links' segments; it takes a few milliseconds now."""
    deep = "/".join(["a"] * 16_000)
    data = _zip([(f"repo-main/{deep}/f{index}", b"") for index in range(40)] + [("repo-main/skills/a/SKILL.md", b"a")],
                [("repo-main/link", b"skills/a/SKILL.md")])
    started = time.perf_counter()
    assert len(list_zip(data)) == 42
    assert time.perf_counter() - started < BUDGET_SECONDS
