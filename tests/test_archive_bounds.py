"""P6-10 spec 7.3, 7.4 and 7.6 (1.23.0; claims T8, T9, T10, T12): the path bound is measured on the stripped name, the whole
archive holds at most `max_entries` central directory headers (counted in its bytes, before `zipfile` parses one),
`REPOSITORY_LIMITS` is the named bound for a repository's archive read under a root, and `ArchiveError` carries `why`."""
from __future__ import annotations

import dataclasses
import io
import struct
import zipfile
import zlib

import pytest

import spellwarden_scan
from spellwarden_scan.archive import DEFAULT_LIMITS, REPOSITORY_LIMITS, ArchiveError, ArchiveLimits, unpack_zip

# The forge's top directory of hashicorp/agent-skills at its pinned commit is 54 characters with its slash (spec 2.4).
TOP = "agent-skills-" + "5e30fa5c867b" + "0" * 28


def _zip(entries: list[tuple[str, bytes]], *, method: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


def _headers(count: int, declared: int) -> bytes:
    """One stored file `skill/SKILL.md` whose central directory repeats its header `count` times, under an end record that
    declares `declared` entries: the shape of spec 7.4.1, where `zipfile` parses every header whatever the record says."""
    name, content = b"skill/SKILL.md", b"---\nname: x\n---\n"
    crc = zlib.crc32(content)
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0, crc, len(content), len(content), len(name), 0)
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0, crc, len(content), len(content), len(name),
                          0, 0, 0, 0, 0, 0) + name
    directory = central * count
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, declared, declared, len(directory), len(local) + len(name) + len(content), 0)
    return local + name + content + directory + end


class _Reached(Exception):
    """Raised by the patched `zipfile.ZipFile`: the archive got past the entry bound."""


@pytest.fixture
def no_zipfile(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise _Reached

    monkeypatch.setattr(zipfile, "ZipFile", refuse)


def test_a_raw_name_over_255_characters_whose_stripped_name_is_within_the_bound_is_read():
    name = "plugins/terraform/skills/terraform-policy/examples/conversion/" + "x" * 142
    assert len(name) == 204 and len(f"{TOP}/{name}") == 258
    data = _zip([(f"{TOP}/SKILL.md", b"a"), (f"{TOP}/{name}", b"b")])
    assert unpack_zip(data) == {"SKILL.md": b"a", name: b"b"}
    scoped = "plugins/terraform/skills/terraform-policy"
    assert set(unpack_zip(data, root=scoped)) == {name}


def test_a_stripped_name_over_255_characters_is_unsafe_path():
    data = _zip([(f"{TOP}/SKILL.md", b"a"), (f"{TOP}/" + "y" * 256, b"b")])
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(data)
    assert caught.value.code == "unsafe_path" and caught.value.why == ""
    assert set(unpack_zip(_zip([(f"{TOP}/SKILL.md", b"a"), (f"{TOP}/" + "y" * 255, b"b")]))) == {"SKILL.md", "y" * 255}


def test_a_long_raw_directory_entry_is_measured_on_its_stripped_name():
    directory = "d" * 210
    assert len(f"{TOP}/{directory}") == 264 and len(directory) <= 255  # the raw directory name alone is over the bound
    data = _zip([(f"{TOP}/SKILL.md", b"a"), (f"{TOP}/{directory}/", b""), (f"{TOP}/{directory}/x", b"b")])
    assert set(unpack_zip(data)) == {"SKILL.md", f"{directory}/x"}
    long = "e" * 256
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(_zip([(f"{TOP}/SKILL.md", b"a"), (f"{TOP}/{long}/", b"")]))
    assert caught.value.code == "unsafe_path"


@pytest.mark.usefixtures("no_zipfile")
def test_more_central_headers_than_the_bound_are_refused_before_zipfile_is_called():
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(_headers(100_001, 1), root="skill")
    assert (caught.value.code, caught.value.why) == ("too_many_files", "archive_entries")
    assert caught.value.detail == "more than 100000 entries in the archive"


def test_an_archive_that_declares_its_100001_entries_truthfully_is_refused_too(monkeypatch):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("skill/SKILL.md", b"a")
        for index in range(100_000):
            archive.writestr(f"vendor/{index}", b"")
    data = buffer.getvalue()

    def refuse(*_args, **_kwargs):
        raise _Reached

    monkeypatch.setattr(zipfile, "ZipFile", refuse)
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(data, REPOSITORY_LIMITS, root="skill")
    assert (caught.value.code, caught.value.why) == ("too_many_files", "archive_entries")


@pytest.mark.usefixtures("no_zipfile")
def test_an_archive_of_exactly_100000_headers_passes_the_bound():
    with pytest.raises(_Reached):
        unpack_zip(_headers(100_000, 1), root="skill")


def test_the_entry_bound_follows_the_limits_given():
    data = _zip([("skill/SKILL.md", b"a"), ("vendor/a", b"b"), ("vendor/b", b"c")])
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(data, ArchiveLimits(max_entries=2), root="skill")
    assert (caught.value.code, caught.value.why) == ("too_many_files", "archive_entries")
    assert unpack_zip(data, ArchiveLimits(max_entries=3), root="skill") == {"skill/SKILL.md": b"a"}


def test_max_files_keeps_its_code_and_detail_with_no_why():
    data = _zip([(f"f{index}", b"x") for index in range(5)])
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(data, ArchiveLimits(max_files=4))
    assert (caught.value.code, caught.value.detail, caught.value.why) == ("too_many_files", "5", "")


def test_the_repository_limits_raise_only_the_compressed_bound():
    assert REPOSITORY_LIMITS.max_compressed == 50 * 2**20
    defaults = ArchiveLimits()
    for field in dataclasses.fields(ArchiveLimits):
        if field.name != "max_compressed":
            assert getattr(REPOSITORY_LIMITS, field.name) == getattr(defaults, field.name), field.name
    assert DEFAULT_LIMITS == ArchiveLimits() and DEFAULT_LIMITS.max_compressed == 20 * 2**20
    assert ArchiveLimits().max_entries == 100_000
    assert spellwarden_scan.REPOSITORY_LIMITS is REPOSITORY_LIMITS


def test_an_archive_of_25_mib_with_a_small_skill_reads_with_the_repository_limits_only():
    data = _zip([("skill/SKILL.md", b"---\nname: x\n---\n"), ("vendor/blob.bin", bytes(25 * 2**20))], method=zipfile.ZIP_STORED)
    assert len(data) > 25 * 2**20
    assert unpack_zip(data, REPOSITORY_LIMITS, root="skill") == {"skill/SKILL.md": b"---\nname: x\n---\n"}
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(data, DEFAULT_LIMITS, root="skill")
    assert caught.value.code == "too_large"


def test_archive_error_why_defaults_to_empty_and_code_and_detail_keep_their_shapes():
    error = ArchiveError("symlink", "x")
    assert (error.code, error.detail, error.why, str(error)) == ("symlink", "x", "", "symlink: x")
    assert ArchiveError("empty").why == "" and str(ArchiveError("empty")) == "empty"
    assert ArchiveError("symlink", "x", why="outside").why == "outside"
