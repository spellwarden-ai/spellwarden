"""Spec 5.6 and claim P4: unsafe and oversize archives are refused with a code."""
from __future__ import annotations

import io
import os
import stat
import zipfile

import pytest

from spellwarden_scan.archive import ArchiveError, ArchiveLimits, unpack_zip


def build(entries: dict[str, bytes], *, attrs: dict[str, int] | None = None, top: str | None = None,
          lie_size: tuple[str, int] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            full = f"{top}/{name}" if top else name
            info = zipfile.ZipInfo(full)
            if attrs and name in attrs:
                info.external_attr = attrs[name]
            zf.writestr(info, content)
    data = buffer.getvalue()
    if lie_size:
        # Rewrite the central-directory uncompressed size of one entry (a lying header). The central
        # record is 46 bytes before the file name; the uncompressed size sits at offset 24 of the record.
        name, declared = lie_size
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            info = zf.getinfo(name)
        marker = info.filename.encode()
        central = data.rfind(marker)
        header = central - 46
        data = data[:header + 24] + declared.to_bytes(4, "little") + data[header + 28:]
    return data


def test_a_plain_archive_unpacks_and_strips_the_common_top_directory():
    data = build({"SKILL.md": b"---\n", "scripts/run.sh": b"x"}, top="repo-main")
    assert unpack_zip(data) == {"SKILL.md": b"---\n", "scripts/run.sh": b"x"}
    assert unpack_zip(build({"SKILL.md": b"a", "other/x": b"b"})) == {"SKILL.md": b"a", "other/x": b"b"}


def test_with_modes_reports_executable_entries():
    data = build({"SKILL.md": b"a", "bin/tool": b"b"}, attrs={"bin/tool": (0o100755 << 16)})
    files, executable = unpack_zip(data, with_modes=True)
    assert set(files) == {"SKILL.md", "bin/tool"} and executable == frozenset({"bin/tool"})


@pytest.mark.parametrize("name", ["../x", "/x", "C:\\x", "a/../../x",
                                  pytest.param("a\\b", marks=pytest.mark.skipif(
                                      os.sep == "\\", reason="zipfile reads a backslash as `/` on Windows")),
                                  "a/./x", "./x", "a//x", "a/."])
def test_unsafe_paths_are_refused(name):
    """A NUL in a name cannot be tested through a real archive: `zipfile` cuts the name at the NUL
    on both write and read, so `_unsafe`'s NUL check is defensive only."""
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(build({name: b"x", "SKILL.md": b"y"}))
    assert caught.value.code == "unsafe_path"


def test_a_symlink_entry_is_refused():
    data = build({"SKILL.md": b"y", "link": b"target"}, attrs={"link": (stat.S_IFLNK | 0o777) << 16})
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(data)
    assert caught.value.code == "symlink"


def test_limits_on_compressed_size_files_and_path_length():
    big = build({"SKILL.md": b"y", "blob": bytes(range(256)) * 64})
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(big, ArchiveLimits(max_compressed=1000))
    assert caught.value.code == "too_large"
    many = build({f"f{i}": b"x" for i in range(5)})
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(many, ArchiveLimits(max_files=4))
    assert caught.value.code == "too_many_files"
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(build({"a" * 300: b"x"}))
    assert caught.value.code == "unsafe_path"


def test_declared_sizes_over_the_limit_are_refused_before_any_entry_is_read(monkeypatch):
    """A header that declares more than the limit is refused from the central directory alone:
    `ZipFile.open` is never called (spec 5.6: the declared sizes are checked first)."""
    data = build({"SKILL.md": b"y", "blob": b"z" * 100}, lie_size=("blob", 10 * 2**20 + 1))

    def never(*args, **kwargs):  # noqa: ARG001
        raise AssertionError("an entry was opened although the declared sizes already exceed the limit")

    monkeypatch.setattr(zipfile.ZipFile, "open", never)
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(data)
    assert caught.value.code == "too_large"


def test_real_bytes_are_counted_while_reading_independently_of_the_headers(monkeypatch):
    """The declared-size check is disabled here on purpose: with chunks of 1024 bytes and a limit of
    2000, a valid 5000-byte entry trips `too_large` on the second chunk, before the CRC is ever
    checked. This is the guarantee that no archive yields more bytes than the limit whatever its
    headers say (spec 5.6, claim P4)."""
    from spellwarden_scan import archive as archive_module

    monkeypatch.setattr(archive_module, "_check_declared", lambda _entries, _limits: None)
    monkeypatch.setattr(archive_module, "_CHUNK", 1024)
    reads = {"n": 0}
    original = zipfile.ZipExtFile.read

    def counting(self, n=-1):
        reads["n"] += 1
        return original(self, n)

    monkeypatch.setattr(zipfile.ZipExtFile, "read", counting)
    data = build({"SKILL.md": b"y", "blob": bytes(range(256)) * 20})
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(data, ArchiveLimits(max_uncompressed=2000))
    assert caught.value.code == "too_large"
    # SKILL.md takes two reads (its byte and the end), the blob trips on its second chunk: four reads, never the six of a full read.
    assert 1 <= reads["n"] <= 4, "the limit tripped mid-stream, long before the 5 chunks of the entry"


def test_a_header_that_understates_the_size_is_bad_zip():
    """`zipfile` never yields more than the declared size, so a header that declares 1 byte for a
    5000-byte entry ends in a size or CRC mismatch, reported as `bad_zip`, never as a silent short read."""
    data = build({"SKILL.md": b"y", "blob": b"z" * 5000}, lie_size=("blob", 1))
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(data)
    assert caught.value.code == "bad_zip"


def test_empty_and_corrupt_archives():
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(build({}))
    assert caught.value.code == "empty"
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(b"not a zip")
    assert caught.value.code == "bad_zip"


@pytest.mark.parametrize("method, skip", [(zipfile.ZIP_DEFLATED, 2), (zipfile.ZIP_BZIP2, 2), (zipfile.ZIP_LZMA, 20)])
def test_a_corrupt_compressed_stream_is_bad_zip(method, skip):
    """r0:F3: a corrupt compressed stream surfaces from `zipfile` as `zlib.error` (deflate), `OSError`
    (bzip2) or `lzma.LZMAError`; each must leave `unpack_zip` as `ArchiveError('bad_zip')`, the only
    error the callers catch."""
    import random
    rng = random.Random(1)
    words = ["alpha", "beta", "gamma", "delta", "spell", "ward"]
    payload = " ".join(rng.choice(words) for _ in range(3000)).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:  # `build` writes stored entries; this needs a real compressed stream
        zf.writestr("a/SKILL.md", payload, compress_type=method)
    data = bytearray(buffer.getvalue())
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as zf:
        info = zf.getinfo("a/SKILL.md")
    start = info.header_offset + 30 + len(info.filename.encode()) + skip  # into the compressed stream, flipping 20 bytes
    for offset in range(start, start + 20):
        data[offset] ^= 0xFF
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(bytes(data))
    assert caught.value.code == "bad_zip"


def raw_zip(names_and_contents: list[tuple[str, bytes]]) -> bytes:
    """An archive that may repeat a name, which `build`'s dict cannot express."""
    import warnings
    buffer = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(buffer, "w") as zf:
        warnings.simplefilter("ignore")  # `zipfile` warns about the duplicate name it is asked to write
        for name, content in names_and_contents:
            zf.writestr(name, content)
    return buffer.getvalue()


@pytest.mark.parametrize("entries", [
    [("SKILL.md", b"scanned"), ("SKILL.md", b"installed")],
    [("SKILL.md", b"scanned"), ("skill.md", b"installed")],
    [("a/run.sh", b"x"), ("a/run.sh/inner", b"y"), ("SKILL.md", b"z")],
])
def test_repeated_or_clashing_names_are_refused(entries):
    """Security review: a later entry with the same name (or one an extractor folds onto it) would
    replace the file the scan read, so the archive is refused instead of keeping either copy."""
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(raw_zip(entries))
    assert caught.value.code == "unsafe_path"


def test_an_unsupported_zip_version_in_the_central_directory_is_bad_zip():
    """r1:F3: `zipfile.ZipFile()` raises `NotImplementedError` for a "version needed to extract" it
    does not support while it reads the central directory; that is `bad_zip` like every corrupt archive."""
    data = bytearray(build({"a/SKILL.md": b"x"}))
    central = data.find(b"PK\x01\x02")
    data[central + 6] = 80  # version needed to extract: 8.0
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(bytes(data))
    assert caught.value.code == "bad_zip"


@pytest.mark.parametrize("entries", [
    [("SKILL.md", b"a"), ("caf\u00e9.md", b"c"), ("cafe\u0301.md", b"d")],  # NFC-equal names
    [("run.sh.", b"x"), ("SKILL.md", b"y")],
    [("run.sh ", b"x"), ("SKILL.md", b"y")],
    [("x/ab:c", b"x"), ("SKILL.md", b"y")],
    [("tools/", b""), ("tools", b"x"), ("SKILL.md", b"y")],
    [("x/../", b""), ("SKILL.md", b"y")],
])
def test_names_that_collide_or_change_on_some_file_system_are_refused(entries):
    """Security review: NFC-equal names (macOS), a trailing dot or space and `:` (Windows), and a file
    that is also a directory entry each make an extractor install something other than what was scanned."""
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(raw_zip(entries))
    assert caught.value.code == "unsafe_path"


@pytest.mark.parametrize("entries", [
    [("docs/2024-01-01T10:00.md", b"x"), ("skill/SKILL.md", b"y")],
    [("Makefile", b"a"), ("makefile", b"b"), ("skill/SKILL.md", b"y")],
    [("README.md", b"a"), ("readme.md", b"b"), ("skill/SKILL.md", b"y")],
    [("notes/run.sh.", b"a"), ("skill/SKILL.md", b"y")],
])
def test_platform_collisions_outside_the_scanned_root_are_kept(entries):
    """Build review: a repository may hold a name Windows refuses, or two names that differ only in case, in a
    directory the scan does not read; only names under `root` must survive every extractor."""
    files = unpack_zip(raw_zip(entries), root="skill")
    assert set(files) == {name for name, _ in entries}
    with pytest.raises(ArchiveError) as caught:
        unpack_zip(raw_zip(entries))  # the default root is the whole archive
    assert caught.value.code == "unsafe_path"
    assert set(unpack_zip(raw_zip(entries), root=None)) == {name for name, _ in entries}


def test_a_name_that_lands_under_the_root_on_some_file_system_counts_as_under_it():
    """Security review of f767f29: `Skill/SKILL.md` and `skill./x` are written into `skill/` by a macOS or Windows
    extractor, so they collide with the scanned files there."""
    for other in ("Skill/SKILL.md", "SKILL /SKILL.md", "skill./SKILL.md", "Skill/evil.sh"):
        with pytest.raises(ArchiveError):
            unpack_zip(raw_zip([("skill/SKILL.md", b"a"), (other, b"b"), ("README.md", b"r")]), root="skill")


def test_under_the_root_case_and_windows_names_are_refused_but_sharp_s_is_not_ss():
    with pytest.raises(ArchiveError):
        unpack_zip(raw_zip([("skill/SKILL.md", b"a"), ("skill/skill.md", b"b"), ("README.md", b"r")]), root="skill")
    with pytest.raises(ArchiveError):
        unpack_zip(raw_zip([("skill/SKILL.md", b"a"), ("skill/run.sh ", b"b"), ("README.md", b"r")]), root="skill")
    kept = unpack_zip(raw_zip([("SKILL.md", b"a"), ("stra\u00dfe.md", b"b"), ("strasse.md", b"c")]))
    assert len(kept) == 3  # NTFS and APFS fold case, not `\u00df` to `ss`


def test_strip_ignores_macosx_and_ds_store():
    from spellwarden_scan.archive import _strip_common_top

    assert _strip_common_top(["skill/SKILL.md", "__MACOSX/._skill", ".DS_Store"]) == "skill"
    assert _strip_common_top(["skill/SKILL.md", "skill/lib/.DS_Store", "__MACOSX/skill/._SKILL.md"]) == "skill"
    assert _strip_common_top(["a/SKILL.md", "b/x"]) == ""
    assert _strip_common_top(["__MACOSX/._x", ".DS_Store"]) == ""


def test_a_hand_made_zip_with_finder_leftovers_strips_like_a_forge_archive():
    data = build({"SKILL.md": b"a", "lib/x.py": b"b", ".DS_Store": b"f"}, top="skill")
    macosx = io.BytesIO(data)
    with zipfile.ZipFile(macosx, "a") as zf:
        zf.writestr("__MACOSX/skill/._SKILL.md", b"fork")
    files = unpack_zip(macosx.getvalue())
    assert {"SKILL.md", "lib/x.py"} <= set(files) and "skill/SKILL.md" not in files
