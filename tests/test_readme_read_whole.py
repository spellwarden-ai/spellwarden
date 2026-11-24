"""P6-10 spec 7.10 (1.23.0; claim T16): the README says the archive reader's link rule, its `why` values and bounds (the figures
held to the constants), the command's link out of the scan root as an error with its way out (owner spec:Q1), the instruction-file
exception (owner spec:Q2), why the command's tree differs from the hosted scan's (owner spec:Q3), and the roadmap moves the
scanner's part to Shipped. Plain English: no em dash, no en dash, no exclamation mark in the new text."""
from __future__ import annotations

from pathlib import Path

from spellwarden_scan.archive import LINK_MAX, REPOSITORY_LIMITS, ArchiveLimits

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
DEFAULTS = ArchiveLimits()


def section(heading: str) -> str:
    start = README.index(heading)
    end = README.find("\n### ", start + len(heading))
    return " ".join(README[start:end if end != -1 else len(README)].split())


def _plain(text: str) -> None:
    for character in ("—", "–", "!"):
        assert character not in text, character


def _unpack_zip_paragraph() -> str:
    start = README.index('- `unpack_zip(data, limits=ArchiveLimits(), with_modes=False, root="")`')
    return README[start:README.index("\n", start)]


def test_the_unpack_zip_paragraph_says_the_link_rule_the_why_values_and_the_bounds():
    text = _unpack_zip_paragraph()
    for why in ("outside", "dangling", "chain", "directory", "through_link", "unsafe_target", "special", "archive_entries"):
        assert f"`{why}`" in text, why
    for needle in (f"{DEFAULTS.max_compressed // 2**20} MiB compressed", f"{DEFAULTS.max_uncompressed // 2**20} MiB uncompressed",
                   f"{DEFAULTS.max_files} files", f"{DEFAULTS.max_file // 2**20} MiB per file", f"{DEFAULTS.max_path} characters a path",
                   f"{DEFAULTS.max_entries:,} entries in the whole archive (`max_entries`)",
                   f"`REPOSITORY_LIMITS` (since 1.23.0) holds the same limits with {REPOSITORY_LIMITS.max_compressed // 2**20} MiB "
                   "compressed", f"over {LINK_MAX:,} bytes", "judged from its text alone", "a regular file inside the tree",
                   "the target's size counts again", "even when a later segment comes back in",
                   "measured on the path inside the archive's top directory",
                   "`list_zip(data, limits=REPOSITORY_LIMITS)` (since 1.23.0)", "opening no entry",
                   "Up to 1.22.0 every link under `root` was `symlink`"):
        assert needle in text, needle
    _plain(text)


def test_what_a_scan_reads_says_the_error_the_tree_and_the_kept_exceptions():
    text = section("### What a scan reads")
    for needle in ("since 1.23.0 one whose relative target leaves the scan root is the error `unsafe_path` as well",
                   "replace the link with the file it names, or leave it out with `exclude`",
                   "up to 1.22.0 it was skipped with a notice and its target text was locked",
                   "the command follows the link rule of the archive reader and the hosted scan, with the scan root as its tree",
                   "the command reads a skill in place in its repository", "the hosted scan judges a copy of the skill's folder alone",
                   "`spellwarden scan path/to/skill` makes the skill's folder the scan root",
                   "an instruction file that is itself a link the scan cannot follow, wherever it points",
                   "a file named like an agent card", "the notice `symlink_skipped`, and the scan can pass with them unread"):
        assert needle in text, needle
    assert "follows one rule" not in text and "skipped with a notice while its target text is locked" not in text
    _plain(text)


def test_instruction_files_say_the_kept_notice_and_the_follow_links_error():
    text = section("### Instruction files")
    for needle in ("one that cannot be followed is the notice `symlink_skipped`, wherever it points, even out of the scan root",
                   "an exception to the link rule", "a link whose target is outside the scan root",
                   "with it, since 1.23.0, the error `unsafe_path` and an incomplete scan, exit 2"):
        assert needle in text, needle
    _plain(text)


def test_exit_codes_and_limits_name_the_link_and_the_archive_bounds():
    exit_codes = section("### Exit codes")
    for needle in ("a symbolic link inside a skill or a local plugin directory whose target leaves the scan root (since 1.23.0)",
                   "a linked instruction folder whose target leaves the scan root (since 1.23.0)"):
        assert needle in exit_codes, needle
    limits = section("### Limits")
    for needle in ("A symbolic link inside a skill or a local plugin directory, or at a configuration path, that the scan does not "
                   "follow is an error", "an instruction file that is a link the scan cannot follow is the exception",
                   f"{DEFAULTS.max_files:,} files, {DEFAULTS.max_uncompressed // 2**20} MiB unpacked and "
                   f"{DEFAULTS.max_file // 2**20} MiB a file", f"{DEFAULTS.max_entries:,} entries",
                   f"{REPOSITORY_LIMITS.max_compressed // 2**20} MiB zipped for a repository read under a named directory "
                   "(`REPOSITORY_LIMITS`, since 1.23.0)", f"{DEFAULTS.max_compressed // 2**20} MiB zipped otherwise"):
        assert needle in limits, needle
    _plain(limits)


def test_the_roadmap_moves_the_scanners_part_to_shipped():
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    shipped = roadmap[roadmap.index("## Shipped\n"):roadmap.index("## Being built now")]
    assert "Since 1.23.0 a skill read from a large repository's archive is read whole" in shipped
    later = roadmap[roadmap.index("## Next\n"):]
    assert "**Repositories the scan cannot read whole, in the hosted product.**" in later
    assert "The scanner's part shipped in 1.23.0." in later
