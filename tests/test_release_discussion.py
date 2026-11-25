"""Community reports spec 11, claims D-1 to D-3: `scripts/release_discussion.py` builds the title and the body of a release's thread
from CHANGELOG.md, deterministically, with no model and no network. The scripts are not in an sdist, so this file skips there."""
from __future__ import annotations

import re

import pytest

from community_cases import ROOT, SCRIPTS, load_script

CHANGELOG = ROOT / "CHANGELOG.md"
if not SCRIPTS.is_dir() or not CHANGELOG.exists():
    pytest.skip("scripts/ and CHANGELOG.md are not in an sdist", allow_module_level=True)

thread = load_script("release_discussion.py", "spellwarden_release_discussion_test")
release_manifest = load_script("release_manifest.py", "spellwarden_release_manifest_discussion_test")
URL = "https://github.com/spellwarden-ai/spellwarden"
PAGE = "https://spellwarden.ai/docs/rules/{}?utm_source=github&utm_medium=discussion&utm_campaign=release-thread"

CHANGES = """# Changelog

## 1.25.0 (2026-12-10)

Rules version 2026.12.1: SW-SKL-009 now reads pip installs in a Makefile, and SW-CFG-003 no longer reports a pinned image; no
other rule changed (66 rules).

1.25.0: two rules.

- Community report COM-0001 (SW-SKL-009, missed detection), reported by Ada Example.
- Community report COM-0002 (SW-CFG-003, false positive).
- Something else.

## 1.24.0 (2026-12-01)

Rules version 2026.11.9, unchanged (66 rules): nothing new.

- Community report COM-0003 (SW-SKL-014, missed
  detection), reported by Grace Hopper.

## 1.23.1 (2026-11-26)

Speed only. No paragraph about the rules, though SW-SKL-001 is mentioned here.

## 1.23.0

Rules version 2026.11.9 (66 rules). Text without an id.
"""


def expected(version: str, date: str | None, rules: str, community: str, *, paragraph: str | None = None) -> str:
    head = f"[Release {version}, {date}]" if date else f"[Release {version}]"
    parts = [f"{head}({URL}/releases/tag/v{version})"]
    if paragraph is not None:
        parts.append(paragraph)
    parts += [rules, "From the community\n\n" + community, thread.CLOSING]
    return "\n\n".join(parts) + "\n"


def listed(*ids: str) -> str:
    return "Rules named in it: " + ", ".join(f"[{rule}]({PAGE.format(rule.lower())})" for rule in ids)


# --- D-1 ----------------------------------------------------------------------------------------------------------------------

def test_the_title_is_exact():
    assert thread.title("1.23.0") == "Release 1.23.0: what changed in the rules"


def test_a_rule_change_lists_the_ids_it_names_sorted_and_linked_and_the_community_lines_as_written():
    paragraph = ("Rules version 2026.12.1: SW-SKL-009 now reads pip installs in a Makefile, and SW-CFG-003 no longer reports a pinned "
                 "image; no other rule changed (66 rules).")
    community = ("- Community report COM-0001 (SW-SKL-009, missed detection), reported by Ada Example.\n"
                 "- Community report COM-0002 (SW-CFG-003, false positive).")
    assert thread.body(CHANGES, "1.25.0") == expected("1.25.0", "2026-12-10", listed("SW-CFG-003", "SW-SKL-009"), community,
                                                      paragraph=paragraph)


def test_an_unchanged_entry_says_no_rule_changed_and_lists_no_id_and_a_wrapped_community_line_is_joined():
    body = thread.body(CHANGES, "1.24.0")
    assert body == expected("1.24.0", "2026-12-01", thread.NO_RULE_CHANGED,
                            "- Community report COM-0003 (SW-SKL-014, missed detection), reported by Grace Hopper.",
                            paragraph="Rules version 2026.11.9, unchanged (66 rules): nothing new.")
    assert "Rules named in it" not in body


def test_a_section_that_does_not_start_with_rules_version_says_so_and_names_no_id():
    body = thread.body(CHANGES, "1.23.1")
    assert body == expected("1.23.1", "2026-11-26", thread.NONE_NAMED, thread.NO_COMMUNITY, paragraph=thread.NO_CHANGELOG_RULES)
    assert "SW-SKL-001" not in body


def test_a_heading_without_a_date_and_a_paragraph_with_no_id_are_handled():
    body = thread.body(CHANGES, "1.23.0")
    assert body == expected("1.23.0", None, thread.NONE_NAMED, thread.NO_COMMUNITY,
                            paragraph="Rules version 2026.11.9 (66 rules). Text without an id.")


def test_unchanged_is_judged_in_the_opening_clause_only():
    text = "## 1.9.0 (2026-01-01)\n\nRules version 2026.1.1: SW-SKL-001 now reads more; the others stay unchanged.\n"
    body = thread.body(text, "1.9.0")
    assert listed("SW-SKL-001") in body and thread.NO_RULE_CHANGED not in body
    text = "## 1.9.0 (2026-01-01)\n\nRules version 2026.1.1, unchanged. SW-SKL-001 is only named here.\n"
    assert thread.NO_RULE_CHANGED in thread.body(text, "1.9.0")


def test_the_real_1_23_0_and_1_22_0_sections():
    text = CHANGELOG.read_text(encoding="utf-8")
    first = thread.body(text, "1.23.0")
    assert first.startswith(f"[Release 1.23.0, 2026-11-24]({URL}/releases/tag/v1.23.0)\n\nRules version 2026.11.9, unchanged (66 rules): ")
    assert f"\n\n{thread.NO_RULE_CHANGED}\n\nFrom the community\n\n{thread.NO_COMMUNITY}\n\n{thread.CLOSING}\n" in first
    second = thread.body(text, "1.22.0")
    ids = ["SW-SKL-001", "SW-SKL-003", "SW-SKL-004", "SW-SKL-005", "SW-SKL-006", "SW-SKL-007", "SW-SKL-008", "SW-SKL-009", "SW-SKL-012",
           "SW-SKL-013", "SW-SKL-014", "SW-SKL-019", "SW-SKL-032", "SW-SKL-037"]
    assert f"\n\n{listed(*ids)}\n\nFrom the community\n\n" in second
    assert "14 skill rules also read a normalised copy of the text" in second and thread.NO_RULE_CHANGED not in second


def test_the_output_is_the_same_every_time_and_has_lf_line_endings_only():
    text = CHANGELOG.read_text(encoding="utf-8")
    assert thread.body(text, "1.22.0") == thread.body(text, "1.22.0") and "\r" not in thread.body(text, "1.22.0")
    assert thread.body(CHANGES.replace("\n", "\r\n"), "1.25.0") == thread.body(CHANGES, "1.25.0")


# --- D-2 ----------------------------------------------------------------------------------------------------------------------

LOG = str(CHANGELOG)


@pytest.mark.parametrize("arguments, text", [
    (["body", "9.9.9", "--changelog", LOG], "CHANGELOG.md has no section for 9.9.9"),
    (["body", "1.23", "--changelog", LOG], "is not of the form X.Y.Z"),
    (["body", "1.23.0\n", "--changelog", LOG], "is not of the form X.Y.Z"),
    (["body", "v1.23.0", "--changelog", LOG], "is not of the form X.Y.Z"),
    (["title", "latest"], "is not of the form X.Y.Z"),
    (["body", "1.23.0", "--changelog", "no-such-file.md"], "no-such-file.md cannot be read as UTF-8 text"),
])
def test_a_missing_or_malformed_version_or_an_unreadable_changelog_is_one_line_and_exit_2(arguments, text, capsysbinary):
    assert thread.main(arguments) == 2
    captured = capsysbinary.readouterr()
    assert captured.out == b"" and captured.err.decode().count("\n") == 1 and text in captured.err.decode()
    assert captured.err.decode().startswith("release_discussion: ")


def test_main_prints_the_title_and_the_body_as_utf_8_with_lf(capsysbinary):
    assert thread.main(["title", "1.23.0"]) == 0
    assert capsysbinary.readouterr().out == b"Release 1.23.0: what changed in the rules\n"
    assert thread.main(["body", "1.23.0", "--changelog", str(CHANGELOG)]) == 0
    out = capsysbinary.readouterr().out
    assert out == thread.body(CHANGELOG.read_text(encoding="utf-8"), "1.23.0").encode("utf-8") and b"\r" not in out


def test_the_fixed_text_has_no_exclamation_mark_no_dash_and_no_ask_for_stars_upvotes_or_reviews():
    fixed = " ".join([thread.CLOSING, thread.NO_COMMUNITY, thread.NO_RULE_CHANGED, thread.NONE_NAMED, thread.NO_CHANGELOG_RULES])
    for character in ("!", "\u2014", "\u2013"):
        assert character not in fixed
    for word in ("star", "upvote", "review", "like and subscribe"):
        assert word not in fixed.lower()
    real = thread.body(CHANGELOG.read_text(encoding="utf-8"), "1.23.0")
    assert "!" not in real and "\u2014" not in real and "\u2013" not in real
    assert "https://spellwarden.ai" not in thread.CLOSING


def test_every_link_to_the_site_carries_the_three_campaign_tags():
    body = thread.body(CHANGES, "1.25.0")
    links = re.findall(r"https://spellwarden\.ai[^\s)]*", body)
    assert links and all(tag in link for link in links for tag in ("utm_source=github", "utm_medium=discussion", "utm_campaign=release-thread"))


# --- D-3 ----------------------------------------------------------------------------------------------------------------------

def test_the_body_reads_the_section_through_the_release_notes_extraction():
    text = CHANGELOG.read_text(encoding="utf-8")
    versions = re.findall(r"^## ([0-9]+\.[0-9]+\.[0-9]+)\b", text, re.M)
    assert versions
    for version in versions:
        section = release_manifest.changelog_section(text, version)
        paragraph = " ".join(section.strip("\n").split("\n\n", 1)[0].split())
        body = thread.body(text, version)
        assert (paragraph in body) == paragraph.startswith("Rules version"), version
    with pytest.raises(thread.Unusable):
        thread.body(text, "0.0.1")
    assert thread._manifest_module().changelog_section(text, "1.23.0") == release_manifest.changelog_section(text, "1.23.0")
