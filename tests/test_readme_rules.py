"""Spec 6.2 and claim C18: the README's rule table is `spellwarden rules --format markdown`, byte for byte."""
from __future__ import annotations

from pathlib import Path

from spellwarden_scan import RuleSet

from spellwarden_cli.rulescmd import rules_markdown

README = Path(__file__).resolve().parents[1] / "README.md"
START, END = "<!-- rules:start -->\n", "<!-- rules:end -->"


def test_the_readme_rule_table_is_generated():
    text = README.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.count(START) == 1 and text.count(END) == 1
    table = text[text.index(START) + len(START):text.index(END)]
    assert table == rules_markdown(RuleSet.baseline()), "regenerate with: spellwarden rules --format markdown"


def test_no_rule_row_sits_outside_the_marked_section():
    # GitHub and PyPI end the table at the HTML comment, so a stray `| SW-` row renders as raw pipes.
    text = README.read_text(encoding="utf-8").replace("\r\n", "\n")
    outside = text[:text.index(START)] + text[text.index(END) + len(END):]
    stray = [line for line in outside.splitlines() if line.startswith("| SW-")]
    assert stray == [], f"rule rows outside the generated section: {stray[:3]}"


CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


def test_the_readme_names_the_reserved_numbers_and_the_malicious_indicators():
    text = README.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert "SW-SKL-033 to 035, SW-CFG-011 and SW-CFG-014 are reserved" in text
    malicious = sorted(rule.id for rule in RuleSet.baseline() if rule.malicious_indicator)
    assert malicious == ["SW-CFG-006", "SW-CFG-007", "SW-SKL-004", "SW-SKL-008", "SW-SKL-032"]
    assert "Five rules are malicious indicators" in text
    assert "(SW-SKL-004, SW-SKL-008, SW-SKL-032, SW-CFG-006, SW-CFG-007)" in text


def test_the_changelog_has_the_1_8_0_entry_with_the_five_titles_and_the_older_scanner_note():
    text = CHANGELOG.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.index("## 1.8.0") < text.index("## 1.7.1")
    entry = text[text.index("## 1.8.0"):text.index("## 1.7.1")]
    ids = {"SW-SKL-032", "SW-SKL-036", "SW-SKL-037", "SW-CFG-012", "SW-CFG-013"}
    new = [rule for rule in RuleSet.baseline() if rule.id in ids]
    assert len(new) == 5
    for rule in new:
        assert f"`{rule.id}`" in entry and rule.title in entry, rule.id
    for needle in ("`2026.11.1`", "65 rules", "unmatched"):
        assert needle in entry, needle
    assert "SW-CFG-011" in entry
