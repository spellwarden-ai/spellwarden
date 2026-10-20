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
