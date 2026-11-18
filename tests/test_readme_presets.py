"""1.18.0: the README's "Presets" section. Its table is `presets.table_markdown`, byte for byte (the table lives in one place,
`spellwarden_cli/presets.py`); the section states the precedence, what a preset never does, connected mode and the base-revision
rule; "Settings" names `SPELLWARDEN_PRESET`; "Limits" counts the findings a preset turns off."""
from __future__ import annotations

from pathlib import Path

from spellwarden_scan import RuleSet

from spellwarden_cli import presets

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
START, END = "<!-- presets:start -->\n", "<!-- presets:end -->"


def section(heading: str) -> str:
    start = README.index(heading)
    return README[start:README.index("\n### ", start + len(heading))]


def test_the_readme_preset_table_is_generated_from_the_data():
    assert README.count(START) == 1 and README.count(END) == 1
    table = README[README.index(START) + len(START):README.index(END)]
    assert table == presets.table_markdown(RuleSet.baseline()), "regenerate it from presets.table_markdown"


def test_the_presets_section_states_what_a_preset_does_and_never_does():
    text = section("### Presets")
    assert START in text
    for needle in ("`--preset strict|balanced|low-noise`", "`SPELLWARDEN_PRESET`", "the flag wins over the environment, which wins "
                   "over the file", "it never lowers or turns off a critical or high finding or a malicious indicator", "`SW-ORG-`",
                   "`SW-REG-`", "it never changes what the baseline accepts", "an incomplete scan stays exit 2",
                   "the upload carries every finding at the rule's own severity", "read from the base revision",
                   "`spellwarden rules --preset NAME`", "`preset_from`", "`SW_PRESET`", "cannot be used with `--user`"):
        assert needle in text, needle
    for character in ("\u2014", "\u2013", "!"):
        assert character not in text.replace("<!--", ""), character  # the table's markers are HTML comments


def test_settings_names_the_variable_and_limits_counts_what_a_preset_turns_off():
    assert "`SPELLWARDEN_PRESET`" in section("### Settings: `.spellwarden/config.yml`")
    assert "A preset (since 1.18.0" in section("### Limits")
    assert "[--preset strict|balanced|low-noise]" in README
