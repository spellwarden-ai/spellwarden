"""P6-9 (spec 8.11, claims 29 and 30): the CHANGELOG entry of 1.25.0, the sentence of CONTRIBUTING.md and the sections of the README and
of benchmarks/README.md about the rules that are measured on a set of their own. The numbers of a measurement are not here: they are
written by the commit that records it, and `tests/test_measured_sets.py` checks them."""
from __future__ import annotations

import re
from pathlib import Path

from spellwarden_scan import RuleSet

ROOT = Path(__file__).resolve().parents[1]
NEW = ("SW-MCP-013", "SW-CFG-015")


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def _entry() -> tuple[str, str]:
    text = _read("CHANGELOG.md")
    assert text.index("## 1.25.0 (") < text.index("## 1.24.0 (")
    raw = text[text.index("## 1.25.0 ("):text.index("## 1.24.0 (")]
    return raw, " ".join(raw.split())


def test_the_changelog_has_the_1_25_0_entry_above_1_24_0():
    raw, entry = _entry()
    assert re.match(r"## 1\.25\.0 \((\d{4}-\d{2}-\d{2}|2026-11-NN)\)\n", raw)
    assert "Rules version 2026.11.10 (68 rules): two rules are new and no rule changed, so every finding 1.24.0 reports keeps" in entry
    titles = {rule.id: rule.title for rule in RuleSet.baseline()}
    for rule_id in NEW:
        assert f'`{rule_id}` "{titles[rule_id]}"' in entry, rule_id
    for needle in ("ASI06", "ASI08", "MCP05", "MCP08", "MCP10", "`SW-OB-008`", "`SW-CFG-014` stays reserved", "medium",
                   "`SW-CFG-015` is high under every preset", "`strict` raises `SW-MCP-013` to high", "`low-noise` keeps it at medium",
                   "`--fail-on medium`",
                   "never silences it", "`lists_cut`",
                   "never the path", "benchmarks/measured_sets.json", "`python benchmarks/rule_benchmark.py check-measured --release`",
                   "at least 0.60 and a lower end of at least 0.45", "0.80 and 0.65", "fewer than 20 labelled units cannot be assessed",
                   "Recall is never a condition and is always published", "MCP05 is now an allowed tag of the baseline", "ASI06 and ASI08 are not added",
                   "Organisation rules keep the tag lists of 1.2.x"):
        assert needle in entry, needle
    for character in ("—", "–", "!"):
        assert character not in raw
    assert not re.search(r"<(?:precision|recall|interval|figure|number|date)>", raw), "a figure is still a slot"


def test_the_changelog_measurement_paragraph_applies_the_bar_to_the_units_scored_not_to_a_held_out_half_only():
    _raw, entry = _entry()
    paragraph = entry[entry.index("Measurement. "):entry.index(" Tags. ")]
    assert "The bar is on precision on the units scored, with its 95% Wilson interval" in paragraph
    assert "the held-out half of a split set, or every flagged unit of a whole-frame set" in paragraph
    assert "on a held-out half, with" not in paragraph
    assert "written into this entry" not in paragraph


# rule: (its bullet's head, the figures the measurement gave, the frame it was measured on).
CHANGELOG_MEASURED = {
    "SW-CFG-015": ('(config, high, MCP02 and ASI03)', ("100.0% (85.1% to 100.0%)", "66.1% (47.0% to 84.8%)"), "9,859 server entries"),
    "SW-MCP-013": ('(mcp, medium, MCP05 and ASI05)', ("66.7% (53.4% to 77.8%)", "13.1% (7.2% to 20.8%)"), "210,994 tools"),
}


def test_the_changelog_gives_each_measured_rule_its_severity_precision_recall_and_whole_frame():
    _raw, entry = _entry()
    for rule_id, (head, figures, frame) in CHANGELOG_MEASURED.items():
        start = entry.index(f"- `{rule_id}` ")
        bullet = re.split(r" - `SW-| Measurement\. ", entry[start + 1:], maxsplit=1)[0]
        for needle in (head, *figures, f"Measured on its whole frame of {frame}", "every flagged unit was labelled", "no part was held out",
                       "was not tuned", "scored once", "Precision", "recall"):
            assert needle in bullet, (rule_id, needle)


def test_contributing_says_a_rule_that_is_not_a_skill_rule_is_measured_on_a_set_of_its_own():
    text = " ".join(_read("CONTRIBUTING.md").split())
    for needle in ("A rule that is not a skill rule is measured on a set of its own before it is released",
                   "benchmarks/README.md#rules-measured-on-a-set-of-their-own", "a rule whose precision does not meet the bar is not released"):
        assert needle in text, needle


def test_the_readme_section_holds_the_markers_once_and_points_to_the_method():
    text = _read("README.md")
    assert text.count("### Rules measured on a set of their own\n") == 1
    assert text.count("<!-- measured-sets:start -->\n") == 1 and text.count("<!-- measured-sets:end -->") == 1
    section = text[text.index("### Rules measured on a set of their own"):text.index("## Measured rates")]
    assert "benchmarks/README.md#rules-measured-on-a-set-of-their-own" in section and "is never published" in section
    assert text.index("## The rules") < text.index("### Rules measured on a set of their own") < text.index("## Measured rates")
    for character in ("—", "–", "!"):
        assert character not in section.replace("<!--", "")


def test_the_benchmark_readme_says_how_a_set_is_made_what_the_bar_is_and_how_a_record_is_finalised():
    text = " ".join(_read("benchmarks/README.md").split())
    assert text.count("## Rules measured on a set of their own") == 1
    section = text[text.index("## Rules measured on a set of their own"):text.index("## Files")]
    for needle in ("The sets hold third-party text, so they are never published", "never a sample, a host, a path, a tool name or a quote",
                   "at most three rounds", "at least 60 distinct units from at least 20 owners or namespaces",
                   "two language models with different batching", "The owner audits a sample of 150 items",
                   "The held-out half is scored once", "at least 0.60 and a lower end of the interval of at least 0.45",
                   "High needs 0.80 and 0.65", "Fewer than 20 labelled units cannot be assessed", "No new rule is released at critical or at low",
                   "Recall is never a condition of release", "language models of one family", "check-measured --release",
                   "`g0_failed`, `precision_below_bar` or `not_assessable`", "keep its id reserved",
                   "The branch is not merged before these commits"):
        assert needle in section, needle
    for character in ("—", "–"):
        assert character not in section
    assert "`measured_sets.json`" in text[text.index("## Files"):]
