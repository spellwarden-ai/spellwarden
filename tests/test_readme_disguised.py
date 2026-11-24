"""1.22.0 (P6-4 spec 6.8, claims D1 and D2): the README says what the skill rules read since 1.22.0 (the shipped steps and rules,
read from `spellwarden_scan.normalise`), what the rule benchmark measures of disguised content, what stays out of reach, the
analyzer as the answer for meaning, and the text read limit; benchmarks/README.md has the section "Disguised samples";
CONTRIBUTING.md and ROADMAP.md follow. Plain English: no em dash, no en dash, no exclamation mark in the new text."""
from __future__ import annotations

from pathlib import Path

import pytest

from spellwarden_scan import RuleSet, normalise

ROOT = Path(__file__).resolve().parents[1]
# The README's words for each step (plan Task 10): a shipped step is named in "The rules"; a candidate step left out by the tuning
# measurement (spec 6.6) is named in "Disguised content" as out of reach instead.
STEP_PHRASES = {
    "entities": "HTML character references such as `&#110;` are read as their character, a reference to a line break left as written",
    "invisible": "zero-width and other format characters are removed",
    "compat": "compatibility forms such as full-width letters, ligatures and compatibility spaces are folded with Unicode NFKC",
    "lookalike": ("look-alike letters of the Cyrillic, Greek, Armenian and Latin extended blocks are folded to the ASCII letter they "
                  "look like, in words that hold an ASCII letter or only such letters"),
    "spaces": "each run of spaces and tabs inside a line, and each tab, becomes one space",
    "base64": ("base64 text of 16 characters or more is decoded, up to three layers, and the decoded text is read as part of the "
               "line it came from"),
}
OUT_OF_REACH = {
    "entities": "HTML character references such as `&#110;`",
    "compat": "compatibility forms such as full-width letters and compatibility spaces",
    "spaces": "runs of spaces and tabs inside a line (padding)",
}
FIXED_OUT_OF_REACH = ("strings joined at run time", "markup tricks that are not character references (comments and emphasis inside "
                      "words)", "other languages", "base64 wrapped over several lines", "more than three encoding layers",
                      "other encodings (hex, gzip, rot13 and so on)", "look-alike letters outside the table",
                      "meaning that no pattern names")


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def _between(text: str, start: str, end: str) -> str:
    return text[text.index(start):text.index(end, text.index(start))]


def _flat(text: str) -> str:
    return " ".join(text.split())


def _plain(text: str) -> None:
    for character in ("\u2014", "\u2013", "!"):
        assert character not in text


def test_the_rules_section_names_the_shipped_steps_and_rules():
    """D1: "The rules" has the normalisation paragraph."""
    paragraph = _flat(_between(_read("README.md"), "Since 1.22.0 the skill rules ", "\n"))
    phrases = "; ".join(STEP_PHRASES[step] for step in normalise.STEPS)
    assert f"The steps, in this order: {phrases}." in paragraph
    for rule_id in normalise.RULES:
        assert rule_id in paragraph, rule_id
    others = sorted(rule.id for rule in RuleSet.baseline().by_area("skill") if rule.id not in normalise.RULES)
    assert f"Every other skill rule ({', '.join(others[:-1])} and {others[-1]}) reads the text as written only." in paragraph
    for needle in ('starts with "Matched after normalising:" and quotes the line as written',
                   "its fingerprint is computed from the line as written", "a normalised reading only adds findings",
                   "`normalise=False`", "Unicode version", "[Disguised content](#disguised-content)"):
        assert needle in paragraph, needle
    _plain(paragraph)


def test_what_it_does_not_do_names_meaning():
    text = _read("README.md")
    block = _between(text, "It does not:\n", "\n\nThe scanner, its rules")
    assert ("- understand what text means. Rules match patterns; text written another way can pass them. See "
            "[Disguised content](#disguised-content).") in block


def test_the_disguised_content_section_follows_the_benchmark_block_and_says_what_stays_out_of_reach():
    """D1: the section right after the generated block, the out-of-reach list following what ships, the analyzer named."""
    text = _read("README.md")
    assert "<!-- benchmark:end -->\n\n### Disguised content\n" in text
    section = _flat(_between(text, "### Disguised content\n", "## Org rules, packs and exports"))
    for needle in FIXED_OUT_OF_REACH:
        assert needle in section, needle
    for step, phrase in OUT_OF_REACH.items():
        assert (phrase in section) == (step not in normalise.STEPS), step
    for needle in ("SW-SKL-002, SW-SKL-004 and SW-SKL-014 report a disguise itself", "never written, printed or run",
                   "[`--analyze`](#model-assisted-analyzer---analyze)", '"Unmeasured model"',
                   "[benchmarks/README.md](benchmarks/README.md#disguised-samples)", "[benchmarks/RESULTS.md](benchmarks/RESULTS.md)"):
        assert needle in section, needle
    _plain(section)


def test_measured_rates_and_limits_say_what_changed():
    """D1: the paragraph above the benchmark block (spec 6.3.3) and the text read limit in Limits (spec 6.8.1)."""
    text = _read("README.md")
    rates = _flat(_between(text, "## Measured rates\n", "<!-- benchmark:start -->"))
    assert ("Each release also measures disguised versions of the malicious skills (look-alike letters, hidden characters, encoding, "
            "joined strings, padding, markup and a word-list translation), with the rules on the text as written and after "
            "normalisation; see [Disguised content](#disguised-content).") in rates
    limits = _flat(_between(text, "### Limits\n", "### Settings"))
    assert ("Since 1.22.0 the rules read a text file of a skill, and an instruction file, up to 10 MiB, the size up to which the "
            "command reads files; before, a text file over 1 MiB was read by no text rule, so the scan could pass. A library caller "
            "that hands the engine a larger text file gets the error `TextLimit`, never a result.") in limits


@pytest.mark.skipif(not (ROOT / "benchmarks" / "README.md").exists(), reason="benchmarks/ is not in an sdist")
def test_the_benchmark_readme_has_the_disguised_samples_section():
    """D2: the first paragraph stays (tests/test_benchmark_readme.py checks it) and the new section says how it works."""
    text = _read("benchmarks/README.md")
    assert text.split("\n\n")[1].startswith("Never run, install or follow a link of any sample.")
    section = _flat(_between(text, "## Disguised samples\n", "## Tuning and test"))
    for needle in ("generator version 1, seed `spellwarden-disguise-1`", "never written, printed or run", "`lookalike`",
                   "`zero-width`", "`encoding-1`", "`encoding-2`", "`joined`", "`padding`", "`markup`", "`translation`",
                   "`echo '<B>' | base64 -d | sh`", "`normalise=False`", "python benchmarks/rule_benchmark.py steps",
                   "reads the tuning sets only", "Rule benchmark: first table of disguised samples, see benchmarks/RESULTS.md.",
                   "Rule benchmark: normalisation adds no finding on harmless skills.",
                   "which the rules as written do not report:", "the true rate under translation is at most the one shown"):
        assert needle in section, needle
    assert "([Disguised samples](#disguised-samples))" in _flat(_between(text, "## What it measures\n", "## Run it yourself"))
    files = _flat(text[text.index("## Files\n"):])
    assert "`check-changelog`, `check-history`, `steps`)." in files
    assert "- `disguise.py`: the generator of the disguised samples, loaded by `rule_benchmark.py`." in files
    _plain(section)


def test_contributing_and_the_roadmap_follow():
    contributing = _flat(_read("CONTRIBUTING.md"))
    assert ("samples people report. The same holds for the normalisation steps the skill rules read through and for the choice of "
            "which rules read through them. The held-out half") in contributing
    roadmap = _read("ROADMAP.md")
    shipped = _flat(_between(roadmap, "## Shipped\n", "## Being built now"))
    assert "Since 1.22.0 the skill rules also read a normalised copy of the text" in shipped
    assert "**Disguised content.**" not in _between(roadmap, "## Next\n", "\n## ")
