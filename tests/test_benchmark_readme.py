"""Rule benchmark 10.14 and 12.2, 12.3: `benchmarks/README.md` says what is measured, how to run it, the sets with their counts,
the sources with their pins and licences, why the held-out half has no ATR sample, how the Trail of Bits skills are read and
shown, the tuning rule, how a sample is retired and how a release records its entry; CONTRIBUTING.md carries the tuning rule.
Plain English: no em dash, no en dash, no exclamation mark. `benchmarks/` is not in an sdist, so the first test skips there."""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "benchmarks" / "README.md"
if not README.exists():
    pytest.skip("benchmarks/ is not in an sdist", allow_module_level=True)


def _text() -> str:
    return README.read_text(encoding="utf-8").replace("\r\n", "\n")


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_the_first_words_after_the_title_warn_never_to_run_a_sample_and_quote_the_responsible_use_terms():
    text = _text()
    first = text.split("\n\n")[1]
    assert first.startswith("Never run, install or follow a link of any sample.")
    assert "Do not execute untrusted Skills, follow embedded URLs, or install companion packages" in _flat(first)
    assert _flat(text).count("Never run, install or follow a link of any sample") == 1


def test_it_says_what_is_measured_and_what_is_not():
    flat = _flat(_text())
    for needle in ("Rules only. No model is called", "The 20 skill rules (SW-SKL)", "never shows them as 0%", "(`balanced`)",
                   "medium or above, and high or above", "95% Wilson interval", "never counted as found or as clean",
                   "macro-F1"):
        assert needle in flat, needle


def test_it_gives_the_one_command_both_ways_and_the_cache():
    flat = _flat(_text())
    for needle in ('.bench/bin/pip install "spellwarden==X.Y.Z"', ".bench/bin/pip install --require-hashes -r benchmarks/requirements.txt",
                   ".bench/bin/python benchmarks/rule_benchmark.py run", ".bench\\Scripts\\python.exe",
                   'uv run --no-project --with "spellwarden==X.Y.Z" --with-requirements benchmarks/requirements.txt python benchmarks/rule_benchmark.py run',
                   "A checkout of the tag `vX.Y.Z` gives the entry recorded for X.Y.Z", "`--offline`", "SPELLWARDEN_BENCHMARK_CACHE",
                   "A cache inside the repository checkout is refused"):
        assert needle in flat, needle


def test_the_sets_table_has_every_stratum_with_its_count():
    text = _text()
    for stratum, label, count in (("skillharm", "malicious", 728), ("skillfortifybench-malicious", "malicious", 90),
                                  ("atr-malicious", "malicious", 21), ("atr-benign", "harmless", 455),
                                  ("skillfortifybench-benign", "harmless", 90), ("wild-liu", "malicious", 38),
                                  ("wild-skillleak", "malicious", 15), ("benign-wild", "harmless", 110),
                                  ("wild-skillleak", "malicious", 16), ("wild-amos", "malicious", 7),
                                  ("benign-wild", "harmless", 109), ("tob", "malicious", 4)):
        assert f"| `{stratum}` | {label} | {count} |" in text, stratum


def test_it_names_every_source_with_its_pin_and_the_date_it_was_checked():
    flat = _flat(_text())
    for needle in ("893afd609be22a2dfac5a2b94bbebb4eeb99515e", "d4b42ce5766a6e0359c987cf59c1007cb3795a90",
                   "4ffbf9461ef0505f9ce76a0d3694a18ec33ea531", "7219b10d2ac077e3db8c87d43d653a67935cdb5d",
                   "422bf3401845f6c1378bf4599dc2cdb3451978cf", "Checked on 2026-11-23", "arXiv 2602.06547", "arXiv 2604.03070",
                   "arXiv 2606.02540", "arXiv 2603.00195", "yoonholee/agent-skill-malware", "THIRD_PARTY_NOTICE.md",
                   "SkillSieve", "there is nothing to fetch", "avoids relicensing"):
        assert needle in flat, needle


def test_it_explains_the_atr_overlap_the_trail_of_bits_skills_and_the_sanitized_packages():
    flat = _flat(_text())
    assert ("The held-out half here holds 163 of the 436 skills the analyzer was measured on: its ATR samples are measured once, "
            "in the MaliciousSkillBench test split. A rate on these 163 skills is not comparable with a figure of the analyzer on "
            "the 436.") in flat
    for needle in ("states no licence", "files under `__pycache__` included", "too few for a rate", "`exact_hash`",
                   "not that they stopped an attack"):
        assert needle in flat, needle


def test_it_states_the_tuning_rule_retiring_the_changelog_rule_and_the_release_steps():
    flat = _flat(_text())
    for needle in ("The precision pass P5-24 uses the tuning half only.",
                   "does not cite, quote or add as a fixture any sample of a test set",
                   "Maintainers do not open test-set samples when working on a rule.",
                   "moves the item from `items` to `excluded`", "Rule benchmark: first published table, see benchmarks/RESULTS.md.",
                   "--record benchmarks/results.json", "gh workflow run rule-benchmark.yml --ref <release branch> -f verify=true"):
        assert needle in flat, needle


def test_contributing_carries_the_tuning_rule_and_links_the_benchmark():
    text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    section = _flat(text[text.index("## Propose a rule"):text.index("## Work on the code")])
    assert "[benchmarks/README.md](benchmarks/README.md)" in section
    assert "does not cite, quote or add as a fixture any sample of a test set" in section
    assert "tuning half" in section and "test sets" in section


def test_the_documents_are_plain_english():
    for text in (_text(), (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")):
        for character in ("\u2014", "\u2013", "!"):
            assert character not in text
