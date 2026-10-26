"""O4 spec 12 and claims P1 (README part), B2 (statement): the README's section "Checking A2A agent cards" says what the spec
names, every A2A notice code is documented, the ping is six fields with the sentence of 6.10, and the CHANGELOG's 1.3.0 section
names the rules that can fail a build. The section holds no dash character and no exclamation mark."""
from __future__ import annotations

import re
from pathlib import Path

from spellwarden_cli.report import NOTICE_CODES

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
A2A_NOTICES = [code for code in NOTICE_CODES if code.startswith("a2a_")]


def section() -> str:
    start = README.index("### Checking A2A agent cards\n")
    return README[start:README.index("\n### ", start + 5)]


def test_the_section_sits_before_probing_and_the_probing_heading_is_renamed():
    assert README.index("### Checking A2A agent cards") < README.index("### Probing: `--probe`")
    assert "Probing MCP servers" not in README and README.count("### Probing: `--probe`") == 1


def test_the_section_holds_no_dash_character_and_no_exclamation_mark():
    assert not re.search("[–—!]", section())
    changelog_section = CHANGELOG[CHANGELOG.index("## 1.3.0"):CHANGELOG.index("## 1.2.1")]
    assert not re.search("[–—!]", changelog_section)


def test_the_section_says_what_the_spec_requires():
    text = section()
    for needle in ("Every key needs a `kid`", "Merge the keys first", "end a URL with `/` for discovery",
                   '"Expired or revoked keys MUST NOT be used for verification" (8.4.3)', "removing a key from `a2a.keys`",
                   "`exclude: [\"samples/**\"]`", "Findings on a remote agent's card do not fail a pull or merge request",
                   "only one of them says who signed", "whoever controls the host", "unsigned_members", "RFC 8785",
                   "deprecated in 1.0 and documented as removed", "DER-encoded ECDSA", "`SW-A2A-018`", "At most 200 cards are read per run",
                   "reported as `unsafe_path`", "reported as `unreadable`", "spelled with its proto field name", "an empty value the `a2a-sdk` form leaves out"):
        assert needle in text, needle
    for code in A2A_NOTICES:
        assert f"`{code}`" in text, code
    assert len(A2A_NOTICES) == 9
    for rule_id in ("SW-A2A-001", "SW-A2A-002", "SW-A2A-003", "SW-A2A-004", "SW-A2A-005", "SW-A2A-010", "SW-A2A-011",
                    "SW-A2A-013", "SW-A2A-016", "SW-A2A-017", "SW-A2A-018"):
        assert rule_id in text, rule_id


def test_the_ping_section_says_six_fields_and_the_one_yes_or_no_fact():
    assert "carries exactly six fields" in README and "five fields" not in README
    assert "| `a2a` | `true` when the run checked at least one agent card" in README
    assert ("No repository content is sent; the ping carries one yes-or-no fact derived from it: whether the run checked an agent "
            "card, from the repository or from an agent you listed.") in README
    assert "the number of those that checked an agent card (`a2a_runs`)" in README
    assert "No repository content is ever sent" not in README


def test_the_other_sections_name_the_new_things():
    assert "`SW-A2A-NNN` (A2A agent cards)" in README
    assert "| A2A agent card |" in README and "a2a:                          # agent cards" in README
    assert "^SW-(SKL|MCP|CFG|REG|A2A|ORG)-[0-9]{3}$" in README
    assert "`canonical_json` (the pack hash) and `canonical_sha256` (the package hash) are not" in README
    assert "The runtime dependencies are PyYAML and `cryptography`" in README
    assert "On a pull or merge request `a2a.keys` and `a2a.agents` are read from the base revision even under `--config`" in README


def test_the_changelog_names_the_rules_that_can_fail_a_build_and_the_notice_codes():
    body = CHANGELOG[CHANGELOG.index("## 1.3.0"):CHANGELOG.index("## 1.2.1")]
    for rule_id in ("SW-A2A-004", "SW-A2A-005", "SW-A2A-010", "SW-A2A-011", "SW-A2A-014", "SW-A2A-015", "SW-A2A-018"):
        assert rule_id in body, rule_id
    for code in A2A_NOTICES:
        assert f"`{code}`" in body, code
    assert "2026.10.4" in body and "a 1.2.x scanner refuses" in body and "`exclude`" in body and "`cryptography`" in body
