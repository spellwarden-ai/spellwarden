"""Spec 5.1 and 5.4, claim C2: the `config` area and id form exist; `logical_commands` and the three shared
detectors are the skill rules' own normalisation and tests, so identical shell text in a skill script and in a
hook command (a `CodeBlock`) yields the same matches, only path and line differing."""
from __future__ import annotations

import json

import pytest
from conftest import FIXTURES

from spellwarden_scan.package import CodeBlock, Package
from spellwarden_scan.rules import AREAS, RULE_ID_RE, RuleSet, make_rule
from spellwarden_scan.rules.skill import decodes_and_runs, logical_commands, pipes_remote_to_shell, sends_file_contents

PAIRED = FIXTURES / "paired"
DETECTORS = {"decodes_and_runs": decodes_and_runs, "pipes_remote_to_shell": pipes_remote_to_shell,
             "sends_file_contents": sends_file_contents}
EXPECTED = json.loads((PAIRED / "expected.json").read_text())
HOOK_PATH, HOOK_LINE = ".claude/settings.json", 7


def test_the_config_area_and_its_ids_are_accepted():
    assert AREAS == ("skill", "mcp", "config", "registry")
    assert RULE_ID_RE.match("SW-CFG-001") and RULE_ID_RE.match("SW-SKL-001") and RULE_ID_RE.match("SW-MCP-011")
    assert not RULE_ID_RE.match("SW-CFG-01") and not RULE_ID_RE.match("SW-XYZ-001")
    extra = make_rule("SW-CFG-999", "Test rule", "low", "config", owasp=("ASI04",), nist=("SR-3",), detect=lambda _c: iter(()))
    rules = RuleSet(RuleSet.baseline().by_area("skill")).with_rules([extra])
    assert rules.ordered_for_scan("config") == (extra,)
    assert all(rule.area != "config" for rule in rules.ordered_for_scan("skill"))
    with pytest.raises(ValueError):
        make_rule("SW-CFG-998", "Bad area", "low", "hooks", owasp=("ASI04",), nist=("SR-3",), detect=lambda _c: iter(()))


def test_logical_commands_is_the_old_normalisation_under_its_new_name():
    unit = Package.build({"scripts/run.sh": b"a \\\n  b\nc |\n  d && \\\n e\nf\n"}).text_files[0]
    assert list(logical_commands(unit)) == [("scripts/run.sh", 1, "a    b"), ("scripts/run.sh", 3, "c |   d &&   e"),
                                            ("scripts/run.sh", 6, "f")]
    prose = Package.build({"SKILL.md": b"| a |\n| b |\n"}).text_files[0]
    assert [line for _, line, _ in logical_commands(prose)] == [1, 2]


def _skill_unit(text: str):
    return Package.build({"scripts/run.sh": text.encode()}).text_files[0]


def _hook_unit(text: str) -> CodeBlock:
    return CodeBlock(HOOK_PATH, "sh", text, HOOK_LINE)


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_a_skill_script_and_a_hook_with_the_same_text_match_alike(case):
    text = (PAIRED / f"{case}.sh").read_text()
    for name, detector in DETECTORS.items():
        in_skill = [(line, matched) for path, line, matched in detector(logical_commands(_skill_unit(text)))]
        in_hook = [(line - HOOK_LINE + 1, matched) for path, line, matched in detector(logical_commands(_hook_unit(text)))]
        assert in_skill == in_hook, f"{case}: {name}"
        assert [line for line, _ in in_skill] == EXPECTED[case][name], f"{case}: {name}"
        assert all(path == HOOK_PATH for path, _, _ in detector(logical_commands(_hook_unit(text))))


def test_every_paired_fixture_has_an_expectation():
    assert sorted(p.stem for p in PAIRED.glob("*.sh")) == sorted(EXPECTED)
