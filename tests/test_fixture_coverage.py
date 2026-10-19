"""Spec 5.11 and claim P2: every rule has a positive and a negative fixture,
and each fixture's expected findings equal what the scan reports for that
rule. This file passes trivially while the rule tuples are empty (Task 1) and
becomes the coverage gate as Tasks 2 and 3 add rules."""
from __future__ import annotations

import json

import pytest
from conftest import PROBE_FIXTURES, SKILL_FIXTURES, load_probe_fixture, load_skill_fixture

from spellwarden_scan.rules import RuleSet

RULES = RuleSet.baseline()
SKILL_IDS = [rule.id for rule in RULES.by_area("skill")]
MCP_IDS = [rule.id for rule in RULES.by_area("mcp")]


def _normalised(result) -> set[tuple[str, str, str, int | None]]:
    """The complete finding set of a scan: `(rule_id, severity, path, line)` of every finding, of every rule."""
    return {(f.rule_id, f.severity, f.location.path, f.location.line) for f in result.findings}


def _expected(document: dict) -> set[tuple[str, str, str, int | None]]:
    return {(f["rule_id"], f["severity"], f["path"], f.get("line")) for f in document["findings"]}


@pytest.mark.parametrize("rule_id", SKILL_IDS)
def test_skill_rule_has_both_fixtures_and_they_match(rule_id):
    """The whole result equals `expected.json`, for both sides: a negative fixture that trips another
    rule must list that finding, and a severity regression shows up as a set difference."""
    from spellwarden_scan.scan import scan_skill_package

    for side in ("positive", "negative"):
        assert (SKILL_FIXTURES / rule_id / side / "expected.json").is_file(), f"{rule_id} lacks a {side} fixture"
        files, expected = load_skill_fixture(rule_id, side)
        result = scan_skill_package(files, RULES, root=expected.get("root", ""))
        assert _normalised(result) == _expected(expected), f"{rule_id} {side}"
        own = {entry for entry in _expected(expected) if entry[0] == rule_id}
        if side == "positive":
            assert own, f"{rule_id} positive fixture expects no finding of its own rule"
        else:
            assert not own, f"{rule_id} negative fixture expects a finding of its own rule"


@pytest.mark.parametrize("rule_id", MCP_IDS)
def test_mcp_rule_has_both_fixtures_and_they_match(rule_id):
    """`expected.findings` is the complete finding set of the evaluation (rule id, severity, path, line),
    compared as a set like the skill fixtures (claim P2), plus the classification keys."""
    from spellwarden_scan.probe import evaluate_probe

    for side in ("positive", "negative"):
        path = PROBE_FIXTURES / "rules" / f"{rule_id}-{side}.json"
        assert path.is_file(), f"{rule_id} lacks a {side} probe fixture"
        probe, expected = load_probe_fixture(f"rules/{rule_id}-{side}")
        result = evaluate_probe(probe, RULES)
        assert _normalised(result) == _expected(expected), f"{rule_id} {side}"
        fired = {entry[0] for entry in _normalised(result)}
        assert (rule_id in fired) == (side == "positive"), f"{rule_id} {side}"
        for key, value in expected.items():
            if key != "findings":
                assert getattr(result, key) == value, f"{rule_id} {side}: {key}"


def test_every_fixture_directory_belongs_to_a_rule():
    # A fresh checkout has no `fixtures/skills` until a rule commits one (git keeps no empty directory): r0:F4.
    on_disk = sorted(p.name for p in SKILL_FIXTURES.iterdir() if p.is_dir()) if SKILL_FIXTURES.is_dir() else []
    assert set(on_disk) <= set(SKILL_IDS)
    for path in (PROBE_FIXTURES / "rules").glob("*.json"):
        assert path.name.rsplit("-", 1)[0] in MCP_IDS, path.name
        json.loads(path.read_text())
