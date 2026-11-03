"""Spec 5.11 and claim P2: every rule has a positive and a negative fixture,
and each fixture's expected findings equal what the scan reports for that
rule. This file passes trivially while the rule tuples are empty (Task 1) and
becomes the coverage gate as Tasks 2 and 3 add rules."""
from __future__ import annotations

import json

import pytest
from a2a_cards import card_bytes
from a2a_rule_cases import CASES as A2A_CASES
from conftest import CONFIG_FIXTURES, PROBE_FIXTURES, SKILL_FIXTURES, config_documents, load_config_fixture, load_probe_fixture, load_skill_fixture

from spellwarden_scan.rules import RuleSet

RULES = RuleSet.baseline()
SKILL_IDS = [rule.id for rule in RULES.by_area("skill")]
MCP_IDS = [rule.id for rule in RULES.by_area("mcp")]
CONFIG_IDS = [rule.id for rule in RULES.by_area("config")]
A2A_IDS = [rule.id for rule in RULES.by_area("a2a")]
INVENTORY_FIXTURES = frozenset({"plugins-settings"})


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


@pytest.mark.parametrize("rule_id", CONFIG_IDS)
def test_config_rule_has_both_fixtures_and_they_match(rule_id):
    """Spec 5.3 and claim C3: the complete `config` finding set of each fixture's documents equals its
    `expected.json`, and the rule fires on its positive fixture only."""
    from spellwarden_scan.scan import scan_agent_config

    for side in ("positive", "negative"):
        assert (CONFIG_FIXTURES / rule_id / side / "expected.json").is_file(), f"{rule_id} lacks a {side} fixture"
        files, expected = load_config_fixture(rule_id, side)
        documents = config_documents(files)
        assert documents and all(doc.error is None for doc in documents), f"{rule_id} {side}: {[d.error for d in documents]}"
        result = scan_agent_config(documents, RULES)
        assert _normalised(result) == _expected(expected), f"{rule_id} {side}"
        own = {entry for entry in _expected(expected) if entry[0] == rule_id}
        assert bool(own) == (side == "positive"), f"{rule_id} {side}"


@pytest.mark.parametrize("rule_id", A2A_IDS)
def test_a2a_rule_has_both_cases_and_they_match(rule_id):
    """O4 claim R1: the complete A2A finding set of each case (rule id, severity, evidence pointer) equals its expectation
    for both sides, and the rule fires on its positive case only. The cards are built in `a2a_rule_cases.py`."""
    from spellwarden_scan.a2a import parse_agent_card
    from spellwarden_scan.rules.a2a import CardSubject
    from spellwarden_scan.scan import run_rules

    assert set(A2A_CASES[rule_id]) == {"positive", "negative"}, rule_id
    for side, case in A2A_CASES[rule_id].items():
        content = case.card if isinstance(case.card, bytes) else card_bytes(case.card)
        subject = CardSubject(parse_agent_card(case.path, content), case.origin, case.signatures, case.path)
        found, _ = run_rules(RULES.ordered_for_scan("a2a"), subject, max_findings=500, max_per_rule=20)
        actual = {(f.rule_id, f.severity, f.evidence.split(": ")[0]) for f in found}
        assert actual == set(case.expected), f"{rule_id} {side}"
        if side == "positive":
            assert any(entry[0] == rule_id for entry in actual), f"{rule_id} positive case does not fire its own rule"
        else:
            assert not any(entry[0] == rule_id for entry in actual), f"{rule_id} negative case fires its own rule"


def test_every_a2a_case_belongs_to_a_rule():
    assert set(A2A_CASES) == set(A2A_IDS)


def test_every_fixture_directory_belongs_to_a_rule():
    # A fresh checkout has no `fixtures/skills` until a rule commits one (git keeps no empty directory): r0:F4.
    on_disk = sorted(p.name for p in SKILL_FIXTURES.iterdir() if p.is_dir()) if SKILL_FIXTURES.is_dir() else []
    assert set(on_disk) <= set(SKILL_IDS)
    # `plugins-settings` is the one inventory fixture (O3 spec 5.1): no rule fires on it, so it has no expected.json.
    assert {p.name for p in CONFIG_FIXTURES.iterdir() if p.is_dir()} <= set(CONFIG_IDS) | INVENTORY_FIXTURES
    for path in (PROBE_FIXTURES / "rules").glob("*.json"):
        assert path.name.rsplit("-", 1)[0] in MCP_IDS, path.name
        json.loads(path.read_text())
