"""Spec 2 invariant 4 and claim C2: no existing rule changes what it detects. The fingerprints, severities,
locations and evidence of every existing fixture's findings equal the golden file recorded from 0.2.0."""
from __future__ import annotations

import json

from golden_record import GOLDEN, entries, render

from spellwarden_scan.rules import RuleSet


# The 17 skill and 11 MCP rules of 0.2.0, literally. A rule added later is not in the record: its own fixtures are skipped
# (`exclude_rules`), and a new rule firing on an old fixture still shows up as a row the record does not hold.
RULES_OF_0_2_0 = (
    "SW-SKL-001", "SW-SKL-002", "SW-SKL-003", "SW-SKL-004", "SW-SKL-005", "SW-SKL-006", "SW-SKL-007", "SW-SKL-008",
    "SW-SKL-009", "SW-SKL-010", "SW-SKL-011", "SW-SKL-012", "SW-SKL-013", "SW-SKL-014", "SW-SKL-015", "SW-SKL-019",
    "SW-SKL-031",
    "SW-MCP-001", "SW-MCP-002", "SW-MCP-003", "SW-MCP-004", "SW-MCP-005", "SW-MCP-006", "SW-MCP-007", "SW-MCP-008",
    "SW-MCP-009", "SW-MCP-010", "SW-MCP-011",
)
EXCLUDED = frozenset(rule.id for rule in RuleSet.baseline()) - set(RULES_OF_0_2_0)


def test_the_literal_list_holds_17_skill_and_11_mcp_rules():
    assert len(RULES_OF_0_2_0) == 28 and len(set(RULES_OF_0_2_0)) == 28
    assert sum(rule.startswith("SW-SKL-") for rule in RULES_OF_0_2_0) == 17
    assert sum(rule.startswith("SW-MCP-") for rule in RULES_OF_0_2_0) == 11


def test_every_existing_fixture_finding_is_byte_identical_to_the_0_2_0_record():
    recorded = json.loads(GOLDEN.read_text())
    live = entries(exclude_rules=EXCLUDED)
    assert live == recorded
    assert render(live) == GOLDEN.read_text()


def test_the_record_covers_every_skill_and_mcp_rule_of_0_2_0():
    recorded = json.loads(GOLDEN.read_text())
    fired = {row["rule_id"] for row in recorded}
    old = set(RULES_OF_0_2_0)
    assert old <= fired, sorted(old - fired)
    assert all(len(row["fingerprint"]) == 64 for row in recorded)
