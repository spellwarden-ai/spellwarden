"""Spec 2 invariant 4 and claim C2: no existing rule changes what it detects. The fingerprints, severities,
locations and evidence of every existing fixture's findings equal the golden file recorded from 0.2.0."""
from __future__ import annotations

import json

from golden_record import GOLDEN, entries, render

from spellwarden_scan.rules import RuleSet


def test_every_existing_fixture_finding_is_byte_identical_to_the_0_2_0_record():
    recorded = json.loads(GOLDEN.read_text())
    live = entries()
    assert live == recorded
    assert render(live) == GOLDEN.read_text()


def test_the_record_covers_every_skill_and_mcp_rule_of_0_2_0():
    recorded = json.loads(GOLDEN.read_text())
    fired = {row["rule_id"] for row in recorded}
    old = {rule.id for rule in RuleSet.baseline() if rule.area in ("skill", "mcp")}
    assert old <= fired, sorted(old - fired)
    assert all(len(row["fingerprint"]) == 64 for row in recorded)
