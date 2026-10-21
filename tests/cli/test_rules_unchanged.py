"""Spec 5.1 and claim E10: `spellwarden rules` still lists the 38 detection rules of 1.0.0. The enforcement rules of
the packs (SW-HK, SW-GW, SW-EG, SW-RG, SW-OB) are not detection rules and organisation rules are never loaded by the CLI."""
from __future__ import annotations

import json
import re


def test_rules_lists_the_38_baseline_rules_and_nothing_else(run_cli):
    code, out, err = run_cli(["rules", "--format", "json"])
    assert (code, err) == (0, "")
    ids = [rule["id"] for rule in json.loads(out)]
    assert len(ids) == 38 and len(set(ids)) == 38
    assert all(re.fullmatch(r"SW-(SKL|MCP|CFG)-\d{3}", rule_id) for rule_id in ids), ids
