"""Phase C spec 5.1 and claim E10, O3 spec 5.2 and claim E2: `spellwarden rules` lists the 38 detection rules of 1.0.0
and, in area order after them, the three registry gate rules. The enforcement rules of the packs (SW-HK, SW-GW,
SW-EG, SW-RG, SW-OB) are not detection rules and organisation rules are never loaded by the CLI."""
from __future__ import annotations

import json
import re


def test_rules_lists_the_38_detection_rules_and_the_three_registry_rules_and_nothing_else(run_cli):
    code, out, err = run_cli(["rules", "--format", "json"])
    assert (code, err) == (0, "")
    ids = [rule["id"] for rule in json.loads(out)]
    assert len(ids) == 41 and len(set(ids)) == 41
    assert all(re.fullmatch(r"SW-(SKL|MCP|CFG|REG)-[0-9]{3}", rule_id) for rule_id in ids), ids
    assert ids[-3:] == ["SW-REG-001", "SW-REG-002", "SW-REG-003"] and not any(i.startswith("SW-REG") for i in ids[:-3])


def test_the_text_listing_gains_three_lines_and_no_heading(run_cli):
    code, out, err = run_cli(["rules"])
    lines = out.splitlines()
    assert (code, err, len(lines)) == (0, "", 41)
    assert [line.split()[0] for line in lines[-3:]] == ["SW-REG-001", "SW-REG-002", "SW-REG-003"]
    assert all(line.startswith("SW-") for line in lines)
