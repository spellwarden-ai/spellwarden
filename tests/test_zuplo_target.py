"""Zuplo export spec 4.2, 4.1 and claims E10 and E11: org rules can name the target `zuplo` (the engine and the schema agree
on three targets), and `packs.TARGET_SINCE` says which engine accepts which target."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from spellwarden_scan.orgrules import TARGETS, OrgRuleError, validate_org_rule
from spellwarden_scan.packs import TARGET_SINCE, PackError, validate_pack

ROOT = Path(__file__).resolve().parents[1]
PACKS = ROOT / "fixtures" / "packs"
BASE = {"id": "SW-ORG-001", "title": "Rule", "severity": "medium", "area": "skill", "owasp": [], "nist": [], "targets": ["zuplo"],
        "malicious": False, "detection": {"kind": "pattern", "files": "**", "in": "lines", "pattern": "abc", "case_sensitive": False}}


def test_e10_the_rule_target_list_in_code_and_schema():
    schema = json.loads((ROOT / "schemas" / "pack.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    for targets in (["claude-code-hooks", "kong", "zuplo"], ["zuplo"], ["kong", "zuplo"]):
        spec = {**BASE, "targets": targets, "detection": {**BASE["detection"], "in": "commands"}}
        validate_org_rule(spec)
        document = json.loads((PACKS / "valid" / "baseline.json").read_text(encoding="utf-8"))
        document["org_rules"] = [spec]
        validator.validate(document)
        validate_pack(document)
    for targets in (["claude-code-hooks", "kong", "zuplo", "kong"], ["zuplo", "zuplo"]):
        with pytest.raises(OrgRuleError) as caught:
            validate_org_rule({**BASE, "targets": targets})
        assert caught.value.code == "bad_target"
        document = json.loads((PACKS / "valid" / "baseline.json").read_text(encoding="utf-8"))
        document["org_rules"] = [{**BASE, "targets": targets}]
        assert not validator.is_valid(document)
        with pytest.raises(PackError):
            validate_pack(document)
    mcp = {"id": "SW-ORG-002", "title": "Server", "severity": "high", "area": "mcp", "owasp": [], "nist": [], "targets": ["zuplo"],
           "detection": {"kind": "probe", "predicate": "transport_in", "values": ["sse"]}}
    with pytest.raises(OrgRuleError):
        validate_org_rule(mcp)


def test_e11_target_since_names_every_org_rule_target():
    assert set(TARGET_SINCE) == set(TARGETS) == {"claude-code-hooks", "kong", "zuplo"}
    assert TARGET_SINCE["zuplo"] == "1.6.0" and TARGET_SINCE["kong"] == TARGET_SINCE["claude-code-hooks"] == "1.1.0"
