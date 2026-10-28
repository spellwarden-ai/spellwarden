"""Zuplo export spec 4.1, 4.3, 4.6 and claims E1 to E9: the dispatch and the coverage table, the five files of the export and
their paths, the policy entry (`checks`, `deployChecks`, the two hashes), org rules the guard cannot express, hostile names,
determinism and the README. E6's grammar is `tests/test_zuplo_part.py`, E10 and E11 are `tests/test_zuplo_target.py`."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from pathlib import Path

import pytest

from spellwarden_scan import __version__
from spellwarden_scan.exports import CANNOT_ENFORCE, EXPORT_TARGETS, README_NAME, VENDOR_LINE, build, coverage
from spellwarden_scan.exports import zuplo as Z
from spellwarden_scan.exports.zuplo_guard import CHECK_MJS, GUARD_TS
from spellwarden_scan.orgrules import compile_pattern
from spellwarden_scan.packs import (
    ENFORCEMENT_IDS, ENFORCEMENT_RULES, baseline_pack, validate_pack,
)
from spellwarden_scan.rules.patterns import INJECTION
from spellwarden_scan.version import RULES_VERSION

ROOT = Path(__file__).resolve().parents[1]
PACKS = ROOT / "fixtures" / "packs"
BUILT = "2026-12-01T10:00:00Z"


def fixture(name: str):
    return validate_pack(json.loads((PACKS / "valid" / f"{name}.json").read_text(encoding="utf-8")))


def fixture_names() -> list[str]:
    return sorted(path.stem for path in (PACKS / "valid").glob("*.json"))


def export(doc) -> dict[str, bytes]:
    return build(doc, "zuplo", built_at=BUILT)


def policy(doc) -> dict:
    return json.loads(export(doc)[Z.POLICIES_PATH])["policies"][0]


def options(doc) -> dict:
    return policy(doc)["handler"]["options"]


def with_rules(doc, *, off=(), org_rules=None):
    rules = tuple((rule_id, rule_id not in off) for rule_id, _ in doc.rules)
    return dataclasses.replace(doc, rules=rules, org_rules=doc.org_rules if org_rules is None else tuple(org_rules))


# --- E1, E2: dispatch and coverage -------------------------------------------------------------------------------

def test_e1_the_five_files_and_the_paths():
    files = export(baseline_pack())
    assert set(files) == {Z.GUARD_PATH, Z.POLICIES_PATH, Z.CHECK_PATH, README_NAME, "SHA256SUMS"}
    assert (Z.GUARD_PATH, Z.POLICIES_PATH, Z.CHECK_PATH) == (
        "zuplo/modules/spellwarden-mcp-guard.ts", "zuplo/config/spellwarden-policies.json", "zuplo/spellwarden-zuplo-check.mjs")
    assert Z.POLICY_NAME == "spellwarden-mcp-guard"
    assert "zuplo" in EXPORT_TARGETS


def test_e1_mode_makes_no_difference():
    doc = baseline_pack()
    assert build(doc, "zuplo", built_at=BUILT, mode="managed") == build(doc, "zuplo", built_at=BUILT, mode="project")


def test_e2_coverage_of_the_baseline():
    enforced, cannot, not_included = coverage(baseline_pack(), "zuplo")
    assert enforced == ["SW-GW-004 (MCP server responses)"]
    assert [rule_id for rule_id, _ in cannot] == [i for i in ENFORCEMENT_IDS if i != "SW-GW-004"]
    assert dict(cannot) == {
        "SW-HK-001": "enforced by the Claude Code hooks export",
        "SW-HK-002": "enforced by the Claude Code hooks export",
        "SW-GW-003": "checked at deploy by the included script when your pipeline runs it; the gateway does not refuse the route",
        "SW-EG-005": "a sandbox egress proxy is not in this version",
        "SW-GW-006": "enforced by the Claude Code hooks export",
        "SW-RG-007": "enforced by the private registry, not by an export",
        "SW-OB-008": "Zuplo's audit logs are an Enterprise add-on set up in the Zuplo portal, not by this export",
    }
    assert not_included == []


def test_the_enforcement_table_names_zuplo_for_sw_gw_004_only():
    assert {rule.id for rule in ENFORCEMENT_RULES if "zuplo" in rule.enforced_by} == {"SW-GW-004"}
    assert all(not reason.endswith(".") for reason in CANNOT_ENFORCE.values())


# --- E3, E4, E5: the policy entry --------------------------------------------------------------------------------

def test_e3_the_policies_file_has_one_entry_with_the_handler_and_the_block():
    document = json.loads(export(baseline_pack())[Z.POLICIES_PATH])
    assert list(document) == ["policies"] and len(document["policies"]) == 1
    entry = document["policies"][0]
    assert entry["name"] == "spellwarden-mcp-guard" and entry["policyType"] == "custom-code-outbound"
    assert entry["handler"]["export"] == "default" and entry["handler"]["module"] == "$import(./modules/spellwarden-mcp-guard)"
    assert list(entry["handler"]["options"]) == ["spellwarden", "maxBodyBytes", "onTooLarge", "checks", "deployChecks"]
    block = entry["handler"]["options"]["spellwarden"]
    assert list(block) == ["format", "pack_id", "pack", "version", "built_at", "engine", "rules_version", "guard_sha256", "options_sha256"]
    assert (block["format"], block["pack_id"], block["pack"], block["version"], block["built_at"]) == (
        1, "baseline", "Spellwarden Baseline for Agents", "1.0", BUILT)
    assert (block["engine"], block["rules_version"]) == (__version__, RULES_VERSION)
    assert entry["handler"]["options"]["maxBodyBytes"] == 1048576 and entry["handler"]["options"]["onTooLarge"] == "block"


def test_e4_the_baseline_checks_are_the_nine_injection_expressions():
    checks = options(baseline_pack())["checks"]
    title = next(rule.title for rule in ENFORCEMENT_RULES if rule.id == "SW-GW-004")
    assert checks == [{"rule_id": "SW-GW-004", "title": title, "parts": [Z.zuplo_part(p.pattern)], "flags": "i", "anchored_end": False}
                      for p in INJECTION]
    assert len(checks) == 9
    assert options(baseline_pack())["deployChecks"] == {"SW-GW-003": True}


def test_e4_switches():
    doc = baseline_pack()
    assert options(with_rules(doc, off=("SW-GW-003",)))["deployChecks"] == {}
    assert options(with_rules(doc, off=("SW-GW-004",)))["checks"] == []
    everything_off = options(fixture("all-off"))
    assert everything_off["checks"] == [] and everything_off["deployChecks"] == {}


def test_e5_an_org_rule_with_the_target_follows_the_injection_entries():
    doc = fixture("with-zuplo-rules")
    checks = options(doc)["checks"]
    org = [check for check in checks if check["rule_id"] != "SW-GW-004"]
    assert [check["rule_id"] for check in checks[:9]] == ["SW-GW-004"] * 9
    assert [check["rule_id"] for check in org] == ["SW-ORG-001", "SW-ORG-002", "SW-ORG-003", "SW-ORG-004"]
    first, second = org[0], org[1]
    assert first["flags"] == "i" and len(first["parts"]) == 2 and first["anchored_end"] is False
    assert second == {"rule_id": "SW-ORG-002", "title": "Tells the agent to leak the secret", "parts": ["leak\\ the\\ secret$"],
                      "flags": "", "anchored_end": True}
    _, _, not_included = coverage(doc, "zuplo")
    assert "SW-ORG-006" in not_included and "SW-ORG-001" not in not_included


def test_invariant_7_a_pack_without_zuplo_rules_exports_with_the_injection_patterns_only():
    """A version published before 1.6.0 holds no org rule for `zuplo`: it exports SW-GW-004's nine patterns and nothing else."""
    doc = fixture("with-org-rules")
    assert {check["rule_id"] for check in options(doc)["checks"]} == {"SW-GW-004"} and len(options(doc)["checks"]) == 9
    _, _, not_included = coverage(doc, "zuplo")
    assert {"SW-ORG-001", "SW-ORG-003"} <= set(not_included)


# --- E6: org rules the guard cannot express ----------------------------------------------------------------------

def test_e6_every_emitted_part_of_the_fixture_packs_passes():
    for name in fixture_names():
        for spec in fixture(name).org_rules:
            detection = spec["detection"]
            if spec["area"] != "skill" or "[a\U0001F600]" in detection["pattern"]:
                continue
            compiled = compile_pattern(detection["pattern"], case_sensitive=bool(detection.get("case_sensitive", False)))
            for part in compiled.parts:
                assert Z.zuplo_part(part.pattern) is not None, (name, spec["id"], part.pattern)


def test_e6_a_rule_whose_part_cannot_be_written_is_not_enforced_with_the_reason():
    doc = fixture("with-zuplo-rules")
    enforced, _, _ = coverage(doc, "zuplo")
    assert "SW-ORG-005" in enforced  # coverage lists it; the export moves it
    readme = export(doc)[README_NAME].decode("ascii")
    assert "SW-ORG-005" in readme.split("## Enabled but not enforced by this target")[1].split("## Not included")[0]
    assert f"Not enforced here: {Z.JS_REASON}." in readme
    assert "SW-ORG-005" not in [check["rule_id"] for check in options(doc)["checks"]]
    assert Z.JS_REASON == "its pattern cannot be written for JavaScript"


# --- E7: hostile names -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["names-quotes", "names-unicode"])
def test_e7_hostile_names_reach_the_json_as_values_and_the_readme_through_comment_safe(name):
    doc = fixture(name)
    files = export(doc)
    text = files[Z.POLICIES_PATH].decode("ascii")
    assert json.loads(text)["policies"][0]["handler"]["options"]["spellwarden"]["pack"] == doc.name
    files[README_NAME].decode("ascii")
    assert files[Z.GUARD_PATH] == export(baseline_pack())[Z.GUARD_PATH] == GUARD_TS.encode("ascii")
    assert files[Z.CHECK_PATH] == export(baseline_pack())[Z.CHECK_PATH] == CHECK_MJS.encode("ascii")


def test_e7_every_fixture_pack_exports_the_same_script_files():
    guards = {export(fixture(name))[Z.GUARD_PATH] for name in fixture_names()}
    checks = {export(fixture(name))[Z.CHECK_PATH] for name in fixture_names()}
    assert len(guards) == 1 and len(checks) == 1


# --- E8: hashes --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["baseline", "with-zuplo-rules", "names-quotes", "names-unicode", "all-off"])
def test_e8_the_hashes_and_the_sums_verify(name):
    files = export(fixture(name))
    block = options(fixture(name))["spellwarden"]
    assert block["guard_sha256"] == hashlib.sha256(files[Z.GUARD_PATH]).hexdigest()
    canonical = json.dumps({**options(fixture(name)), "spellwarden": {k: v for k, v in block.items() if k != "options_sha256"}},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert block["options_sha256"] == hashlib.sha256(canonical.encode("ascii")).hexdigest() == Z.options_sha256(options(fixture(name)))
    lines = files["SHA256SUMS"].decode("ascii").splitlines()
    assert [line.split("  ", 1)[1] for line in lines] == sorted(path for path in files if path != "SHA256SUMS")
    for line in lines:
        digest, path = line.split("  ", 1)
        assert hashlib.sha256(files[path]).hexdigest() == digest


def test_e8_the_files_are_ascii_and_the_policies_file_ends_with_one_newline():
    for content in export(fixture("names-unicode")).values():
        content.decode("ascii")
    text = export(baseline_pack())[Z.POLICIES_PATH].decode("ascii")
    assert text.endswith("}\n") and not text.endswith("\n\n")


# --- E9: determinism and invariant 1 -----------------------------------------------------------------------------

def test_e9_two_builds_are_equal_and_the_build_time_matters():
    doc = fixture("with-zuplo-rules")
    assert export(doc) == export(doc)
    assert build(doc, "zuplo", built_at="2026-12-02T10:00:00Z") != export(doc)


# --- the README (spec 4.6) -----------------------------------------------------------------------------------------

def test_the_readme_has_the_common_sections_the_install_steps_and_the_limits():
    text = export(baseline_pack())[README_NAME].decode("ascii")
    for heading in ("## Enforced by this export", "## Enabled but not enforced by this target", "## Not included", "## Install", "## Limits"):
        assert heading in text
    assert text.rstrip().endswith(VENDOR_LINE)
    assert "SW-GW-003: Deny MCP upstreams without OAuth. Not enforced here: checked at deploy by the included script" in text
    assert "compatibilityDate` 2026-03-01 or later" in text and "https://zuplo.com/pricing" in text
    assert "Enterprise" in text and "plan" in text  # P21: the plans are linked, not named
    assert not re.search(r"\b(Free|Builder|Business) plan", text)
    for sentence in ("server_request", "SHA256SUMS", "SW-MCP-011", "text that is itself JSON-encoded", "UTF-16"):
        assert sentence in text
