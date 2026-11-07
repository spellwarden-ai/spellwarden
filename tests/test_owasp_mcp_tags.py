"""The OWASP MCP Top 10 (2025) tags of every rule, pinned (1.9.1). Until 1.9.0 the scanner could tag only MCP01, MCP02 and
MCP10, so rules whose subject is another entry carried the nearest allowed one: tool poisoning (SW-MCP-011) and a server
missing from the private registry (SW-REG-002) were tagged MCP10 "Context Injection & Over-Sharing", and the
authentication and plain-HTTP rules MCP01 "Token Mismanagement and Secret Exposure". Each tag below names the entry whose description, as
published at github.com/OWASP/www-project-mcp-top-10 (read 2026-11-07), covers what the rule detects. A rule with no tag
here has none. A change to this map is a change of what Spellwarden claims, so it is made here on purpose."""
from __future__ import annotations

from spellwarden_scan.packs.enforcement import ENFORCEMENT_RULES
from spellwarden_scan import RuleSet
from spellwarden_scan.rules import ALLOWED_OWASP, BASELINE_ONLY_TAGS, ORG_ALLOWED_OWASP

MCP_TAGS = {
    # MCP01 Token Mismanagement and Secret Exposure: secrets written into packages and configuration.
    "SW-SKL-011": ("MCP01",),
    # MCP01 and MCP07: a secret in configuration, a static key, is also a static credential ("Use of static credentials in
    # configuration files").
    "SW-CFG-002": ("MCP01", "MCP07"),
    "SW-CFG-010": ("MCP01", "MCP07"),
    "SW-MCP-002": ("MCP01", "MCP07"),
    # MCP02 Privilege Escalation via Scope Creep: write access where a read-only mode exists.
    "SW-CFG-013": ("MCP02",),
    # MCP03 Tool Poisoning: instructions hidden in a tool's description (the entry's "Detection Indicators").
    "SW-MCP-011": ("MCP03",),
    # MCP04 Software Supply Chain Attacks & Dependency Tampering: MCP servers, plug-ins and code from floating references
    # without an integrity check.
    "SW-SKL-007": ("MCP04",),
    "SW-SKL-009": ("MCP04",),
    "SW-SKL-037": ("MCP04",),
    "SW-CFG-003": ("MCP04",),
    "SW-CFG-009": ("MCP04",),
    # MCP06: instructions in content the agent retrieves into its context (here external content fetched without an
    # allowlist). Rules on a skill's own text or an agent card do not read MCP context and carry ASI01 only.
    "SW-SKL-019": ("MCP06",),
    # MCP07 Insufficient Authentication & Authorization: no authentication, unprotected registration, unvalidated issuer.
    "SW-MCP-001": ("MCP07",),
    "SW-MCP-003": ("MCP07",),
    "SW-MCP-010": ("MCP07",),
    # MCP09 Shadow MCP Servers: an MCP server outside the organisation's approved list.
    "SW-REG-002": ("MCP09",),
    # Plain HTTP (SW-MCP-009, SW-CFG-001) has no tag: no 2025 entry is about transport, and the rules fire whether or not
    # a credential is sent.
}

ENFORCEMENT_MCP_TAGS = {
    "SW-HK-002": ("MCP01",),
    "SW-GW-003": ("MCP07",),
    "SW-GW-004": ("MCP06",),
    "SW-OB-008": ("MCP08",),
}

NEW_MCP_TAGS = {"MCP03", "MCP04", "MCP06", "MCP07", "MCP08", "MCP09"}
BASELINE = tuple(RuleSet.baseline())


def test_every_rule_carries_exactly_its_pinned_owasp_mcp_tags():
    actual = {rule.id: rule.owasp_mcp for rule in BASELINE if rule.owasp_mcp}
    assert actual == MCP_TAGS


def test_every_enforcement_rule_carries_exactly_its_pinned_owasp_mcp_tags():
    actual = {rule.id: rule.owasp_mcp for rule in ENFORCEMENT_RULES if rule.owasp_mcp}
    assert actual == ENFORCEMENT_MCP_TAGS


def test_no_rule_is_tagged_context_injection_and_over_sharing_any_more():
    tagged = [rule.id for rule in (*BASELINE, *ENFORCEMENT_RULES) if "MCP10" in rule.owasp_mcp]
    assert tagged == []


def test_the_new_tags_are_allowed_for_the_baseline_and_stay_out_of_organisation_rules():
    assert NEW_MCP_TAGS <= set(ALLOWED_OWASP)
    assert NEW_MCP_TAGS <= BASELINE_ONLY_TAGS
    assert not NEW_MCP_TAGS & set(ORG_ALLOWED_OWASP)
