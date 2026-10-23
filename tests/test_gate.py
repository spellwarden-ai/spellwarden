"""O3 spec 5.2 and claim E3: `gate_finding` gives the documented rule, fingerprint, location and bounded masked
evidence; the bindings of P48 make an acceptance of SW-REG-003 specific to one entry as it stands."""
from __future__ import annotations

import hashlib
import re

import pytest
from conftest import credential

from spellwarden_scan import gate
from spellwarden_scan.evidence import fingerprint
from spellwarden_scan.gate import GATE_KINDS, GATE_REASONS, GATE_RULE_IDS, gate_finding, resolver_binding, unhashable_binding
from spellwarden_scan.identity import package_sha256
from spellwarden_scan.model import Location

PIN = "git:https://github.com/a/b@" + "c" * 40


def test_constants():
    assert GATE_RULE_IDS == ("SW-REG-001", "SW-REG-002", "SW-REG-003")
    assert GATE_KINDS == ("skill", "server", "stdio", "plugin", "marketplace")
    assert GATE_REASONS == ("unhashable", "unresolved", "insecure", "unpinned", "unknown_launcher", "launch_override",
                            "resolver_override")


def test_gate_finding_rule_per_kind_and_reason():
    assert gate_finding("skill", ".claude/skills/d", None, "d", "a" * 64, "not_admitted").rule_id == "SW-REG-001"
    assert gate_finding("plugin", "m.json", 3, "p", PIN, "not_admitted").rule_id == "SW-REG-001"
    assert gate_finding("marketplace", "s.json", 3, "p", PIN, "not_admitted").rule_id == "SW-REG-001"
    assert gate_finding("server", ".mcp.json", 7, "s", "b" * 64, "not_admitted").rule_id == "SW-REG-002"
    assert gate_finding("stdio", ".mcp.json", 8, "s", "cmd:npx x@1.0.0", "not_admitted").rule_id == "SW-REG-002"
    for reason in GATE_REASONS:
        found = gate_finding("stdio", ".mcp.json", 8, "s", None, reason, "r" * 64)
        assert found.rule_id == "SW-REG-003" and found.severity == "high"


def test_gate_finding_fingerprint_location_and_evidence():
    found = gate_finding("server", ".mcp.json", 7, "s", "b" * 64, "not_admitted")
    assert found.fingerprint == fingerprint("SW-REG-002", ".mcp.json", "b" * 64)
    assert found.location == Location(".mcp.json", 7) and found.evidence == "s: " + "b" * 64
    assert found.title == "MCP server not admitted in the organisation's private registry"
    assert found.malicious_indicator is False
    skill = gate_finding("skill", "skills/d", None, "d", None, "unhashable", "f" * 64)
    assert skill.location == Location("skills/d", None) and skill.evidence == "d: unhashable"


def test_sw_reg_003_fingerprints_bind_one_entry():
    first = gate_finding("stdio", ".mcp.json", 3, "a", None, "unpinned", "1" * 64)
    second = gate_finding("stdio", ".mcp.json", 9, "b", None, "unpinned", "2" * 64)
    assert first.fingerprint == fingerprint("SW-REG-003", ".mcp.json", "unpinned:" + "1" * 64)
    assert first.fingerprint != second.fingerprint
    skill = gate_finding("skill", "skills/d", None, "d", None, "unhashable", "9" * 64)
    assert skill.fingerprint == fingerprint("SW-REG-003", "skills/d", "unhashable:" + "9" * 64)
    with pytest.raises(ValueError):
        gate_finding("stdio", ".mcp.json", 3, "a", None, "unpinned")
    with pytest.raises(ValueError):
        gate_finding("stdio", ".mcp.json", 3, "a", None, "unpinned", None)


def test_the_binding_is_not_part_of_a_not_admitted_fingerprint():
    one = gate_finding("server", ".mcp.json", 7, "s", "b" * 64, "not_admitted")
    two = gate_finding("server", ".mcp.json", 7, "s", "b" * 64, "not_admitted", "x" * 64)
    assert one.fingerprint == two.fingerprint


def test_resolver_binding_changes_with_the_resolver_file_and_the_entry():
    r1, r2 = "1" * 64, "2" * 64
    base = resolver_binding(r1, {".npmrc": b"registry=a"})
    assert re.fullmatch(r"[0-9a-f]{64}", base) and base == resolver_binding(r1, {".npmrc": b"registry=a"})
    assert base != resolver_binding(r1, {".npmrc": b"registry=b"})
    assert resolver_binding(r1, {".npmrc": b"registry=b"}) != resolver_binding(r2, {".npmrc": b"registry=a"})
    assert base == hashlib.sha256((r1 + "\0" + package_sha256({".npmrc": b"registry=a"})).encode()).hexdigest()


def test_unhashable_binding_changes_with_the_hashable_files_and_the_offending_paths():
    v1 = unhashable_binding({"SKILL.md": b"v1"}, ("s/node_modules",))
    assert re.fullmatch(r"[0-9a-f]{64}", v1)
    assert v1 != unhashable_binding({"SKILL.md": b"v2"}, ("s/node_modules",))
    two = unhashable_binding({"SKILL.md": b"v1"}, ("s/node_modules", "s/.venv"))
    assert v1 != two
    assert two == unhashable_binding({"SKILL.md": b"v1"}, ["s/.venv", "s/node_modules", "s/.venv"])
    expected = package_sha256({"SKILL.md": b"v1"}) + "\0" + "s/.venv\0s/node_modules"
    assert two == hashlib.sha256(expected.encode()).hexdigest()


def test_gate_finding_refuses_unknown_kind_or_reason():
    with pytest.raises(ValueError):
        gate_finding("package", "p", None, "n", "i", "not_admitted")
    with pytest.raises(ValueError):
        gate_finding("skill", "p", None, "n", None, "bogus", "b")
    with pytest.raises(ValueError):
        gate_finding("skill", "p", None, "n", "i", "unpinned")  # an identity goes with not_admitted only
    with pytest.raises(ValueError):
        gate_finding("skill", "p", None, "n", None, "not_admitted", "b")  # not_admitted needs an identity


def test_evidence_is_bounded_and_masked():
    long = gate_finding("server", ".mcp.json", 1, "n" * 400, "b" * 64, "not_admitted")
    assert len(long.evidence) == 300 and long.evidence.endswith("...")
    masked = gate_finding("server", ".mcp.json", 1, credential("github"), "b" * 64, "not_admitted")
    assert credential("github") not in masked.evidence


def test_the_module_exports_its_interface():
    assert {"gate_finding", "resolver_binding", "unhashable_binding"} <= set(dir(gate))
