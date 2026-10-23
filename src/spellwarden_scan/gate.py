"""Gate findings (O3 spec 5.2): the findings of the registry rules SW-REG-001 to SW-REG-003, built from an identity the
connected command computed (`identity.py`). Pure. The three rules have no detector; this is the one place that makes
their findings, so that the command and the tests agree on rule, location, evidence and fingerprint."""
from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping

from spellwarden_scan.evidence import bounded_evidence, fingerprint, mask_credentials
from spellwarden_scan.identity import package_sha256
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.rules import registry

GATE_RULE_IDS = ("SW-REG-001", "SW-REG-002", "SW-REG-003")
GATE_REASONS = ("unhashable", "unresolved", "insecure", "unpinned", "unknown_launcher", "launch_override",
                "resolver_override")
GATE_KINDS = ("skill", "server", "stdio", "plugin", "marketplace")
NOT_ADMITTED = "not_admitted"
_RULES = {rule.id: rule for rule in registry.RULES}


def gate_finding(kind: str, path: str, line: int | None, name: str, identity: str | None, reason: str,
                 binding: str | None = None) -> Finding:
    """SW-REG-001 (skill, plugin, marketplace) or SW-REG-002 (server, stdio) for an identity with `reason ==
    "not_admitted"`; SW-REG-003 for `identity is None` with one of `GATE_REASONS`. `binding` is required for SW-REG-003
    and ties an acceptance to the entry as it stands (P48); it takes no part in the other two fingerprints."""
    if kind not in GATE_KINDS:
        raise ValueError(f"unknown gate kind {kind!r}")
    if identity is not None:
        if reason != NOT_ADMITTED:
            raise ValueError(f"an identified entry has the reason {NOT_ADMITTED!r}, not {reason!r}")
        rule_id = "SW-REG-002" if kind in ("server", "stdio") else "SW-REG-001"
        matched = identity
    else:
        if reason not in GATE_REASONS:
            raise ValueError(f"unknown gate reason {reason!r}")
        if binding is None:
            raise ValueError("SW-REG-003 needs a binding")
        rule_id = "SW-REG-003"
        matched = f"{reason}:{binding}"
    rule = _RULES[rule_id]
    return Finding(
        rule_id=rule_id, severity=rule.severity_default, title=rule.title, location=Location(path, line),
        evidence=bounded_evidence(mask_credentials(f"{name}: {identity or reason}")),
        fingerprint=fingerprint(rule_id, path, matched), malicious_indicator=False,
    )


def resolver_binding(raw_sha256: str, resolver: Mapping[str, bytes]) -> str:
    """The binding of a `resolver_override` finding: the entry's hash with the bytes of every resolver file of its
    launcher family, so a change to any of them is a new finding (P48)."""
    return hashlib.sha256(f"{raw_sha256}\0{package_sha256(resolver)}".encode()).hexdigest()


def unhashable_binding(files: Mapping[str, bytes], offending: Iterable[str]) -> str:
    """The binding of an `unhashable` skill: the hash of its hashable files (`PackageFiles.files`) and the sorted,
    deduplicated offending paths, so an edit to `SKILL.md` or a script is a new finding (P48)."""
    paths = "\0".join(sorted(set(offending)))
    return hashlib.sha256(f"{package_sha256(files)}\0{paths}".encode()).hexdigest()


__all__ = ["GATE_KINDS", "GATE_REASONS", "GATE_RULE_IDS", "gate_finding", "resolver_binding", "unhashable_binding"]
