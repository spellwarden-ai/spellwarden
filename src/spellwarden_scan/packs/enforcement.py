"""The eight enforcement rules of product spec 9.4 screen 4 (Phase C spec 5.3),
renamed to the `SW-` prefix. An enforcement rule is not a detection rule: it
names a control an export can enforce. `targets` is what the rule is meant
for; `enforced_by` is the subset this release enforces (an export, or the
private registry's admission policy for SW-RG-007). Checked once, at import,
like `make_rule`."""
from __future__ import annotations

from dataclasses import dataclass

from spellwarden_scan.model import SEVERITY_RANK
from spellwarden_scan.rules import ALLOWED_NIST, ALLOWED_OWASP

TARGET_IDS = ("claude-code-hooks", "kong", "zuplo", "agentcore-policy", "cloudflare-egress", "registry")


@dataclass(frozen=True, slots=True)
class EnforcementRule:
    id: str
    title: str
    severity: str
    owasp_agentic: tuple[str, ...]
    owasp_mcp: tuple[str, ...]
    nist: tuple[str, ...]
    targets: tuple[str, ...]
    enforced_by: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "severity": self.severity, "owasp_agentic": list(self.owasp_agentic),
            "owasp_mcp": list(self.owasp_mcp), "nist": list(self.nist), "targets": list(self.targets),
            "enforced_by": list(self.enforced_by),
        }


def _rule(rule_id: str, title: str, severity: str, *, owasp: tuple[str, ...], nist: tuple[str, ...],
          targets: tuple[str, ...], enforced_by: tuple[str, ...]) -> EnforcementRule:
    if severity not in SEVERITY_RANK:
        raise ValueError(f"bad severity {severity!r} for {rule_id}")
    for identifier in owasp:
        if identifier not in ALLOWED_OWASP:
            raise ValueError(f"{rule_id}: {identifier} is not an allowed OWASP identifier")
    for identifier in nist:
        if identifier not in ALLOWED_NIST:
            raise ValueError(f"{rule_id}: {identifier} is not an allowed NIST identifier")
    for target in targets:
        if target not in TARGET_IDS:
            raise ValueError(f"{rule_id}: {target} is not a target id")
    if not set(enforced_by) <= set(targets):
        raise ValueError(f"{rule_id}: enforced_by must be a subset of targets")
    return EnforcementRule(
        id=rule_id, title=title, severity=severity,
        owasp_agentic=tuple(i for i in owasp if i.startswith("ASI")),
        owasp_mcp=tuple(i for i in owasp if i.startswith("MCP")),
        nist=nist, targets=targets, enforced_by=enforced_by,
    )


# Id order is the order of the numbers (001 to 008), which are unique across the prefixes; the pack document's
# `rules` list follows it (spec 5.4).
ENFORCEMENT_RULES: tuple[EnforcementRule, ...] = (
    _rule("SW-HK-001", "Block remote scripts piped to a shell in agent shell tools", "high",
          owasp=("ASI04",), nist=("SR-3",), targets=("claude-code-hooks",), enforced_by=("claude-code-hooks",)),
    _rule("SW-HK-002", "Block reads of credential files (~/.aws, ~/.ssh, .env)", "high",
          owasp=("MCP01",), nist=("IA-5",), targets=("claude-code-hooks", "cloudflare-egress"),
          enforced_by=("claude-code-hooks",)),
    _rule("SW-GW-003", "Deny MCP upstreams without OAuth", "high",
          owasp=("MCP01",), nist=("AC-3",), targets=("kong", "zuplo", "agentcore-policy"), enforced_by=()),
    _rule("SW-GW-004", "Prompt-injection deny patterns on prompts and tool results", "medium",
          owasp=("ASI01", "MCP10"), nist=("SI-10",), targets=("kong", "zuplo"), enforced_by=("kong", "zuplo")),
    _rule("SW-EG-005", "Sandbox egress only to registry-admitted hosts", "medium",
          owasp=("ASI10",), nist=("SC-7",), targets=("cloudflare-egress",), enforced_by=()),
    _rule("SW-GW-006", "Destructive tool verbs require human approval", "high",
          owasp=("ASI10",), nist=("AC-6",), targets=("agentcore-policy", "claude-code-hooks"),
          enforced_by=("claude-code-hooks",)),
    _rule("SW-RG-007", "Registry admits only curated, auth-enabled entries on spec 2026-07-28 (or grace-flagged before "
          "the deadline) with no open critical or high finding", "medium",
          owasp=("ASI04",), nist=("SR-3",), targets=("registry",), enforced_by=("registry",)),
    _rule("SW-OB-008", "Emit an audit record for every tool call", "low",
          owasp=(), nist=("AU-2",), targets=("claude-code-hooks", "kong", "zuplo", "agentcore-policy", "cloudflare-egress"),
          enforced_by=()),
)
ENFORCEMENT_IDS: tuple[str, ...] = tuple(rule.id for rule in ENFORCEMENT_RULES)

__all__ = ["ENFORCEMENT_IDS", "ENFORCEMENT_RULES", "TARGET_IDS", "EnforcementRule"]
