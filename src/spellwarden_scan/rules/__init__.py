"""The rule registry (spec 5.2): `Rule`, `RuleSet`, `make_rule` and the
baseline of this release. Rule modules build their rules with `make_rule`,
which checks the id, the mappings and the severity once, at import."""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from spellwarden_scan.model import SEVERITY_RANK, Finding

RULE_ID_RE = re.compile(r"^SW-(SKL|MCP|CFG|REG|A2A|ORG)-[0-9]{3}$")
ALLOWED_OWASP = ("ASI01", "ASI03", "ASI04", "ASI07", "ASI10", "MCP01", "MCP10")
ALLOWED_NIST = ("AC-3", "AC-6", "AU-2", "IA-5", "SC-7", "SC-8", "SI-10", "SI-7", "SR-3")
# O4 spec 5.4 adds `ASI03`, `ASI07`, `SC-8` and `SI-7` for the A2A rules. An organisation rule may map to the tags of 1.2.x
# only: a pack that used a new one would be refused by every older scanner (`bad_mapping`), and the pack schema is frozen.
A2A_ONLY_TAGS = frozenset({"ASI03", "ASI07", "SC-8", "SI-7"})
ORG_ALLOWED_OWASP = tuple(tag for tag in ALLOWED_OWASP if tag not in A2A_ONLY_TAGS)
ORG_ALLOWED_NIST = tuple(tag for tag in ALLOWED_NIST if tag not in A2A_ONLY_TAGS)
AREAS = ("skill", "mcp", "config", "registry", "a2a")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity_default: str
    area: str
    owasp_agentic: tuple[str, ...]
    owasp_mcp: tuple[str, ...]
    nist: tuple[str, ...]
    targets: tuple[str, ...]
    malicious_indicator: bool
    detect: Callable[[Any], Iterable[Finding]]

    NIST_NOTE = "provisional mapping to SP 800-53 base controls"

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "severity_default": self.severity_default, "area": self.area,
            "owasp_agentic": list(self.owasp_agentic), "owasp_mcp": list(self.owasp_mcp), "nist": list(self.nist),
            "targets": list(self.targets), "malicious_indicator": self.malicious_indicator,
        }


def make_rule(rule_id: str, title: str, severity: str, area: str, *, owasp: Iterable[str], nist: Iterable[str],
              detect: Callable[[Any], Iterable[Finding]], malicious: bool = False, targets: Iterable[str] = ()) -> Rule:
    """The one constructor of rules; `owasp` holds both ASI and MCP identifiers and is split."""
    if rule_id.startswith("SW-ORG-"):  # organisation rules are made by `compile_org_rule` only (Phase C spec 5.2.1)
        raise ValueError(f"bad rule id {rule_id!r}: SW-ORG ids belong to organisation rules")
    if RULE_ID_RE.match(rule_id) is None:
        raise ValueError(f"bad rule id {rule_id!r}")
    if severity not in SEVERITY_RANK:
        raise ValueError(f"bad severity {severity!r} for {rule_id}")
    if area not in AREAS:
        raise ValueError(f"bad area {area!r} for {rule_id}")
    owasp_ids = tuple(owasp)
    nist_ids = tuple(nist)
    for identifier in owasp_ids:
        if identifier not in ALLOWED_OWASP:
            raise ValueError(f"{rule_id}: {identifier} is not an allowed OWASP identifier")
    for identifier in nist_ids:
        if identifier not in ALLOWED_NIST:
            raise ValueError(f"{rule_id}: {identifier} is not an allowed NIST identifier")
    return Rule(
        id=rule_id, title=title, severity_default=severity, area=area,
        owasp_agentic=tuple(i for i in owasp_ids if i.startswith("ASI")),
        owasp_mcp=tuple(i for i in owasp_ids if i.startswith("MCP")),
        nist=nist_ids, targets=tuple(targets), malicious_indicator=malicious, detect=detect,
    )


class RuleSet:
    """An ordered, immutable set of rules; iteration is in id order."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        by_id: dict[str, Rule] = {}
        for rule in rules:
            if rule.id in by_id:
                raise ValueError(f"duplicate rule id {rule.id}")
            by_id[rule.id] = rule
        self._rules: tuple[Rule, ...] = tuple(by_id[key] for key in sorted(by_id))

    @classmethod
    def baseline(cls) -> RuleSet:
        from spellwarden_scan.rules import a2a, config, mcp, registry, skill

        return cls(skill.RULES + mcp.RULES + config.RULES + registry.RULES + a2a.RULES)

    def with_rules(self, extra: Iterable[Rule]) -> RuleSet:
        return RuleSet(self._rules + tuple(extra))

    def get(self, rule_id: str) -> Rule | None:
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None

    def by_area(self, area: str) -> tuple[Rule, ...]:
        return tuple(rule for rule in self._rules if rule.area == area)

    def ordered_for_scan(self, area: str) -> tuple[Rule, ...]:
        """Worst severity first, then id: what the caps of spec 5.2 keep."""
        return tuple(sorted(self.by_area(area), key=lambda r: (SEVERITY_RANK[r.severity_default], r.id)))

    def __iter__(self) -> Iterator[Rule]:
        return iter(self._rules)

    def __len__(self) -> int:
        return len(self._rules)


__all__ = ["ALLOWED_NIST", "ALLOWED_OWASP", "SEVERITY_RANK", "Rule", "RuleSet", "make_rule"]
