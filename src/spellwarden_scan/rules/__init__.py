"""The rule registry (spec 5.2): `Rule`, `RuleSet`, `make_rule` and the
baseline of this release. Rule modules build their rules with `make_rule`,
which checks the id, the mappings and the severity once, at import."""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from spellwarden_scan.frameworks import AST_IDS, ATLAS_TECHNIQUES
from spellwarden_scan.model import SEVERITY_RANK, Finding

RULE_ID_RE = re.compile(r"^SW-(SKL|MCP|CFG|REG|A2A|ORG)-[0-9]{3}$")
ALLOWED_OWASP = ("ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI07", "ASI09", "ASI10", "MCP01", "MCP02", "MCP03", "MCP04",
                 "MCP05", "MCP06", "MCP07", "MCP08", "MCP09", "MCP10")
ALLOWED_NIST = ("AC-3", "AC-6", "AU-2", "CM-7", "IA-5", "SC-7", "SC-8", "SI-10", "SI-3", "SI-7", "SR-3")
# O4 spec 5.4 added `ASI03`, `ASI07`, `SC-8` and `SI-7` for the A2A rules; the rule batch of 1.8.0 added `ASI02`, `ASI05`,
# `ASI09`, `MCP02`, `CM-7` and `SI-3`; 1.9.1 added `MCP03`, `MCP04`, `MCP06`, `MCP07`, `MCP08` and `MCP09`, so that a rule carries the
# OWASP MCP Top 10 entry it detects instead of the nearest one allowed before (`tests/test_owasp_mcp_tags.py`); 1.25.0 added `MCP05`
# for SW-MCP-013 (P6-9). An organisation rule may map to the tags of 1.2.x only: a pack that used a newer
# one would be refused by every older scanner (`bad_mapping`), and the pack schema is frozen. The org-rule lists below are
# therefore the 1.2.x lists.
BASELINE_ONLY_TAGS = frozenset({"ASI02", "ASI03", "ASI05", "ASI07", "ASI09", "MCP02", "MCP03", "MCP04", "MCP05", "MCP06",
                                "MCP07", "MCP08", "MCP09", "SC-8", "SI-3", "SI-7", "CM-7"})
# The name of 1.3.0 to 1.7.1, kept for code that imports it; it is the same set and will be removed in 2.0.0.
A2A_ONLY_TAGS = BASELINE_ONLY_TAGS
ORG_ALLOWED_OWASP = tuple(tag for tag in ALLOWED_OWASP if tag not in BASELINE_ONLY_TAGS)
ORG_ALLOWED_NIST = tuple(tag for tag in ALLOWED_NIST if tag not in BASELINE_ONLY_TAGS)
AREAS = ("skill", "mcp", "config", "registry", "a2a")
# 1.21.0 (P6-15 spec 4.2, 4.3): the page of a baseline rule, and the form every fix sentence keeps (F1 to F6). The first word of a
# sentence is one of FIX_VERBS, so a new rule's sentence that does not open with an instruction fails at import and is looked at.
RULE_PAGE = "https://spellwarden.ai/docs/rules/{}"
FIX_MAX = 200
FIX_VERBS = frozenset({"Add", "Call", "Change", "Commit", "Define", "Delete", "Download", "Fix", "Give", "Keep", "Launch", "List",
                       "Make", "Move", "Pin", "Publish", "Read", "Remove", "Replace", "Request", "Require", "Revoke", "Rewrite",
                       "Scope", "Send", "Serve", "Set", "Sign", "Start", "Stop", "Take", "Turn", "Update", "Write"})
_FIX_FORBIDDEN = frozenset("!?;<>|`")


def fix_problem(fix: str) -> str | None:
    """Why `fix` is not a fix sentence of the form of P6-15 spec 4.2 (F1 to F6), or None when it is one."""
    if not fix or not ("A" <= fix[0] <= "Z") or not fix.endswith(".") or ". " in fix:
        return "it is not one sentence that starts with a capital letter and ends with a full stop"
    if len(fix) > FIX_MAX:
        return f"it is longer than {FIX_MAX} characters"
    if any(not (" " <= char <= "~") for char in fix):
        return "it holds a character that is not printable ASCII"
    if any(char in _FIX_FORBIDDEN for char in fix):
        return "it holds one of ! ? ; < > | or a backtick"
    if "://" in fix or "spellwarden" in fix.lower():
        return "it holds an address or the product name"
    if fix.split(" ", 1)[0] not in FIX_VERBS:
        return "its first word is not one of FIX_VERBS"
    return None


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
    # 1.13.0 (Phase 3 batch 1 spec 9.2, 11.3): MITRE ATLAS technique ids (`frameworks.ATLAS_TECHNIQUES`; empty is the explicit "no
    # technique", with its reason in `frameworks.NO_ATLAS`) and OWASP Agentic Skills Top 10 ids (AST01 to AST10). An organisation rule
    # carries neither: the pack schema is frozen.
    atlas: tuple[str, ...] = ()
    owasp_ast: tuple[str, ...] = ()
    # 1.21.0 (P6-15 spec 6.2): the rule's fix sentence (section 5 of the spec), "" for an organisation rule, whose pack schema
    # holds no fix text
    fix: str = ""

    NIST_NOTE = "provisional mapping to SP 800-53 base controls"

    @property
    def page(self) -> str | None:
        """The address of the rule's page, the id in lower case and no campaign tags; None for an organisation rule."""
        return None if self.id.startswith("SW-ORG-") else RULE_PAGE.format(self.id.lower())

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "severity_default": self.severity_default, "area": self.area,
            "owasp_agentic": list(self.owasp_agentic), "owasp_mcp": list(self.owasp_mcp), "nist": list(self.nist),
            "targets": list(self.targets), "malicious_indicator": self.malicious_indicator,
            "atlas": list(self.atlas), "owasp_ast": list(self.owasp_ast),
            "fix": self.fix or None, "page": self.page,
        }


def make_rule(rule_id: str, title: str, severity: str, area: str, *, owasp: Iterable[str], nist: Iterable[str],
              atlas: Iterable[str], detect: Callable[[Any], Iterable[Finding]], malicious: bool = False,
              targets: Iterable[str] = (), owasp_ast: Iterable[str] = (), fix: str = "") -> Rule:
    """The one constructor of rules; `owasp` holds both ASI and MCP identifiers and is split. `atlas` has no default, so every
    rule states its ATLAS technique ids, or an empty tuple on purpose (1.13.0). `fix` (1.21.0) is the rule's fix sentence, checked
    against the form of `fix_problem` when given; every baseline rule has one (`RuleSet.baseline`), and a rule of your own built
    without one has none."""
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
    atlas_ids = tuple(atlas)
    ast_ids = tuple(owasp_ast)
    for identifier in atlas_ids:
        if identifier not in ATLAS_TECHNIQUES:
            raise ValueError(f"{rule_id}: {identifier} is not a technique of the pinned MITRE ATLAS release")
    for identifier in ast_ids:
        if identifier not in AST_IDS:
            raise ValueError(f"{rule_id}: {identifier} is not an OWASP Agentic Skills Top 10 identifier")
    if fix:
        problem = fix_problem(fix)
        if problem is not None:
            raise ValueError(f"{rule_id}: the fix sentence breaks its form: {problem}")
    return Rule(
        id=rule_id, title=title, severity_default=severity, area=area,
        owasp_agentic=tuple(i for i in owasp_ids if i.startswith("ASI")),
        owasp_mcp=tuple(i for i in owasp_ids if i.startswith("MCP")),
        nist=nist_ids, targets=tuple(targets), malicious_indicator=malicious, detect=detect,
        atlas=atlas_ids, owasp_ast=ast_ids, fix=fix,
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

        rules = skill.RULES + mcp.RULES + config.RULES + registry.RULES + a2a.RULES
        missing = [rule.id for rule in rules if not rule.fix]
        if missing:  # 1.21.0 (P6-15 spec 6.2): a baseline rule without its fix sentence cannot load
            raise ValueError(f"baseline rules without a fix sentence: {', '.join(missing)}")
        return cls(rules)

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


__all__ = ["ALLOWED_NIST", "ALLOWED_OWASP", "FIX_MAX", "FIX_VERBS", "RULE_PAGE", "SEVERITY_RANK", "Rule", "RuleSet", "fix_problem",
           "make_rule"]
