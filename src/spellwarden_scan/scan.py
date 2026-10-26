"""`scan_skill_package` (spec 5.2): builds the package view, runs the skill
rules worst severity first, keeps at most `max_per_rule` findings per rule and
`max_findings` in all, counts what it drops, sorts what it kept.
`scan_agent_config` (spec 5.5) does the same for the `config` rules over parsed
configuration documents. `evaluate_agent_card` (O4 spec 5.2) does it for one A2A agent card."""
from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence

from spellwarden_scan.a2a import AgentCardDocument
from spellwarden_scan.a2a_checklist import a2a_checklist
from spellwarden_scan.canonical import canonical_sha256
from spellwarden_scan.identity import package_files, package_sha256
from spellwarden_scan.model import (
    SEVERITY_RANK, A2aScanResult, CardOrigin, ConfigDocument, ConfigScanResult, Finding, SignatureOutcome, SkillScanResult,
)
from spellwarden_scan.orgrules import BudgetMeter, OrgRuleBudget, is_org_rule
from spellwarden_scan.package import Package
from spellwarden_scan.rules import RuleSet
from spellwarden_scan.rules.config import AgentConfig
from spellwarden_scan.version import RULES_VERSION, __version__

_retained_list = list


def _sort_key(finding: Finding) -> tuple:
    return (SEVERITY_RANK[finding.severity], finding.rule_id, finding.location.path, finding.location.line or 0)


def run_rules(rules, subject, *, max_findings: int, max_per_rule: int,
              meter: BudgetMeter | None = None) -> tuple[list[Finding], int]:
    """Shared by the skill and the probe scans: lazily consumes each rule's
    findings, keeps at most the caps, counts the rest. With a `meter`, an org rule
    (Phase C spec 5.2.2) reads its units through it; baseline rules never do."""
    retained = _retained_list()
    truncated = 0
    for rule in rules:
        kept_for_rule = 0
        budgeted = meter is not None and is_org_rule(rule)
        for finding in (rule.detect.evaluate(subject, meter) if budgeted else rule.detect(subject)):
            if kept_for_rule >= max_per_rule or len(retained) >= max_findings:
                truncated += 1
                continue
            retained.append(finding)
            kept_for_rule += 1
    retained.sort(key=_sort_key)
    return retained, truncated


def scan_skill_package(files: Mapping[str, bytes], rules: RuleSet, *, root: str = "",
                       executable_paths: Collection[str] = frozenset(), max_findings: int = 500,
                       max_per_rule: int = 100, org_rule_budget: OrgRuleBudget | None = None,
                       nested_roots: Iterable[str] = ()) -> SkillScanResult:
    """`org_rule_budget` bounds the time org rules may take (Phase C spec 5.2.2); a non-empty
    `org_rules_incomplete` on the result is an incomplete policy evaluation, never a clean one. `nested_roots` are the
    skill directories inside `root` (`identity.nested_skill_roots`); the result's `package_sha256` leaves them out."""
    package = Package.build(files, root=root, executable_paths=executable_paths)
    meter = BudgetMeter(org_rule_budget)
    retained, truncated = run_rules(rules.ordered_for_scan("skill"), package, max_findings=max_findings,
                                    max_per_rule=max_per_rule, meter=meter)
    identified = package_files(files, root, nested_roots)
    return SkillScanResult(
        findings=tuple(retained), truncated=truncated, sha256=canonical_sha256(files), metadata=package.metadata,
        files_scanned=package.files_scanned, rules_version=RULES_VERSION, scanner_version=__version__,
        package_sha256=None if identified.unhashable else package_sha256(identified.files),
        org_rules_incomplete=tuple(sorted(meter.incomplete)),
    )


def scan_agent_config(documents: Sequence[ConfigDocument], rules: RuleSet, *, max_findings: int = 500,
                      max_per_rule: int = 100) -> ConfigScanResult:
    """Every `config` rule over the documents that parsed (no error) or were truncated (their kept entries are
    judged; spec 5.2); a document with any other error is not judged and the caller reports it."""
    judged = AgentConfig(doc for doc in documents if doc.error in (None, "truncated"))
    retained, truncated = run_rules(rules.ordered_for_scan("config"), judged, max_findings=max_findings,
                                    max_per_rule=max_per_rule)
    return ConfigScanResult(findings=tuple(retained), truncated=truncated,
                            documents=tuple(doc.path for doc in judged.documents), rules_version=RULES_VERSION,
                            scanner_version=__version__)


A2A_MAX_FINDINGS = 500
A2A_MAX_PER_RULE = 20  # below the default of 100 for skills and probes: a card with a hundred skills must not drown the report


def evaluate_agent_card(document: AgentCardDocument, rules: RuleSet, *, origin: CardOrigin,
                        signatures: Sequence[SignatureOutcome], location_path: str) -> A2aScanResult:
    """Every `a2a` rule over one card in `rules.ordered_for_scan("a2a")` order, then the status fields and the migration
    checklist (O4 spec 5.2, 5.8). `signatures` are the outcomes the command recorded, one per entry of the card's `signatures`
    (the engine never verifies); `location_path` is where findings point: the card's own path for a repository card, the
    settings file for a remote one. A document that could not be read has only SW-A2A-018 (for a well-known or listed card)
    and the status `invalid`."""
    # Here, not at the top: `rules.a2a` imports `rules.mcp`, which imports `probe`, which imports `run_rules` from this module.
    from spellwarden_scan.rules.a2a import CardSubject, signature_status_of

    outcomes = tuple(signatures)
    subject = CardSubject(document, origin, outcomes, location_path)
    retained, truncated = run_rules(rules.ordered_for_scan("a2a"), subject, max_findings=A2A_MAX_FINDINGS,
                                    max_per_rule=A2A_MAX_PER_RULE)
    findings = tuple(retained)
    root = document.root
    signed = root is not None and isinstance(root.get("signatures"), list) and bool(root["signatures"])
    checklist = a2a_checklist(document, findings)
    fired = {finding.rule_id for finding in findings}
    if document.card_format == "unknown":
        status = "invalid"
    elif (document.card_format == "1.0" and not fired & {"SW-A2A-001", "SW-A2A-002", "SW-A2A-003", "SW-A2A-005"}
          and [item.key for item in checklist] == ["rescan"]):
        status = "ready"
    else:
        status = "to_migrate"
    return A2aScanResult(
        findings=findings, truncated=truncated, card_format=document.card_format, protocol_versions=document.protocol_versions,
        migration_status=status, signature_status=signature_status_of(outcomes, signed=signed), signatures=outcomes,
        checklist=checklist, document_truncated=document.truncated)
