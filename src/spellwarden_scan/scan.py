"""`scan_skill_package` (spec 5.2): builds the package view, runs the skill
rules worst severity first, keeps at most `max_per_rule` findings per rule and
`max_findings` in all, counts what it drops, sorts what it kept.
`scan_agent_config` (spec 5.5) does the same for the `config` rules over parsed
configuration documents."""
from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence

from spellwarden_scan.canonical import canonical_sha256
from spellwarden_scan.model import SEVERITY_RANK, ConfigDocument, ConfigScanResult, Finding, SkillScanResult
from spellwarden_scan.package import Package
from spellwarden_scan.rules import RuleSet
from spellwarden_scan.rules.config import AgentConfig
from spellwarden_scan.version import RULES_VERSION, __version__

_retained_list = list


def _sort_key(finding: Finding) -> tuple:
    return (SEVERITY_RANK[finding.severity], finding.rule_id, finding.location.path, finding.location.line or 0)


def run_rules(rules, subject, *, max_findings: int, max_per_rule: int) -> tuple[list[Finding], int]:
    """Shared by the skill and the probe scans: lazily consumes each rule's
    findings, keeps at most the caps, counts the rest."""
    retained = _retained_list()
    truncated = 0
    for rule in rules:
        kept_for_rule = 0
        for finding in rule.detect(subject):
            if kept_for_rule >= max_per_rule or len(retained) >= max_findings:
                truncated += 1
                continue
            retained.append(finding)
            kept_for_rule += 1
    retained.sort(key=_sort_key)
    return retained, truncated


def scan_skill_package(files: Mapping[str, bytes], rules: RuleSet, *, root: str = "",
                       executable_paths: Collection[str] = frozenset(), max_findings: int = 500,
                       max_per_rule: int = 100) -> SkillScanResult:
    package = Package.build(files, root=root, executable_paths=executable_paths)
    retained, truncated = run_rules(rules.ordered_for_scan("skill"), package, max_findings=max_findings,
                                    max_per_rule=max_per_rule)
    return SkillScanResult(
        findings=tuple(retained), truncated=truncated, sha256=canonical_sha256(files), metadata=package.metadata,
        files_scanned=package.files_scanned, rules_version=RULES_VERSION, scanner_version=__version__,
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
