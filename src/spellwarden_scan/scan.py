"""`scan_skill_package` (spec 5.2): builds the package view, runs the skill
rules worst severity first, keeps at most `max_per_rule` findings per rule and
`max_findings` in all, counts what it drops, sorts what it kept."""
from __future__ import annotations

from collections.abc import Collection, Mapping

from spellwarden_scan.canonical import canonical_sha256
from spellwarden_scan.model import SEVERITY_RANK, Finding, SkillScanResult
from spellwarden_scan.package import Package
from spellwarden_scan.rules import RuleSet
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
