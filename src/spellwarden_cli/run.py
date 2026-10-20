"""One scan (spec 6.5): list the files, discover the items, call the engine
once per skill and once for every configuration document, then the probe,
the baseline and the lock, and return the sorted `Report`. The three seams
at the end are filled by Task 8 (baseline, lock) and Task 11 (probe)."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import date

from spellwarden_scan import RULES_VERSION, RuleSet, __version__, scan_agent_config, scan_skill_package

from spellwarden_cli import discover, files
from spellwarden_cli.discover import Discovery
from spellwarden_cli.report import LockState, Notice, ProbeReport, Report, ReportFinding
from spellwarden_cli.settings import Settings


def _silent(_line: str) -> None:
    return None


@dataclass(frozen=True)
class ScanOptions:
    root: str  # absolute
    settings: Settings
    as_of: date
    locked: bool = False
    baseline: str | None = None  # scan-root-relative baseline file; None means .spellwarden/baseline.yml
    env: Mapping[str, str] = field(default_factory=dict)
    log: Callable[[str], None] = _silent  # --verbose lines (stderr)


def scan(options: ScanOptions) -> Report:
    rules = RuleSet.baseline()
    fileset = files.list_files(options.root, options.settings)
    found = discover.discover(fileset)
    notices: list[Notice] = [*fileset.notices, *found.notices]
    errors: list[Notice] = [*fileset.errors, *found.errors]
    options.log(f"{len(fileset.entries)} files listed, {len(found.items)} items discovered")
    findings = engine_findings(found, rules, notices)
    probes = run_probes(options, found, rules, findings, notices)
    findings = apply_baseline(options, findings, notices, errors)
    lock = check_lock(options, found, errors)
    report = Report(
        scanner_version=__version__, rules_version=RULES_VERSION, as_of=options.as_of.isoformat(),
        fail_on=options.settings.fail_on, items=found.items, findings=tuple(findings), probes=tuple(probes), lock=lock,
        notices=tuple(notices), errors=tuple(errors), repo_prefix=fileset.repo_prefix, rules=rules)
    return report.sorted()


def engine_findings(found: Discovery, rules: RuleSet, notices: list[Notice]) -> list[ReportFinding]:
    """The engine once per skill (only that package's files, under scan-root keys, so finding paths are scan-root
    paths) and once for every configuration document that parsed or was truncated (spec 5.5, 6.5)."""
    findings: list[ReportFinding] = []
    for skill in found.skills:
        result = scan_skill_package(skill.files, rules, root="" if skill.path == "." else skill.path,
                                    executable_paths=skill.executable)
        findings.extend(ReportFinding(finding, skill.path) for finding in result.findings)
        if result.truncated:
            notices.append(Notice("findings_truncated", skill.path, f"{result.truncated} more findings were not kept"))
    judged = [document for document in found.documents if document.error in (None, "truncated")]
    if judged:
        result = scan_agent_config(judged, rules)
        findings.extend(ReportFinding(finding, finding.location.path) for finding in result.findings)
        if result.truncated:
            notices.append(Notice("findings_truncated", "", f"{result.truncated} more configuration findings were not kept"))
    return findings


def apply_baseline(options: ScanOptions, findings: list[ReportFinding], notices: list[Notice], errors: list[Notice]) -> list[ReportFinding]:  # noqa: E501, ARG001
    """Seam: Task 8 replaces this body (spec 6.7)."""
    return findings


def check_lock(options: ScanOptions, found: Discovery, errors: list[Notice]) -> LockState:  # noqa: ARG001
    """Seam: Task 8 replaces this body (spec 6.6)."""
    return LockState()


def run_probes(options: ScanOptions, found: Discovery, rules: RuleSet, findings: list[ReportFinding], notices: list[Notice]) -> list[ProbeReport]:  # noqa: E501, ARG001
    """Seam: Task 11 replaces this body (spec 6.8)."""
    return []
