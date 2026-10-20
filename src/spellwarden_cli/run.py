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


def apply_baseline(options: ScanOptions, findings: list[ReportFinding], notices: list[Notice], errors: list[Notice]) -> list[ReportFinding]:  # noqa: E501
    """Spec 6.7: findings that a valid, current entry accepts are suppressed; an invalid entry or an unusable
    file is an error (exit 2) and suppresses nothing."""
    from spellwarden_cli import baseline  # here, not at the top: baseline's commands import this module

    relative = options.baseline or baseline.BASELINE_PATH
    try:
        loaded = baseline.load_baseline(options.root, relative, required=options.baseline is not None)
    except baseline.BaselineError as exc:
        errors.append(Notice("baseline_invalid", relative, str(exc)))
        return findings
    kept, more_notices, more_errors = baseline.apply(loaded, findings, as_of=options.as_of, name=relative)
    notices.extend(more_notices)
    errors.extend(more_errors)
    return kept


def check_lock(options: ScanOptions, found: Discovery, errors: list[Notice]) -> LockState:
    """Spec 6.6: under `--locked`, the computed lock is compared with `.spellwarden/lock.json`; an unreadable lock
    file is an error (exit 2)."""
    from spellwarden_cli import lockfile  # here, not at the top: lockfile's command imports this module

    if not options.locked:
        return LockState()
    try:
        return lockfile.compare_lock(options.root, lockfile.compute_lock(found))
    except lockfile.LockUnreadable as exc:
        errors.append(Notice("lock_unreadable", lockfile.LOCK_PATH, str(exc)))
        return LockState()


def run_probes(options: ScanOptions, found: Discovery, rules: RuleSet, findings: list[ReportFinding], notices: list[Notice]) -> list[ProbeReport]:  # noqa: E501
    """Spec 6.8: the opt-in probe phase. Off unless `probe` is set; off on a pull or merge request from a fork or
    Dependabot; private addresses only on a trusted run (`ci.private_probe_trusted`), whatever the flag says.
    `run.scan` calls this before `apply_baseline`, so probe findings appended to `findings` are baselined there."""
    from spellwarden_cli import ci, net, probing  # here, not at the top, like the other seams

    if not options.settings.probe:
        return []
    context = ci.detect(options.env)
    targets, skipped = probing.probe_targets(found)
    for report in skipped:
        notices.append(Notice("probe_skipped", report.item, "not probed (unresolved: the URL holds a ${...} reference)"))
    if context.is_request and (context.fork or context.dependabot):
        notices.append(Notice("probe_fork_disabled", "", "--probe is off on a pull or merge request from a fork or "
                                                         "Dependabot: whoever opened it controls its endpoints"))
        forked = [ProbeReport(target.item, "skipped", "fork", None) for target in targets]
        return sorted([*skipped, *forked], key=lambda report: report.item)
    allow_private = options.settings.probe_private
    if allow_private and not ci.private_probe_trusted(context):
        notices.append(Notice("probe_private_untrusted", "", "--probe-private is ignored: it takes effect only on a "
                                                             "local run or on a protected ref outside pull and merge requests"))
        allow_private = False
    on_event = probing.event_logger(options.log)
    reports, probe_findings = probing.run_phase(
        targets, rules, fetcher_factory=lambda: net.Fetcher(allow_private=allow_private, on_event=on_event),
        now_iso=f"{options.as_of.isoformat()}T00:00:00Z", notices=notices)
    findings.extend(probe_findings)
    return sorted([*skipped, *reports], key=lambda report: report.item)
