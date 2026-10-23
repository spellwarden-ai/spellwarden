"""One scan (spec 6.5): list the files, discover the items, call the engine
once per skill and once for every configuration document, then the probe,
the baseline and the lock, and return the sorted `Report`. The three seams
at the end are filled by Task 8 (baseline, lock) and Task 11 (probe)."""
from __future__ import annotations

from collections.abc import Callable, Mapping
import dataclasses
from dataclasses import dataclass, field
from datetime import date
import re
from typing import TYPE_CHECKING

from spellwarden_scan import RULES_VERSION, Finding, RuleSet, __version__, scan_agent_config, scan_skill_package

from spellwarden_cli import discover, files
from spellwarden_cli.discover import Discovery, SkillPackage
from spellwarden_cli.report import LockState, Notice, ProbeReport, Report, ReportFinding
from spellwarden_cli.secret import Credentials
from spellwarden_cli.settings import Settings

if TYPE_CHECKING:
    from spellwarden_cli.ci import CiContext, RevisionSource


# O3 spec 6.2: the shape of a pipeline key. A connector token (`swc_`) or a CI token (`swt_`) does not match.
KEY_RE = re.compile(r"swk_[A-Za-z0-9_-]{40}")


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
    context: CiContext | None = None  # the CI context `main` detected once; None: detected from `env` when needed
    revision: RevisionSource | None = None  # where the default baseline is read (D35); None: the working tree
    credentials: Credentials | None = None  # read once from the environment by `main` (O3 spec 6.1); None: none
    api_url: str | None = None  # SPELLWARDEN_API_URL when honoured (loopback HTTP only; O3 spec 6.2), else None
    as_of_given: bool = False  # `--as-of` was passed; refused in connected mode
    scope: str | None = ""  # the scan root below its work tree (`ci.scan_scope`, P41); None: outside the grammar of 8.4


def connected_config_problem(options: ScanOptions) -> Notice | None:
    """The checks of O3 spec 6.2 that need no network, in order: both credentials, a key of the wrong shape, `--as-of`
    in connected mode. The result is an error that stops the run before any file is listed and any request is made.
    Whether the run is connected is `connected.activation`'s decision (Task 8); here only what the variables and the
    settings in force already say. No message carries a credential."""
    credentials = options.credentials
    if credentials is None:
        return None
    if credentials.org and credentials.key:
        return Notice("connected_config", "", "SPELLWARDEN_ORG and SPELLWARDEN_API_KEY are both set. Use SPELLWARDEN_ORG "
                      "with the pipeline's identity, or SPELLWARDEN_API_KEY alone, not both.")
    if credentials.key is not None and KEY_RE.fullmatch(credentials.key.value) is None:
        return Notice("connected_key_invalid", "", "SPELLWARDEN_API_KEY is not a CI key. A CI key starts with swk_. "
                      "Create one under Settings, API keys, with access CI.")
    in_ci = options.context is not None and options.context.provider is not None
    connected = bool(credentials.org) or credentials.key is not None or (options.settings.connected.required and in_ci)
    if connected and options.as_of_given:
        return Notice("connected_config", "", "--as-of cannot be used in connected mode: the server works out when "
                      "baseline entries expire.")
    return None


def _stopped(options: ScanOptions, notices: list[Notice], problem: Notice) -> Report:
    """A report that holds the one error and the notices that explain where the settings came from."""
    return Report(scanner_version=__version__, rules_version=RULES_VERSION, as_of=options.as_of.isoformat(),
                  fail_on=options.settings.fail_on, items=(), findings=(), probes=(), lock=LockState(),
                  notices=tuple(notices), errors=(problem,), repo_prefix=None, rules=RuleSet.baseline()).sorted()


def scan(options: ScanOptions) -> Report:
    rules = RuleSet.baseline()
    early: list[Notice] = [*(options.revision.notices if options.revision else ())]
    if options.api_url is not None:
        early.append(Notice("api_url_override", "", "SPELLWARDEN_API_URL is honoured: the connected calls go to a loopback "
                                                    "address, not to the Spellwarden service."))
    problem = connected_config_problem(options)
    if problem is not None:
        return _stopped(options, early, problem)
    fileset = files.list_files(options.root, options.settings, env=options.env)
    found = discover.discover(fileset)
    notices: list[Notice] = [*fileset.notices, *found.notices, *early]
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
        # a case variant of SKILL.md is read under the engine's SKILL.md key and reported as written (spec 6.5)
        result = scan_skill_package(skill.engine_files(), rules, root="" if skill.path == "." else skill.path,
                                    executable_paths=skill.engine_executable(), nested_roots=skill.nested)
        findings.extend(ReportFinding(_as_written(skill, finding), skill.path) for finding in result.findings)
        if result.truncated:
            notices.append(Notice("findings_truncated", skill.path, f"{result.truncated} more findings were not kept"))
    judged = [document for document in found.documents if document.error in (None, "truncated")]
    if judged:
        result = scan_agent_config(judged, rules)
        findings.extend(ReportFinding(finding, finding.location.path) for finding in result.findings)
        if result.truncated:
            notices.append(Notice("findings_truncated", "", f"{result.truncated} more configuration findings were not kept"))
    return findings


def _as_written(skill: SkillPackage, finding: Finding) -> Finding:
    path = skill.as_written(finding.location.path)
    if path == finding.location.path:
        return finding
    return dataclasses.replace(finding, location=dataclasses.replace(finding.location, path=path))


def apply_baseline(options: ScanOptions, findings: list[ReportFinding], notices: list[Notice], errors: list[Notice]) -> list[ReportFinding]:  # noqa: E501
    """Spec 6.7: findings that a valid, current entry accepts are suppressed; an invalid entry or an unusable
    file is an error (exit 2) and suppresses nothing. The default file is read where `options.revision` says (on a
    pull or merge request, the base revision, D35); a `--baseline` file from the working tree, as the operator named it."""
    from spellwarden_cli import baseline  # here, not at the top: baseline's commands import this module

    relative = options.baseline or baseline.BASELINE_PATH
    read = options.revision.read if options.revision is not None and options.baseline is None else None
    try:
        loaded = baseline.load_baseline(options.root, relative, required=options.baseline is not None, read=read)
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
    Dependabot; private addresses only on a trusted run (`ci.private_probe_trusted`), whatever the flag says, and
    then only at the origins of the configured servers' URLs: a URL a probed server supplies, or a redirect that
    leaves the origin, gets the public-address rules (`net.Fetcher(private_origins=...)`).
    `run.scan` calls this before `apply_baseline`, so probe findings appended to `findings` are baselined there."""
    from spellwarden_cli import ci, net, probing  # here, not at the top, like the other seams

    if not options.settings.probe:
        return []
    context = options.context if options.context is not None else ci.detect(options.env)
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
                                                             "local run or on a push, schedule or manual run of a "
                                                             "protected ref"))
        allow_private = False
    private_origins = frozenset(target.url for target in targets) if allow_private else frozenset()
    on_event = probing.event_logger(options.log)
    reports, probe_findings = probing.run_phase(
        targets, rules, fetcher_factory=lambda: net.Fetcher(private_origins=private_origins, on_event=on_event),
        now_iso=f"{options.as_of.isoformat()}T00:00:00Z", notices=notices)
    findings.extend(probe_findings)
    return sorted([*skipped, *reports], key=lambda report: report.item)
