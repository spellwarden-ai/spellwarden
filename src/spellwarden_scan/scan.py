"""`scan_skill_package` (spec 5.2): builds the package view, runs the skill
rules worst severity first, keeps at most `max_per_rule` findings per rule and
`max_findings` in all, counts what it drops, sorts what it kept.
`scan_agent_config` (spec 5.5) does the same for the `config` rules over parsed
configuration documents. `evaluate_agent_card` (O4 spec 5.2) does it for one A2A agent card."""
from __future__ import annotations

import dataclasses
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence

from spellwarden_scan import lint
from spellwarden_scan.a2a import AgentCardDocument
from spellwarden_scan.a2a_checklist import a2a_checklist
from spellwarden_scan.canonical import canonical_sha256
from spellwarden_scan.deadline import Deadline, Meter
from spellwarden_scan.evidence import bounded_evidence, fingerprint
from spellwarden_scan.identity import package_files, package_sha256
from spellwarden_scan.model import (
    SEVERITY_RANK, A2aScanResult, CardOrigin, ConfigDocument, ConfigScanResult, Finding, Location, SignatureOutcome, SkillMeta,
    SkillScanResult,
)
from spellwarden_scan.normalise import CANDIDATE_STEPS, EVIDENCE_PREFIX, STEPS
from spellwarden_scan.normalise import RULES as NORMALISED_RULES
from spellwarden_scan.orgrules import BudgetMeter, OrgRuleBudget, is_org_rule
from spellwarden_scan.package import Package, View
from spellwarden_scan.rules import Rule, RuleSet
from spellwarden_scan.rules.config import AgentConfig
from spellwarden_scan.version import RULES_VERSION, __version__

_retained_list = list


def _sort_key(finding: Finding) -> tuple:
    return (SEVERITY_RANK[finding.severity], finding.rule_id, finding.location.path, finding.location.line or 0)


def run_rules(rules, subject, *, max_findings: int, max_per_rule: int,
              meter: BudgetMeter | None = None, time_meter: Meter | None = None) -> tuple[list[Finding], int]:
    """Shared by the skill and the probe scans: lazily consumes each rule's
    findings, keeps at most the caps, counts the rest. With a `meter`, an org rule
    (Phase C spec 5.2.2) reads its units through it; baseline rules never do. With a `time_meter` (1.24.0, only
    `scan_skill_package` passes one) the clock is read before each rule, and the subject's lines tick it as rules read them."""
    retained = _retained_list()
    truncated = 0
    for rule in rules:
        if time_meter is not None:
            time_meter.check()
        kept_for_rule = 0
        seen: set[tuple[str, int | None, str]] = set()
        budgeted = meter is not None and is_org_rule(rule)
        for finding in (rule.detect.evaluate(subject, meter) if budgeted else rule.detect(subject)):
            key = (finding.location.path, finding.location.line, finding.fingerprint)
            if key in seen:  # 1.28.0 (spec D13): a line read through two units gives one finding, never two or a count left out
                continue
            seen.add(key)
            if kept_for_rule >= max_per_rule or len(retained) >= max_findings:
                truncated += 1
                continue
            retained.append(finding)
            kept_for_rule += 1
    retained.sort(key=_sort_key)
    return retained, truncated


def normalisation_steps(normalise: bool | Collection[str]) -> tuple[str, ...]:
    """The steps `scan_skill_package(normalise=...)` reads with (P6-4 spec 6.5.8): `normalise.STEPS` for True, none for False,
    the steps of a collection in the order they apply. A step id not in `normalise.CANDIDATE_STEPS` is a `ValueError`."""
    if normalise is True:
        return STEPS
    if normalise is False:
        return ()
    if isinstance(normalise, str) or not isinstance(normalise, Collection):
        raise ValueError("normalise must be True, False or a collection of step ids")
    unknown = sorted(set(normalise) - set(CANDIDATE_STEPS))
    if unknown:
        raise ValueError(f"unknown normalisation step {unknown[0]!r}; the steps are {', '.join(CANDIDATE_STEPS)}")
    return tuple(step for step in CANDIDATE_STEPS if step in normalise)


def read_through(rule: Rule, package: Package, views: Sequence[View], time_meter: Meter | None = None) -> Rule:
    """`rule` with a detector that yields its findings on `package` unchanged, then (spec 6.5.6) its findings on each view at a
    line where it has none yet, each moved to the original line it stands for and rewritten to quote that line as written:
    evidence `EVIDENCE_PREFIX` and the line, fingerprint from the line. A finding without a line is dropped. With a `time_meter`
    (1.24.0) the clock is read before the rule's pass over each view."""
    texts = {unit.path: unit.lines for unit in package.text_files}

    def detect(subject: Package) -> Iterator[Finding]:
        seen: set[tuple[str, int | None]] = set()
        for finding in rule.detect(subject):
            seen.add((finding.location.path, finding.location.line))
            yield finding
        for view in views:
            if time_meter is not None:
                time_meter.check()
            for finding in rule.detect(view):
                path, line = finding.location.path, finding.location.line
                original = view.original_line(path, line) if line is not None else None
                lines = texts.get(path, ())
                if original is None or not 1 <= original <= len(lines) or (path, original) in seen:
                    continue
                seen.add((path, original))
                text = lines[original - 1]
                yield Finding(rule.id, finding.severity, finding.title, Location(path, original),
                              bounded_evidence(EVIDENCE_PREFIX + text), fingerprint(rule.id, path, text),
                              finding.malicious_indicator)

    return dataclasses.replace(rule, detect=detect)


SCAN_KINDS = ("skill", "instructions")
# The two rules about the SKILL.md frontmatter: an instruction file (AGENTS.md, CLAUDE.md) has none to judge.
INSTRUCTION_SKIPPED_RULES = frozenset({"SW-SKL-015", "SW-SKL-031"})


def scan_skill_package(files: Mapping[str, bytes], rules: RuleSet, *, root: str = "",
                       executable_paths: Collection[str] = frozenset(), max_findings: int = 500,
                       max_per_rule: int = 100, org_rule_budget: OrgRuleBudget | None = None,
                       nested_roots: Iterable[str] = (), kind: str = "skill",
                       markdown_paths: Collection[str] = frozenset(),
                       normalise: bool | Collection[str] = True, deadline: Deadline | None = None) -> SkillScanResult:
    """`kind` is `"skill"` (the default) or `"instructions"`; any other value is a `ValueError`. With `"instructions"`
    the package is an instruction file such as AGENTS.md, so SW-SKL-015 and SW-SKL-031 (`INSTRUCTION_SKIPPED_RULES`)
    are not run and every other skill rule is. `org_rule_budget` bounds the time org rules may take (Phase C spec 5.2.2);
    a non-empty `org_rules_incomplete` on the result is an incomplete policy evaluation, never a clean one. `nested_roots` are the
    skill directories inside `root` (`identity.nested_skill_roots`); the result's `package_sha256` leaves them out.
    `markdown_paths` (1.13.0) are paths read as Markdown whatever their suffix (`Package.build`): the command passes the path of
    an instruction file such as a Cursor `.mdc` rule. The default changes nothing. Raises `frontmatter.FrontmatterLimit` (1.19.0)
    naming the file when a front matter it reads is past one of the limits, and `package.TextLimit` (1.22.0) naming a text file
    over `package.TEXT_MAX`: content left unread is the caller's error to report. `normalise` (1.22.0, P6-4 spec 6.5.8): True
    (the default) also reads the rules of `normalise.RULES` through the normalised views with `normalise.STEPS`, False reads the
    text as written only (the reading of 1.21.0), a collection of step ids reads with those steps; a normalised reading only adds
    findings, each quoting the line as written. `deadline` (1.24.0) is a `deadline.Deadline`, one for every package of a scan:
    when its clock reaches it the call raises `deadline.TimeLimit` (naming the file and the stage) and returns nothing for the
    package, the fourth exception it can raise beside the two above and `ValueError`. The clock is read before each file, view
    and rule and once for every 64 KiB of line text read; without `deadline` nothing changes."""
    if kind not in SCAN_KINDS:
        raise ValueError(f"kind must be one of {', '.join(SCAN_KINDS)}, not {kind!r}")
    steps = normalisation_steps(normalise)
    time_meter = Meter(deadline) if deadline is not None else None
    if time_meter is not None:
        time_meter.check()  # stage `before`: a deadline that has passed raises before any file is read
    package = Package.build(files, root=root, executable_paths=executable_paths, markdown_paths=markdown_paths,
                            meter=time_meter)
    meter = BudgetMeter(org_rule_budget)
    ordered = rules.ordered_for_scan("skill")
    if kind == "instructions":
        ordered = tuple(rule for rule in ordered if rule.id not in INSTRUCTION_SKIPPED_RULES)
    views = package.views(steps) if steps else ()
    if views:
        ordered = tuple(read_through(rule, package, views, time_meter) if rule.id in NORMALISED_RULES else rule
                        for rule in ordered)
    if time_meter is not None:
        time_meter.stage = "judging"
    retained, truncated = run_rules(ordered, package, max_findings=max_findings,
                                    max_per_rule=max_per_rule, meter=meter, time_meter=time_meter)
    identified = package_files(files, root, nested_roots)
    # Phase 4 batch B spec 11.4: the single-skill notes of the description lint; an instruction file has no description to lint
    notes = (tuple(lint.single(SkillMeta(root.strip("/"), package.metadata.name, package.metadata.description)))
             if kind == "skill" else ())
    return SkillScanResult(
        findings=tuple(retained), truncated=truncated, sha256=canonical_sha256(files), metadata=package.metadata,
        files_scanned=package.files_scanned, rules_version=RULES_VERSION, scanner_version=__version__,
        package_sha256=None if identified.unhashable else package_sha256(identified.files),
        org_rules_incomplete=tuple(sorted(meter.incomplete)), lint=notes,
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
