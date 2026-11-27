"""The Markdown report (spec 6.9): what a person reads in the job summary and the pull or merge request comment.
It starts with the comment marker, states the verdict and the counts, lists at most 25 open findings, the lock
changes, the probe summary and the accepted findings, and never exceeds 60,000 characters. Every value from the
scanned revision or a probed server is escaped (spec 6.13)."""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from spellwarden_scan.gate import GATE_REASONS

from spellwarden_cli import escape, instruction_files, presets
from spellwarden_cli.output import agents as agent_view
from spellwarden_cli.output.fixes import ORG_LINE, rule_fixes
from spellwarden_cli.output.text import client_lines, connected_lines, not_done_why
from spellwarden_cli.report import CONNECTED_ERRORS, Report, ReportFinding

if TYPE_CHECKING:  # a type only: this module never imports `ci` when it runs
    from spellwarden_cli.ci import CiContext

MARKER = "<!-- spellwarden-scan -->"
MAX_CHARS = 60_000
MAX_ROWS = 25
CELL_MAX = 200
ERROR_FIX_MAX = 1000  # a connected error says what to fix: it is not cut at a table cell's length
# 1.24.0: nor is the error of a scan that reached `--time-limit`, whose message ends with the way out
WHOLE_ERRORS = (*CONNECTED_ERRORS, "time_limit")
README_URL = "https://github.com/spellwarden-ai/spellwarden"
# O3 spec 6.10: where the README explains why an item cannot be judged. Its connected-mode section has one heading per
# reason, "Gate reason: <reason>", whose GitHub anchor is this (tests/test_readme_connected.py reads them back).
REASON_ANCHORS = {reason: f"#gate-reason-{reason.replace('_', '-')}" for reason in GATE_REASONS}
_SEVERITIES = ("critical", "high", "medium", "low")
_LINK = re.compile(r"https://[A-Za-z0-9._~:/?#@!$&'*+,;=%-]+")
_CUT = "\n\nThe report was cut at 60,000 characters. The JSON and SARIF reports hold everything.\n"
# Links back (spec 5.1): the `utm_medium` of every spellwarden.ai and dash link this report writes names the CI service the run
# detected. A closed table: the medium never comes from the environment.
MEDIUMS = {"github": "github-action", "gitlab": "gitlab-component", "other": "ci", None: "cli"}
RULES_DOCS_PAGE = "https://spellwarden.ai/docs/rules"
LINT_GUIDE_PAGE = "https://spellwarden.ai/docs/activation-checks"
ANALYZER_GUIDE_PAGE = "https://spellwarden.ai/docs/model-assisted-analyzer"
PRESETS_GUIDE_PAGE = "https://spellwarden.ai/docs/presets"


@dataclass(frozen=True)
class MarkdownLinks:
    """What the report's links and invitation lines depend on (spec 5.1); the default is a local run with no invitation."""
    medium: str = "cli"   # a value of MEDIUMS: the utm_medium of every spellwarden.ai and dash link the report writes
    invite: bool = False  # the dashboard line may be written (free mode decides the rest, spec 5.5)
    badge: bool = False   # the badge offer may be written (free mode and the cap decide the rest, spec 5.6, 5.7)


LOCAL_LINKS = MarkdownLinks()


def links_for(context: CiContext, *, invite: bool) -> MarkdownLinks:
    """The links of a run in `context` (spec 5.1): the medium of its CI service; the badge offer only for a default-branch run of
    a public GitHub repository, and only when `invite`."""
    badge = (invite and context.provider == "github" and context.run_kind() == "default_branch"
             and context.visibility == "public")
    return MarkdownLinks(medium=MEDIUMS.get(context.provider, MEDIUMS["other"]), invite=invite, badge=badge)


def tagged(page: str, medium: str, campaign: str) -> str:
    """`page` with the scanner's campaign tags (spec 5.1)."""
    return f"{page}?utm_source=scanner&utm_medium={medium}&utm_campaign={campaign}"


def _short(text: str) -> str:
    return text if len(text) <= CELL_MAX else text[:CELL_MAX - 3] + "..."


def _text(text: str) -> str:
    return escape.markdown(_short(text))


def _code(text: str) -> str:
    return escape.code_span(_short(text))


def _code_cell(text: str) -> str:
    """A code span inside a table cell: GitHub splits cells at every unescaped `|`, code spans included."""
    return _code(text).replace("|", "\\|")


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def _verdict(report: Report) -> str:
    code = report.exit_code()
    if code == 2:
        return "incomplete: some agent content could not be scanned"
    if code == 1:
        return f"failed at {report.fail_on}"
    if code == 3:
        return "failed: the lock file is out of date"
    return "passed"


def _counts(open_findings: Sequence[ReportFinding], accepted: int) -> str:
    by_severity = {severity: 0 for severity in _SEVERITIES}
    for item in open_findings:
        by_severity[item.finding.severity] += 1
    parts = ", ".join(f"{by_severity[severity]} {severity}" for severity in _SEVERITIES)
    return f"{_plural(len(open_findings), 'finding')} ({parts}), {accepted} accepted."


def _location(item: ReportFinding) -> str:
    location = item.finding.location
    return f"{location.path}:{location.line}" if location.line else location.path


def _rule_cell(report: Report, rule_id: str, medium: str) -> str:
    """Spec 5.2: a baseline rule's id links to its page; an organisation rule and an id the set lacks stay plain text."""
    rule = report.rules.get(rule_id)
    page = rule.page if rule is not None else None
    return rule_id if page is None else f"[{rule_id}]({tagged(page, medium, 'rule-docs')})"


def _findings(report: Report, open_findings: Sequence[ReportFinding], medium: str = "cli") -> list[str]:
    if not open_findings:
        return []
    lines = ["| Severity | Rule | Location | Title |", "|---|---|---|---|"]
    for item in open_findings[:MAX_ROWS]:
        finding = item.finding
        severity = finding.severity
        if item.preset_from is not None and report.preset is not None:  # 1.18.0: how a preset moved it
            severity += f" ({presets.change_words(item.preset_from, finding.severity, report.preset['name'])})"
        lines.append(f"| {severity} | {_rule_cell(report, finding.rule_id, medium)} | {_code_cell(_location(item))} | "
                     f"{_text(finding.title)} |")
    if len(open_findings) > MAX_ROWS:
        lines += ["", f"{len(open_findings) - MAX_ROWS} more findings are in the JSON and SARIF reports."]
    fixes = _fixes(report, open_findings[:MAX_ROWS], medium)
    if fixes:
        lines += ["", *fixes]
    return lines + [""]


def _fixes(report: Report, shown: Sequence[ReportFinding], medium: str = "cli") -> list[str]:
    """1.21.0 (P6-15 spec 6.6): the section "How to fix" for the rows the table shows: one bullet per baseline rule, in rule id
    order, with its fix sentence and its page, and under it one bullet per distinct set of setting lines; then the organisation
    line when a shown row is an organisation rule's. The JSON and SARIF reports hold every rule's fix."""
    fixes, organisation = rule_fixes(report, shown)
    if not fixes and not organisation:
        return []
    lines = ["**How to fix**", ""]
    for entry in fixes:
        page = tagged(report.rules.get(entry.rule_id).page, medium, "rule-fix")  # spec 5.3; FIX_TAGS stays for the other reports
        lines.append(f"- **{entry.rule_id}** {escape.markdown(entry.sentence)} [Rule page]({page})")
        lines += [f"  - In {escape.markdown(fix.where)}, write: {escape.code_span(fix.text)}" for fix in entry.lines]
    if organisation:
        lines.append(f"- {escape.markdown(ORG_LINE)}")
    return lines


def _preset(report: Report, medium: str = "cli") -> list[str]:
    """1.18.0: the preset's notice under the verdict, its guide as a link; nothing without a preset or with balanced."""
    notice = presets.notice_of(report)
    if notice is None:
        return []
    body = notice.message.removesuffix(f" See {presets.GUIDE_URL}")
    return [f"**Preset:** {escape.markdown(body)} [How presets work]({tagged(PRESETS_GUIDE_PAGE, medium, 'presets')})", ""]


def _instruction_files(report: Report) -> list[str]:
    """Phase 3 batch 1 spec 10.4: how many instruction files were scanned and, for each one with an open finding, when the agent
    applies it (a table row has no line under it, so the scope words sit here). Nothing when there is no instruction file."""
    scopes = instruction_files.scopes(report.items)
    if not scopes:
        return []
    lines = [f"**Instruction files:** {_plural(len(scopes), 'file')} scanned.", ""]
    with_findings = sorted({item.item for item in report.unsuppressed() if item.item in scopes})
    lines += [f"- {_code(path)}: {_text(scopes[path])}" for path in with_findings[:MAX_ROWS]]
    if len(with_findings) > MAX_ROWS:
        lines.append(f"- and {len(with_findings) - MAX_ROWS} more in the JSON report")
    return [*lines, ""] if with_findings else lines


def _errors(report: Report) -> list[str]:
    if not report.errors:
        return []
    lines = ["**These problems stopped a complete scan:**", ""]
    for error in report.errors[:MAX_ROWS]:
        where = f" {_code(error.path)}" if error.path else ""
        message = escape.markdown(error.message[:ERROR_FIX_MAX]) if error.code in WHOLE_ERRORS else _text(error.message)
        lines.append(f"- {error.code}{where}: {message}")
    if len(report.errors) > MAX_ROWS:
        lines.append(f"- and {len(report.errors) - MAX_ROWS} more in the JSON report")
    return lines + [""]


def _lock(report: Report) -> list[str]:
    state = report.lock
    if state.status == "absent":
        return ["**Lock file:** `.spellwarden/lock.json` is missing. Run `spellwarden lock` and commit the file.", ""]
    if state.status != "stale":
        return []
    changes = [(label, change) for label, group in (("added", state.added), ("removed", state.removed),
                                                    ("changed", state.changed)) for change in group]
    lines = ["**Lock file:** these agent files changed since `.spellwarden/lock.json` was written:", ""]
    lines += [f"- {label} {_text(change['kind'])} {_code(change['path'])}" for label, change in changes[:MAX_ROWS]]
    if len(changes) > MAX_ROWS:
        lines.append(f"- and {len(changes) - MAX_ROWS} more in the JSON report")
    return lines + [""]


def _probes(report: Report) -> list[str]:
    if not report.probes:
        return []
    lines = ["**MCP servers probed:**", "", "| Server | Result | Transport | Auth | Spec version | Migration |",
             "|---|---|---|---|---|---|"]
    for probe in report.probes[:MAX_ROWS]:
        outcome = "probed" if probe.status == "probed" else f"skipped ({probe.skip_reason})"
        result = probe.result
        cells = ([result.transport, result.auth_mode, result.spec_version or "-", result.migration_status]
                 if result is not None else ["-", "-", "-", "-"])
        lines.append(f"| {_code_cell(probe.item)} | {_text(outcome)} | " + " | ".join(_text(cell) for cell in cells) + " |")
    if len(report.probes) > MAX_ROWS:
        lines += ["", f"{len(report.probes) - MAX_ROWS} more servers are in the JSON report."]
    return lines + [""]


def _agents(report: Report) -> list[str]:
    """O4 spec 6.10: the section "A2A agent cards": one row per agent (where it came from, format and versions, migration,
    signature with its key source), and under it what each agent still needs: the members its signature does not cover and the
    checklist. The note on remote agents follows when it applies."""
    if not report.agents:
        return []
    shown = agent_view.views(report)
    lines = ["**A2A agent cards:**", "", "| Agent | Origin | Card | Signature |", "|---|---|---|---|"]
    for view in shown[:MAX_ROWS]:
        lines.append(f"| {_code_cell(view.item)} | {_text(view.origin)} | {_text(view.summary)} | "
                     f"{_text(view.signature or '-')} |")
    if len(shown) > MAX_ROWS:
        lines += ["", f"{len(shown) - MAX_ROWS} more agents are in the JSON report."]
    for view in shown[:MAX_ROWS]:
        if view.unsigned or len(view.checklist) > 1:
            lines += ["", f"{_code(view.item)}:"]
            if view.unsigned:
                lines.append(f"- verified without these members: {_text(', '.join(view.unsigned))}")
            lines += [f"- {_text(step)}" for step in view.checklist if not step.endswith("Re-run the Spellwarden scan")]
    if agent_view.remote_note_applies(report):
        lines += ["", agent_view.REMOTE_NOTE]
    return lines + [""]


def _lint(report: Report, medium: str = "cli") -> list[str]:
    """Phase 4 batch B spec 11.4: the section "Description lint": one row per note (at most 25), informational; nothing when
    no skill has a note."""
    rows = [(entry.skill, note) for entry in report.lint or () for note in entry.notes]
    left_out = sum(entry.left_out for entry in report.lint or ())
    if not rows and not left_out:
        return []
    lines = [f"**Description lint (informational, never changes the exit code):** {_plural(len(rows) + left_out, 'note')}. "
             f"[What each check means]({tagged(LINT_GUIDE_PAGE, medium, 'description-lint')})", "",
             "| Skill | Check | Note |", "|---|---|---|"]
    for skill, note in rows[:MAX_ROWS]:
        lines.append(f"| {_code_cell(skill)} | {note.id} | {_text(note.message)} |")
    more = len(rows) - MAX_ROWS + left_out if len(rows) > MAX_ROWS else left_out
    if more > 0:
        lines += ["", f"{more} more notes are in the JSON report."]
    return lines + [""]


def _analysis(report: Report, medium: str = "cli") -> list[str]:
    """Phase 4 batch B spec 11.3: the section "Model-assisted analysis" under `--analyze`: one row per skill (at most 25) with
    its status and the categories with an issue; advisory. Nothing without `--analyze`."""
    if report.analysis is None:
        return []
    lines = [f"**Model-assisted analysis (advisory, its verdicts never change the exit code):** "
             f"[How it works and what it was measured on]({tagged(ANALYZER_GUIDE_PAGE, medium, 'analyzer')})", "",
             "| Skill | Model | Result |", "|---|---|---|"]
    for entry in report.analysis[:MAX_ROWS]:
        if entry["status"] == "analyzed":
            issues = [f"{category['id']} ({category['confidence']})" for category in entry["categories"]
                      if category["verdict"] == "issue"]
            result = "issues: " + ", ".join(issues) if issues else "no issue found by the model"
        else:
            result = f"{entry['status']}: {not_done_why(entry)}"
        lines.append(f"| {_code_cell(entry['skill'])} | {_text(entry['model'])} | {_text(result)} |")
    if len(report.analysis) > MAX_ROWS:
        lines += ["", f"{len(report.analysis) - MAX_ROWS} more skills are in the JSON report."]
    return lines + [""]


def _not_admitted(report: Report) -> list[str]:
    """The section of O3 spec 6.10 for the items of the registry gate that failed it: `Request admission` for an item the
    registry does not hold (the link is only ever one under the dashboard address, `connected.run_gate`), the reason
    and the README anchor for an item that cannot be judged."""
    registry = (report.connected or {}).get("registry") or {}
    rows = []
    for item in registry.get("items") or ():
        if not item.get("in_scope"):
            continue
        label = f"{_text(str(item.get('name')))} ({_text(str(item.get('kind')))}, {_code(str(item.get('path')))})"
        reason = item.get("reason")
        if item.get("identity") is None and reason in REASON_ANCHORS:
            rows.append(f"- {label}: cannot be judged ([{reason}]({README_URL}{REASON_ANCHORS[reason]}))")
        elif item.get("admitted") is False:
            url = item.get("request_url")
            rows.append(f"- {label}: [Request admission]({url})" if isinstance(url, str) and _LINK.fullmatch(url) else
                        f"- {label}: not admitted")
    if not rows:
        return []
    shown = rows[:MAX_ROWS]
    if len(rows) > MAX_ROWS:
        shown.append(f"- and {len(rows) - MAX_ROWS} more in the JSON report")
    return ["**Not admitted in the private registry**", "", *shown, ""]


def connected_section(report: Report) -> str:
    """O3 spec 6.10, a pure function of the report's `connected` block and notices (P28): the lines of the text
    output under a heading, each escaped; a result link only when it is a plain https address; then, when the gate
    produced findings, the section "Not admitted in the private registry". Empty in free mode."""
    lines = connected_lines(report)
    if not lines:
        return ""
    out = ["**Connected mode**", ""]
    for line in lines:
        if line.startswith("Results: "):
            url = line[len("Results: "):]
            out += [f"Results: <{url}>" if _LINK.fullmatch(url) else "Results: see the JSON report", ""]
        else:
            out += [_text(line), ""]
    return "\n".join([*out, *_not_admitted(report)])


def render(report: Report, links: MarkdownLinks = LOCAL_LINKS) -> str:
    medium = links.medium
    open_findings = report.unsuppressed()
    accepted = len(report.findings) - len(open_findings)
    lines = [MARKER, f"**Spellwarden scan {_verdict(report)}.** {_counts(open_findings, accepted)}", "",
             *_preset(report, medium)]
    section = connected_section(report)
    if section:
        lines.append(section)
    if report.clients is not None:  # `scan --user` (phase 3 batch 2a spec 11.3)
        lines += ["**Clients:**", "", *(f"- {_text(line)}" for line in client_lines(report)), ""]
    lines += _findings(report, open_findings, medium) + _instruction_files(report)
    lines += _errors(report) + _lock(report) + _probes(report) + _agents(report) + _lint(report, medium)
    lines += _analysis(report, medium)
    if accepted:
        lines += [f"{_plural(accepted, 'accepted finding')} with {'its' if accepted == 1 else 'their'} reasons "
                  f"{'is' if accepted == 1 else 'are'} listed in the baseline file.", ""]
    lines.append(f"Spellwarden {_text(report.scanner_version)}, rules {_text(report.rules_version)}. "
                 f"[What each rule checks]({tagged(RULES_DOCS_PAGE, medium, 'rule-docs')}), [source code]({README_URL})")
    text = escape.log_lines("\n".join(lines) + "\n")
    if len(text) > MAX_CHARS:
        text = text[:text.rfind("\n", 0, MAX_CHARS - len(_CUT))] + _CUT
    return text
