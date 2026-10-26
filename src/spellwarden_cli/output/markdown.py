"""The Markdown report (spec 6.9): what a person reads in the job summary and the pull or merge request comment.
It starts with the comment marker, states the verdict and the counts, lists at most 25 open findings, the lock
changes, the probe summary and the accepted findings, and never exceeds 60,000 characters. Every value from the
scanned revision or a probed server is escaped (spec 6.13)."""
from __future__ import annotations

import re
from collections.abc import Sequence

from spellwarden_scan.gate import GATE_REASONS

from spellwarden_cli import escape
from spellwarden_cli.output import agents as agent_view
from spellwarden_cli.output.text import connected_lines
from spellwarden_cli.report import CONNECTED_ERRORS, Report, ReportFinding

MARKER = "<!-- spellwarden-scan -->"
MAX_CHARS = 60_000
MAX_ROWS = 25
CELL_MAX = 200
ERROR_FIX_MAX = 1000  # a connected error says what to fix: it is not cut at a table cell's length
README_URL = "https://github.com/spellwarden-ai/spellwarden"
RULES_URL = f"{README_URL}#the-rules"
# O3 spec 6.10: where the README explains why an item cannot be judged. Its connected-mode section has one heading per
# reason, "Gate reason: <reason>", whose GitHub anchor is this (tests/test_readme_connected.py reads them back).
REASON_ANCHORS = {reason: f"#gate-reason-{reason.replace('_', '-')}" for reason in GATE_REASONS}
_SEVERITIES = ("critical", "high", "medium", "low")
_LINK = re.compile(r"https://[A-Za-z0-9._~:/?#@!$&'*+,;=%-]+")
_CUT = "\n\nThe report was cut at 60,000 characters. The JSON and SARIF reports hold everything.\n"


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


def _findings(open_findings: Sequence[ReportFinding]) -> list[str]:
    if not open_findings:
        return []
    lines = ["| Severity | Rule | Location | Title |", "|---|---|---|---|"]
    for item in open_findings[:MAX_ROWS]:
        finding = item.finding
        lines.append(f"| {finding.severity} | {finding.rule_id} | {_code_cell(_location(item))} | {_text(finding.title)} |")
    if len(open_findings) > MAX_ROWS:
        lines += ["", f"{len(open_findings) - MAX_ROWS} more findings are in the JSON and SARIF reports."]
    return lines + [""]


def _errors(report: Report) -> list[str]:
    if not report.errors:
        return []
    lines = ["**These problems stopped a complete scan:**", ""]
    for error in report.errors[:MAX_ROWS]:
        where = f" {_code(error.path)}" if error.path else ""
        message = escape.markdown(error.message[:ERROR_FIX_MAX]) if error.code in CONNECTED_ERRORS else _text(error.message)
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


def render(report: Report) -> str:
    open_findings = report.unsuppressed()
    accepted = len(report.findings) - len(open_findings)
    lines = [MARKER, f"**Spellwarden scan {_verdict(report)}.** {_counts(open_findings, accepted)}", ""]
    section = connected_section(report)
    if section:
        lines.append(section)
    lines += _findings(open_findings) + _errors(report) + _lock(report) + _probes(report) + _agents(report)
    if accepted:
        lines += [f"{_plural(accepted, 'accepted finding')} with {'its' if accepted == 1 else 'their'} reasons "
                  f"{'is' if accepted == 1 else 'are'} listed in the baseline file.", ""]
    lines.append(f"Spellwarden {_text(report.scanner_version)}, rules {_text(report.rules_version)}. "
                 f"[What each rule checks]({RULES_URL})")
    text = escape.log_lines("\n".join(lines) + "\n")
    if len(text) > MAX_CHARS:
        text = text[:text.rfind("\n", 0, MAX_CHARS - len(_CUT))] + _CUT
    return text
