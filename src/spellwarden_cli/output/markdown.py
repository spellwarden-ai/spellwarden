"""The Markdown report (spec 6.9): what a person reads in the job summary and the pull or merge request comment.
It starts with the comment marker, states the verdict and the counts, lists at most 25 open findings, the lock
changes, the probe summary and the accepted findings, and never exceeds 60,000 characters. Every value from the
scanned revision or a probed server is escaped (spec 6.13)."""
from __future__ import annotations

from collections.abc import Sequence

from spellwarden_cli import escape
from spellwarden_cli.report import Report, ReportFinding

MARKER = "<!-- spellwarden-scan -->"
MAX_CHARS = 60_000
MAX_ROWS = 25
CELL_MAX = 200
RULES_URL = "https://github.com/spellwarden-ai/spellwarden#the-rules"
_SEVERITIES = ("critical", "high", "medium", "low")
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
        lines.append(f"- {error.code}{where}: {_text(error.message)}")
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


def render(report: Report) -> str:
    open_findings = report.unsuppressed()
    accepted = len(report.findings) - len(open_findings)
    lines = [MARKER, f"**Spellwarden scan {_verdict(report)}.** {_counts(open_findings, accepted)}", ""]
    lines += _findings(open_findings) + _errors(report) + _lock(report) + _probes(report)
    if accepted:
        lines += [f"{_plural(accepted, 'accepted finding')} with {'its' if accepted == 1 else 'their'} reasons "
                  f"{'is' if accepted == 1 else 'are'} listed in the baseline file.", ""]
    lines.append(f"Spellwarden {_text(report.scanner_version)}, rules {_text(report.rules_version)}. "
                 f"[What each rule checks]({RULES_URL})")
    text = escape.log_lines("\n".join(lines) + "\n")
    if len(text) > MAX_CHARS:
        text = text[:text.rfind("\n", 0, MAX_CHARS - len(_CUT))] + _CUT
    return text
