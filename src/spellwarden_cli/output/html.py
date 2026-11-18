"""`--format html` (1.18.0): the report as one self-contained HTML file for a person to open in a browser. It is hostile-data
output: every string from the scanned revision or a probed server, and every string of Spellwarden's own, passes through
`escape.html`; attributes hold only the scanner's own values (fixed class names, `finding-N` ids, and the rule page of a rule id
that matches `RULE_ID_RE` and names a rule of the scanner); there is no script element, no event attribute, no form, no frame,
no image and no external asset, one inline style without `url(`, and a Content-Security-Policy that forbids every fetch, so
opening the file makes no network request. It holds every finding, notice and error the JSON report holds, in its order, without
a cap of its own, and the same report gives the same bytes."""
from __future__ import annotations

from collections import Counter

from spellwarden_scan.rules import RULE_ID_RE

from spellwarden_cli import escape, presets
from spellwarden_cli.output import agents as agent_view
from spellwarden_cli.output.text import client_lines, not_done_why
from spellwarden_cli.report import Report, ReportFinding

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
RULE_DOCS = "https://spellwarden.ai/docs/rules/{}?utm_source=scanner&utm_medium=html-report&utm_campaign=rule-docs"
TITLE = "Spellwarden scan report"
SEVERITIES = ("critical", "high", "medium", "low")
_OUTCOME = {0: "passed", 1: "failed", 2: "incomplete", 3: "failed"}
STYLE = (
    ":root{color-scheme:light dark;--fg:#1d1d1f;--bg:#ffffff;--muted:#5f6368;--line:#d0d4d9;--critical:#a50e0e;"
    "--high:#c5221f;--medium:#b06000;--low:#1a73e8}"
    "@media (prefers-color-scheme:dark){:root{--fg:#e8eaed;--bg:#16181b;--muted:#9aa0a6;--line:#3c4043;"
    "--critical:#f28b82;--high:#ee675c;--medium:#fdd663;--low:#8ab4f8}}"
    "body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}"
    "main{max-width:960px;margin:0 auto;padding:24px 16px}"
    "h1{font-size:24px;margin:0 0 4px}"
    "h2{font-size:18px;margin:32px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--line)}"
    "h3{font-size:15px;margin:20px 0 8px}"
    "h3,td,th,pre,code,li{overflow-wrap:anywhere}"
    ".meta,.fingerprint{color:var(--muted)}"
    "table{border-collapse:collapse}"
    "th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}"
    ".finding{border-left:4px solid var(--line);padding:4px 12px;margin:12px 0}"
    ".severity-critical{border-left-color:var(--critical)}.severity-high{border-left-color:var(--high)}"
    ".severity-medium{border-left-color:var(--medium)}.severity-low{border-left-color:var(--low)}"
    ".severity{font-weight:600;text-transform:uppercase;font-size:12px}"
    "pre,code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}"
    "pre{white-space:pre-wrap;background:rgba(127,127,127,.12);padding:8px;margin:4px 0}"
    ".outcome-failed,.outcome-incomplete,.errors{font-weight:600}"
)


def _e(value: object) -> str:
    return escape.html(str(value))


def _rule_link(report: Report, rule_id: str) -> str | None:
    """The rule page of one of the scanner's rules, a plain link a person may click, escaped for the attribute; None for an
    organisation rule, a rule the set lacks or an id that is not an id."""
    if RULE_ID_RE.fullmatch(rule_id) is None or rule_id.startswith("SW-ORG-") or report.rules.get(rule_id) is None:
        return None
    return escape.html(RULE_DOCS.format(rule_id))


def _verdict(report: Report) -> tuple[str, str]:
    code = report.exit_code()
    words = {0: "passed", 1: f"failed at {report.fail_on}", 2: "incomplete: some agent content could not be scanned",
             3: f"failed: the lock file is {report.lock.status}"}[code]
    return _OUTCOME[code], f"{words}; exit code {code}"


def _finding(report: Report, row: ReportFinding, number: int) -> list[str]:
    f = row.finding
    severity_class = f"severity-{f.severity}" if f.severity in SEVERITIES else "severity-unknown"
    link = _rule_link(report, f.rule_id)
    rule = f'<a href="{link}">{_e(f.rule_id)}</a>' if link else _e(f.rule_id)
    location = f"{f.location.path}:{f.location.line}" if f.location.line else f.location.path
    lines = [f'<article class="finding {severity_class}" id="finding-{number}">',
             f'<p><span class="severity">{_e(f.severity)}</span> {rule} {_e(f.title)}</p>']
    if row.preset_from is not None and report.preset is not None:
        lines.append(f'<p class="preset-from">{_e(presets.change_words(row.preset_from, f.severity, report.preset["name"]))}</p>')
    if f.malicious_indicator:
        lines.append('<p class="malicious">Malicious indicator</p>')
    lines.append(f"<p>Location: <code>{_e(location)}</code></p>")
    if f.evidence:
        lines.append(f'<pre class="evidence">{_e(f.evidence)}</pre>')
    lines.append(f'<p class="fingerprint">Fingerprint <code>{_e(f.fingerprint)}</code></p>')
    if row.suppressed:
        baseline = row.baseline or {}
        until = f" until {baseline['expires']}" if baseline.get("expires") else ""
        lines.append(f'<p class="accepted">Accepted by the baseline{_e(until)}: {_e(baseline.get("reason", ""))}</p>')
    if link:
        lines.append(f'<p class="fix">How to fix: <a href="{link}">the rule page</a></p>')
    return [*lines, "</article>"]


def _notices(report: Report) -> list[str]:
    parts: list[str] = []
    groups = (("Notices", report.notices, "notices"), ("Errors: the scan is incomplete", report.errors, "errors"))
    for title, entries, css in groups:
        if not entries:
            continue
        parts += [f"<h2>{_e(title)}</h2>", f'<ul class="{css}">']
        for entry in entries:
            where = f" <code>{_e(entry.path)}</code>" if entry.path else ""
            detail = f" (<code>{_e(entry.detail)}</code>)" if entry.detail else ""
            parts.append(f"<li><code>{_e(entry.code)}</code>{where}: {_e(entry.message)}{detail}</li>")
        parts.append("</ul>")
    return parts


def _findings(report: Report) -> list[str]:
    parts = ["<h2>Findings</h2>"]
    if not report.findings:
        if report.errors:
            return [*parts, "<p>No findings in what was read; the scan is incomplete (see the errors above).</p>"]
        return [*parts, "<p>No findings.</p>"]
    by_item: dict[str, list[ReportFinding]] = {}
    for row in report.findings:
        by_item.setdefault(row.item, []).append(row)
    number = 0
    for item in sorted(by_item):
        parts += ['<section class="item">', f"<h3>{_e(item)}</h3>"]
        for row in by_item[item]:
            number += 1
            parts += _finding(report, row, number)
        parts.append("</section>")
    return parts


def _clients(report: Report) -> list[str]:
    if report.clients is None:
        return []
    return ["<h2>Clients</h2>", "<ul>", *(f"<li>{_e(line)}</li>" for line in client_lines(report)), "</ul>"]


def _items(report: Report) -> list[str]:
    if not report.items:
        return []
    return ["<h2>Items scanned</h2>", "<table>", "<tr><th>Kind</th><th>Path</th><th>Name</th></tr>",
            *(f"<tr><td>{_e(item.kind)}</td><td><code>{_e(item.path)}</code></td><td>{_e(item.name)}</td></tr>"
              for item in report.items), "</table>"]


def _probes(report: Report) -> list[str]:
    if not report.probes:
        return []
    parts = ["<h2>MCP servers probed</h2>", "<table>",
             "<tr><th>Server</th><th>Result</th><th>Transport</th><th>Auth</th><th>Spec version</th><th>Migration</th></tr>"]
    for probe in report.probes:
        result = probe.result
        outcome = "probed" if probe.status == "probed" else f"skipped ({probe.skip_reason})"
        cells = ([result.transport, result.auth_mode, result.spec_version or "-", result.migration_status]
                 if result is not None else ["-", "-", "-", "-"])
        parts.append(f"<tr><td><code>{_e(probe.item)}</code></td><td>{_e(outcome)}</td>"
                     + "".join(f"<td>{_e(cell)}</td>" for cell in cells) + "</tr>")
    return [*parts, "</table>"]


def _agents(report: Report) -> list[str]:
    if not report.agents:
        return []
    parts = ["<h2>A2A agent cards</h2>", "<ul>"]
    for view in agent_view.views(report):
        signature = f"; {_e(view.signature)}" if view.signature is not None else ""
        unsigned = f"<br>verified without these members: {_e(', '.join(view.unsigned))}" if view.unsigned else ""
        steps = "".join(f"<br>{_e(step)}" for step in view.checklist)
        parts.append(f"<li><code>{_e(view.item)}</code> ({_e(view.origin)}): {_e(view.summary)}"
                     f"{signature}{unsigned}{steps}</li>")
    parts.append("</ul>")
    if agent_view.remote_note_applies(report):
        parts.append(f"<p>{_e(agent_view.REMOTE_NOTE)}</p>")
    return parts


def _lock(report: Report) -> list[str]:
    state = report.lock
    if state.status not in ("stale", "absent"):
        return []
    parts = [f"<h2>Lock file: {_e(state.status)}</h2>"]
    changes = [(label, change) for label, group in (("added", state.added), ("removed", state.removed),
                                                    ("changed", state.changed)) for change in group]
    if changes:
        parts += ["<ul>", *(f"<li>{label} {_e(change['kind'])} <code>{_e(change['path'])}</code></li>"
                            for label, change in changes), "</ul>"]
    else:
        parts.append("<p><code>.spellwarden/lock.json</code> is missing. Run <code>spellwarden lock</code> and commit the "
                     "file.</p>")
    return parts


def _lint(report: Report) -> list[str]:
    entries = [entry for entry in report.lint or () if entry.notes or entry.left_out]
    if not entries:
        return []
    parts = ["<h2>Description lint (informational, never changes the exit code)</h2>", "<table>",
             "<tr><th>Skill</th><th>Check</th><th>Note</th></tr>"]
    for entry in entries:
        for note in entry.notes:
            other = f" (with {note.other_path})" if note.other_path is not None else ""
            parts.append(f"<tr><td><code>{_e(entry.skill)}</code></td><td>{_e(note.id)}</td>"
                         f"<td>{_e(note.message + other)}</td></tr>")
    parts.append("</table>")
    left_out = sum(entry.left_out for entry in entries)
    if left_out:
        parts.append(f"<p>{left_out} more notes were not kept.</p>")
    return parts


def _analysis(report: Report) -> list[str]:
    if report.analysis is None:
        return []
    parts = ["<h2>Model-assisted analysis (advisory, its verdicts never change the exit code)</h2>"]
    for entry in report.analysis:
        if entry["status"] != "analyzed":
            parts.append(f"<p><code>{_e(entry['skill'])}</code>: {_e(entry['status'])} ({_e(not_done_why(entry))})</p>")
            continue
        cached = ", cached" if entry["cached"] else ""
        parts.append(f"<p><code>{_e(entry['skill'])}</code>: analysed by {_e(entry['model'])}{cached}</p>")
        issues = [category for category in entry["categories"] if category["verdict"] == "issue"]
        if not issues:
            parts.append("<p>No issue found by the model (advisory).</p>")
            continue
        parts.append("<ul>")
        for category in issues:
            spans = "".join(f"<br><code>{_e(span['path'])}:{_e(span['line'])}</code> {_e(span['text'])}"
                            for span in category["spans"])
            more = f"<br>{category['spans_left_out']} more spans were not kept" if category["spans_left_out"] else ""
            parts.append(f"<li>{_e(category['id'])} ({_e(category['confidence'])}): {_e(category['summary'])}{spans}{more}</li>")
        parts.append("</ul>")
    return parts


def render(report: Report) -> str:
    open_findings = report.unsuppressed()
    counts = Counter(row.finding.severity for row in open_findings)
    outcome, verdict = _verdict(report)
    parts = ["<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
             f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">', f"<title>{_e(TITLE)}</title>",
             f"<style>{STYLE}</style>", "</head>", "<body>", "<main>", f"<h1>{_e(TITLE)}</h1>",
             f'<p class="meta">Spellwarden {_e(report.scanner_version)}, rules {_e(report.rules_version)}, '
             f"as of {_e(report.as_of)}</p>"]
    notice = presets.notice_of(report)
    if notice is not None:
        parts.append(f'<p class="preset">{_e(notice.message)}</p>')
    parts.append(f'<p class="outcome outcome-{outcome}">{_e(verdict)}</p>')
    parts += ['<table class="counts">', "<tr><th>Severity</th><th>Open findings</th></tr>",
              *(f"<tr><td>{severity}</td><td>{counts[severity]}</td></tr>" for severity in SEVERITIES),
              f"<tr><td>accepted</td><td>{len(report.findings) - len(open_findings)}</td></tr>", "</table>"]
    parts += _notices(report) + _clients(report) + _findings(report) + _items(report) + _probes(report) + _agents(report)
    parts += _lock(report) + _lint(report) + _analysis(report)
    parts += ["</main>", "</body>", "</html>"]
    return escape.log_lines("\n".join(parts) + "\n")
