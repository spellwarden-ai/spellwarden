"""The terminal report (spec 6.9): one block per item with findings, then the
lock changes, the probes, the notices, the errors and a summary line. Every
string from the scanned revision is escaped with `escape.terminal`."""
from __future__ import annotations

from spellwarden_cli.escape import terminal
from spellwarden_cli.report import Report

_VERDICT = {0: "passed", 2: "incomplete: see the errors above"}


def _summary(report: Report) -> str:
    counts = {severity: 0 for severity in ("critical", "high", "medium", "low")}
    for rf in report.unsuppressed():
        counts[rf.finding.severity] += 1
    accepted = len(report.findings) - len(report.unsuppressed())
    code = report.exit_code()
    if code == 1:
        verdict = f"failed at {report.fail_on}"
    elif code == 3:
        verdict = f"lock file {report.lock.status}"
    else:
        verdict = _VERDICT[code]
    return (f"{sum(counts.values())} findings ({counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low), {accepted} accepted; {verdict}")


def render(report: Report) -> str:
    lines: list[str] = []
    by_item: dict[str, list] = {}
    for rf in report.findings:
        by_item.setdefault(rf.item, []).append(rf)
    for item in sorted(by_item):
        lines.append(terminal(item))
        for rf in by_item[item]:
            f = rf.finding
            line = "-" if f.location.line is None else str(f.location.line)
            accepted = f" (accepted: {terminal(rf.baseline['reason'])})" if rf.suppressed and rf.baseline else ""
            lines.append(f"  {f.severity} {f.rule_id} {terminal(f.location.path)}:{line} {terminal(f.title)}{accepted}")
        lines.append("")
    if report.lock.status in ("stale", "absent"):
        lines.append(f"lock: {report.lock.status}")
        for label, changes in (("added", report.lock.added), ("removed", report.lock.removed),
                               ("changed", report.lock.changed)):
            for change in changes:
                lines.append(f"  {label} {terminal(change['kind'])} {terminal(change['path'])}")
        lines.append("")
    for probe in report.probes:
        detail = probe.skip_reason if probe.status == "skipped" else (
            probe.result.migration_status if probe.result is not None else "")
        lines.append(f"probe {terminal(probe.item)}: {probe.status} {terminal(detail or '')}".rstrip())
    for notice in report.notices:
        lines.append(f"notice {notice.code} {terminal(notice.path)}: {terminal(notice.message)}")
    for error in report.errors:
        lines.append(f"error {error.code} {terminal(error.path)}: {terminal(error.message)}")
    lines.append(_summary(report))
    return "\n".join(lines) + "\n"
