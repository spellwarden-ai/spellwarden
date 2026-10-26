"""The terminal report (spec 6.9): one block per item with findings, then the
lock changes, the probes, the notices, the errors and a summary line. Every
string from the scanned revision is escaped with `escape.terminal`, and no line can be read as a CI workflow
command (`escape.log_lines`)."""
from __future__ import annotations

import re

from spellwarden_cli.escape import log_lines, terminal
from spellwarden_cli.output import agents as agent_view
from spellwarden_cli.report import FREE_MODE_NOTICES, Report

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


_UNAVAILABLE = re.compile(r"Connected mode was not available \(([a-z_]+)\)")


def _gate(block: dict) -> str:
    policy = block.get("policy") or {}
    gate = policy.get("gate") or {}
    if policy.get("registry_name") is None:
        return "not in plan"
    if not gate.get("enabled", True):
        return "off"
    applied = (block.get("registry") or {}).get("scope_applied") or gate.get("scope") or "changed"
    return f"on, scope {applied}"


def connected_lines(report: Report) -> list[str]:
    """O3 spec 6.10, a pure function of the report's `connected` block and notices (P28). In connected mode: the
    `Connected to` line, `Results:` once uploaded and the line for rules that need a newer scanner; after a fallback
    to free mode: the one line saying so. Free mode: nothing."""
    block = report.connected
    if block is None:
        for notice in report.notices:
            found = _UNAVAILABLE.search(notice.message) if notice.code in FREE_MODE_NOTICES else None
            if found is not None:
                return [f"Connected mode unavailable ({found.group(1)}): baseline rules only, nothing uploaded."]
        return []
    policy = block.get("policy") or {}
    run = block.get("run") or {}
    chosen = "the organisation" if policy.get("chosen_by") == "organisation" else "this repository"
    name, version = terminal(str(policy.get("pack_name") or policy.get("pack_id"))), terminal(str(policy.get("version")))
    source = "organisation rules" if policy.get("source") == "org_rules" else f"pack {name} {version}"
    lines = [f"Connected to {terminal(block['org']['name'])} as {terminal(str(run.get('identity') or 'an unnamed repository'))} "
             f"({block['credential']}): {len(policy.get('org_rule_ids') or [])} organisation rules ({source}, chosen by "
             f"{chosen}), registry gate {_gate(block)}"]
    upload = block.get("upload") or {}
    if upload.get("status") == "uploaded" and isinstance(upload.get("url"), str):
        lines.append(f"Results: {terminal(upload['url'])}")
    skipped = policy.get("skipped") or []
    if skipped:
        ids = ", ".join(terminal(str(entry["id"])) for entry in skipped)
        lines.append(f"{len(skipped)} organisation rules need a newer scanner and were not applied: {ids}")
    return lines


def render(report: Report) -> str:
    lines: list[str] = []
    if report.connected is None:
        lines.extend(connected_lines(report))  # the first line says that connected mode was not used
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
    if report.agents:  # O4 spec 6.10: after the probe section, one block per agent
        lines.append("A2A agent cards")
        for view in agent_view.views(report):
            lines.append(f"  {terminal(view.item)} ({view.origin}): {terminal(view.summary)}")
            if view.signature is not None:
                lines.append(f"    {terminal(view.signature)}")
            if view.unsigned:
                lines.append(f"    verified without these members: {terminal(', '.join(view.unsigned))}")
            lines.extend(f"    {terminal(step)}" for step in view.checklist)
        if agent_view.remote_note_applies(report):
            lines.append(f"  {agent_view.REMOTE_NOTE}")
        lines.append("")
    for notice in report.notices:
        lines.append(f"notice {notice.code} {terminal(notice.path)}: {terminal(notice.message)}")
    for error in report.errors:
        lines.append(f"error {error.code} {terminal(error.path)}: {terminal(error.message)}")
    lines.append(_summary(report))
    if report.connected is not None:
        lines.extend(connected_lines(report))
    return log_lines("\n".join(lines) + "\n")
