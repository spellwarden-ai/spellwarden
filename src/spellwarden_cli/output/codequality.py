"""GitLab Code Quality (spec 6.9): one issue per unsuppressed finding, with the engine's fingerprint, the GitLab
severity, and the repository-relative path GitLab resolves. Descriptions follow the terminal escaping of 6.13. With a preset
other than balanced (1.18.0) the first issue's description gains the preset's notice as a second line, and a finding the preset
moved says how; when no finding is left, one informational issue on an empty path carries the notice."""
from __future__ import annotations

import hashlib
import json

from spellwarden_cli import escape, presets
from spellwarden_cli.output.upload import upload_path
from spellwarden_cli.report import Report

SEVERITY = {"critical": "critical", "high": "major", "medium": "minor", "low": "info"}
PRESET_CHECK = "spellwarden-preset"


def render(report: Report) -> str:
    issues = []
    for item in report.unsuppressed():
        finding = item.finding
        text = f"{finding.title}: {finding.evidence}" if finding.evidence else finding.title
        description = escape.codequality(text)
        if item.preset_from is not None and report.preset is not None:
            description += f" ({presets.change_words(item.preset_from, finding.severity, report.preset['name'])})"
        issues.append({
            "description": description,
            "check_name": finding.rule_id,
            "fingerprint": finding.fingerprint,
            "severity": SEVERITY[finding.severity],
            "location": {"path": upload_path(report, finding.location.path), "lines": {"begin": finding.location.line or 1}},
        })
    notice = presets.notice_of(report)
    if notice is not None and report.preset is not None:
        if issues:
            issues[0]["description"] += "\n" + escape.codequality(notice.message)
        else:
            issues.append({"description": escape.codequality(notice.message), "check_name": PRESET_CHECK,
                           "fingerprint": hashlib.sha256(f"{PRESET_CHECK}\n{report.preset['name']}".encode()).hexdigest(),
                           "severity": "info", "location": {"path": "", "lines": {"begin": 1}}})
    return json.dumps(issues, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
