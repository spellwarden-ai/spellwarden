"""GitLab Code Quality (spec 6.9): one issue per unsuppressed finding, with the engine's fingerprint, the GitLab
severity, and the repository-relative path GitLab resolves. Descriptions follow the terminal escaping of 6.13."""
from __future__ import annotations

import json

from spellwarden_cli import escape
from spellwarden_cli.output.upload import upload_path
from spellwarden_cli.report import Report

SEVERITY = {"critical": "critical", "high": "major", "medium": "minor", "low": "info"}


def render(report: Report) -> str:
    issues = []
    for item in report.unsuppressed():
        finding = item.finding
        text = f"{finding.title}: {finding.evidence}" if finding.evidence else finding.title
        issues.append({
            "description": escape.codequality(text),
            "check_name": finding.rule_id,
            "fingerprint": finding.fingerprint,
            "severity": SEVERITY[finding.severity],
            "location": {"path": upload_path(report, finding.location.path), "lines": {"begin": finding.location.line or 1}},
        })
    return json.dumps(issues, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
