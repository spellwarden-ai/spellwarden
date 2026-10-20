"""Spec 6.9 "Upload paths": GitHub code scanning and GitLab Code Quality resolve paths from the repository root,
so those two formats prefix scan-root paths with the scan root's repository prefix; outside a repository there is
no prefix and the report carries the notice `upload_paths_scan_root`."""
from __future__ import annotations

from spellwarden_cli.report import Report


def upload_path(report: Report, path: str) -> str:
    prefix = (report.repo_prefix or "").strip("/")
    return f"{prefix}/{path}" if prefix else path
