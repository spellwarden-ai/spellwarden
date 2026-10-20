"""The report of one scan (spec 6.12) and the closed enumerations every
output and schema shares (spec 6.14). Task 6 holds the notices; Task 7 adds
`Report`."""
from __future__ import annotations

from dataclasses import dataclass

from spellwarden_scan.agentconfig import DOCUMENT_ERRORS

ITEM_KINDS = ("skill", "marketplace", "plugin", "mcp-config", "mcp-server", "settings", "hooks", "plugin-manifest")
ERROR_CODES = (*DOCUMENT_ERRORS, "unsafe_path", "case_collision", "unreadable", "package_too_large", "path_not_directory",
               "settings_invalid", "baseline_invalid", "lock_unreadable", "invalid_input", "crash")
NOTICE_CODES = ("no_agent_content", "git_unavailable", "exec_bits_unknown", "symlink_skipped", "file_too_large",
                "non_utf8_path", "upload_paths_scan_root", "findings_truncated", "baseline_mismatch", "baseline_expired",
                "probe_private_untrusted", "probe_fork_disabled", "probe_skipped", "comment_permission", "comment_failed",
                "comment_token_missing", "comment_no_request", "ping_url_ignored", "file_missing", "reference_not_config")
PROBE_SKIP_REASONS = ("unresolved", "limit", "budget", "fork", "refused")
LOCK_STATUSES = ("ok", "stale", "absent", "not_checked")


@dataclass(frozen=True)
class Notice:
    """A notice (informational) or an error (exit 2): `code` from the lists above, `path` scan-root-relative
    ("" when the notice concerns the whole scan), `message` plain text, escaped by each output."""
    code: str
    path: str
    message: str

    def to_dict(self) -> dict:
        return {"code": self.code, "path": self.path, "message": self.message}
