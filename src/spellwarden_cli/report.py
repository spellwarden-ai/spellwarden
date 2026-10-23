"""The report of one scan (spec 6.12) and the closed enumerations every
output and schema shares (spec 6.14). Every output module is a pure function
of a `Report`; `exit_code()` implements the precedence of spec 6.2."""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from spellwarden_scan import SEVERITY_RANK, Finding, McpScanResult, RuleSet
from spellwarden_scan.agentconfig import DOCUMENT_ERRORS

if TYPE_CHECKING:
    from spellwarden_cli.discover import Item

ITEM_KINDS = ("skill", "marketplace", "plugin", "mcp-config", "mcp-server", "settings", "hooks", "plugin-manifest")
ERROR_CODES = (*DOCUMENT_ERRORS, "unsafe_path", "case_collision", "unreadable", "package_too_large", "path_not_directory",
               "settings_invalid", "baseline_invalid", "lock_unreadable", "invalid_input", "crash",
               # O3 spec 6.9: connected mode
               "connected_config", "connected_key_invalid", "connected_no_credential", "connected_auth",
               "connected_subscription", "connected_ci_key_required", "connected_forbidden", "connected_rate_limited",
               "connected_unavailable", "connected_required", "policy_not_found", "policy_invalid", "org_rules_incomplete",
               "registry_check_failed", "registry_check_too_large")
NOTICE_CODES = ("no_agent_content", "git_unavailable", "exec_bits_unknown", "symlink_skipped", "file_too_large",
                "non_utf8_path", "upload_paths_scan_root", "findings_truncated", "baseline_mismatch", "baseline_expired",
                "probe_private_untrusted", "probe_fork_disabled", "probe_skipped", "comment_permission", "comment_failed",
                "comment_token_missing", "comment_no_request", "ping_url_ignored", "file_missing", "reference_not_config",
                "settings_from_base", "base_unavailable", "skill_name_case",
                # O3 spec 6.9: connected mode
                "connected", "connected_fallback", "dependabot_free_mode", "fork_free_mode", "api_url_override",
                "reg_baseline_from_base", "gate_scope_all", "org_rules_skipped", "plugin_marketplace_unknown", "uploaded",
                "upload_failed", "upload_skipped", "upload_ci_only", "upload_disabled", "registry_gate_off",
                "mcp_rules_need_probe", "policy_newer_than_scanner")
PROBE_SKIP_REASONS = ("unresolved", "limit", "budget", "fork", "refused")
LOCK_STATUSES = ("ok", "stale", "absent", "not_checked")
LOCK_ITEM_KINDS = ("document", "mcp-server", "plugin", "plugin-dir", "skill")


@dataclass(frozen=True)
class Notice:
    """A notice (informational) or an error (exit 2): `code` from the lists above, `path` scan-root-relative
    ("" when the notice concerns the whole scan), `message` plain text, escaped by each output."""
    code: str
    path: str
    message: str

    def to_dict(self) -> dict:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class LockState:
    status: str = "not_checked"
    added: tuple[dict, ...] = ()
    removed: tuple[dict, ...] = ()
    changed: tuple[dict, ...] = ()

    def to_dict(self) -> dict:
        return {"status": self.status, "added": list(self.added), "removed": list(self.removed),
                "changed": list(self.changed)}


@dataclass(frozen=True)
class ReportFinding:
    finding: Finding
    item: str
    suppressed: bool = False
    baseline: dict | None = None  # {"reason", "added", "expires"} when a baseline entry matched

    def to_dict(self) -> dict:
        return {**self.finding.to_dict(), "item": self.item, "suppressed": self.suppressed, "baseline": self.baseline}


@dataclass(frozen=True)
class ProbeReport:
    item: str
    status: str  # "probed" | "skipped"
    skip_reason: str | None
    result: McpScanResult | None

    def to_dict(self) -> dict:
        extra = self.result.to_dict() if self.result is not None else {}
        return {**extra, "item": self.item, "status": self.status, "skip_reason": self.skip_reason}


def finding_order(rf: ReportFinding) -> tuple:
    f = rf.finding
    return (SEVERITY_RANK[f.severity], f.rule_id, f.location.path, f.location.line or 0, f.fingerprint, rf.item)


def _notice_order(notice: Notice) -> tuple:
    return (notice.code, notice.path, notice.message)


def _change_order(change: dict) -> tuple:
    return (change["kind"], change["path"])


@dataclass(frozen=True)
class Report:
    scanner_version: str
    rules_version: str
    as_of: str
    fail_on: str
    items: tuple[Item, ...]
    findings: tuple[ReportFinding, ...]
    probes: tuple[ProbeReport, ...]
    lock: LockState
    notices: tuple[Notice, ...]
    errors: tuple[Notice, ...]
    repo_prefix: str | None
    rules: RuleSet
    # O3 spec 6.9: the connected block, present only when the session was established; serialised only when not None.
    connected: dict | None = None

    def unsuppressed(self) -> tuple[ReportFinding, ...]:
        return tuple(rf for rf in self.findings if not rf.suppressed)

    def exit_code(self) -> int:
        """Spec 6.2: 2 (incomplete) outranks 1 (failing findings), which outranks 3 (lock absent or stale)."""
        if self.errors:
            return 2
        if self.fail_on != "never":
            limit = SEVERITY_RANK[self.fail_on]
            if any(SEVERITY_RANK[rf.finding.severity] <= limit for rf in self.unsuppressed()):
                return 1
        if self.lock.status in ("stale", "absent"):
            return 3
        return 0

    def sorted(self) -> Report:
        """Every collection in the total order of spec 6.9, whatever order discovery or probes produced."""
        lock = replace(self.lock, added=tuple(sorted(self.lock.added, key=_change_order)),
                       removed=tuple(sorted(self.lock.removed, key=_change_order)),
                       changed=tuple(sorted(self.lock.changed, key=_change_order)))
        return replace(
            self, items=tuple(sorted(self.items, key=lambda item: (item.kind, item.path))),
            findings=tuple(sorted(self.findings, key=finding_order)),
            probes=tuple(sorted(self.probes, key=lambda probe: probe.item)), lock=lock,
            notices=tuple(sorted(self.notices, key=_notice_order)), errors=tuple(sorted(self.errors, key=_notice_order)))


def to_json_dict(report: Report) -> dict:
    """The JSON format of spec 6.9 (`schemas/report.schema.json`)."""
    document = {
        "schema": 1, "scanner_version": report.scanner_version, "rules_version": report.rules_version,
        "as_of": report.as_of, "items": [item.to_dict() for item in report.items],
        "findings": [rf.to_dict() for rf in report.findings], "probes": [probe.to_dict() for probe in report.probes],
        "lock": report.lock.to_dict(), "notices": [n.to_dict() for n in report.notices],
        "errors": [e.to_dict() for e in report.errors], "fail_on": report.fail_on, "exit_code": report.exit_code(),
    }
    if report.connected is not None:
        document["connected"] = report.connected
    return document
