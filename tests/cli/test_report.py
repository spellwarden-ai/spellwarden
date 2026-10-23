"""Spec 6.2 and 6.12, claim C10: the exit code precedence 2 > 1 > 3 and the
total orders of spec 6.9, on `Report` values built directly."""
from __future__ import annotations

import itertools
from dataclasses import replace

import pytest

from spellwarden_scan import RULES_VERSION, Finding, Location, RuleSet, __version__
from spellwarden_cli.discover import Item
from spellwarden_cli.report import LockState, Notice, ProbeReport, Report, ReportFinding, to_json_dict


def _finding(rule_id="SW-SKL-007", severity="high", path="a/run.sh", line=1, fingerprint="f" * 64):
    return Finding(rule_id, severity, "title", Location(path, line), "evidence", fingerprint)


def _report(*, errors=(), findings=(), lock=None, fail_on="high", notices=(), items=(), probes=()):
    return Report(scanner_version=__version__, rules_version=RULES_VERSION, as_of="2026-12-01", fail_on=fail_on,
                  items=tuple(items), findings=tuple(findings), probes=tuple(probes), lock=lock or LockState(), notices=tuple(notices),
                  errors=tuple(errors), repo_prefix="", rules=RuleSet.baseline())


ERROR = Notice("not_json", ".mcp.json", "broken")
FAILING = ReportFinding(_finding(), "a")
STALE = LockState("stale", added=({"kind": "skill", "path": "a"},))


@pytest.mark.parametrize("error, failing, stale, expected", [
    (e, f, s, 2 if e else 1 if f else 3 if s else 0) for e, f, s in itertools.product((False, True), repeat=3)])
def test_exit_code_precedence(error, failing, stale, expected):
    report = _report(errors=[ERROR] if error else [], findings=[FAILING] if failing else [],
                     lock=STALE if stale else LockState())
    assert report.exit_code() == expected


def test_absent_lock_is_three_and_not_checked_is_zero():
    assert _report(lock=LockState("absent")).exit_code() == 3
    assert _report(lock=LockState("ok")).exit_code() == 0
    assert _report(lock=LockState()).exit_code() == 0


@pytest.mark.parametrize("fail_on, severity, expected", [
    ("high", "critical", 1), ("high", "high", 1), ("high", "medium", 0), ("medium", "medium", 1), ("low", "low", 1),
    ("critical", "high", 0), ("never", "critical", 0)])
def test_fail_on_threshold(fail_on, severity, expected):
    assert _report(findings=[ReportFinding(_finding(severity=severity), "a")], fail_on=fail_on).exit_code() == expected


def test_suppressed_findings_do_not_fail():
    accepted = ReportFinding(_finding(severity="critical"), "a", suppressed=True,
                             baseline={"reason": "r", "added": "2026-11-01", "expires": "2026-12-31"})
    assert _report(findings=[accepted]).exit_code() == 0


def test_sorted_applies_every_total_order():
    findings = [ReportFinding(_finding("SW-SKL-009", "medium", "b", 2), "b"), ReportFinding(_finding("SW-SKL-004", "critical", "z", 9), "z"),
                ReportFinding(_finding("SW-SKL-009", "medium", "b", None), "b"), ReportFinding(_finding("SW-SKL-007", "high", "a", 3), "a")]
    report = _report(findings=findings, items=[Item("skill", "z", "z"), Item("mcp-config", ".mcp.json", ".mcp.json")],
                     notices=[Notice("b", "x", "m"), Notice("a", "y", "m")], errors=[Notice("unreadable", "b", "m"), Notice("crash", "", "m")],
                     probes=[ProbeReport("y", "skipped", "limit", None), ProbeReport("x", "skipped", "budget", None)],
                     lock=LockState("stale", changed=({"kind": "skill", "path": "b"}, {"kind": "document", "path": "z"})))
    ordered = report.sorted()
    assert [(rf.finding.rule_id, rf.finding.location.line) for rf in ordered.findings] == [
        ("SW-SKL-004", 9), ("SW-SKL-007", 3), ("SW-SKL-009", None), ("SW-SKL-009", 2)]
    assert [i.kind for i in ordered.items] == ["mcp-config", "skill"]
    assert [n.code for n in ordered.notices] == ["a", "b"]
    assert [e.code for e in ordered.errors] == ["crash", "unreadable"]
    assert [p.item for p in ordered.probes] == ["x", "y"]
    assert [c["kind"] for c in ordered.lock.changed] == ["document", "skill"]


def test_json_dict_shape():
    document = to_json_dict(_report(findings=[FAILING], items=[Item("skill", "a", "a")]))
    assert sorted(document) == ["as_of", "errors", "exit_code", "fail_on", "findings", "items", "lock", "notices", "probes",
                                "rules_version", "scanner_version", "schema"]
    assert document["findings"][0]["item"] == "a" and document["findings"][0]["suppressed"] is False
    assert document["findings"][0]["baseline"] is None
    assert document["lock"] == {"status": "not_checked", "added": [], "removed": [], "changed": []}
    assert document["items"] == [{"kind": "skill", "path": "a", "name": "a", "plugin": None}]


# --- O3 spec 6.9 ---------------------------------------------------------------------------------------------------

TODAYS_NOTICE_CODES = (
    "no_agent_content", "git_unavailable", "exec_bits_unknown", "symlink_skipped", "file_too_large", "non_utf8_path",
    "upload_paths_scan_root", "findings_truncated", "baseline_mismatch", "baseline_expired", "probe_private_untrusted",
    "probe_fork_disabled", "probe_skipped", "comment_permission", "comment_failed", "comment_token_missing",
    "comment_no_request", "ping_url_ignored", "file_missing", "reference_not_config", "settings_from_base",
    "base_unavailable", "skill_name_case")
TODAYS_ERROR_CODES = (
    "too_large", "not_utf8", "not_json", "duplicate_key", "too_deep", "not_an_object", "truncated", "unsafe_path",
    "case_collision", "unreadable", "package_too_large", "path_not_directory", "settings_invalid", "baseline_invalid",
    "lock_unreadable", "invalid_input", "crash")


def test_notice_and_error_codes_are_todays_plus_the_closed_lists_of_spec_6_9():
    from spellwarden_cli.report import ERROR_CODES, NOTICE_CODES

    assert NOTICE_CODES == TODAYS_NOTICE_CODES + (
        "connected", "connected_fallback", "dependabot_free_mode", "fork_free_mode", "api_url_override",
        "reg_baseline_from_base", "gate_scope_all", "org_rules_skipped", "plugin_marketplace_unknown", "uploaded",
        "upload_failed", "upload_skipped", "upload_ci_only", "upload_disabled", "registry_gate_off",
        "mcp_rules_need_probe", "policy_newer_than_scanner")
    assert ERROR_CODES == TODAYS_ERROR_CODES + (
        "connected_config", "connected_key_invalid", "connected_no_credential", "connected_auth", "connected_subscription",
        "connected_ci_key_required", "connected_forbidden", "connected_rate_limited", "connected_unavailable",
        "connected_required", "policy_not_found", "policy_invalid", "org_rules_incomplete", "registry_check_failed",
        "registry_check_too_large")
    assert len(set(NOTICE_CODES)) == len(NOTICE_CODES) and len(set(ERROR_CODES)) == len(ERROR_CODES)


def test_report_connected_is_absent_unless_set():
    assert "connected" not in to_json_dict(_report())
    assert _report().connected is None
    block = {"credential": "key", "org": {"slug": "acme", "name": "Acme"}}
    assert to_json_dict(replace(_report(), connected=block))["connected"] == block
    assert replace(_report(), connected=block).sorted().connected == block
