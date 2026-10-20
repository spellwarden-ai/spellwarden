"""Spec 6.2 and 6.12, claim C10: the exit code precedence 2 > 1 > 3 and the
total orders of spec 6.9, on `Report` values built directly."""
from __future__ import annotations

import itertools

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
