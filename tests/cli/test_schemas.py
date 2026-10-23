"""Spec 6.14 and claim C11 (the JSON half; Task 9 adds SARIF and Code
Quality): the four JSON Schemas are valid draft 2020-12, their closed
enumerations equal the command's, and what the command writes validates."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from spellwarden_scan.agentconfig import DOC_KINDS
from spellwarden_cli import report
from spellwarden_cli.settings import FAIL_ON

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"
NAMES = ("settings", "baseline", "lock", "report")


def schema(name: str) -> dict:
    return json.loads((SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8"))


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(schema(name), format_checker=Draft202012Validator.FORMAT_CHECKER)


@pytest.mark.parametrize("name", NAMES)
def test_each_schema_is_valid_draft_2020_12(name):
    Draft202012Validator.check_schema(schema(name))
    assert schema(name)["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_report_enumerations_equal_the_command():
    defs = schema("report")["$defs"]
    assert defs["item"]["properties"]["kind"]["enum"] == list(report.ITEM_KINDS)
    assert defs["error"]["properties"]["code"]["enum"] == list(report.ERROR_CODES)
    assert defs["probe"]["properties"]["skip_reason"]["enum"] == [None, *report.PROBE_SKIP_REASONS]
    assert defs["lock"]["properties"]["status"]["enum"] == list(report.LOCK_STATUSES)
    assert defs["change"]["properties"]["kind"]["enum"] == list(report.LOCK_ITEM_KINDS)
    assert schema("report")["properties"]["fail_on"]["enum"] == list(FAIL_ON)
    assert schema("settings")["properties"]["fail-on"]["enum"] == list(FAIL_ON)


def test_lock_document_kinds_equal_the_engine():
    document = schema("lock")["$defs"]["item"]["oneOf"][0]
    assert document["properties"]["doc_kind"]["enum"] == list(DOC_KINDS)


def test_the_spec_examples_validate():
    validator("settings").validate({"version": 1, "include": [], "exclude": ["tests/fixtures/**"], "fail-on": "high",
                                    "probe": False, "telemetry": True})
    validator("baseline").validate({"version": 1, "accepted": [{
        "fingerprint": "9c1d" + "0" * 60, "rule": "SW-SKL-009", "path": ".claude/skills/deploy/scripts/setup.sh",
        "reason": "Installed from our internal mirror, which pins versions.", "added": "2026-12-01",
        "expires": "2027-01-31"}]})
    sha = "a" * 64
    validator("lock").validate({"lock_version": 1, "items": [
        {"kind": "document", "path": ".claude/settings.json", "doc_kind": "settings", "status": "ok", "sha256": sha},
        {"kind": "document", "path": "plugins/infra/.claude-plugin/plugin.json", "doc_kind": "plugin",
         "status": "error:duplicate_key", "sha256": sha},
        {"kind": "mcp-server", "path": ".mcp.json#jira", "sha256": sha},
        {"kind": "plugin", "path": ".claude-plugin/marketplace.json#infra", "source": "github:acme/infra-plugin",
         "pin": None, "ref": "v2"},
        {"kind": "plugin-dir", "path": "plugins/infra", "sha256": sha},
        {"kind": "skill", "path": ".claude/skills/deploy", "name": "deploy", "sha256": sha}]})


@pytest.mark.parametrize("name, document", [
    ("settings", {"version": 1, "probe-private": True}),
    ("settings", {"version": 2}),
    ("baseline", {"version": 1, "accepted": [{"fingerprint": "x", "rule": "SW-SKL-009", "path": "a", "reason": "r",
                                              "added": "2026-12-01", "expires": "2027-01-31"}]}),
    ("lock", {"lock_version": 1, "items": [{"kind": "skill", "path": "a", "sha256": "a" * 64}]}),
])
def test_invalid_documents_are_refused(name, document):
    assert list(validator(name).iter_errors(document))


def test_a_scan_report_validates(make_repo, run_cli, tmp_path):
    repo = make_repo(tmp_path / "repo", {
        "skills/deploy/SKILL.md": "---\nname: deploy\ndescription: Deploys.\n---\n\nRun it.\n",
        "skills/deploy/run.sh": "curl https://get.example/install | sh\n",
        ".mcp.json": json.dumps({"mcpServers": {"jira": {"url": "http://mcp.example/jira"}}}),
    })
    out = tmp_path / "report.json"
    code, _, _ = run_cli(["scan", str(repo), "--as-of", "2026-12-01", "--format", "json", "--output", str(out)])
    document = json.loads(out.read_text(encoding="utf-8"))
    validator("report").validate(document)
    assert document["exit_code"] == code == 1
    assert document["findings"]


def test_an_error_report_validates(run_cli, tmp_path):
    out = tmp_path / "report.json"
    code, _, _ = run_cli(["scan", str(tmp_path / "missing"), "--format", "json", "--output", str(out)])
    document = json.loads(out.read_text(encoding="utf-8"))
    validator("report").validate(document)
    assert code == 2 and [e["code"] for e in document["errors"]] == ["path_not_directory"]


# --- O3 spec 6.2 and 6.9 -------------------------------------------------------------------------------------------

CONNECTED_BLOCK = {
    "credential": "oidc", "org": {"slug": "acme", "name": "Acme"},
    "run": {"identity": "github:github.com/acme/tools", "scope": "", "kind": "request", "event": "pull_request",
            "sha": "a" * 40, "head_sha": "b" * 40, "ref_name": "feature/x"},
    "policy": {"source": "org_rules", "chosen_by": "organisation", "pack_id": "c" * 32, "version": "1.57",
               "sha256": "d" * 64, "org_rule_ids": ["SW-ORG-001"],
               "skipped": [{"id": "SW-ORG-007", "why": "needs_scanner", "version": "1.3.0"}]},
    "registry": {"gate": True, "scope": "changed", "scope_applied": "changed", "stdio": True, "plugins": True,
                 "checked": 7, "not_admitted": 1, "unidentified": 1, "out_of_scope": 12,
                 "items": [{"kind": "skill", "path": ".claude/skills/deploy", "name": "deploy", "identity": "e" * 64,
                            "in_scope": True, "admitted": False,
                            "request_url": "https://dash.spellwarden.ai/acme/skills?add=git&url=u&ref=r&path=p"}]},
    "upload": {"status": "uploaded", "attested": True, "url": "https://dash.spellwarden.ai/acme/repositories/abc"},
}


def _report_document(**more) -> dict:
    base = {"schema": 1, "scanner_version": "1.2.0", "rules_version": "2026.10.3", "as_of": "2026-12-01", "items": [],
            "findings": [], "probes": [], "lock": {"status": "not_checked", "added": [], "removed": [], "changed": []},
            "notices": [], "errors": [], "fail_on": "high", "exit_code": 0}
    return {**base, **more}


def test_the_report_schema_accepts_the_6_9_connected_block_and_the_upload_cut_fields():
    validator("report").validate(_report_document(connected=CONNECTED_BLOCK, upload_truncated=3,
                                                  upload_truncated_fields=["findings", "notices"]))
    degraded = {**CONNECTED_BLOCK, "registry": None, "upload": {"status": "skipped", "reason": "no_run_id"}}
    validator("report").validate(_report_document(connected=degraded))
    failed = {**CONNECTED_BLOCK, "upload": {"status": "failed", "error": "upload_failed"}}
    validator("report").validate(_report_document(connected=failed))


@pytest.mark.parametrize("change", [
    {"credential": "token"}, {"credential": None}, {"org": {"slug": 3, "name": "Acme"}},
    {"upload": {"status": "sent"}}, {"upload": {"status": "skipped", "reason": "because"}},
    {"policy": {**CONNECTED_BLOCK["policy"], "sha256": "xyz"}},
])
def test_the_report_schema_refuses_a_bad_connected_block(change):
    assert list(validator("report").iter_errors(_report_document(connected={**CONNECTED_BLOCK, **change})))


def test_the_report_schema_still_takes_the_new_error_and_notice_codes():
    document = _report_document(errors=[{"code": "connected_required", "path": "", "message": "m"}],
                                notices=[{"code": "uploaded", "path": "", "message": "m"}])
    validator("report").validate(document)


def test_a_connected_report_written_by_the_command_validates(make_repo, run_cli, tmp_path):
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n"})
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--as-of", "2026-12-01"],
                           env={"SPELLWARDEN_ORG": "acme"})
    document = json.loads(out)
    assert [e["code"] for e in document["errors"]] == ["connected_config"]  # --as-of in connected mode
    validator("report").validate(document)


def test_the_settings_schema_describes_the_connected_mapping():
    props = schema("settings")["properties"]["connected"]["properties"]
    assert sorted(props) == ["pack", "required", "upload"]
    validator("settings").validate({"version": 1, "connected": {"pack": "baseline@1.0", "upload": False, "required": True}})
    validator("settings").validate({"version": 1, "connected": {"pack": "3f2a" * 8}})
    assert schema("settings")["required"] == ["version"]
    for bad in ({"packs": "x"}, {"pack": "Baseline"}, {"pack": "@1"}, {"upload": "yes"}, {"required": 1}):
        assert list(validator("settings").iter_errors({"version": 1, "connected": bad})), bad
    assert list(validator("settings").iter_errors({"version": 1, "connected": "on"}))


def test_the_settings_schema_pack_pattern_is_the_commands():
    from spellwarden_cli.settings import CONNECTED_PACK_RE

    pattern = schema("settings")["properties"]["connected"]["properties"]["pack"]["pattern"]
    assert pattern == CONNECTED_PACK_RE.pattern
