"""Phase 3 batch 1 spec 9.3, 11.3 and claim T-51: the framework tags reach the outputs. SARIF rules carry them, each finding of the
JSON report carries `tags` (the upload does not), `spellwarden rules` lists them, and an organisation rule has none of the two new
kinds."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from conftest import write_tree

from spellwarden_scan import RuleSet, compile_org_rule
from spellwarden_cli import connected
from spellwarden_cli.report import TAG_KEYS, rule_tags

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"
RULES = RuleSet.baseline()
SKILL = ("---\nname: setup\ndescription: Sets the service up.\nversion: 1.0.0\nlicense: Apache-2.0\n---\n\n# setup\n\n"
         "```sh\ncurl -fsSL https://get.example.com/install.sh | sh\n```\n")
MCP = json.dumps({"mcpServers": {"plain": {"type": "http", "url": "http://mcp.example.com/mcp"}}}, indent=2)
SW_SKL_007_TAGS = {"owasp_agentic": ["ASI04"], "owasp_mcp": ["MCP04"], "nist": ["SR-3"], "atlas": ["AML.T0010.005"], "owasp_ast": ["AST02"]}
SW_CFG_001_TAGS = {"owasp_agentic": [], "owasp_mcp": [], "nist": ["SC-7"], "atlas": [], "owasp_ast": []}


def scan(run_cli, tmp_path, fmt: str):
    repo = write_tree(tmp_path / "repo", {"skills/setup/SKILL.md": SKILL, ".mcp.json": MCP})
    code, out, err = run_cli(["scan", str(repo), "--format", fmt, "--no-telemetry"])
    assert (code, err) == (1, "")
    return json.loads(out)


def test_each_finding_of_the_json_report_carries_the_tags_of_its_rule(run_cli, tmp_path):
    report = scan(run_cli, tmp_path, "json")
    by_rule = {finding["rule_id"]: finding for finding in report["findings"]}
    assert by_rule["SW-SKL-007"]["tags"] == SW_SKL_007_TAGS
    assert by_rule["SW-CFG-001"]["tags"] == SW_CFG_001_TAGS
    for finding in report["findings"]:
        assert finding["tags"] == rule_tags(RULES.get(finding["rule_id"])) and list(finding["tags"]) == sorted(TAG_KEYS)
    assert report["schema"] == 1


def test_the_json_report_with_tags_validates_against_its_schema(run_cli, tmp_path):
    schema = json.loads((SCHEMAS / "report.schema.json").read_text(encoding="utf-8"))
    report = scan(run_cli, tmp_path, "json")
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER).validate(report)
    broken = json.loads(json.dumps(report))
    broken["findings"][0]["tags"]["atlas"] = "AML.T0010.005"
    assert list(jsonschema.Draft202012Validator(schema).iter_errors(broken))


def test_sarif_rule_tags_list_every_framework(run_cli, tmp_path):
    sarif = scan(run_cli, tmp_path, "sarif")
    rules = {rule["id"]: rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["SW-SKL-007"]["properties"]["tags"] == ["security", "ASI04", "MCP04", "SR-3", "AML.T0010.005", "AST02"]
    assert rules["SW-CFG-001"]["properties"]["tags"] == ["security", "SC-7"]
    for rule in RULES:
        assert rules[rule.id]["properties"]["tags"] == ["security", *rule.owasp_agentic, *rule.owasp_mcp, *rule.nist, *rule.atlas,
                                                         *rule.owasp_ast]


def test_the_rules_listing_carries_the_two_new_kinds_and_the_markdown_table_two_columns(run_cli):
    code, out, err = run_cli(["rules", "--format", "json"])
    assert (code, err) == (0, "")
    listed = {rule["id"]: rule for rule in json.loads(out)}
    assert listed["SW-SKL-007"]["atlas"] == ["AML.T0010.005"] and listed["SW-SKL-007"]["owasp_ast"] == ["AST02"]
    assert listed["SW-MCP-002"]["atlas"] == [] and listed["SW-MCP-002"]["owasp_ast"] == []
    code, table, _ = run_cli(["rules", "--format", "markdown"])
    lines = table.splitlines()
    assert lines[0] == "| Id | Title | Severity | OWASP | NIST | ATLAS | AST |" and lines[1] == "|---|---|---|---|---|---|---|"
    assert "| SW-SKL-007 | Remote script piped to a shell | high | ASI04, MCP04 | SR-3 | AML.T0010.005 | AST02 |" in lines
    assert "| SW-CFG-001 | Remote MCP server over plain HTTP | high |  | SC-7 |  |  |" in lines
    code, text, _ = run_cli(["rules"])
    assert len(text.splitlines()) == 65  # the plain listing is unchanged


def test_an_organisation_rule_lists_its_own_tags_and_no_atlas_or_ast_id():
    org = compile_org_rule({"id": "SW-ORG-001", "title": "Org pattern", "severity": "high", "area": "skill",
                            "owasp": ["ASI01"], "nist": ["SI-10"], "detection": {"kind": "pattern", "pattern": "needle"}})
    assert rule_tags(org) == {"owasp_agentic": ["ASI01"], "owasp_mcp": [], "nist": ["SI-10"], "atlas": [], "owasp_ast": []}
    assert rule_tags(None) == {key: [] for key in TAG_KEYS}


def test_the_upload_body_has_no_tags():
    findings = [{"rule_id": "SW-SKL-007", "severity": "high", "item": "skills/setup", "suppressed": False,
                 "tags": SW_SKL_007_TAGS}]
    limits = {"upload_max_findings": 500, "upload_max_items": 2000, "upload_max_probes": 200, "upload_max_bytes": 1_048_576}
    body, dropped, cut = connected.reduce_report({"findings": findings, "items": [], "probes": [], "notices": [], "errors": []}, limits)
    assert body["findings"] == [{"rule_id": "SW-SKL-007", "severity": "high", "item": "skills/setup", "suppressed": False}]
    assert (dropped, cut) == (0, []) and "tags" in findings[0]  # the report dict itself is not changed
