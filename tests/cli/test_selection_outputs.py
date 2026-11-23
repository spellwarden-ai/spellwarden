"""Engine 1.20.0 (claim C34): the selection fixture's new items, and its SW-CFG-012 and SW-CFG-013 findings on the servers of
`.gemini/settings.json` and `.codex/config.toml`, appear in every output format."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("fixture_reports", ROOT / "tests" / "golden" / "fixture_reports.py")
reports = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reports)
FORMATS = {"claude-rule", "claude-md", "agents-md", "windsurf-rules", "github-instructions", "claude-command", "claude-agent",
           "claude-output-style", "cursor-agent", "codex-agent", "gemini-agent", "devin-agent", "github-agent"}
FINDINGS = {("SW-CFG-012", ".gemini/settings.json"), ("SW-CFG-012", ".codex/config.toml"), ("SW-CFG-013", ".codex/config.toml"),
            ("SW-SKL-036", ".claude/commands/deploy.md")}


@pytest.fixture(scope="module")
def outputs(tmp_path_factory):
    base = tmp_path_factory.mktemp("selection")
    code, written = reports.render(reports.build_repo("fixtures/selection", base / "repo"), base / "out",
                                   formats=reports.ALL_FORMATS)
    return code, {fmt: data.decode("utf-8") for fmt, data in written.items()}


def test_the_json_report_holds_every_new_kind_of_item_and_both_rules(outputs):
    code, text = outputs
    report = json.loads(text["json"])
    formats = {item["format"] for item in report["items"] if item["kind"] == "instructions"}
    assert FORMATS <= formats
    kinds = {(item["kind"], item["path"]) for item in report["items"]}
    assert {("settings", ".codex/config.toml"), ("plugin", ".codex/config.toml#plugins.review@tools"),
            ("marketplace", ".codex/config.toml#marketplaces.tools"), ("hooks", ".github/hooks/audit.json"),
            ("mcp-config", ".github/mcp.json"), ("mcp-server", ".gemini/settings.json#trusted")} <= kinds
    assert FINDINGS <= {(f["rule_id"], f["location"]["path"]) for f in report["findings"]}
    assert code == 1


def test_sarif_carries_the_findings_and_the_format_of_an_instruction_file(outputs):
    sarif = json.loads(outputs[1]["sarif"])
    results = sarif["runs"][0]["results"]
    located = {(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]) for r in results}
    assert FINDINGS <= located
    formats = {r["properties"]["instructions"]["format"] for r in results if "instructions" in r.get("properties", {})}
    assert "claude-command" in formats


def test_cyclonedx_has_a_component_for_each_new_item(outputs):
    text = outputs[1]["cyclonedx"]
    items = json.loads(outputs[1]["json"])["items"]
    missing = [item["path"] for item in items if item["kind"] in ("instructions", "mcp-server", "settings", "hooks", "mcp-config")
               and item["path"] not in text]
    assert missing == []


@pytest.mark.parametrize("fmt", ["markdown", "text", "html"])
def test_the_readable_reports_name_the_new_findings(outputs, fmt):
    text = outputs[1][fmt]
    for _rule, path in FINDINGS:
        assert path in text, (fmt, path)
