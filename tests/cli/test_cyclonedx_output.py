"""Phase 3 batch 2a spec 7.3 (scanner column), 11.5 and T-8: `--format cyclonedx` writes the recorded documents of a repository,
of each system's fixture home and of an inventory; each validates against the vendored 1.7.2 schema, every reference resolves,
and the mapping holds for the objects of the repository."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from conftest import _RUNNER_VARIABLES, cyclonedx_problems
from homes import USER_VARIABLES

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "golden" / "1.14.0"
_spec = importlib.util.spec_from_file_location("record_1_14_0", ROOT / "tests" / "golden" / "record_1_14_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)
TAGS = "utm_source=scanner&utm_medium=cyclonedx&utm_campaign=ai-bom"


@pytest.fixture
def clean(monkeypatch):
    for name in (*_RUNNER_VARIABLES, *USER_VARIABLES):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def repository(tmp_path, clean) -> dict:  # noqa: ARG001 -- `clean` runs first
    return json.loads(record.repository_document(tmp_path))


@pytest.mark.usefixtures("clean")
def test_the_repository_document_is_the_recorded_one_and_valid(tmp_path):
    produced = record.repository_document(tmp_path)
    assert produced == (GOLDEN / "repo.cdx.json").read_bytes().decode("utf-8")
    assert cyclonedx_problems(json.loads(produced)) == []


def _without_home(text: str) -> dict:
    """A home document without what depends on where the fixture home was copied: `~/.claude.json` names the home's own path
    (its projects), so its hash and therefore the serial number differ from copy to copy."""
    document = json.loads(text)
    del document["serialNumber"]
    for component in document.get("components", []):
        if component["bom-ref"].startswith("document:~/.claude.json"):
            component.pop("hashes", None)
    return document


@pytest.mark.usefixtures("clean")
@pytest.mark.parametrize("system, inventory", record.HOME_DOCUMENTS)
def test_each_home_document_is_the_recorded_one_and_valid(tmp_path, system, inventory):
    produced = record.home_document(tmp_path, system, inventory)
    assert _without_home(produced) == _without_home((GOLDEN / record.home_name(system, inventory)).read_bytes().decode("utf-8"))
    document = json.loads(produced)
    assert cyclonedx_problems(document) == []
    assert document["metadata"]["component"] == {"type": "device", "name": "workstation"}
    assert ("vulnerabilities" in document) is not inventory


def test_the_repository_mapping(repository):
    by_ref = {entry["bom-ref"]: entry for key in ("components", "services") for entry in repository[key]}
    assert repository["metadata"]["component"] == {"type": "application", "name": "repo"}
    assert by_ref["skill:.claude/skills/deploy"]["type"] == "library" and by_ref["skill:.claude/skills/deploy"]["hashes"]
    assert by_ref["plugin:.claude-plugin/marketplace.json#lint"]["externalReferences"] == [
        {"type": "vcs", "url": "https://github.com/example/lint-plugin"}]
    assert by_ref["marketplace:.claude-plugin/marketplace.json"]["type"] == "data"
    assert by_ref["instructions:AGENTS.md"]["type"] == "file"
    assert by_ref["document:.mcp.json"]["type"] == "file" and by_ref["document:.claude/settings.json"]["type"] == "file"
    remote = by_ref["mcp-server:.mcp.json#remote"]
    assert remote["endpoints"] == ["https://mcp.example.com/mcp"]  # the query is gone
    files = {prop["name"]: prop["value"] for prop in by_ref["mcp-server:.mcp.json#files"]["properties"]}
    assert files["spellwarden:transport"] == "stdio" and files["spellwarden:command_reason"] == "unpinned"
    assert "/srv/data" not in json.dumps(repository)  # a stdio argument
    agent = by_ref["agent:a2a-card:.well-known/agent-card.json"]
    assert {prop["name"] for prop in agent["properties"]} >= {"spellwarden:kind", "spellwarden:card_format",
                                                              "spellwarden:protocol_version"}
    assert {"ref": "marketplace:.claude-plugin/marketplace.json", "dependsOn": ["plugin:.claude-plugin/marketplace.json#lint"]} \
        in repository["dependencies"]
    assert {"ref": "document:.mcp.json", "dependsOn": ["mcp-server:.mcp.json#files", "mcp-server:.mcp.json#remote"]} \
        in repository["dependencies"]


def test_findings_map_to_vulnerabilities_with_their_analysis(repository):
    vulnerabilities = {entry["id"]: entry for entry in repository["vulnerabilities"]}
    accepted = vulnerabilities["SW-CFG-009"]
    assert accepted["analysis"] == {"state": "exploitable", "response": ["will_not_fix"],
                                    "detail": "The lint plugin is reviewed at every release of the marketplace."}
    assert {"name": "spellwarden:expires", "value": "2027-05-01"} in accepted["properties"]
    assert accepted["affects"] == [{"ref": "marketplace:.claude-plugin/marketplace.json"}]
    opened = vulnerabilities["SW-SKL-007"]
    assert opened["analysis"] == {"state": "in_triage"} and opened["affects"] == [{"ref": "skill:.claude/skills/deploy"}]
    assert opened["source"]["url"] == f"https://spellwarden.ai/docs/rules/SW-SKL-007?{TAGS}"
    assert opened["ratings"] == [{"source": opened["source"], "severity": "high", "method": "other"}]
    assert vulnerabilities["SW-A2A-002"]["affects"] == [{"ref": "agent:a2a-card:.well-known/agent-card.json"}]
    tool = repository["metadata"]["tools"]["components"][0]
    assert tool["externalReferences"] == [{"type": "website", "url": f"https://spellwarden.ai/?{TAGS}"}]


@pytest.mark.usefixtures("clean")
def test_the_same_scan_gives_the_same_bytes(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    assert record.repository_document(first) == record.repository_document(second)


@pytest.mark.parametrize("auth_mode, authenticated", [("static-key", True), ("none", False), ("unknown", None)])
def test_a_probed_server_carries_its_tools_auth_mode_and_migration_status(auth_mode, authenticated):
    """Review r0:F5: the `--probe` part of the mapping (spec 7.3, 11.5): one `spellwarden:tool` per listed tool name, the
    auth mode and migration status, and `authenticated` only for an auth mode that says so."""
    from dataclasses import replace

    from spellwarden_scan import McpScanResult
    from test_outputs import make_report

    from spellwarden_cli.discover import Item
    from spellwarden_cli.output import cyclonedx
    from spellwarden_cli.report import ProbeReport

    result = McpScanResult(findings=(), truncated=0, spec_version="2026-07-28", transport="streamable-http",
                           auth_mode=auth_mode, deprecated_features=(), migration_status="ready", checklist=(),
                           rules_version="2026.12.1", scanner_version="0.3.0")
    probe = ProbeReport(".mcp.json#jira", "probed", None, result, tools=("search", "create_issue", "delete_issue"))
    report = replace(make_report(probes=[probe]), items=(Item("mcp-server", ".mcp.json#jira", "jira"),),
                     details={".mcp.json#jira": {"transport": "streamable-http", "endpoint": "https://mcp.example.com/mcp"}})
    document = json.loads(cyclonedx.render(report))
    assert cyclonedx_problems(document) == []
    (service,) = document["services"]
    properties = [(entry["name"], entry["value"]) for entry in service["properties"]]
    assert [value for name, value in properties if name == "spellwarden:tool"] == ["search", "create_issue", "delete_issue"]
    assert ("spellwarden:auth_mode", auth_mode) in properties
    assert ("spellwarden:migration_status", "ready") in properties
    assert service.get("authenticated") is authenticated
    assert service["endpoints"] == ["https://mcp.example.com/mcp"]

