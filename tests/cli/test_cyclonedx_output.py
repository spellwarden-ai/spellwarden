"""Phase 3 batch 2a spec 7.3 (scanner column), 11.5 and T-8: `--format cyclonedx` writes the recorded document of a repository;
it validates against the vendored 1.7.2 schema, every reference resolves, and the mapping holds for the repository's objects."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from conftest import _RUNNER_VARIABLES, cyclonedx_problems

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "golden" / "1.14.0"
_spec = importlib.util.spec_from_file_location("record_1_14_0", ROOT / "tests" / "golden" / "record_1_14_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)
TAGS = "utm_source=scanner&utm_medium=cyclonedx&utm_campaign=ai-bom"


@pytest.fixture
def clean(monkeypatch):
    for name in _RUNNER_VARIABLES:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def repository(tmp_path, clean) -> dict:  # noqa: ARG001 -- `clean` runs first
    return json.loads(record.repository_document(tmp_path))


@pytest.mark.usefixtures("clean")
def test_the_repository_document_is_the_recorded_one_and_valid(tmp_path):
    produced = record.repository_document(tmp_path)
    assert produced == (GOLDEN / "repo.cdx.json").read_bytes().decode("utf-8")
    assert cyclonedx_problems(json.loads(produced)) == []


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
