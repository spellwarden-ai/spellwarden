"""SW-CFG-013: database or cluster MCP server with write access although a read-only mode exists. The rule is not
registered yet, so the tests call the module's `detect` directly."""
from __future__ import annotations

import ast
import inspect
import json
import time

import pytest
from conftest import CONFIG_FIXTURES, _read_dir, config_documents, load_config_fixture

from spellwarden_scan.agentconfig import parse_document, parse_mcp_config
from spellwarden_scan.rules import growth_cfg_013
from spellwarden_scan.rules.growth_cfg_013 import MALICIOUS, NIST, OWASP, RULE_ID, SEVERITY, TITLE, detect

NEW_IDS = frozenset({f"SW-SKL-{n:03d}" for n in range(32, 38)} | {f"SW-CFG-{n:03d}" for n in range(12, 15)})


def config(*documents):
    from spellwarden_scan.rules.config import AgentConfig  # a test may import the rule module; the detector may not

    return AgentConfig(documents)


def run(servers: dict, path: str = ".mcp.json", key: str = "mcpServers"):
    document = parse_mcp_config(path, json.dumps({key: servers}, indent=2).encode())
    assert document.error is None
    return list(detect(config(document)))


def test_module_constants():
    assert RULE_ID == "SW-CFG-013"
    assert TITLE == "Database or cluster MCP server with write access although a read-only mode exists"
    assert SEVERITY == "high"
    assert OWASP == ("MCP02", "ASI03")
    assert NIST == ("AC-3", "AC-6")
    assert MALICIOUS is False


def test_module_imports_no_rule_modules_at_top_level():
    tree = ast.parse(inspect.getsource(growth_cfg_013))
    imported = {node.module for node in tree.body if isinstance(node, ast.ImportFrom)}
    assert not {"spellwarden_scan.rules.skill", "spellwarden_scan.rules.config"} & imported


# --- positives ------------------------------------------------------------------------------------------------

def test_hosted_endpoint_without_read_only_fires_at_the_server_line():
    findings = run({"shop": {"type": "http", "url": "https://mcp.supabase.com/mcp?project_ref=abc"}})
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.rule_id, finding.severity, finding.title) == (RULE_ID, "high", TITLE)
    assert (finding.location.path, finding.location.line) == (".mcp.json", 3)
    assert finding.malicious_indicator is False
    assert "shop" in finding.evidence and "read_only=true" in finding.evidence
    assert len(finding.fingerprint) > 8


@pytest.mark.parametrize("url", [
    "https://mcp.supabase.com/mcp",
    "https://MCP.Supabase.com/mcp?project_ref=abc",
    "https://mcp.supabase.com/mcp?read_only=false",
    "https://mcp.supabase.com/mcp?read_only=truee",
    "https://mcp.supabase.com/mcp?features=database,docs",
    "https://mcp.supabase.com:443/mcp?project_ref=abc#read_only=true",
])
def test_hosted_endpoint_variants_without_read_only_fire(url):
    assert len(run({"s": {"url": url}})) == 1


@pytest.mark.parametrize("command,args", [
    ("npx", ["-y", "@supabase/mcp-server-supabase@latest", "--project-ref=abc"]),
    ("bunx", ["@supabase/mcp-server-supabase"]),
    ("pnpm", ["dlx", "@supabase/mcp-server-supabase@0.4.1"]),
    ("npx", ["-y", "@supabase/mcp-server-supabase@latest", "--read-only=false"]),
])
def test_stdio_package_without_read_only_fires(command, args):
    findings = run({"s": {"command": command, "args": args}})
    assert [f.location.line for f in findings] == [3]
    assert "--read-only" in findings[0].evidence


@pytest.mark.parametrize("command,args,env", [
    ("npx", ["-y", "mcp-server-kubernetes"], {}),
    ("npx", ["-y", "@flux159/mcp-server-kubernetes@latest"], {}),
    ("pnpm", ["dlx", "kubernetes-mcp-server@latest"], {}),
    ("kubernetes-mcp-server", [], {}),
    ("/usr/local/bin/kubernetes-mcp-server", ["--port", "8080"], {}),
    ("npx", ["-y", "mcp-server-kubernetes"], {"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS": "false"}),
    ("kubernetes-mcp-server", ["--read-only=false"], {}),
])
def test_kubernetes_server_without_either_switch_fires(command, args, env):
    findings = run({"k": {"command": command, "args": args, "env": env}})
    assert [f.location.line for f in findings] == [3]
    assert "--read-only" in findings[0].evidence and "--disable-destructive" in findings[0].evidence


@pytest.mark.parametrize("env", [
    {"ACCESS_MODE": "unrestricted"},
    {"MCP_ACCESS_MODE": "Unrestricted"},
    {"ALLOW_INSERT_OPERATION": "true"},
    {"ALLOW_UPDATE_OPERATION": "TRUE"},
    {"ALLOW_DELETE_OPERATION": "true"},
    {"ALLOW_DDL_OPERATION": "true"},
])
def test_other_database_server_with_unrestricted_env_fires(env):
    findings = run({"db": {"command": "db-mcp", "env": env}})
    assert [f.location.line for f in findings] == [3]
    assert next(iter(env)) in findings[0].evidence


def test_one_finding_per_server_with_distinct_fingerprints_per_server():
    findings = run({
        "a": {"command": "db-mcp", "env": {"ALLOW_INSERT_OPERATION": "true", "ALLOW_DELETE_OPERATION": "true"}},
        "b": {"command": "db-mcp", "env": {"ALLOW_INSERT_OPERATION": "true"}},
    })
    assert [f.location.line for f in findings] == [3, 10]
    assert len({f.fingerprint for f in findings}) == 2


def test_stdio_package_launched_through_the_hosted_bridge_is_read_as_the_hosted_endpoint():
    findings = run({"s": {"command": "npx", "args": ["-y", "mcp-remote", "https://mcp.supabase.com/mcp?project_ref=abc"]}})
    assert len(findings) == 1
    assert run({"s": {"command": "npx", "args": ["-y", "mcp-remote", "https://mcp.supabase.com/mcp?read_only=true"]}}) == []


def test_vscode_and_cursor_documents_and_servers_key_are_read():
    server = {"command": "kubernetes-mcp-server"}
    for path in (".vscode/mcp.json", "sub/.cursor/mcp.json", "deep/er/.mcp.json"):
        assert len(run({"k": server}, path=path)) == 1
    assert len(run({"k": server}, path=".vscode/mcp.json", key="servers")) == 1


# --- negatives ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("server", [
    {"url": "https://mcp.supabase.com/mcp?read_only=true"},
    {"url": "https://mcp.supabase.com/mcp?project_ref=abc&read_only=TRUE&features=database"},
    {"url": "https://mcp.supabase.com/mcp?features=docs"},
    {"url": "https://mcp.supabase.com/mcp?features=docs,docs"},
    {"command": "npx", "args": ["-y", "@supabase/mcp-server-supabase@latest", "--read-only"]},
    {"command": "npx", "args": ["-y", "@supabase/mcp-server-supabase@latest", "--read-only=true"]},
    {"command": "npx", "args": ["-y", "@supabase/mcp-server-supabase@latest", "--features=docs"]},
    {"command": "kubernetes-mcp-server", "args": ["--read-only"]},
    {"command": "kubernetes-mcp-server", "args": ["--disable-destructive"]},
    {"command": "npx", "args": ["-y", "mcp-server-kubernetes"], "env": {"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS": "true"}},
    {"command": "npx", "args": ["-y", "mcp-server-kubernetes"], "env": {"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS": "TRUE"}},
    {"command": "db-mcp", "env": {"ACCESS_MODE": "restricted"}},
    {"command": "db-mcp", "env": {"ALLOW_INSERT_OPERATION": "false", "ALLOW_DDL_OPERATION": "0"}},
    {"command": "db-mcp", "args": ["--read-only"], "env": {"ALLOW_INSERT_OPERATION": "true"}},
    {"command": "db-mcp", "readOnly": True, "env": {"ACCESS_MODE": "unrestricted"}},
    {"command": "db-mcp", "read_only": True, "env": {"ALLOW_DELETE_OPERATION": "true"}},
])
def test_the_restricting_switch_keeps_a_server_quiet(server):
    assert run({"a": server}) == []


@pytest.mark.parametrize("disabled", [{"disabled": True}, {"enabled": False}])
def test_disabled_entries_are_quiet(disabled):
    for server in ({"url": "https://mcp.supabase.com/mcp"}, {"command": "kubernetes-mcp-server"},
                   {"command": "db-mcp", "env": {"ALLOW_DELETE_OPERATION": "true"}}):
        assert run({"a": {**server, **disabled}}) == []


def test_explicitly_enabled_entries_still_fire():
    assert len(run({"a": {"command": "kubernetes-mcp-server", "disabled": False, "enabled": True}})) == 1


@pytest.mark.parametrize("server", [
    {"url": "https://mcp.supabase.com.example.net/mcp"},
    {"url": "https://notmcp.supabase.com/mcp"},
    {"url": "https://docs.example.com/mcp?host=mcp.supabase.com"},
    {"command": "npx", "args": ["-y", "@supabase/other-package"]},
    {"command": "npx", "args": ["-y", "supabase-mcp-server-supabase"]},
    {"command": "npx", "args": ["-y", "kubernetes-mcp-server-docs"]},
    {"command": "kubectl", "args": ["get", "pods"]},
    {"command": "db-mcp", "env": {"ALLOW_INSERT_OPERATION_NOTES": "true"}},
    {"command": "db-mcp", "args": ["--note", "ALLOW_DELETE_OPERATION=true"]},
    {"command": "db-mcp"},
])
def test_near_misses_do_not_fire(server):
    assert run({"a": server}) == []


def test_env_key_outside_a_server_and_other_document_kinds_are_not_read():
    document = parse_mcp_config(".mcp.json", json.dumps({
        "env": {"ALLOW_DELETE_OPERATION": "true"}, "url": "https://mcp.supabase.com/mcp",
        "mcpServers": {"a": {"command": "a"}}}).encode())
    assert list(detect(config(document))) == []
    settings = parse_document("settings", ".claude/settings.json",
                              json.dumps({"mcpServers": {"a": {"command": "kubernetes-mcp-server"}}}).encode())
    assert list(detect(config(settings))) == []


def test_evidence_is_short_for_a_long_server_name():
    findings = run({"n" * 5000: {"command": "kubernetes-mcp-server"}})
    assert len(findings) == 1 and len(findings[0].evidence) < 400


# --- linear time ------------------------------------------------------------------------------------------------

def test_a_300000_character_url_and_argument_are_read_in_under_a_second():
    long_host = "mcp.supabase.com" * 18_750
    servers = [{"url": f"https://{long_host}/mcp?"},
               {"url": "https://mcp.supabase.com/mcp?" + "read_only=false&" * 18_750},
               {"command": "npx", "args": ["-y", "@supabase/mcp-server-supabase@" + "1" * 300_000]},
               {"command": "kubernetes-mcp-server", "args": ["--disable-destructive-" + "x" * 300_000]},
               {"command": "db-mcp", "env": {"ALLOW_DELETE_OPERATION": "true" * 75_000}}]
    documents = [parse_mcp_config(".mcp.json", json.dumps({"mcpServers": {"a": server}}).encode()) for server in servers]
    assert all(document.error is None for document in documents)
    started = time.perf_counter()
    counts = [len(list(detect(config(document)))) for document in documents]
    assert time.perf_counter() - started < 1
    assert counts == [0, 1, 1, 1, 0]


def test_many_servers_and_arguments_give_bounded_output_in_linear_time():
    servers = {f"s{n}": {"command": "kubernetes-mcp-server", "args": ["-x"] * 200} for n in range(2000)}
    text = json.dumps({"mcpServers": servers}).encode()
    started = time.perf_counter()
    findings = list(detect(config(parse_mcp_config(".mcp.json", text))))
    assert time.perf_counter() - started < 2
    assert len(findings) <= 2000


# --- fixtures and invariant 4 -------------------------------------------------------------------------------------

def _fixture_documents(side: str):
    return config_documents(_read_dir(CONFIG_FIXTURES / RULE_ID / side))


def test_positive_fixture_fires_on_each_server_and_negative_fixture_is_quiet():
    positive = list(detect(config(*_fixture_documents("positive"))))
    assert len(positive) == 4 and {f.location.path for f in positive} == {".mcp.json"}
    assert len({f.location.line for f in positive}) == 4
    assert list(detect(config(*_fixture_documents("negative")))) == []


def test_detector_is_quiet_on_every_existing_config_fixture():
    checked = 0
    for directory in sorted(p for p in CONFIG_FIXTURES.iterdir() if p.is_dir() and p.name not in NEW_IDS):
        sides = [directory] if directory.name == "plugins-settings" else sorted(p for p in directory.iterdir() if p.is_dir())
        for side in sides:
            documents = config_documents(_read_dir(side))
            checked += len(documents)
            assert list(detect(config(*documents))) == [], side
    assert checked > 20


def test_existing_fixtures_still_match_their_expected_json():
    from spellwarden_scan.rules import RuleSet
    from spellwarden_scan.scan import scan_agent_config

    rules = RuleSet.baseline()
    checked = 0
    for expected_file in sorted(CONFIG_FIXTURES.glob("*/*/expected.json")):
        if expected_file.parent.parent.name in NEW_IDS:
            continue
        expected = json.loads(expected_file.read_text())
        files, _ = load_config_fixture(expected_file.parent.parent.name, expected_file.parent.name)
        result = scan_agent_config(config_documents(files), rules)
        actual = {(f.rule_id, f.severity, f.location.path, f.location.line) for f in result.findings}
        assert actual == {(f["rule_id"], f["severity"], f["path"], f.get("line")) for f in expected["findings"]}, expected_file
        checked += 1
    assert checked >= 20
