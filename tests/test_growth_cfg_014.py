"""SW-CFG-014: insecure or credential-bearing MCP server in a configuration copy. The rule is not registered yet, so the
tests call the module's `detect` directly."""
from __future__ import annotations

import ast
import inspect
import json
import time

import pytest
from conftest import CONFIG_FIXTURES, _read_dir, config_documents, credential

from spellwarden_scan.agentconfig import parse_document, parse_mcp_config
from spellwarden_scan.rules import growth_cfg_014
from spellwarden_scan.rules.growth_cfg_014 import MALICIOUS, NIST, OWASP, RULE_ID, SEVERITY, TITLE, detect

NEW_IDS = frozenset({f"SW-SKL-{n:03d}" for n in range(32, 38)} | {f"SW-CFG-{n:03d}" for n in range(12, 15)})
LIVE = "k3Vq9TzW1mXb7RcYd2LgHs8NpJf4AaEu0QoI"  # high entropy, no placeholder word


def config(*documents):
    from spellwarden_scan.rules.config import AgentConfig  # a test may import the rule module; the detector may not

    return AgentConfig(documents)


def copy_of(servers: dict, path: str = ".mcp.json.bak"):
    document = parse_document("mcp_copy", path, json.dumps({"mcpServers": servers}, indent=2).encode())
    assert document.error is None
    return document


def run(servers: dict, path: str = ".mcp.json.bak"):
    return list(detect(config(copy_of(servers, path))))


def test_module_constants():
    assert RULE_ID == "SW-CFG-014"
    assert TITLE == "Insecure or credential-bearing MCP server in a configuration copy"
    assert SEVERITY == "high"
    assert OWASP == ("MCP01", "ASI04")
    assert NIST == ("IA-5", "CM-7")
    assert MALICIOUS is False


def test_module_imports_no_rule_modules_at_top_level():
    tree = ast.parse(inspect.getsource(growth_cfg_014))
    imported = {node.module for node in tree.body if isinstance(node, ast.ImportFrom)}
    assert not {"spellwarden_scan.rules.skill", "spellwarden_scan.rules.config"} & imported


# --- the document kind ----------------------------------------------------------------------------------------

def test_the_copy_parser_reads_mcp_servers_only():
    ok = parse_document("mcp_copy", ".mcp.json.bak", b'{"mcpServers": {"a": {"url": "http://x.example.com"}}}')
    assert (ok.kind, ok.error, [s.name for s in ok.servers]) == ("mcp_copy", None, ["a"])
    for text in (b'{"servers": {"a": {}}}', b'{"mcpServers": []}', b"[]", b"{{ template }}", b'{"mcpServers": 3}'):
        assert parse_document("mcp_copy", ".mcp.json.bak", text).error is not None


def test_copies_are_invisible_to_the_accessors_existing_rules_use():
    from spellwarden_scan.rules.config import AgentConfig

    original = parse_mcp_config(".mcp.json", b'{"mcpServers": {"a": {"url": "https://a.example.com"}}}')
    copy = copy_of({"b": {"url": "http://b.example.com"}})
    both = AgentConfig([copy, original])
    assert [d.path for d in both.documents] == [".mcp.json"]
    assert [(d.path, e.name) for d, e in both.servers()] == [(".mcp.json", "a")]
    assert [(d.path, e.name) for d, e in both.copy_servers()] == [(".mcp.json.bak", "b")]
    assert list(both.hooks()) == list(both.settings()) == list(both.plugins()) == []


def test_original_documents_are_not_read_by_the_rule():
    original = parse_mcp_config(".mcp.json", b'{"mcpServers": {"a": {"url": "http://a.example.com"}}}')
    assert list(detect(config(original))) == []


# --- plain http -----------------------------------------------------------------------------------------------

def test_plain_http_to_a_remote_host_fires_at_the_server_line():
    findings = run({"api": {"type": "http", "url": "http://mcp.example.com/api"}})
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.rule_id, finding.severity, finding.title) == (RULE_ID, "high", TITLE)
    assert (finding.location.path, finding.location.line) == (".mcp.json.bak", 3)
    assert finding.malicious_indicator is False
    assert "api" in finding.evidence and "http://mcp.example.com/api" in finding.evidence
    assert len(finding.fingerprint) == 64


def test_transport_does_not_matter_and_userinfo_is_masked():
    (finding,) = run({"api": {"command": "x", "url": "http://user:swordfish2pass@mcp.example.com/api"}})
    assert "swordfish2pass" not in finding.evidence and "***@mcp.example.com" in finding.evidence


@pytest.mark.parametrize("url", ["http://localhost:3000/mcp", "http://127.0.0.1/mcp", "http://[::1]:8080/mcp",
                                 "https://mcp.example.com/api", "ws://mcp.example.com", "stdio:///bin/x"])
def test_loopback_and_encrypted_urls_are_quiet(url):
    assert run({"api": {"url": url}}) == []


def test_disabled_entries_still_count_in_a_copy():
    assert len(run({"api": {"url": "http://mcp.example.com", "disabled": True}})) == 1


# --- credentials ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("server", [
    {"env": {"API_KEY": LIVE}},
    {"env": {"GITHUB_TOKEN": LIVE}},
    {"env": {"db_password": LIVE}},
    {"env": {"AUTH": LIVE}},
    {"env": {"MY_BEARER": LIVE}},
    {"env": {"APP_SECRET": LIVE}},
    {"headers": {"X-Api-Key": LIVE}},
    {"headers": {"Authorization": "Bearer " + LIVE}},
    {"args": ["--api-key=" + LIVE]},
    {"args": ["--token", LIVE]},
    {"args": ["-y", "server", "--auth", LIVE]},
])
def test_a_literal_secret_under_a_secret_like_name_fires(server):
    (finding,) = run({"svc": {"command": "npx", **server}})
    assert (finding.rule_id, finding.location.line) == (RULE_ID, 3)
    assert LIVE not in finding.evidence and "svc" in finding.evidence


@pytest.mark.parametrize("kind", ["github", "aws", "slack", "anthropic", "gitlab", "google"])
def test_a_known_token_prefix_fires_under_any_name(kind):
    token = credential(kind)
    (finding,) = run({"svc": {"command": "x", "env": {"WHATEVER": token}}})
    assert token not in finding.evidence
    (finding,) = run({"svc": {"command": "x", "args": ["--target", token]}})
    assert token not in finding.evidence


def test_each_credential_field_is_one_finding_with_its_own_fingerprint():
    findings = run({"svc": {"command": "x", "env": {"API_KEY": LIVE, "OTHER_TOKEN": LIVE + "9"},
                            "headers": {"Authorization": "Bearer " + LIVE}}})
    assert len(findings) == 3 and len({f.fingerprint for f in findings}) == 3


def test_url_and_credential_on_one_server_are_two_findings():
    assert len(run({"svc": {"url": "http://mcp.example.com", "headers": {"X-Api-Key": LIVE}}})) == 2


@pytest.mark.parametrize("value", [
    "${API_KEY}", "$API_KEY", "${env:API_KEY}", "${input:api-key}", "<your-api-key>", "<TOKEN>", "{{ api_key }}",
    "your-api-key-goes-here-1234", "YOUR_API_KEY_FOR_THE_SERVICE", "paste_token_HERE_please_xxxxx", "xxxxxxxxxxxxxxxxxxxx",
    "changeme-changeme-changeme", "example-api-key-value-0123456789", "sample-token-value-0123456789",
    "fake-token-value-0123456789", "dummy-token-value-0123456789", "op://vault/item/field-name-long-enough",
    "short-secret", "aaaaaaaaaaaaaaaaaaaaaaaa", "abababababababababababab", "Bearer ${API_KEY}", "Bearer <token>",
    "", "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE12",
])
def test_references_placeholders_and_weak_values_are_quiet(value):
    assert run({"svc": {"command": "x", "env": {"API_KEY": value}, "headers": {"Authorization": value}}}) == []


def test_a_long_value_under_a_plain_name_is_quiet():
    assert run({"svc": {"command": "x", "env": {"DATA_DIRECTORY": LIVE, "REGION": "eu-central-1-long-region-name"},
                        "args": ["--config", LIVE, "--name=" + LIVE]}}) == []


def test_paths_and_urls_under_a_secret_like_name_are_quiet():
    assert run({"svc": {"command": "x", "env": {"TOKEN_FILE_PATH": "/home/user/.config/service/credentials-file.json",
                                                "API_KEY_URL": "https://vault.example.com/v1/secret/data/service"}}}) == []


# --- linear time ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("make", [
    lambda n: {"svc": {"url": "http://" + "a." * (n // 2)}},
    lambda n: {"svc": {"command": "x", "env": {"API_KEY": "A1" * (n // 2)}}},
    lambda n: {"svc": {"command": "x", "env": {"WHATEVER": "ghp_" + "A" * n}}},
    lambda n: {"svc": {"command": "x", "headers": {"Authorization": "Bearer " + " " * n}}},
    lambda n: {"svc": {"command": "x", "args": ["--token=" + "<" * n]}},
])
def test_long_values_are_read_in_linear_time(make):
    document = copy_of(make(300_000))
    started = time.perf_counter()
    list(detect(config(document)))
    assert time.perf_counter() - started < 1.0


# --- fixtures and invariant 4 -------------------------------------------------------------------------------------

def _fixture_documents(side: str):
    return config_documents(_read_dir(CONFIG_FIXTURES / RULE_ID / side))


def test_positive_fixture_fires_on_each_copy_and_negative_fixture_is_quiet():
    documents = _fixture_documents("positive")
    assert {d.kind for d in documents} == {"mcp_copy"}
    findings = list(detect(config(*documents)))
    assert {f.location.path for f in findings} == {".mcp.json.disabled", ".mcp.json.full"}
    negative = _fixture_documents("negative")
    assert len(negative) >= 4
    assert list(detect(config(*negative))) == []


def test_negative_fixture_has_a_copy_that_does_not_parse():
    documents = _fixture_documents("negative")
    assert any(d.error is not None for d in documents)


def test_no_existing_config_fixture_holds_a_copy_and_the_detector_is_quiet_on_all():
    checked = 0
    for directory in sorted(p for p in CONFIG_FIXTURES.iterdir() if p.is_dir() and p.name not in NEW_IDS):
        sides = [directory] if directory.name == "plugins-settings" else sorted(p for p in directory.iterdir() if p.is_dir())
        for side in sides:
            documents = config_documents(_read_dir(side))
            checked += len(documents)
            assert all(d.kind != "mcp_copy" for d in documents), side
            assert list(detect(config(*documents))) == [], side
    assert checked > 20


def test_existing_fixtures_still_match_their_expected_json():
    from spellwarden_scan.rules import RuleSet
    from spellwarden_scan.scan import scan_agent_config

    from conftest import load_config_fixture

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
