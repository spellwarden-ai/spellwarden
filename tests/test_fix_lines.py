"""1.21.0 (P6-15 spec 4.4, 6.3, 6.12 E-11): the setting lines. SW-CFG-013 writes them for the hosted Supabase endpoint (the query
parameter alone, in the server's `url` or in a launcher argument) and for `mcp-server-kubernetes` (its environment variable, in
the syntax of the document the finding is in: a JSON member, and a TOML key in Codex's `config.toml`; the owner's answer to plan
Q2); it writes none for the Supabase package and `kubernetes-mcp-server` (their documentation did not confirm `--read-only` on
2026-11-23, `rules/fix_lines.py`) or for any other server; SW-A2A-006 and SW-MCP-003 always write theirs. No line holds a
character of the scanned configuration, a finding without lines serialises as in 1.20.0, and the fingerprint does not read them."""
from __future__ import annotations

import json
import tomllib

import pytest
from a2a_cards import card_bytes
from a2a_rule_cases import with_flow

from spellwarden_scan.a2a import parse_agent_card
from spellwarden_scan.agentconfig import parse_mcp_config, parse_selected
from spellwarden_scan.model import AuthServerMetadata, CardOrigin, Finding, FixLines, Location, ProbeResult
from spellwarden_scan.probe import evaluate_probe
from spellwarden_scan.rules import RuleSet, fix_lines
from spellwarden_scan.rules.a2a import CardSubject
from spellwarden_scan.rules.growth_cfg_013 import detect
from spellwarden_scan.scan import run_rules

RULES = RuleSet.baseline()
HOSTED = FixLines("the query of the mcp.supabase.com address", "read_only=true")
KUBERNETES = FixLines("the server's env", '"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS": "true"')
KUBERNETES_TOML = FixLines("the server's env table", 'ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS = "true"')


def cfg_013(server: dict) -> list[Finding]:
    from spellwarden_scan.rules.config import AgentConfig

    document = parse_mcp_config(".mcp.json", json.dumps({"mcpServers": {"db": server}}, indent=2).encode())
    assert document.error is None
    return list(detect(AgentConfig([document])))


@pytest.mark.parametrize("server, expected", [
    ({"type": "http", "url": "https://mcp.supabase.com/mcp?project_ref=abcdefghijklmnop"}, HOSTED),
    ({"command": "npx", "args": ["-y", "mcp-remote", "https://mcp.supabase.com/mcp?project_ref=abcdefghijklmnop&features=database"]},
     HOSTED),
    ({"command": "npx", "args": ["-y", "mcp-server-kubernetes"]}, KUBERNETES),
    ({"command": "npx", "args": ["-y", "@supabase/mcp-server-supabase@latest", "--project-ref=abcdefghijklmnop"]}, None),
    ({"command": "npx", "args": ["-y", "kubernetes-mcp-server@latest"]}, None),
    ({"command": "npx", "args": ["-y", "@example/postgres-mcp"], "env": {"POSTGRES_ACCESS_MODE": "unrestricted"}}, None),
])
def test_sw_cfg_013_writes_the_lines_of_its_row(server, expected):
    (finding,) = cfg_013(server)
    assert finding.rule_id == "SW-CFG-013" and finding.fix_lines == expected


def test_a_line_follows_the_syntax_of_its_document():
    """The owner's answer to plan Q2. A server of Codex's `config.toml`, a TOML file, gets the `mcp-server-kubernetes` line as a
    TOML key, and a server of a JSON document gets it as a JSON member; the hosted Supabase line is a query parameter, the same
    in both; a server without lines has none in either. The command reads the TOML itself and hands the engine the same tree,
    so each document is built here as tests/test_growth_cfg_013.py builds it."""
    from spellwarden_scan.rules.config import AgentConfig

    servers = {"cluster": {"command": "npx", "args": ["-y", "mcp-server-kubernetes"]},
               "db": {"type": "http", "url": "https://mcp.supabase.com/mcp?project_ref=abcdefghijklmnop"},
               "other": {"command": "npx", "args": ["-y", "kubernetes-mcp-server@latest"]}}
    text = json.dumps({"mcpServers": servers}, indent=2).encode()
    for path, kubernetes in ((".codex/config.toml", KUBERNETES_TOML), ("home/.codex/Config.TOML", KUBERNETES_TOML),
                             (".gemini/settings.json", KUBERNETES)):
        document = parse_selected("settings", path, text, lambda root: ([root.get("mcpServers")], None))
        assert document.error is None
        found = {finding.evidence.split(":", 1)[0]: finding.fix_lines for finding in detect(AgentConfig([document]))}
        assert found == {"cluster": kubernetes, "db": HOSTED, "other": None}, path


def test_each_form_of_the_kubernetes_line_is_valid_in_its_syntax_and_ends_the_finding():
    """The JSON member and the TOML key are one entry of the server's env, each valid where it is written (under the header of
    the server's env table, and inside an inline table), and a server that holds the entry has no finding: the line is the
    switch the rule reads, so writing it restricts the server."""
    entry = {"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS": "true"}
    assert json.loads("{" + KUBERNETES.text + "}") == entry
    assert tomllib.loads("[mcp_servers.cluster.env]\n" + KUBERNETES_TOML.text + "\n")["mcp_servers"]["cluster"]["env"] == entry
    assert tomllib.loads("env = { " + KUBERNETES_TOML.text + " }\n")["env"] == entry
    assert cfg_013({"command": "npx", "args": ["-y", "mcp-server-kubernetes"], "env": entry}) == []


def test_no_line_holds_a_character_of_the_scanned_configuration():
    secret = "projectrefsecret42"
    server = {"type": "http", "url": f"https://mcp.supabase.com/mcp?project_ref={secret}", "headers": {"X-Token": secret}}
    (finding,) = cfg_013(server)
    assert secret not in finding.fix_lines.where + finding.fix_lines.text
    for row in fix_lines.SOURCES:
        assert row.lines.where.isascii() and row.lines.text.isascii()


def test_sw_a2a_006_always_writes_its_line():
    path = "public/.well-known/agent-card.json"
    subject = CardSubject(parse_agent_card(path, card_bytes(with_flow(pkceRequired=False))), CardOrigin("repository", "well_known"),
                          (), path)
    findings, _ = run_rules(RULES.ordered_for_scan("a2a"), subject, max_findings=500, max_per_rule=20)
    (finding,) = [f for f in findings if f.rule_id == "SW-A2A-006"]
    assert finding.fix_lines == FixLines("the authorizationCode flow of the card's OAuth scheme", '"pkceRequired": true')
    assert all(f.fix_lines is None for f in findings if f.rule_id != "SW-A2A-006")


def test_sw_mcp_003_always_writes_its_line():
    dcr = AuthServerMetadata(issuer="https://auth.example", metadata_url="https://auth.example/.well-known/oauth-authorization-server",
                             registration_endpoint="https://auth.example/register")
    probe = ProbeResult(endpoint="https://mcp.example/mcp", reachable=True, post_status=200, post_content_type="application/json",
                        discover={"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}},
                        capabilities={"tools": {}}, unauthenticated_status=401,
                        resource_metadata={"resource": "https://mcp.example/mcp",
                                           "authorization_servers": ["https://auth.example"]},
                        auth_server_metadata=dcr)
    (finding,) = [f for f in evaluate_probe(probe, RULES).findings if f.rule_id == "SW-MCP-003"]
    assert finding.fix_lines == FixLines("the authorization server's metadata", '"client_id_metadata_document_supported": true')


def test_the_table_names_its_sources_and_keeps_the_bounds():
    assert [(row.rule_id, row.lines) for row in fix_lines.SOURCES] == [
        ("SW-CFG-013", HOSTED), ("SW-CFG-013", KUBERNETES), ("SW-CFG-013", KUBERNETES_TOML),
        ("SW-A2A-006", FixLines("the authorizationCode flow of the card's OAuth scheme", '"pkceRequired": true')),
        ("SW-MCP-003", FixLines("the authorization server's metadata", '"client_id_metadata_document_supported": true'))]
    for row in fix_lines.SOURCES:
        assert row.source.startswith("https://") and row.checked == "2026-11-23"
        assert len(row.lines.where) <= 80 and len(row.lines.text) <= 200 and row.lines.text.count("\n") < 3
    # the TOML form alone names a second page, the one that gives its syntax; its switch is the JSON form's, from the same page
    sources = {row.lines: row for row in fix_lines.SOURCES}
    assert [row.lines for row in fix_lines.SOURCES if row.syntax] == [KUBERNETES_TOML]
    assert sources[KUBERNETES_TOML].syntax.startswith("https://")
    assert sources[KUBERNETES_TOML].source == sources[KUBERNETES].source


def test_a_finding_without_lines_serialises_as_before_and_one_with_them_round_trips():
    plain = Finding("SW-SKL-009", "medium", "t", Location("SKILL.md", 3), "e", "f" * 64)
    assert list(plain.to_dict()) == ["rule_id", "severity", "title", "location", "evidence", "fingerprint", "malicious_indicator"]
    with_lines = Finding("SW-CFG-013", "high", "t", Location(".mcp.json", 3), "e", "f" * 64, False, HOSTED)
    data = json.loads(json.dumps(with_lines.to_dict()))
    assert data["fix_lines"] == {"where": HOSTED.where, "text": HOSTED.text}
    assert Finding.from_dict(data) == with_lines and Finding.from_dict(plain.to_dict()) == plain
