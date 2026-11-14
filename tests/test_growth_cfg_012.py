"""SW-CFG-012: MCP server configured to approve every tool call automatically, and the `options` field of
`McpServerEntry` it reads. The rule is not registered yet, so the tests call the module's `detect` directly."""
from __future__ import annotations

import ast
import inspect
import json
import os
import time

import pytest
from conftest import CONFIG_FIXTURES, _read_dir, config_documents, config_kind, load_config_fixture

from spellwarden_scan.agentconfig import parse_document, parse_mcp_config
from spellwarden_scan.rules import growth_cfg_012
from spellwarden_scan.rules.growth_cfg_012 import MALICIOUS, NIST, OWASP, RULE_ID, SEVERITY, TITLE, detect

# Wall-clock budgets scale with SPELLWARDEN_SPEED_FACTOR when it is set (CI sets 3: shared runners, Windows above all, are
# slower), as tests/otel/test_speed.py and tests/test_rules_mcp.py do.
SPEED_FACTOR = float(os.environ.get("SPELLWARDEN_SPEED_FACTOR", "1"))

NEW_IDS = frozenset({"SW-SKL-032", "SW-SKL-036", "SW-SKL-037", "SW-CFG-012", "SW-CFG-013"})


def config(*documents):
    from spellwarden_scan.rules.config import AgentConfig  # a test may import the rule module; the detector may not

    return AgentConfig(documents)


def run(servers: dict, path: str = ".mcp.json", key: str = "mcpServers"):
    document = parse_mcp_config(path, json.dumps({key: servers}, indent=2).encode())
    assert document.error is None
    return list(detect(config(document)))


def test_module_constants():
    assert RULE_ID == "SW-CFG-012"
    assert TITLE == "MCP server configured to approve every tool call automatically"
    assert SEVERITY == "high"
    assert OWASP == ("ASI02",)
    assert NIST == ("AC-6", "CM-7")
    assert MALICIOUS is False


def test_module_imports_no_rule_modules_at_top_level():
    tree = ast.parse(inspect.getsource(growth_cfg_012))
    imported = {node.module for node in tree.body if isinstance(node, ast.ImportFrom)}
    assert not {"spellwarden_scan.rules.skill", "spellwarden_scan.rules.config"} & imported


# --- the options field ------------------------------------------------------------------------------------------

def test_server_options_hold_approval_and_access_keys_with_values_and_lines():
    document = parse_mcp_config(".mcp.json", json.dumps({"mcpServers": {"a": {
        "command": "a", "autoApprove": ["x", "y"], "alwaysAllow": [], "trust": True,
        "default_tools_approval_mode": "Approve", "disabled": False, "enabled": True, "read_only": True,
        "readOnly": False, "tools": {"t": {"approval_mode": "prompt", "other": 1}, "u": "no"}}}}, indent=2).encode())
    options = document.servers[0].options
    assert options["autoApprove"]["value"] == ["x", "y"]
    assert options["alwaysAllow"]["value"] == []
    assert options["trust"]["value"] is True
    assert options["default_tools_approval_mode"]["value"] == "Approve"
    assert options["disabled"]["value"] is False and options["enabled"]["value"] is True
    assert options["read_only"]["value"] is True and options["readOnly"]["value"] is False
    assert options["tools.t.approval_mode"]["value"] == "prompt"
    assert "tools.u.approval_mode" not in options
    assert all(isinstance(item["line"], int) and item["line"] > 1 for item in options.values())
    assert options["autoApprove"]["line"] == 5


def test_server_without_those_keys_has_empty_options_and_the_old_to_dict_shape():
    document = parse_mcp_config(".mcp.json", b'{"mcpServers": {"a": {"command": "a", "args": ["x"]}}}')
    server = document.servers[0]
    assert server.options == {}
    assert "options" not in server.to_dict()
    assert set(server.to_dict()) == {"name", "line", "transport", "url", "command", "args", "env", "headers", "raw_sha256"}


def test_non_empty_options_are_never_serialised_and_from_dict_still_loads():
    from spellwarden_scan.model import ConfigDocument

    document = parse_mcp_config(".mcp.json", b'{"mcpServers": {"a": {"command": "a", "disabled": true, "autoApprove": ["x"]}}}')
    assert document.servers[0].options
    dumped = document.to_dict()
    assert "options" not in dumped["servers"][0]
    assert ConfigDocument.from_dict(dumped).servers[0].options == {}


def test_options_do_not_enter_the_raw_hash():
    plain = parse_mcp_config(".mcp.json", b'{"mcpServers": {"a": {"command": "a", "autoApprove": ["x"]}}}')
    canonical = json.dumps({"autoApprove": ["x"], "command": "a"}, sort_keys=True, separators=(",", ":")).encode()
    import hashlib

    assert plain.servers[0].raw_sha256 == hashlib.sha256(canonical).hexdigest()


def test_options_are_bounded():
    tools = {f"t{n}": {"approval_mode": "approve"} for n in range(1000)}
    document = parse_mcp_config(".mcp.json", json.dumps({"mcpServers": {"a": {
        "command": "a", "autoApprove": [f"tool{n}" for n in range(1000)], "tools": tools}}}).encode())
    options = document.servers[0].options
    assert len(options["autoApprove"]["value"]) <= 64
    assert len(options) <= 300


@pytest.mark.parametrize("tool", ["browser_resize", "search_vendor_docs", "getStatus", "list-items"])
def test_automatic_approval_of_a_read_only_tool_is_quiet(tool):
    assert run({"docs": {"command": "docs", "tools": {tool: {"approval_mode": "approve"}}}}) == []
    assert run({"docs": {"command": "docs", "autoApprove": [tool]}}) == []


@pytest.mark.parametrize("tool", ["fetch_page", "write_file", "run_query", "search_and_replace_edit", "*", "do_thing"])
def test_automatic_approval_of_a_tool_that_may_act_fires(tool):
    assert len(run({"ops": {"command": "ops", "tools": {tool: {"approval_mode": "approve"}}}})) == 1
    assert len(run({"ops": {"command": "ops", "autoApprove": ["get_status", tool]}})) == 1


def test_a_cut_list_or_dropped_approving_tools_fire_whatever_the_names():
    padded = [f"get_item_{n}" for n in range(70)] + ["wipe_disk"]
    assert len(run({"ops": {"command": "ops", "autoApprove": padded}})) == 1
    tools = {f"get_item_{n}": {"approval_mode": "approve"} for n in range(220)}
    assert run({"ops": {"command": "ops", "tools": tools}})


@pytest.mark.parametrize("tool", ["get_and_wipe", "list_then_delete_all", "read_secret", "get_" + "x" * 250, "gét_status"])
def test_names_that_may_act_or_cannot_be_judged_fire(tool):
    assert len(run({"ops": {"command": "ops", "tools": {tool: {"approval_mode": "approve"}}}})) == 1


def test_inline_servers_of_a_plugin_manifest_are_read():
    from spellwarden_scan.agentconfig import parse_plugin_manifest

    manifest = json.dumps({"name": "acme", "mcpServers": {"ops": {"command": "ops", "trust": True}}}, indent=2).encode()
    document = parse_plugin_manifest("plugins/acme/.claude-plugin/plugin.json", manifest)
    assert len(list(detect(config(document)))) == 1


def test_an_approving_tool_after_many_ordinary_ones_is_kept():
    tools = {f"t{n}": {"approval_mode": "prompt"} for n in range(500)}
    tools["shell_exec"] = {"approval_mode": "approve"}
    findings = run({"ops": {"command": "ops", "tools": tools}})
    assert len(findings) == 1 and "tools.shell_exec.approval_mode" in findings[0].evidence


def test_a_later_tool_with_the_same_cut_name_cannot_hide_an_approving_one():
    long = "x" * 300
    tools = {long + "a": {"approval_mode": "approve"}, long + "b": {"approval_mode": "prompt"}}
    assert len(run({"ops": {"command": "ops", "tools": tools}})) == 1


# --- the rule ------------------------------------------------------------------------------------------------------

def test_non_empty_auto_approve_fires_at_the_key_line():
    findings = run({"notes": {"command": "notes", "autoApprove": ["send_message"]}})
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.rule_id, finding.severity, finding.title) == (RULE_ID, "high", TITLE)
    assert (finding.location.path, finding.location.line) == (".mcp.json", 5)
    assert finding.malicious_indicator is False
    assert "notes" in finding.evidence and "autoApprove" in finding.evidence
    assert len(finding.fingerprint) > 8


def test_non_empty_always_allow_fires():
    findings = run({"notes": {"command": "notes", "alwaysAllow": ["search", "delete_note"]}})
    assert [f.location.line for f in findings] == [5]
    assert "alwaysAllow" in findings[0].evidence


@pytest.mark.parametrize("mode", ["approve", "APPROVE", "Approve"])
def test_default_approval_mode_approve_fires_case_insensitively(mode):
    findings = run({"wiki": {"url": "https://wiki.example.org/mcp", "default_tools_approval_mode": mode}})
    assert [f.location.line for f in findings] == [5]
    assert "default_tools_approval_mode" in findings[0].evidence


def test_per_tool_approve_fires_at_the_approval_mode_line_and_names_the_tool():
    findings = run({"cal": {"command": "cal", "tools": {"create_event": {"approval_mode": "approve"},
                                                        "list_events": {"approval_mode": "prompt"}}}})
    assert len(findings) == 1
    assert findings[0].location.line == 7
    assert "create_event" in findings[0].evidence


def test_trust_true_fires_and_trust_false_does_not():
    assert [f.location.line for f in run({"a": {"url": "https://tickets.example.com/mcp", "trust": True}})] == [5]
    assert run({"a": {"url": "https://tickets.example.com/mcp", "trust": False}}) == []


def test_several_triggers_in_one_server_each_report_their_own_line():
    findings = run({"a": {"command": "a", "trust": True, "autoApprove": ["x"]}})
    assert sorted(f.location.line for f in findings) == [5, 6]
    assert len({f.fingerprint for f in findings}) == 2


def test_vscode_and_cursor_documents_and_servers_key_are_read():
    for path in (".vscode/mcp.json", "sub/.cursor/mcp.json", "deep/er/.mcp.json"):
        assert len(run({"a": {"command": "a", "trust": True}}, path=path)) == 1
    assert len(run({"a": {"command": "a", "trust": True}}, path=".vscode/mcp.json", key="servers")) == 1


@pytest.mark.parametrize("server", [
    {"command": "a", "autoApprove": []},
    {"command": "a", "alwaysAllow": []},
    {"command": "a", "default_tools_approval_mode": "prompt"},
    {"command": "a", "default_tools_approval_mode": True},
    {"command": "a", "tools": {"t": {"approval_mode": "prompt"}}},
    {"command": "a", "tools": {"t": "approve"}},
    {"command": "a", "autoApprove": "all"},
    {"command": "a", "trust": "true"},
    {"command": "a", "disabled": True},
])
def test_near_misses_do_not_fire(server):
    assert run({"a": server}) == []


def test_keys_outside_a_server_do_not_fire():
    document = parse_mcp_config(".mcp.json", json.dumps({
        "autoApprove": ["x"], "trust": True, "default_tools_approval_mode": "approve",
        "mcpServers": {"a": {"command": "a", "env": {"autoApprove": "x"}, "headers": {"trust": "true"},
                              "args": ["--trust"]}}}).encode())
    assert list(detect(config(document))) == []


def test_other_document_kinds_are_not_read():
    settings = parse_document("settings", ".claude/settings.json",
                              json.dumps({"mcpServers": {"a": {"command": "a", "trust": True}}}).encode())
    assert list(detect(config(settings))) == []


def test_evidence_is_masked_and_short():
    findings = run({"a": {"command": "a", "autoApprove": ["x" * 5000]}})
    assert len(findings) == 1 and len(findings[0].evidence) < 400


def test_a_long_tool_list_is_read_in_linear_time_and_findings_are_bounded():
    tools = {f"tool_{n}": {"approval_mode": "approve"} for n in range(5000)}
    text = json.dumps({"mcpServers": {"a": {"command": "a", "autoApprove": ["t"] * 100_000, "tools": tools}}}).encode()
    started = time.perf_counter()
    document = parse_mcp_config(".mcp.json", text)
    findings = list(detect(config(document)))
    assert time.perf_counter() - started < 1 * SPEED_FACTOR
    assert 1 <= len(findings) <= 30


def test_a_300000_character_value_is_read_in_under_a_second():
    value = "approve" * 43_000
    text = json.dumps({"mcpServers": {"a": {"command": "a", "default_tools_approval_mode": value, "autoApprove": [value]}}}).encode()
    started = time.perf_counter()
    findings = list(detect(config(parse_mcp_config(".mcp.json", text))))
    assert time.perf_counter() - started < 1 * SPEED_FACTOR
    assert len(findings) == 1


# --- fixtures and invariant 4 -------------------------------------------------------------------------------------

def _fixture_documents(side: str):
    return config_documents(_read_dir(CONFIG_FIXTURES / RULE_ID / side))


def test_positive_fixture_fires_on_each_server_and_negative_fixture_is_quiet():
    positive = list(detect(config(*_fixture_documents("positive"))))
    assert len(positive) == 4 and {f.location.path for f in positive} == {".mcp.json"}
    assert len({f.location.line for f in positive}) == 4
    assert list(detect(config(*_fixture_documents("negative")))) == []


def _existing_config_dirs():
    return sorted(p for p in CONFIG_FIXTURES.iterdir() if p.is_dir() and p.name not in NEW_IDS)


def test_detector_is_quiet_on_every_existing_config_fixture():
    checked = 0
    for directory in _existing_config_dirs():
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


def test_raw_sha256_of_every_existing_fixture_server_is_the_hash_of_its_own_json():
    import hashlib

    checked = 0
    for path in sorted(CONFIG_FIXTURES.rglob("*")):
        if not path.is_file() or path.relative_to(CONFIG_FIXTURES).parts[0] in NEW_IDS or config_kind(path.as_posix()) != "mcp":
            continue
        try:
            root = json.loads(path.read_bytes())
        except ValueError:
            continue  # JSONC: not readable by the standard library
        document = parse_document("mcp", path.name, path.read_bytes())
        expected = {name: hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                                         .encode()).hexdigest()
                    for key in ("mcpServers", "servers") if isinstance(root.get(key), dict)
                    for name, entry in root[key].items() if isinstance(entry, dict)}
        assert {s.name: s.raw_sha256 for s in document.servers} == expected, path
        checked += len(expected)
    assert checked > 10


def test_existing_fixture_documents_serialise_without_an_options_key():
    checked = 0
    for path in sorted(CONFIG_FIXTURES.rglob("*")):
        if not path.is_file() or path.relative_to(CONFIG_FIXTURES).parts[0] in NEW_IDS or config_kind(path.as_posix()) is None:
            continue
        document = parse_document(config_kind(path.as_posix()), path.name, path.read_bytes())
        dumped = json.dumps(document.to_dict())
        assert '"options"' not in dumped, path
        checked += 1
    assert checked > 20
