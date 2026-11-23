"""Engine 1.20.0 (owner decision spec:Q1, spec 7.19; claims C43, C44, C45, C47): SW-CFG-012 and SW-CFG-013 judge the MCP
servers of settings documents, Codex's `config.toml` and Gemini CLI's `settings.json`, in a repository and in a home; a finding on
a home configuration document carries no evidence and no canary reaches a report."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from conftest import scan_json

from spellwarden_cli import userscan
from spellwarden_cli.output import json_out
from spellwarden_cli.settings import Settings

CODEX = '''[mcp_servers.docs]
url = "https://docs.example.com/mcp"
default_tools_approval_mode = "approve"

[mcp_servers.docs.tools.search_docs]
approval_mode = "approve"

[mcp_servers.docs.tools.delete_page]
approval_mode = "approve"

[mcp_servers.db]
url = "https://mcp.supabase.com/mcp?project_ref=demo"

[mcp_servers.off]
url = "https://mcp.supabase.com/mcp?project_ref=off"
enabled = false
'''


def gemini(trust: bool) -> str:
    server = {"httpUrl": "https://maps.example.com/mcp", "trust": True} if trust else {"httpUrl": "https://maps.example.com/mcp"}
    return json.dumps({"mcpServers": {"maps": server}}, indent=2)


def _found(report: dict, rule: str) -> list[tuple[str, int]]:
    return sorted((f["location"]["path"], f["location"]["line"]) for f in report["findings"] if f["rule_id"] == rule)


def test_a_repository_s_codex_and_gemini_servers_are_judged_by_both_rules(make_repo, tmp_path, run_cli):
    repo = make_repo(tmp_path / "repo", {".codex/config.toml": CODEX, ".gemini/settings.json": gemini(True),
                                         "tests/.codex/config.toml": CODEX})
    code, report, _out, _err = scan_json(run_cli, repo)
    assert _found(report, "SW-CFG-012") == [(".codex/config.toml", 3), (".codex/config.toml", 9),
                                            (".gemini/settings.json", 5), ("tests/.codex/config.toml", 3),
                                            ("tests/.codex/config.toml", 9)]
    assert _found(report, "SW-CFG-013") == [(".codex/config.toml", 11)]  # `off` is disabled; `tests/` stays quiet
    assert {f["severity"] for f in report["findings"] if f["rule_id"] in ("SW-CFG-012", "SW-CFG-013")} == {"high"}
    assert code == 1


def test_a_settings_file_a_plugin_names_as_its_servers_gets_both_rules(make_repo, tmp_path, run_cli):
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "p", "source": "./.claude"}]}),
        ".claude/.claude-plugin/plugin.json": json.dumps({"name": "p", "mcpServers": "settings.json"}),
        ".claude/settings.json": json.dumps({"mcpServers": {
            "db": {"type": "http", "url": "https://mcp.supabase.com/mcp?project_ref=x", "trust": True}}}, indent=2),
    })
    _code, report, _out, _err = scan_json(run_cli, repo)
    assert _found(report, "SW-CFG-012") == [(".claude/settings.json", 6)]
    assert _found(report, "SW-CFG-013") == [(".claude/settings.json", 3)]


def test_the_selection_fixture_gets_both_rules_on_its_settings_documents(run_cli, tmp_path, make_repo):
    source = Path(__file__).resolve().parents[2] / "fixtures" / "selection"
    files = {path.relative_to(source).as_posix(): path.read_bytes() for path in source.rglob("*") if path.is_file()}
    _code, report, _out, _err = scan_json(run_cli, make_repo(tmp_path / "repo", files))
    assert (".gemini/settings.json", 3) in _found(report, "SW-CFG-012")
    assert (".codex/config.toml", 6) in _found(report, "SW-CFG-012")
    assert (".codex/config.toml", 8) in _found(report, "SW-CFG-013")


def _user_scan(home: Path):
    report, _ = userscan.scan(str(home), "linux", {}, settings=Settings(telemetry=False), as_of=date(2026, 11, 23),
                              inventory=False)
    return report


def test_a_home_gemini_server_with_trust_fails_a_scan_that_passed_and_carries_no_evidence(tmp_path):
    clean, trusted = tmp_path / "clean", tmp_path / "trusted"
    for home, trust in ((clean, False), (trusted, True)):
        (home / ".gemini").mkdir(parents=True)
        (home / ".gemini" / "settings.json").write_text(gemini(trust), encoding="utf-8")
    assert _user_scan(clean).exit_code() == 0
    report = _user_scan(trusted)
    (finding,) = [f for f in report.findings if f.finding.rule_id == "SW-CFG-012"]
    assert (finding.finding.severity, finding.finding.location.path, finding.finding.location.line) == (
        "high", "~/.gemini/settings.json", 5)
    assert finding.finding.evidence == "" and report.exit_code() == 1


def test_a_finding_on_a_fixture_home_server_carries_no_evidence_and_no_canary(tmp_path):
    from homes import CANARIES, make_home

    home = make_home(tmp_path, "linux")
    path = home / ".gemini" / "settings.json"
    settings = json.loads(path.read_text(encoding="utf-8"))
    settings["mcpServers"]["maps"]["trust"] = True  # beside the fixture's header and query canaries
    path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    report = _user_scan(home)
    found = [f for f in report.findings if f.finding.rule_id == "SW-CFG-012"]
    assert [f.finding.location.path for f in found] == ["~/.gemini/settings.json"] and found[0].finding.evidence == ""
    text = json_out.render(report)
    assert not [canary for canary in CANARIES if canary in text]


def test_a_home_codex_server_set_to_approve_or_with_write_access_is_judged(tmp_path):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text(CODEX, encoding="utf-8")
    report = _user_scan(home)
    found = sorted((f.finding.rule_id, f.finding.location.line, f.finding.evidence) for f in report.findings
                   if f.finding.rule_id in ("SW-CFG-012", "SW-CFG-013"))
    assert found == [("SW-CFG-012", 3, ""), ("SW-CFG-012", 9, ""), ("SW-CFG-013", 11, "")]
    assert report.exit_code() == 1
