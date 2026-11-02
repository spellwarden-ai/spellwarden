"""SW-CFG-014 discovery: configuration copies (`.mcp.json.bak`, `.vscode/mcp.json.old`, ...) are documents of their own
kind that only SW-CFG-014 reads. No existing rule, item, lock entry, count, exit code or output field changes because a
copy exists. The byte-identity tests run the real command."""
from __future__ import annotations

import json

import pytest

from spellwarden_scan import RuleSet

from spellwarden_cli.discover import discover
from spellwarden_cli.files import list_files
from spellwarden_cli.run import engine_findings
from spellwarden_cli.settings import Settings

PLAIN_HTTP = json.dumps({"mcpServers": {"api": {"type": "http", "url": "http://mcp.example.com/api"}}}, indent=2)
SAFE = json.dumps({"mcpServers": {"api": {"type": "http", "url": "https://mcp.example.com/api",
                                          "headers": {"Authorization": "Bearer ${API_TOKEN}"}}}}, indent=2)
PLACEHOLDERS = json.dumps({"mcpServers": {"api": {"command": "npx", "args": ["-y", "some-server"],
                                                   "env": {"API_KEY": "<your-api-key>", "TOKEN": "${TOKEN}"}}}}, indent=2)
SKILL = "---\nname: demo\ndescription: A demo skill.\n---\n\nRead the task.\n"


def rules_with_cfg_014() -> RuleSet:
    return RuleSet.baseline()


def rules_without_cfg_014() -> RuleSet:
    return RuleSet(rule for rule in RuleSet.baseline() if rule.id != "SW-CFG-014")


def _discover(root):
    return discover(list_files(str(root), Settings()))


def _copy_paths(found):
    return [document.path for document in found.config_copies]


def test_copy_names_are_found_at_any_depth_and_only_under_the_client_directories(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {
        ".mcp.json.bak": PLAIN_HTTP, "deep/er/.mcp.json.disabled": PLAIN_HTTP,
        ".vscode/mcp.json.old": PLAIN_HTTP, "app/.cursor/mcp.json.full": PLAIN_HTTP,
        "mcp.json.bak": PLAIN_HTTP, "docs/mcp.json.bak": PLAIN_HTTP, ".mcp.json.": PLAIN_HTTP, ".mcp.jsonx": PLAIN_HTTP,
        "other/.vscode/settings.json.bak": PLAIN_HTTP,
    })
    found = _discover(repo)
    assert _copy_paths(found) == [".mcp.json.bak", ".vscode/mcp.json.old", "app/.cursor/mcp.json.full",
                                  "deep/er/.mcp.json.disabled"]
    assert {document.kind for document in found.config_copies} == {"mcp_copy"}
    assert found.documents == ()
    assert found.items == ()
    assert found.errors == ()


def test_a_copy_that_does_not_parse_or_has_no_server_map_is_skipped_silently(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {
        "SKILL.md": SKILL, ".mcp.json.template": '{"mcpServers": {{ servers }}}', ".mcp.json.empty": "",
        ".mcp.json.list": "[]", ".mcp.json.vscode": json.dumps({"servers": {"a": {"url": "http://mcp.example.com"}}}),
        ".mcp.json.string": json.dumps({"mcpServers": "x"}), ".mcp.json.dup": '{"mcpServers": {"a": {}, "a": {}}}',
        ".mcp.json.big": " " * (1024 * 1024 + 10) + "{}",
    })
    without = _discover(make_repo(tmp_path / "plain", {"SKILL.md": SKILL}))
    found = _discover(repo)
    assert found.config_copies == ()
    assert (found.errors, found.notices, found.items) == (without.errors, without.notices, without.items)


def test_a_copy_with_an_empty_server_map_is_a_document_with_no_servers(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".mcp.json.bak": json.dumps({"mcpServers": {}})})
    (document,) = _discover(repo).config_copies
    assert (document.kind, document.error, document.servers) == ("mcp_copy", None, ())


def test_copies_change_nothing_a_discovery_reports(make_repo, tmp_path):
    base = {".claude/skills/demo/SKILL.md": SKILL, ".mcp.json": SAFE}
    plain = _discover(make_repo(tmp_path / "plain", base))
    with_copies = _discover(make_repo(tmp_path / "copies", {**base, ".mcp.json.bak": PLAIN_HTTP,
                                                            ".vscode/mcp.json.old": PLAIN_HTTP}))
    assert with_copies.documents == plain.documents
    assert (with_copies.items, with_copies.skills, with_copies.plugin_dirs) == (plain.items, plain.skills, plain.plugin_dirs)
    assert (with_copies.notices, with_copies.errors, with_copies.agent_cards) == (plain.notices, plain.errors, plain.agent_cards)
    assert len(with_copies.config_copies) == 2


def test_a_copy_is_no_agent_content(make_repo, tmp_path):
    found = _discover(make_repo(tmp_path / "repo", {".mcp.json.bak": PLAIN_HTTP}))
    assert [notice.code for notice in found.notices] == ["no_agent_content"]


def test_a_copy_is_read_from_its_own_bytes_never_through_a_link(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".mcp.json.bak": PLAIN_HTTP})
    (document,) = _discover(repo).config_copies
    assert [server.name for server in document.servers] == ["api"]
    assert document.servers[0].line == 3


def test_the_same_insecure_server_is_a_finding_of_the_original_and_of_the_copy_by_different_rules(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".mcp.json": PLAIN_HTTP, ".mcp.json.bak": PLAIN_HTTP})
    found = _discover(repo)
    reported = [(f.finding.rule_id, f.finding.location.path) for f in engine_findings(found, rules_with_cfg_014(), [])]
    assert sorted(reported) == [("SW-CFG-001", ".mcp.json"), ("SW-CFG-014", ".mcp.json.bak")]


def test_a_repository_with_only_a_copy_still_yields_the_copys_finding(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".vscode/mcp.json.bak": PLAIN_HTTP})
    found = _discover(repo)
    reported = [(f.finding.rule_id, f.finding.location.path) for f in engine_findings(found, rules_with_cfg_014(), [])]
    assert reported == [("SW-CFG-014", ".vscode/mcp.json.bak")]


def test_no_other_rule_reads_anything_from_a_copy(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".mcp.json": SAFE, ".mcp.json.bak": PLAIN_HTTP})
    assert engine_findings(_discover(repo), rules_without_cfg_014(), []) == []


def test_a_copy_beside_a_clean_configuration_is_not_a_judged_document(make_repo, tmp_path):
    from spellwarden_scan import scan_agent_config

    repo = make_repo(tmp_path / "repo", {".mcp.json": SAFE, ".mcp.json.bak": PLAIN_HTTP})
    found = _discover(repo)
    result = scan_agent_config([*found.documents, *found.config_copies], rules_with_cfg_014())
    assert result.documents == (".mcp.json",)
    assert [f.rule_id for f in result.findings] == ["SW-CFG-014"]


def _scan(run_cli, repo, tmp_path, name):
    out_json, out_sarif = tmp_path / f"{name}.json", tmp_path / f"{name}.sarif"
    code, stdout, _stderr = run_cli(["scan", str(repo), "--as-of", "2026-12-01", "--format", "json", "--output", str(out_json),
                                    "--format", "sarif", "--output", str(out_sarif)])
    return code, stdout, out_json.read_bytes(), out_sarif.read_bytes()


@pytest.mark.parametrize("copy", [SAFE, PLACEHOLDERS, json.dumps({"mcpServers": {}}), '{"mcpServers": {{ template }}}'])
def test_a_copy_with_no_finding_leaves_json_and_sarif_byte_identical(make_repo, run_cli, tmp_path, copy):
    base = {".claude/skills/demo/SKILL.md": SKILL, ".mcp.json": SAFE}
    plain = make_repo(tmp_path / "plain", base)
    copied = make_repo(tmp_path / "copied", {**base, ".mcp.json.bak": copy, ".vscode/mcp.json.old": copy})
    assert _scan(run_cli, plain, tmp_path, "plain") == _scan(run_cli, copied, tmp_path, "copied")


def test_a_copy_does_not_change_the_lock_file(make_repo, run_cli, tmp_path):
    base = {".claude/skills/demo/SKILL.md": SKILL, ".mcp.json": SAFE}
    plain = make_repo(tmp_path / "plain", base)
    copied = make_repo(tmp_path / "copied", {**base, ".mcp.json.bak": PLAIN_HTTP})
    for repo in (plain, copied):
        assert run_cli(["lock", str(repo)])[0] == 0
    assert (plain / ".spellwarden/lock.json").read_bytes() == (copied / ".spellwarden/lock.json").read_bytes()
