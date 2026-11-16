"""1.16.1 (review High 1, README "Limits"): a repository file over 10 MiB that is agent content is the error `unreadable`
and an incomplete scan (exit 2), with `exclude` as the way out; any other file over 10 MiB stays the notice
`file_too_large` and leaves the exit code alone."""
from __future__ import annotations

import json
import os

import pytest
from conftest import scan_json
from instruction_fixture import INJECTION

from spellwarden_cli.files import FILE_MAX

ELEVEN_MB = 11_000_000
assert ELEVEN_MB > FILE_MAX
CLEAN_MCP = '{"mcpServers": {"docs": {"type": "http", "url": "https://mcp.example.com/mcp"}}}'
SKILL = "---\nname: helper\ndescription: Helps with the build.\n---\n\nRun the tests.\n"


def _big(path, head: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(head.encode("utf-8"))
        handle.truncate(ELEVEN_MB)


def _codes(entries, code):
    return [entry["path"] for entry in entries if entry["code"] == code]


def _repo(make_repo, tmp_path, files, big):
    base = tmp_path / "repo"
    base.mkdir()
    for name, head in big.items():
        _big(base.joinpath(*name.split("/")), head)
    return make_repo(base, files)


def test_an_oversize_agents_md_starting_with_an_injection_is_an_incomplete_scan(make_repo, tmp_path, run_cli):
    repo = _repo(make_repo, tmp_path, {}, {"AGENTS.md": "# Agents\n\n" + INJECTION})
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 2
    assert _codes(report["errors"], "unreadable") == ["AGENTS.md"]
    error = next(e for e in report["errors"] if e["path"] == "AGENTS.md")
    assert "10 MiB" in error["message"] and "exclude" in error["message"]
    assert _codes(report["notices"], "file_too_large") == []
    assert _codes(report["notices"], "no_agent_content") == []  # the repository holds agent content, left unread


def test_a_large_binary_that_is_no_agent_content_stays_a_notice(make_repo, tmp_path, run_cli):
    repo = _repo(make_repo, tmp_path, {".mcp.json": CLEAN_MCP}, {"assets/video.bin": ""})
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 0
    assert _codes(report["notices"], "file_too_large") == ["assets/video.bin"]
    assert report["errors"] == []


@pytest.mark.parametrize("name", [".mcp.json", ".claude/settings.json", "skills/helper/big.md", "skills/helper/SKILL.md",
                                  ".well-known/agent-card.json", "docs/agent-card.json", "plugins/p/data.bin",
                                  ".cursor/rules/big.mdc"])
def test_every_kind_of_agent_content_over_the_limit_is_an_error(make_repo, tmp_path, run_cli, name):
    files = {".mcp.json": CLEAN_MCP, "skills/helper/SKILL.md": SKILL,
             ".claude-plugin/marketplace.json": '{"name": "m", "owner": {"name": "o"}, "plugins": '
                                                '[{"name": "p", "source": "./plugins/p"}]}',
             "plugins/p/.claude-plugin/plugin.json": '{"name": "p"}'}
    files.pop(name, None)
    repo = _repo(make_repo, tmp_path, files, {name: ""})
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 2
    assert _codes(report["errors"], "unreadable") == [name]
    assert _codes(report["notices"], "file_too_large") == []


def test_exclude_is_the_way_out(make_repo, tmp_path, run_cli):
    repo = _repo(make_repo, tmp_path, {".mcp.json": CLEAN_MCP, ".spellwarden/config.yml": 'version: 1\nexclude: ["AGENTS.md"]\n'},
                 {"AGENTS.md": INJECTION})
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 0
    assert report["errors"] == []
    assert _codes(report["notices"], "file_too_large") == []  # an excluded file is not part of the scan


def test_with_instruction_files_off_an_oversize_agents_md_is_a_notice(make_repo, tmp_path, run_cli):
    repo = _repo(make_repo, tmp_path, {".mcp.json": CLEAN_MCP, ".spellwarden/config.yml": "version: 1\ninstructions: false\n"},
                 {"AGENTS.md": INJECTION})
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 0
    assert _codes(report["notices"], "file_too_large") == ["AGENTS.md"]


def test_a_link_at_an_instruction_file_to_an_oversize_file_is_an_error(make_repo, tmp_path, run_cli):
    base = tmp_path / "repo"
    base.mkdir()
    _big(base / "docs" / "everything.md", INJECTION)
    try:
        os.symlink("docs/everything.md", base / "AGENTS.md")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")
    repo = make_repo(base, {".mcp.json": CLEAN_MCP})
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 2
    assert _codes(report["errors"], "unreadable") == ["AGENTS.md"]
    assert _codes(report["notices"], "symlink_skipped") == []
    assert _codes(report["notices"], "file_too_large") == ["docs/everything.md"]  # on its own it is no agent content


@pytest.mark.parametrize("link, listed", [(".well-known/agent-card.json", False), ("cards/agent.json", True)])
def test_a_link_at_an_agent_card_path_to_an_oversize_file_is_the_error_unreadable(make_repo, tmp_path, run_cli, link,
                                                                                   listed):
    # 1.16.1 review: as at every agent-content path (CHANGELOG, README "Limits"), not the card finding SW-A2A-018
    base = tmp_path / "repo"
    (base / os.path.dirname(link)).mkdir(parents=True)
    _big(base / "data" / "card.bin", '{"name": "agent"')
    try:
        os.symlink(os.path.relpath(base / "data" / "card.bin", (base / link).parent), base / link)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")
    files = {".mcp.json": CLEAN_MCP}
    if listed:
        files[".spellwarden/config.yml"] = f'version: 1\na2a:\n  cards: ["{link}"]\n'
    repo = make_repo(base, files)
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 2
    assert _codes(report["errors"], "unreadable") == [link]
    assert "10 MiB" in next(e for e in report["errors"] if e["path"] == link)["message"]
    assert "SW-A2A-018" not in json.dumps(report)
    assert _codes(report["notices"], "file_missing") == [] and _codes(report["notices"], "symlink_skipped") == []
