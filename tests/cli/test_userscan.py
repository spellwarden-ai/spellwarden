"""Phase 3 batch 2a spec 11.2, 11.3, T-1 and T-7: on each system's fixture home, every planted item of every row is found once,
with its clients, kind and home-relative path; links inside the home are followed, others skipped; the limits are errors."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from homes import SYSTEMS, make_home

from spellwarden_cli import clients, userscan

STATE, PLUGINS = "claude-code/state", "claude-code/plugins"
PLUGIN_DIR = "~/.claude/plugins/cache/tools/lint/1.0.0"
OUTSIDE = "outside-home:9a1042f5/app"  # sha256 of "/srv/outside/app", the directory as `.claude.json` writes it
COMMON = [
    ("mcp-config", "~/.claude.json", [STATE]), ("mcp-server", "~/.claude.json#github", [STATE]),
    ("mcp-config", "~/.claude.json#~/work/app", [STATE]), ("mcp-server", "~/.claude.json#~/work/app#db", [STATE]),
    ("mcp-config", f"~/.claude.json#{OUTSIDE}", [STATE]), ("mcp-server", f"~/.claude.json#{OUTSIDE}#db", [STATE]),
    ("settings", "~/.claude/settings.json", ["claude-code/settings"]),
    ("skill", "~/.claude/skills/deploy", ["claude-code/skills", "vscode/claude-skills"]),
    ("instructions", "~/.claude/CLAUDE.md", ["claude-code/memory"]),
    ("instructions", "~/.claude/rules/typescript.md", ["claude-code/rules"]),
    ("plugin", "~/.claude/plugins/installed_plugins.json#lint@tools", [PLUGINS]),
    ("plugin-manifest", f"{PLUGIN_DIR}/.claude-plugin/plugin.json", [PLUGINS]),
    ("mcp-config", f"{PLUGIN_DIR}/.mcp.json", [PLUGINS]), ("mcp-server", f"{PLUGIN_DIR}/.mcp.json#lint-server", [PLUGINS]),
    ("hooks", f"{PLUGIN_DIR}/hooks/hooks.json", [PLUGINS]), ("skill", f"{PLUGIN_DIR}/skills/lint-rules", [PLUGINS]),
    ("marketplace", "~/.claude/plugins/known_marketplaces.json#tools", ["claude-code/marketplaces"]),
    ("mcp-config", "~/.cursor/mcp.json", ["cursor/mcp"]), ("mcp-server", "~/.cursor/mcp.json#search", ["cursor/mcp"]),
    ("hooks", "~/.cursor/hooks.json", ["cursor/hooks"]),
    ("mcp-config", "~/.copilot/mcp-config.json", ["vscode/copilot"]),
    ("mcp-server", "~/.copilot/mcp-config.json#copilot-tools", ["vscode/copilot"]),
    ("skill", "~/.copilot/skills/review", ["vscode/skills"]),
    ("skill", "~/.agents/skills/shared", ["vscode/agents-skills", "windsurf/agents-skills", "codex/skills",
                                          "gemini-cli/agents-skills"]),
    ("mcp-config", "~/.config/devin/mcp_config.json", ["windsurf/mcp"]),
    ("mcp-server", "~/.config/devin/mcp_config.json#tickets", ["windsurf/mcp"]),
    ("instructions", "~/.devin/global_rules.md", ["windsurf/global-rules"]),
    ("instructions", "~/.devin/rules/style.md", ["windsurf/rules"]),
    ("skill", "~/.config/devin/skills/notes", ["windsurf/skills"]),
    ("settings", "~/.codex/config.toml", ["codex/config"]), ("mcp-server", "~/.codex/config.toml#docs", ["codex/config"]),
    ("mcp-server", "~/.codex/config.toml#remote", ["codex/config"]),
    ("plugin", "~/.codex/config.toml#review@tools", ["codex/config"]),
    ("marketplace", "~/.codex/config.toml#tools", ["codex/config"]),
    ("hooks", "~/.codex/hooks.json", ["codex/hooks"]), ("instructions", "~/.codex/AGENTS.md", ["codex/agents"]),
    ("settings", "~/.gemini/settings.json", ["gemini-cli/settings"]),
    *(("mcp-server", f"~/.gemini/settings.json#{name}", ["gemini-cli/settings"]) for name in ("maps", "events", "local")),
    ("instructions", "~/.gemini/GEMINI.md", ["gemini-cli/memory"]),
    ("skill", "~/.gemini/skills/research", ["gemini-cli/skills"]),
    ("plugin", "~/.gemini/extensions/jira", ["gemini-cli/extensions"]),
    ("plugin-manifest", "~/.gemini/extensions/jira/gemini-extension.json", ["gemini-cli/extensions"]),
    ("mcp-server", "~/.gemini/extensions/jira/gemini-extension.json#jira-ext", ["gemini-cli/extensions"]),
    ("hooks", "~/.gemini/extensions/jira/hooks/hooks.json", ["gemini-cli/extensions"]),
    ("instructions", "~/.gemini/extensions/jira/JIRA.md", ["gemini-cli/extensions"]),
]
_PLACES = {"linux": "~/.config", "macos": "~/Library/Application Support", "windows": "~/AppData/Roaming"}


def by_system(system: str) -> list:
    place = _PLACES[system]
    return [
        ("mcp-config", f"{place}/Claude/claude_desktop_config.json", [f"claude-desktop/{system}"]),
        ("mcp-server", f"{place}/Claude/claude_desktop_config.json#weather", [f"claude-desktop/{system}"]),
        ("mcp-config", f"{place}/Code/User/mcp.json", [f"vscode/{system}"]),
        ("mcp-server", f"{place}/Code/User/mcp.json#fs", [f"vscode/{system}"]),
        ("mcp-config", f"{place}/Code/User/profiles/work/mcp.json", [f"vscode/{system}"]),
        ("mcp-server", f"{place}/Code/User/profiles/work/mcp.json#jira", [f"vscode/{system}"]),
    ]


def expected(system: str) -> set[tuple[str, str, tuple[str, ...]]]:
    """The planted items whose rows the table still holds (a row dropped at build time drops its items, D21)."""
    rows = {row.id: row for row in clients.ROWS}
    found = set()
    for kind, path, ids in COMMON + by_system(system):
        kept = {rows[row_id].client for row_id in ids if row_id in rows}
        if kept:
            found.add((kind, path, tuple(client for client in clients.CLIENTS if client in kept)))
    return found


@pytest.mark.parametrize("system", SYSTEMS)
def test_every_planted_item_of_every_row_is_found_once_with_its_clients(tmp_path, system):
    home = make_home(tmp_path, system)
    discovered = userscan.discover_home(str(home), system, {})
    items = [(item.kind, item.path, item.clients) for item in discovered.found.items]
    assert len(items) == len(set(items))
    assert set(items) == expected(system)
    assert discovered.found.errors == () and discovered.found.notices == ()
    assert [entry["client"] for entry in discovered.clients] == list(clients.CLIENTS)
    assert all(entry["found"] for entry in discovered.clients) and discovered.not_found == ()
    scopes = {item.path: item.scope for item in discovered.found.items if item.scope is not None}
    assert scopes == {"~/.claude.json#~/work/app": "~/work/app", "~/.claude.json#~/work/app#db": "~/work/app",
                      f"~/.claude.json#{OUTSIDE}": OUTSIDE, f"~/.claude.json#{OUTSIDE}#db": OUTSIDE}


def test_every_row_has_a_planted_item_on_its_systems():
    for system in SYSTEMS:
        planted = {row_id for _, _, ids in COMMON + by_system(system) for row_id in ids}
        missing = [row.id for row in clients.rows_for(system) if row.id not in planted]
        assert missing == [], (system, missing)


def test_a_home_without_any_client_file_finds_no_client(tmp_path):
    (tmp_path / "home").mkdir()
    discovered = userscan.discover_home(str(tmp_path / "home"), "linux", {})
    assert discovered.found.items == () and discovered.not_found == clients.CLIENTS
    assert [entry["found"] for entry in discovered.clients] == [False] * len(clients.CLIENTS)
    assert [notice.code for notice in discovered.found.notices] == ["no_agent_content"]


def test_a_base_variable_moves_the_files_it_names(tmp_path):
    home = make_home(tmp_path, "linux")
    moved = tmp_path / "elsewhere"
    (home / ".codex").rename(moved)
    discovered = userscan.discover_home(str(home), "linux", {"CODEX_HOME": str(moved)})
    paths = {item.path for item in discovered.found.items}
    assert "$CODEX_HOME/config.toml#docs" in paths and "~/.codex/config.toml#docs" not in paths


def _link(target: Path, link: Path, *, directory: bool) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except OSError as exc:  # Windows without the privilege to create links
        pytest.skip(f"symbolic links are not available here ({exc})")


def test_links_to_directories_inside_the_home_are_read_as_the_table_paths(tmp_path):
    home = make_home(tmp_path, "linux")
    dotfiles = home / "dotfiles"
    dotfiles.mkdir()
    (home / ".codex").rename(dotfiles / "codex")
    _link(dotfiles / "codex", home / ".codex", directory=True)
    (home / ".gemini" / "skills").rename(dotfiles / "gemini-skills")
    _link(dotfiles / "gemini-skills", home / ".gemini" / "skills", directory=True)
    (home / ".claude" / "skills" / "deploy").rename(dotfiles / "deploy")
    _link(dotfiles / "deploy", home / ".claude" / "skills" / "deploy", directory=True)
    discovered = userscan.discover_home(str(home), "linux", {})
    items = {(item.kind, item.path, item.clients) for item in discovered.found.items}
    assert items == expected("linux")
    assert not any("dotfiles" in item.path for item in discovered.found.items)


def test_a_link_out_of_the_home_or_dangling_is_skipped_with_a_notice(tmp_path):
    home = make_home(tmp_path, "linux")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "mcp.json").write_text('{"mcpServers": {"x": {"command": "npx", "args": ["x@1.0.0"]}}}', encoding="utf-8")
    (home / ".cursor" / "mcp.json").unlink()
    _link(outside / "mcp.json", home / ".cursor" / "mcp.json", directory=False)
    (home / ".gemini" / "GEMINI.md").unlink()
    _link(home / "missing", home / ".gemini" / "GEMINI.md", directory=False)
    discovered = userscan.discover_home(str(home), "linux", {})
    paths = {item.path for item in discovered.found.items}
    assert "~/.cursor/mcp.json" not in paths and "~/.gemini/GEMINI.md" not in paths
    skipped = {notice.path for notice in discovered.found.notices if notice.code == "symlink_skipped"}
    assert {"~/.cursor/mcp.json", "~/.gemini/GEMINI.md"} <= skipped
    assert discovered.found.errors == ()


def test_a_client_base_directory_that_is_a_link_out_of_the_home_is_skipped_and_one_inside_is_read(tmp_path):
    home = make_home(tmp_path, "linux")
    outside = tmp_path / "outside"
    (home / ".claude").rename(outside)
    _link(outside, home / ".claude", directory=True)
    discovered = userscan.discover_home(str(home), "linux", {})
    paths = {item.path for item in discovered.found.items}
    assert not any(path.startswith("~/.claude/") for path in paths)
    skipped = {notice.path for notice in discovered.found.notices if notice.code == "symlink_skipped"}
    assert "~/.claude" in skipped
    assert discovered.found.errors == ()
    (home / ".claude").unlink()
    dotfiles = home / "dotfiles"
    dotfiles.mkdir()
    outside.rename(dotfiles / "claude")
    _link(dotfiles / "claude", home / ".claude", directory=True)
    inside = userscan.discover_home(str(home), "linux", {})
    assert {(item.kind, item.path, item.clients) for item in inside.found.items} == expected("linux")


def test_more_than_300_instruction_files_of_one_client_is_an_error(tmp_path):
    home = make_home(tmp_path, "linux")
    for number in range(301):
        (home / ".claude" / "rules" / f"r{number:03d}.md").write_text("# Rule\n", encoding="utf-8")
    found = userscan.discover_home(str(home), "linux", {}).found
    (error,) = [e for e in found.errors if e.code == "user_instructions_limit"]
    assert "3 more instruction files of Claude Code were not read" in error.message and "at most 300" in error.message
    assert sum(1 for item in found.items if item.kind == "instructions" and "claude-code" in item.clients) == 300


def test_more_than_1000_skills_in_one_skills_directory_is_an_error(tmp_path):
    home = make_home(tmp_path, "linux")
    for number in range(1000):
        skill = home / ".gemini" / "skills" / f"s{number:04d}"
        skill.mkdir()
        (skill / "SKILL.md").write_text("---\nname: s\ndescription: d\n---\n", encoding="utf-8")
    found = userscan.discover_home(str(home), "linux", {}).found
    (error,) = [e for e in found.errors if e.code == "user_skills_limit"]
    assert error.path == "~/.gemini/skills" and error.message.startswith("1 more skills were not read")


def test_a_client_file_that_cannot_be_read_is_an_error_with_its_path(tmp_path):
    home = make_home(tmp_path, "linux")
    (home / ".cursor" / "mcp.json").unlink()
    (home / ".cursor" / "mcp.json").mkdir()
    found = userscan.discover_home(str(home), "linux", {}).found
    assert [(e.code, e.path) for e in found.errors] == [("unreadable", "~/.cursor/mcp.json")]


def _skill(directory: Path) -> None:
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text("---\nname: s\ndescription: d\n---\n", encoding="utf-8")


def test_a_directory_several_clients_read_names_only_the_clients_found_by_their_own_files(tmp_path):
    home = tmp_path / "home"
    _skill(home / ".claude" / "skills" / "deploy")  # Claude Code's own directory, which VS Code reads too
    _skill(home / ".agents" / "skills" / "shared")  # read by VS Code, Windsurf, Codex and Gemini CLI
    (home / ".codex").mkdir()
    (home / ".codex" / "AGENTS.md").write_text("# Codex\n", encoding="utf-8")
    discovered = userscan.discover_home(str(home), "linux", {})
    assert [entry["client"] for entry in discovered.clients if entry["found"]] == ["claude-code", "codex"]
    clients_of = {item.path: item.clients for item in discovered.found.items}
    assert clients_of["~/.claude/skills/deploy"] == ("claude-code",) and clients_of["~/.agents/skills/shared"] == ("codex",)
    assert discovered.not_found == ("claude-desktop", "cursor", "vscode", "windsurf", "gemini-cli")
    assert {entry["client"]: entry["roots"] for entry in discovered.clients}["vscode"] == []


def test_a_shared_directory_alone_is_listed_for_every_client_that_reads_it(tmp_path):
    home = tmp_path / "home"
    _skill(home / ".agents" / "skills" / "shared")
    discovered = userscan.discover_home(str(home), "linux", {})
    assert [item.clients for item in discovered.found.items] == [("vscode", "windsurf", "codex", "gemini-cli")]
    assert [entry["client"] for entry in discovered.clients if entry["found"]] == ["vscode", "windsurf", "codex", "gemini-cli"]


def test_a_project_that_is_the_home_itself_has_a_scope_the_upload_accepts(tmp_path):
    home = make_home(tmp_path, "linux")
    state = home / ".claude.json"
    data = json.loads(state.read_text(encoding="utf-8"))
    data["projects"][str(home)] = {"mcpServers": {"here": {"command": "npx", "args": ["here-mcp@1.0.0"]}}}
    state.write_text(json.dumps(data), encoding="utf-8")
    scopes = {item.path: item.scope for item in userscan.discover_home(str(home), "linux", {}).found.items if item.scope}
    assert scopes["~/.claude.json#~/#here"] == "~/"  # spec 6.3: a scope starts with `~/` or `outside-home:`, never a bare `~`


def test_a_skill_file_over_the_size_limit_is_an_error_and_never_a_skip(tmp_path, monkeypatch):
    home = make_home(tmp_path, "linux")
    monkeypatch.setattr(userscan, "FILE_MAX", 64)  # the limit of a skill's members; the table's files keep their 10 MiB
    (home / ".gemini" / "skills" / "research" / "big.bin").write_bytes(b"x" * 65)
    found = userscan.discover_home(str(home), "linux", {}).found
    assert ("unreadable", "~/.gemini/skills/research/big.bin") in [(e.code, e.path) for e in found.errors]
    assert not [notice for notice in found.notices if notice.code == "file_too_large"]
