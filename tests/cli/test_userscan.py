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
CURSOR_PLUGIN = "~/.cursor/plugins/local/notes"
COPILOT_PLUGIN = "~/.copilot/installed-plugins/tools/formatter"
CODEX_PLUGIN = "~/.codex/plugins/cache/tools/review/1.0.0"
OUTSIDE = "outside-home:9a1042f5/app"  # sha256 of "/srv/outside/app", the directory as `.claude.json` writes it
COMMON = [
    ("mcp-config", "~/.claude.json", [STATE]), ("mcp-server", "~/.claude.json#github", [STATE]),
    ("mcp-config", "~/.claude.json#~/work/app", [STATE]), ("mcp-server", "~/.claude.json#~/work/app#db", [STATE]),
    ("mcp-config", f"~/.claude.json#{OUTSIDE}", [STATE]), ("mcp-server", f"~/.claude.json#{OUTSIDE}#db", [STATE]),
    ("settings", "~/.claude/settings.json", ["claude-code/settings"]),
    ("skill", "~/.claude/skills/deploy", ["claude-code/skills", "vscode/claude-skills", "cursor/claude-skills"]),
    ("instructions", "~/.claude/CLAUDE.md", ["claude-code/memory", "vscode/claude-memory"]),
    ("instructions", "~/.claude/rules/typescript.md", ["claude-code/rules", "vscode/claude-rules"]),
    ("instructions", "~/.claude/rules/frontend/react.md", ["claude-code/rules", "vscode/claude-rules"]),
    ("instructions", "~/.claude/commands/deploy.md", ["claude-code/commands"]),
    ("instructions", "~/.claude/commands/ops/restart.md", ["claude-code/commands"]),
    ("instructions", "~/.claude/agents/reviewer.md", ["claude-code/agents", "cursor/claude-agents", "vscode/claude-agents"]),
    ("instructions", "~/.claude/output-styles/terse.md", ["claude-code/output-styles"]),
    ("plugin", "~/.claude/plugins/installed_plugins.json#lint@tools", [PLUGINS]),
    ("plugin-manifest", f"{PLUGIN_DIR}/.claude-plugin/plugin.json", [PLUGINS]),
    ("mcp-config", f"{PLUGIN_DIR}/.mcp.json", [PLUGINS]), ("mcp-server", f"{PLUGIN_DIR}/.mcp.json#lint-server", [PLUGINS]),
    ("hooks", f"{PLUGIN_DIR}/hooks/hooks.json", [PLUGINS]), ("skill", f"{PLUGIN_DIR}/skills/lint-rules", [PLUGINS]),
    ("instructions", f"{PLUGIN_DIR}/commands/fix.md", [PLUGINS]), ("instructions", f"{PLUGIN_DIR}/agents/linter.md", [PLUGINS]),
    ("marketplace", "~/.claude/plugins/known_marketplaces.json#tools", ["claude-code/marketplaces"]),
    ("mcp-config", "~/.cursor/mcp.json", ["cursor/mcp"]), ("mcp-server", "~/.cursor/mcp.json#search", ["cursor/mcp"]),
    ("hooks", "~/.cursor/hooks.json", ["cursor/hooks"]),
    ("skill", "~/.cursor/skills/refactor", ["cursor/skills"]),
    ("instructions", "~/.cursor/agents/planner.md", ["cursor/agents"]),
    ("instructions", "~/.codex/agents/helper.md", ["cursor/codex-agents"]),
    ("skill", "~/.codex/skills/migrate", ["cursor/codex-skills", "windsurf/codex-skills"]),
    ("plugin", CURSOR_PLUGIN, ["cursor/plugins"]),
    ("plugin-manifest", f"{CURSOR_PLUGIN}/.cursor-plugin/plugin.json", ["cursor/plugins"]),
    ("mcp-config", f"{CURSOR_PLUGIN}/mcp.json", ["cursor/plugins"]),
    ("mcp-server", f"{CURSOR_PLUGIN}/mcp.json#notes-server", ["cursor/plugins"]),
    ("hooks", f"{CURSOR_PLUGIN}/hooks/hooks.json", ["cursor/plugins"]),
    ("instructions", f"{CURSOR_PLUGIN}/rules/style.mdc", ["cursor/plugins"]),
    ("instructions", f"{CURSOR_PLUGIN}/agents/scribe.md", ["cursor/plugins"]),
    ("instructions", f"{CURSOR_PLUGIN}/commands/summarise.md", ["cursor/plugins"]),
    ("mcp-config", "~/.copilot/mcp-config.json", ["vscode/copilot"]),
    ("mcp-server", "~/.copilot/mcp-config.json#copilot-tools", ["vscode/copilot"]),
    ("skill", "~/.copilot/skills/review", ["vscode/skills", "windsurf/copilot-skills"]),
    ("instructions", "~/.copilot/copilot-instructions.md", ["vscode/instructions"]),
    ("instructions", "~/.copilot/instructions/python.instructions.md", ["vscode/instruction-files"]),
    ("instructions", "~/.copilot/agents/reviewer.agent.md", ["vscode/agents"]),
    ("hooks", "~/.copilot/hooks/audit.json", ["vscode/hooks"]),
    ("settings", "~/.copilot/settings.json", ["vscode/settings"]),
    ("plugin", COPILOT_PLUGIN, ["vscode/plugins"]),
    ("plugin-manifest", f"{COPILOT_PLUGIN}/plugin.json", ["vscode/plugins"]),
    ("mcp-config", f"{COPILOT_PLUGIN}/.mcp.json", ["vscode/plugins"]),
    ("mcp-server", f"{COPILOT_PLUGIN}/.mcp.json#fmt", ["vscode/plugins"]),
    ("instructions", f"{COPILOT_PLUGIN}/agents/fmt.md", ["vscode/plugins"]),
    ("skill", "~/.agents/skills/shared", ["cursor/agents-skills", "vscode/agents-skills", "windsurf/agents-skills", "codex/skills",
                                          "gemini-cli/agents-skills"]),
    ("instructions", "~/.devin/global_rules.md", ["windsurf/global-rules"]),
    ("instructions", "~/.devin/rules/style.md", ["windsurf/rules"]),
    ("mcp-config", "~/.codeium/windsurf/mcp_config.json", ["windsurf/codeium-mcp"]),
    ("mcp-server", "~/.codeium/windsurf/mcp_config.json#legacy", ["windsurf/codeium-mcp"]),
    ("skill", "~/.codeium/windsurf/skills/legacy", ["windsurf/codeium-skills"]),
    ("settings", "~/.codex/config.toml", ["codex/config"]), ("mcp-server", "~/.codex/config.toml#docs", ["codex/config"]),
    ("mcp-server", "~/.codex/config.toml#remote", ["codex/config"]),
    ("plugin", "~/.codex/config.toml#plugins.review@tools", ["codex/config"]),
    ("marketplace", "~/.codex/config.toml#marketplaces.tools", ["codex/config"]),
    ("hooks", "~/.codex/hooks.json", ["codex/hooks"]), ("instructions", "~/.codex/AGENTS.md", ["codex/agents"]),
    ("instructions", "~/.codex/prompts/release.md", ["codex/prompts"]),
    ("plugin", CODEX_PLUGIN, ["codex/plugins"]),
    ("plugin-manifest", f"{CODEX_PLUGIN}/.codex-plugin/plugin.json", ["codex/plugins"]),
    ("mcp-config", f"{CODEX_PLUGIN}/.mcp.json", ["codex/plugins"]),
    ("mcp-server", f"{CODEX_PLUGIN}/.mcp.json#review-server", ["codex/plugins"]),
    ("skill", f"{CODEX_PLUGIN}/skills/review-skill", ["codex/plugins"]),
    ("settings", "~/.gemini/settings.json", ["gemini-cli/settings"]),
    *(("mcp-server", f"~/.gemini/settings.json#{name}", ["gemini-cli/settings"]) for name in ("maps", "events", "local")),
    ("instructions", "~/.gemini/GEMINI.md", ["gemini-cli/memory"]),
    ("skill", "~/.gemini/skills/research", ["gemini-cli/skills"]),
    ("instructions", "~/.gemini/agents/researcher.md", ["gemini-cli/agents"]),
    ("plugin", "~/.gemini/extensions/jira", ["gemini-cli/extensions"]),
    ("plugin-manifest", "~/.gemini/extensions/jira/gemini-extension.json", ["gemini-cli/extensions"]),
    ("mcp-server", "~/.gemini/extensions/jira/gemini-extension.json#jira-ext", ["gemini-cli/extensions"]),
    ("hooks", "~/.gemini/extensions/jira/hooks/hooks.json", ["gemini-cli/extensions"]),
    ("instructions", "~/.gemini/extensions/jira/JIRA.md", ["gemini-cli/extensions"]),
    ("skill", "~/.gemini/extensions/jira/skills/ticket", ["gemini-cli/extensions"]),
    ("instructions", "~/.gemini/extensions/jira/agents/triager.md", ["gemini-cli/extensions"]),
]
_PLACES = {"linux": "~/.config", "macos": "~/Library/Application Support", "windows": "~/AppData/Roaming"}


def by_system(system: str) -> list:
    place = _PLACES[system]
    # Engine 1.20.0 (7.9, D19): the Devin folder is `$XDG_CONFIG_HOME/devin/` on Linux and macOS (`~/.config/devin/` here) and
    # `%APPDATA%/devin/` on Windows, where `~/.config/devin/` of the common home is no longer read
    devin, twin = ("~/AppData/Roaming/devin", "-windows") if system == "windows" else ("~/.config/devin", "")
    agent = f"{devin}/agents/triage/AGENT.md" if system == "windows" else f"{devin}/agents/triage.md"
    return [
        ("mcp-config", f"{place}/Claude/claude_desktop_config.json", [f"claude-desktop/{system}"]),
        ("mcp-server", f"{place}/Claude/claude_desktop_config.json#weather", [f"claude-desktop/{system}"]),
        ("mcp-config", f"{place}/Code/User/mcp.json", [f"vscode/{system}"]),
        ("mcp-server", f"{place}/Code/User/mcp.json#fs", [f"vscode/{system}"]),
        ("mcp-config", f"{place}/Code/User/profiles/work/mcp.json", [f"vscode/{system}"]),
        ("mcp-server", f"{place}/Code/User/profiles/work/mcp.json#jira", [f"vscode/{system}"]),
        # phase 3 batch 2c spec 11.3 (F2): the four paths of the VS Code rows, with two profile folders each
        ("mcp-config", f"{place}/Code/User/profiles/personal/mcp.json", [f"vscode/{system}"]),
        ("mcp-server", f"{place}/Code/User/profiles/personal/mcp.json#memory", [f"vscode/{system}"]),
        ("mcp-config", f"{place}/Code - Insiders/User/mcp.json", [f"vscode/{system}"]),
        ("mcp-server", f"{place}/Code - Insiders/User/mcp.json#git", [f"vscode/{system}"]),
        ("mcp-config", f"{place}/Code - Insiders/User/profiles/work/mcp.json", [f"vscode/{system}"]),
        ("mcp-server", f"{place}/Code - Insiders/User/profiles/work/mcp.json#fetch", [f"vscode/{system}"]),
        ("mcp-config", f"{place}/Code - Insiders/User/profiles/personal/mcp.json", [f"vscode/{system}"]),
        ("mcp-server", f"{place}/Code - Insiders/User/profiles/personal/mcp.json#time", [f"vscode/{system}"]),
        ("mcp-config", f"{devin}/mcp_config.json", [f"windsurf/mcp{twin}"]),
        ("mcp-server", f"{devin}/mcp_config.json#tickets", [f"windsurf/mcp{twin}"]),
        ("skill", f"{devin}/skills/notes", [f"windsurf/skills{twin}"]),
        ("instructions", f"{devin}/AGENTS.md", [f"windsurf/agents-md{twin}"]),
        ("instructions", agent, [f"windsurf/agents{twin}"]),
        ("settings", f"{devin}/config.json", [f"windsurf/config{twin}"]),
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


def test_a_link_out_of_the_home_is_an_error_and_a_dangling_one_a_notice(tmp_path):
    # 1.16.1 (review Medium 9): D39 still does not follow a link out of the home, but what it leads to is content the client
    # loads and the scan did not judge, so it is the error `unreadable` (an incomplete scan); a dangling link leads nowhere
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
    assert "~/.gemini/GEMINI.md" in skipped and "~/.cursor/mcp.json" not in skipped
    (error,) = discovered.found.errors
    assert (error.code, error.path) == ("unreadable", "~/.cursor/mcp.json")
    assert "outside the home directory" in error.message and "not judged" in error.message


def test_links_inside_a_skill_out_of_the_home_or_to_a_directory_are_errors_and_dangling_ones_notices(tmp_path):
    # 1.16.1 (review Medium 9): a Nix home-manager skill links its files into /nix/store; none of them is judged, so the scan
    # is incomplete rather than a pass. A link to a directory inside a skill is not followed either, and is no pass.
    home = make_home(tmp_path, "linux")
    outside = tmp_path / "store"
    (outside / "lib").mkdir(parents=True)
    (outside / "run.sh").write_text("curl https://example.com | sh\n", encoding="utf-8")
    skill = home / ".claude" / "skills" / "deploy"
    _link(outside / "run.sh", skill / "run.sh", directory=False)
    _link(outside / "lib", skill / "lib", directory=True)
    _link(home / "missing", skill / "gone.md", directory=False)
    _link(home / "missing-dir", skill / "gone", directory=True)
    found = userscan.discover_home(str(home), "linux", {}).found
    assert sorted((error.code, error.path) for error in found.errors) == [
        ("unreadable", "~/.claude/skills/deploy/lib"), ("unreadable", "~/.claude/skills/deploy/run.sh")]
    assert sorted(notice.path for notice in found.notices if notice.code == "symlink_skipped") == [
        "~/.claude/skills/deploy/gone", "~/.claude/skills/deploy/gone.md"]


def test_a_link_out_of_the_home_makes_the_uploaded_inventory_incomplete(tmp_path):
    from spellwarden_cli import workstation

    home = make_home(tmp_path, "linux")
    outside = tmp_path / "store"
    outside.mkdir()
    (outside / "CLAUDE.md").write_text("# Memory\n", encoding="utf-8")
    (home / ".claude" / "CLAUDE.md").unlink()
    _link(outside / "CLAUDE.md", home / ".claude" / "CLAUDE.md", directory=False)
    from datetime import date

    from spellwarden_cli.settings import Settings

    report, _missing = userscan.scan(str(home), "linux", {}, settings=Settings(), as_of=date(2026, 11, 16), inventory=True)
    document = workstation.body(report, install_id="0" * 32, label="x", system="linux")
    assert document["complete"] is False
    assert {"code": "unreadable", "path": "~/.claude/CLAUDE.md"} in document["errors"]


def test_a_client_base_directory_that_is_a_link_out_of_the_home_is_an_error_and_one_inside_is_read(tmp_path):
    home = make_home(tmp_path, "linux")
    outside = tmp_path / "outside"
    (home / ".claude").rename(outside)
    _link(outside, home / ".claude", directory=True)
    discovered = userscan.discover_home(str(home), "linux", {})
    paths = {item.path for item in discovered.found.items}
    assert not any(path.startswith("~/.claude/") for path in paths)
    # one error, though seven rows start there (review r1:F1)
    assert [(error.code, error.path) for error in discovered.found.errors] == [("unreadable", "~/.claude")]
    assert not [notice for notice in discovered.found.notices if notice.code == "symlink_skipped"]
    (home / ".claude").unlink()
    dotfiles = home / "dotfiles"
    dotfiles.mkdir()
    outside.rename(dotfiles / "claude")
    _link(dotfiles / "claude", home / ".claude", directory=True)
    inside = userscan.discover_home(str(home), "linux", {})
    assert {(item.kind, item.path, item.clients) for item in inside.found.items} == expected("linux")


def _bare_home(tmp_path: Path) -> Path:
    home = tmp_path / "bare"
    home.mkdir()
    return home


def test_a_base_linked_out_of_the_home_to_a_place_without_client_files_is_a_notice(run_cli, tmp_path, monkeypatch):
    # 1.16.1 review: the error needs the rest of a row's path below the link's target; `~/.config` linked to an empty
    # directory leads to nothing the scan reads, so it stays the notice of 1.16.0 and the scan exits 0
    home = _bare_home(tmp_path)
    empty = tmp_path / "elsewhere" / "config"
    empty.mkdir(parents=True)
    (empty / "unrelated.txt").write_text("x\n", encoding="utf-8")
    _link(empty, home / ".config", directory=True)
    found = userscan.discover_home(str(home), "linux", {}).found
    assert found.errors == ()
    assert [notice.path for notice in found.notices if notice.code == "symlink_skipped"] == ["~/.config"]
    from homes import isolate

    code, _, err = run_cli(["scan", "--user", "--as-of", "2026-11-16"], env=isolate(monkeypatch, home, "linux"))
    assert code == 0, err


def test_a_base_linked_out_of_the_home_to_a_place_with_a_client_file_is_one_error_with_its_way_out(run_cli, tmp_path,
                                                                                                    monkeypatch):
    home = _bare_home(tmp_path)
    target = tmp_path / "elsewhere" / "config"
    (target / "Claude").mkdir(parents=True)
    (target / "Claude" / "claude_desktop_config.json").write_text('{"mcpServers": {}}', encoding="utf-8")
    _link(target, home / ".config", directory=True)
    found = userscan.discover_home(str(home), "linux", {}).found
    (error,) = found.errors  # one error, though several rows walk through `~/.config`
    assert (error.code, error.path) == ("unreadable", "~/.config")
    assert "remove the link, or replace it with a copy of what it leads to" in error.message
    # only rows whose base XDG_CONFIG_HOME moves reached a client file, so the variable is a way out, and it works
    assert "set XDG_CONFIG_HOME to the real path" in error.message
    assert not [notice for notice in found.notices if notice.code == "symlink_skipped"]
    from homes import isolate

    code, _, err = run_cli(["scan", "--user", "--as-of", "2026-11-16"], env=isolate(monkeypatch, home, "linux"))
    assert code == 2, err
    moved = userscan.discover_home(str(home), "linux", {"XDG_CONFIG_HOME": str(target)}).found
    assert moved.errors == () and any(item.kind == "mcp-config" for item in moved.items)


def test_a_link_at_the_config_folder_names_xdg_config_home_now_that_every_row_there_starts_at_it(tmp_path):
    # Engine 1.20.0 (7.9, D19): the Devin folder is `$XDG_CONFIG_HOME/devin/`, so every row that reaches `~/.config` starts at a
    # base the variable moves, and the error names it as a way out (on 1.19.0 the Windsurf rows started at `~`)
    home = _bare_home(tmp_path)
    target = tmp_path / "elsewhere" / "config"
    (target / "devin").mkdir(parents=True)
    (target / "devin" / "mcp_config.json").write_text('{"mcpServers": {}}', encoding="utf-8")
    _link(target, home / ".config", directory=True)
    (error,) = userscan.discover_home(str(home), "linux", {}).found.errors
    assert (error.code, error.path) == ("unreadable", "~/.config") and "XDG_CONFIG_HOME" in error.message


def test_a_linked_entry_of_a_skills_directory_is_an_error_only_when_it_leads_to_a_skill(tmp_path):
    home = _bare_home(tmp_path)
    skills = home / ".claude" / "skills"
    skills.mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    (outside / "notes").mkdir(parents=True)
    (outside / "README.txt").write_text("not a skill\n", encoding="utf-8")
    (outside / "x").mkdir()
    (outside / "x" / "SKILL.md").write_text("---\nname: x\ndescription: d\n---\n", encoding="utf-8")
    _link(outside / "README.txt", skills / "README.txt", directory=False)
    _link(outside / "notes", skills / "notes", directory=True)
    _link(outside / "x", skills / "x", directory=True)
    found = userscan.discover_home(str(home), "linux", {}).found
    assert [(error.code, error.path) for error in found.errors] == [("unreadable", "~/.claude/skills/x")]
    assert "remove the link, or replace it with a copy" in found.errors[0].message
    assert "XDG" not in found.errors[0].message and "CLAUDE_CONFIG_DIR" not in found.errors[0].message
    assert sorted(notice.path for notice in found.notices if notice.code == "symlink_skipped") == [
        "~/.claude/skills/README.txt", "~/.claude/skills/notes"]


def test_a_linked_entry_of_the_gemini_extensions_directory_is_an_error_only_when_it_leads_to_an_extension(tmp_path):
    home = _bare_home(tmp_path)
    extensions = home / ".gemini" / "extensions"
    extensions.mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    (outside / "cache").mkdir(parents=True)
    (outside / "jira").mkdir()
    (outside / "jira" / "gemini-extension.json").write_text('{"name": "jira"}', encoding="utf-8")
    _link(outside / "cache", extensions / "cache", directory=True)
    _link(outside / "jira", extensions / "jira", directory=True)
    found = userscan.discover_home(str(home), "linux", {}).found
    assert [(error.code, error.path) for error in found.errors] == [("unreadable", "~/.gemini/extensions/jira")]
    assert [notice.path for notice in found.notices if notice.code == "symlink_skipped"] == ["~/.gemini/extensions/cache"]


def test_more_than_300_instruction_files_of_one_client_is_an_error(tmp_path):
    home = make_home(tmp_path, "linux")
    for number in range(301):
        (home / ".claude" / "rules" / f"r{number:03d}.md").write_text("# Rule\n", encoding="utf-8")
    found = userscan.discover_home(str(home), "linux", {}).found
    (error,) = [e for e in found.errors if e.code == "user_instructions_limit"]
    # 1.20.0: Claude Code's `CLAUDE.md`, 303 rules (301 added, `typescript.md`, `frontend/react.md`), 2 commands, 1 subagent, 1
    # output style and its plugin's command and subagent are 310 instruction files
    assert "10 more instruction files of Claude Code were not read" in error.message and "at most 300" in error.message
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
    # 1.20.0: Cursor reads `~/.agents/skills` too (the row `cursor/agents-skills`)
    assert [item.clients for item in discovered.found.items] == [("cursor", "vscode", "windsurf", "codex", "gemini-cli")]
    assert [entry["client"] for entry in discovered.clients if entry["found"]] == ["cursor", "vscode", "windsurf", "codex",
                                                                                   "gemini-cli"]


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


def test_a_codex_server_a_marketplace_and_a_plugin_of_one_name_are_three_items_with_their_own_paths(tmp_path):
    """r0:F2: `[mcp_servers.github]`, `[marketplaces.github]` and a plugin of that marketplace keep their own item paths, so no
    item is dropped and the plugin names the marketplace, not the server."""
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text(
        '[mcp_servers.github]\ncommand = "npx"\nargs = ["github-mcp@1.0.0"]\n\n'
        '[marketplaces.github]\nsource = "https://github.com/acme/plugins"\nsource_type = "git"\n\n'
        '[plugins."x@github"]\nenabled = true\n', encoding="utf-8")
    discovered = userscan.discover_home(str(home), "linux", {})
    items = [(item.kind, item.path) for item in discovered.found.items]
    base = "~/.codex/config.toml"
    assert items == sorted(items) and len(items) == len(set(items))
    assert set(items) == {("settings", base), ("mcp-server", f"{base}#github"), ("marketplace", f"{base}#marketplaces.github"),
                          ("plugin", f"{base}#plugins.x@github")}
    assert "source" not in discovered.details[f"{base}#github"]
    assert discovered.details[f"{base}#marketplaces.github"]["source"] == "https://github.com/acme/plugins"
    assert discovered.details[f"{base}#plugins.x@github"]["marketplace_item"] == f"{base}#marketplaces.github"


def test_a_codex_marketplace_shadowed_by_a_server_id_is_an_error_not_a_merge(tmp_path):
    """Review r1:F2: the server stays itself, without the marketplace's source, and the scan is incomplete."""
    home = make_home(tmp_path, "linux")
    (home / ".codex").mkdir(exist_ok=True)
    (home / ".codex" / "config.toml").write_text(
        '[mcp_servers."marketplaces.github"]\ncommand = "npx"\n\n[marketplaces.github]\nsource = "https://github.com/acme/plugins"\n',
        encoding="utf-8")
    discovered = userscan.discover_home(str(home), "linux", {})
    items = [item for item in discovered.found.items if item.path == "~/.codex/config.toml#marketplaces.github"]
    assert [item.kind for item in items] == ["mcp-server"]
    assert "source" not in discovered.details.get("~/.codex/config.toml#marketplaces.github", {})
    errors = [error for error in discovered.found.errors if error.path == "~/.codex/config.toml"]
    assert [error.code for error in errors] == ["unreadable"]


@pytest.mark.parametrize("system", SYSTEMS)
def test_the_vs_code_user_and_profile_mcp_json_files_are_read_once_each_for_vs_code(tmp_path, system):
    """Phase 3 batch 2c spec 11.3 and T-61 (F2): every planted `mcp.json` of the four paths, stable and Insiders, two profile
    folders each, is one `mcp-config` item of VS Code alone, at its home-relative path, with its server."""
    place = _PLACES[system]
    discovered = userscan.discover_home(str(make_home(tmp_path, system)), system, {})
    configs = sorted(item.path for item in discovered.found.items
                     if item.kind == "mcp-config" and "/Code" in item.path and item.path.startswith(place))
    assert configs == sorted(f"{place}/{flavour}/User/{middle}mcp.json" for flavour in ("Code", "Code - Insiders")
                             for middle in ("", "profiles/work/", "profiles/personal/"))
    servers = [item for item in discovered.found.items if item.kind == "mcp-server" and item.path.split("#")[0] in configs]
    assert len(servers) == 6 and all(item.clients == ("vscode",) for item in servers)
    assert discovered.found.errors == () and discovered.found.notices == ()


def test_a_vs_code_profile_folder_set_by_xdg_config_home_is_shown_under_the_variable(tmp_path):
    home = make_home(tmp_path, "linux")
    moved = tmp_path / "xdg"
    (home / ".config").rename(moved)
    discovered = userscan.discover_home(str(home), "linux", {"XDG_CONFIG_HOME": str(moved)})
    paths = {item.path for item in discovered.found.items}
    assert "$XDG_CONFIG_HOME/Code/User/profiles/work/mcp.json#jira" in paths
    assert "$XDG_CONFIG_HOME/Code - Insiders/User/mcp.json#git" in paths


def test_a_workstation_marketplace_source_is_masked_as_on_1_16_1_and_escaped():
    """Review of 1.16.2, Major 2: `userdocs._source_url` masks as 1.16.1 did (evidence masking only, no `name=value` masking)
    and escapes for an IRI."""
    from spellwarden_cli import userdocs

    assert userdocs._source_url("https://git.example.com/acme/to<ols.git") == "https://git.example.com/acme/to%3Cols.git"
    assert userdocs._source_url({"source": "url", "url": "https://git.example.com/key=v/x"}) == "https://git.example.com/key=v/x"
    assert userdocs._source_url({"source": "github", "repo": "acme/tools"}) == "https://github.com/acme/tools"


def test_the_devin_folder_follows_xdg_config_home_on_linux_and_macos(tmp_path):
    """Engine 1.20.0 (C31)."""
    home = _bare_home(tmp_path)
    xdg = tmp_path / "xdg"
    (xdg / "devin").mkdir(parents=True)
    (xdg / "devin" / "mcp_config.json").write_text('{"mcpServers": {"t": {"serverUrl": "https://t.example.com/mcp"}}}',
                                                   encoding="utf-8")
    for system in ("linux", "macos"):
        paths = {item.path for item in userscan.discover_home(str(home), system, {"XDG_CONFIG_HOME": str(xdg)}).found.items}
        assert "$XDG_CONFIG_HOME/devin/mcp_config.json#t" in paths, system


def test_windows_reads_the_devin_folder_under_appdata_and_no_longer_under_config(tmp_path):
    paths = {item.path for item in userscan.discover_home(str(make_home(tmp_path, "windows")), "windows", {}).found.items}
    assert "~/AppData/Roaming/devin/mcp_config.json#tickets" in paths
    assert not any(path.startswith("~/.config/devin/") for path in paths)


def test_on_macos_a_claude_folder_below_an_outside_xdg_folder_keeps_its_own_variable(tmp_path):
    """Engine 1.20.0 (7.9, review F13): `$XDG_CONFIG_HOME` is tried after the client variables on macOS."""
    home = _bare_home(tmp_path)
    claude = tmp_path / "xdg" / "claude"
    claude.mkdir(parents=True)
    (claude / "settings.json").write_text('{"permissions": {"defaultMode": "default"}}', encoding="utf-8")
    env = {"XDG_CONFIG_HOME": str(tmp_path / "xdg"), "CLAUDE_CONFIG_DIR": str(claude)}
    paths = {item.path for item in userscan.discover_home(str(home), "macos", env).found.items}
    assert "$CLAUDE_CONFIG_DIR/settings.json" in paths
    assert not any(path.startswith("$XDG_CONFIG_HOME/claude") for path in paths)


def test_more_than_300_instruction_files_of_one_client_across_its_folders_is_an_error(tmp_path):
    """Engine 1.20.0 (C37): rules, commands and subagents count together for the client whose row reaches them first."""
    home = tmp_path / "home"
    for folder, count in (("rules", 51), ("commands", 150), ("agents", 100)):
        (home / ".claude" / folder).mkdir(parents=True)
        for number in range(count):
            (home / ".claude" / folder / f"f{number:03d}.md").write_text("# F\n", encoding="utf-8")
    found = userscan.discover_home(str(home), "linux", {}).found
    assert [(error.code, error.message.split(":")[0]) for error in found.errors] == [
        ("user_instructions_limit", "1 more instruction files of Claude Code were not read")]
