"""Engine 1.20.0 (scan selection, 7.10 to 7.12; claims C30, C32, C33): `**` in a row's path reads every depth, shallowest first,
by the workstation scan's link rules; the plugin directories of Codex, Copilot and Cursor are `plugin` items with their files;
an installed Claude Code plugin's commands and agents and a Gemini CLI extension's skills and subagents are read. The rows are
set by each test, so the client table's own rows do not matter here."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from homes import make_home

from spellwarden_cli import clients, userscan

SKILL = "---\nname: s\ndescription: A skill.\n---\n\n# s\n"
MCP = json.dumps({"mcpServers": {"server": {"command": "npx", "args": ["server-mcp@1.0.0"]}}})
CLAUDE_HOOKS = json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "./done.sh"}]}]}})
CURSOR_HOOKS = json.dumps({"version": 1, "hooks": {"afterFileEdit": [{"command": "./format.sh"}]}})
COPILOT_HOOKS = json.dumps({"version": 1, "hooks": {"sessionStart": [{"type": "command", "bash": "./a.sh", "powershell": "./a.ps1"}]}})
PLUGIN_DIR = "~/.claude/plugins/cache/tools/lint/1.0.0"


def _write(root: Path, files: dict[str, str]) -> Path:
    for path, text in files.items():
        target = root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def _row(row_id: str, base: str, paths: tuple[str, ...], reader: str, *, format: str | None = None) -> clients.Row:
    return clients.Row(row_id, row_id.split("/")[0], clients.ALL, base, paths, reader, "test", "https://example.invalid/docs",
                       "2026-11-23", format=format)


def _rows(monkeypatch, *rows: clients.Row) -> None:
    monkeypatch.setattr(clients, "ROWS", rows)


def _link(target: Path, link: Path, *, directory: bool) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symbolic links are not available here ({exc})")


def _found(home: Path):
    return userscan.discover_home(str(home), "linux", {}).found


RULES = _row("claude-code/rules", "$CLAUDE_CONFIG_DIR", ("rules/**/*.md",), "instructions", format="claude-rule")


def test_double_star_reads_every_depth_shallowest_first_and_names_match_by_case(tmp_path, monkeypatch):
    home = _write(tmp_path / "home", {".claude/rules/a.md": "# A\n", ".claude/rules/z/b.md": "# B\n",
                                      ".claude/rules/z/y/c.md": "# C\n", ".claude/rules/m/d.MD": "# D\n",
                                      ".claude/rules/node_modules/e.md": "# E\n"})
    _rows(monkeypatch, RULES)
    found = _found(home)
    assert [f.path for f in found.instruction_files] == ["~/.claude/rules/a.md", "~/.claude/rules/z/b.md",
                                                         "~/.claude/rules/z/y/c.md"]
    assert found.errors == () and found.notices == ()
    monkeypatch.setattr(userscan, "MAX_INSTRUCTIONS", 2)
    limited = _found(home)
    assert [f.path for f in limited.instruction_files] == ["~/.claude/rules/a.md", "~/.claude/rules/z/b.md"]
    assert [(e.code, e.message.split(":")[0]) for e in limited.errors] == [
        ("user_instructions_limit", "1 more instruction files of Claude Code were not read")]


def test_double_star_follows_links_by_the_rules_of_the_workstation_scan(tmp_path, monkeypatch):
    home = _write(tmp_path / "home", {".claude/rules/a.md": "# A\n", "shared/b.md": "# B\n"})
    outside = _write(tmp_path / "outside", {"c.md": "# C\n", "file.txt": "x\n"})
    rules = home / ".claude" / "rules"
    _link(home / "shared", rules / "team", directory=True)  # a directory inside the home: followed
    _link(outside, rules / "out", directory=True)  # a directory out of the home: unreadable
    _link(home / "missing.md", rules / "gone.md", directory=False)  # dangling, named like a rule: the notice
    _link(outside / "file.txt", rules / "notes.txt", directory=False)  # a file out of the home, no rule's name: nothing
    _link(home / "nowhere", rules / "old", directory=True)  # dangling, no rule's name: nothing
    _link(rules, rules / "loop", directory=True)  # a loop: entered once
    _rows(monkeypatch, RULES)
    found = _found(home)
    assert [f.path for f in found.instruction_files] == ["~/.claude/rules/a.md", "~/.claude/rules/team/b.md"]
    assert [(e.code, e.path) for e in found.errors] == [("unreadable", "~/.claude/rules/out")]
    assert [(n.code, n.path) for n in found.notices] == [("symlink_skipped", "~/.claude/rules/gone.md")]


def test_codex_copilot_and_cursor_plugin_directories_are_plugin_items_with_their_files(tmp_path, monkeypatch):
    codex, copilot, direct, cursor = (".codex/plugins/cache/tools/review/1.0.0", ".copilot/installed-plugins/tools/fmt",
                                      ".copilot/installed-plugins/_direct/src-1", ".cursor/plugins/local/notes")
    home = _write(tmp_path / "home", {
        f"{codex}/.codex-plugin/plugin.json": '{"name": "review"}', f"{codex}/plugin.json": '{"name": "review"}',
        f"{codex}/mcp.json": MCP, f"{codex}/hooks/hooks.json": CLAUDE_HOOKS, f"{codex}/skills/s/SKILL.md": SKILL,
        f"{copilot}/.github/plugin/plugin.json": '{"name": "fmt"}', f"{copilot}/hooks.json": COPILOT_HOOKS,
        f"{copilot}/agents/sub/a.md": "# A\n", f"{direct}/plugin.json": '{"name": "direct"}',
        f"{cursor}/.cursor-plugin/plugin.json": '{"name": "notes"}', f"{cursor}/mcp.json": MCP,
        f"{cursor}/hooks/hooks.json": CURSOR_HOOKS, f"{cursor}/rules/x/style.mdc": "---\nglobs: *.md\n---\nx\n",
        f"{cursor}/rules/readme.md": "not a rule\n", f"{cursor}/agents/scribe.md": "# S\n", f"{cursor}/commands/sum.md": "# C\n",
    })
    _rows(monkeypatch, _row("codex/plugins", "$CODEX_HOME", ("plugins/cache/*/*/*",), "codex-plugins"),
          _row("vscode/plugins", "$COPILOT_HOME", ("installed-plugins/*/*",), "copilot-plugins"),
          _row("cursor/plugins", "~", (".cursor/plugins/local/*",), "cursor-plugins"))
    found = _found(home)
    items = {(item.kind, item.path, item.name, item.plugin, item.format) for item in found.items}
    x, v, d, c = (f"~/{codex}", f"~/{copilot}", f"~/{direct}", f"~/{cursor}")
    assert {("plugin", x, "review", None, None), ("plugin-manifest", f"{x}/.codex-plugin/plugin.json", "plugin.json", "review", None),
            ("plugin-manifest", f"{x}/plugin.json", "plugin.json", "review", None), ("mcp-config", f"{x}/mcp.json", "mcp.json", "review", None),
            ("mcp-server", f"{x}/mcp.json#server", "server", "review", None),
            ("hooks", f"{x}/hooks/hooks.json", "hooks.json", "review", None), ("skill", f"{x}/skills/s", "s", "review", None),
            ("plugin", v, "fmt", None, None), ("plugin-manifest", f"{v}/.github/plugin/plugin.json", "plugin.json", "fmt", None),
            ("hooks", f"{v}/hooks.json", "hooks.json", "fmt", None), ("instructions", f"{v}/agents/sub/a.md", "a.md", "fmt", "github-agent"),
            ("plugin", d, "src-1", None, None), ("plugin-manifest", f"{d}/plugin.json", "plugin.json", "src-1", None),
            ("plugin", c, "notes", None, None), ("plugin-manifest", f"{c}/.cursor-plugin/plugin.json", "plugin.json", "notes", None),
            ("mcp-config", f"{c}/mcp.json", "mcp.json", "notes", None), ("hooks", f"{c}/hooks/hooks.json", "hooks.json", "notes", None),
            ("instructions", f"{c}/rules/x/style.mdc", "style.mdc", "notes", "cursor-mdc"),
            ("instructions", f"{c}/agents/scribe.md", "scribe.md", "notes", "cursor-agent"),
            ("instructions", f"{c}/commands/sum.md", "sum.md", "notes", "cursor-command")} <= items
    assert not any(path.endswith("rules/readme.md") for _, path, *_ in items)
    assert {document.path: len(document.hooks) for document in found.documents}[f"{v}/hooks.json"] == 2
    assert found.errors == ()


def test_more_plugin_directories_than_the_limit_in_one_row_is_truncated(tmp_path, monkeypatch):
    home = _write(tmp_path / "home", {f".cursor/plugins/local/{name}/plugin.json": '{"name": "x"}' for name in ("a", "b", "c")})
    _rows(monkeypatch, _row("cursor/plugins", "~", (".cursor/plugins/local/*",), "cursor-plugins"))
    monkeypatch.setattr(userscan, "MAX_PLUGINS", 2)
    found = _found(home)
    assert sorted(item.path for item in found.items if item.kind == "plugin") == ["~/.cursor/plugins/local/a",
                                                                                   "~/.cursor/plugins/local/b"]
    (error,) = found.errors
    assert error.code == "truncated" and error.message.startswith("1 more plugin directories of Cursor")


def test_a_plugin_directory_entry_linked_out_of_the_home_is_unreadable(tmp_path, monkeypatch):
    home = _write(tmp_path / "home", {".cursor/plugins/local/a/plugin.json": '{"name": "a"}'})
    outside = _write(tmp_path / "outside", {"plugin.json": '{"name": "b"}'})
    _link(outside, home / ".cursor" / "plugins" / "local" / "b", directory=True)
    _rows(monkeypatch, _row("cursor/plugins", "~", (".cursor/plugins/local/*",), "cursor-plugins"))
    found = _found(home)
    assert [(e.code, e.path) for e in found.errors] == [("unreadable", "~/.cursor/plugins/local/b")]


def test_an_installed_claude_code_plugin_s_commands_and_agents_are_read_with_its_name(tmp_path):
    home = make_home(tmp_path, "linux")
    plugin = home / ".claude" / "plugins" / "cache" / "tools" / "lint" / "1.0.0"
    _write(plugin, {"commands/fix.md": "# Fix\n", "commands/sub/all.md": "# All\n", "agents/linter.md": "# Lint\n"})
    items = {(item.path, item.format, item.plugin) for item in _found(home).items if item.kind == "instructions"}
    assert {(f"{PLUGIN_DIR}/commands/fix.md", "claude-command", "lint"), (f"{PLUGIN_DIR}/commands/sub/all.md", "claude-command", "lint"),
            (f"{PLUGIN_DIR}/agents/linter.md", "claude-agent", "lint")} <= items


def test_a_claude_code_plugin_read_as_one_skill_keeps_its_commands_as_skill_files(tmp_path):
    home = make_home(tmp_path, "linux")
    plugin = home / ".claude" / "plugins" / "cache" / "tools" / "lint" / "1.0.0"
    for path in sorted((plugin / "skills").rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    (plugin / "skills").rmdir()
    _write(plugin, {"SKILL.md": SKILL, "commands/fix.md": "# Fix\n"})
    found = _found(home)
    assert not [item for item in found.items if item.kind == "instructions" and item.path.startswith(PLUGIN_DIR)]
    (skill,) = [skill for skill in found.skills if skill.path == PLUGIN_DIR]
    assert f"{PLUGIN_DIR}/commands/fix.md" in skill.files


def test_a_gemini_cli_extension_s_skills_and_subagents_are_read_with_its_name(tmp_path):
    home = make_home(tmp_path, "linux")
    _write(home / ".gemini" / "extensions" / "jira", {"skills/ticket/SKILL.md": SKILL, "agents/triager.md": "# Triage\n",
                                                      "agents/deep/no.md": "# not read\n"})
    items = {(item.kind, item.path, item.plugin, item.format) for item in _found(home).items}
    assert ("skill", "~/.gemini/extensions/jira/skills/ticket", "jira", None) in items
    assert ("instructions", "~/.gemini/extensions/jira/agents/triager.md", "jira", "gemini-agent") in items
    assert not any(path.endswith("deep/no.md") for _, path, _, _ in items)


def test_the_copilot_and_devin_readers_of_the_table(tmp_path, monkeypatch):
    home = _write(tmp_path / "home", {
        ".copilot/hooks/audit.json": COPILOT_HOOKS,
        ".copilot/settings.json": json.dumps({"enabledPlugins": {"fmt@tools": True}, "permissions": {"defaultMode": "bypassPermissions"},
                                              "hooks": {"preToolUse": [{"type": "command", "bash": "./guard.sh"}]}}),
        ".config/devin/config.json": json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "./done.sh"}]}]}}),
    })
    _rows(monkeypatch, _row("vscode/hooks", "$COPILOT_HOME", ("hooks/*.json",), "copilot-hooks"),
          _row("vscode/settings", "$COPILOT_HOME", ("settings.json",), "copilot-settings"),
          _row("windsurf/config", "$XDG_CONFIG_HOME", ("devin/config.json",), "devin-config"))
    documents = {document.path: document for document in _found(home).documents}
    assert (documents["~/.copilot/hooks/audit.json"].kind, len(documents["~/.copilot/hooks/audit.json"].hooks)) == ("hooks", 2)
    settings = documents["~/.copilot/settings.json"]
    assert (settings.kind, settings.settings, [h.command for h in settings.hooks]) == ("settings", (), ["./guard.sh"])
    assert [h.command for h in documents["~/.config/devin/config.json"].hooks] == ["./done.sh"]
