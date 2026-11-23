"""Phase 3 batch 2a spec 11.2 and T-2: every row of the client table has a cited source and the date it was checked, and the
README's table and "Not read" list are `clients.readme_block()`, byte for byte."""
from __future__ import annotations

import re
from pathlib import Path

from spellwarden_cli import clients, instruction_files

README = Path(__file__).resolve().parents[1] / "README.md"
START, END = "<!-- clients:start -->\n", "<!-- clients:end -->"


def test_the_readme_client_table_is_generated():
    text = README.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert text.count(START) == 1 and text.count(END) == 1
    block = text[text.index(START) + len(START):text.index(END)]
    assert block == clients.readme_block(), "regenerate with: python -c 'from spellwarden_cli import clients; " \
                                            "print(clients.readme_block(), end=\"\")'"
    section = text[text.index("### Scanning a workstation"):text.index("### The usage ping")]
    assert START in section


def test_every_row_has_a_source_a_checked_date_and_known_values():
    ids = [row.id for row in clients.ROWS]
    assert len(ids) == len(set(ids))
    for row in clients.ROWS:
        assert re.fullmatch(r"https://[^\s<>|]+", row.source), row.id
        assert all(re.fullmatch(r"https://[^\s<>|]+", page) for page in row.path_from), row.id
        assert re.fullmatch(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]", row.checked), row.id
        assert row.id.startswith(row.client + "/") and row.client in clients.CLIENTS
        assert row.base in clients.BASES and row.reader in clients.READERS and row.paths
        assert set(row.systems) <= set(clients.SYSTEMS) and row.systems
        assert all("\\" not in path and not path.startswith("/") for path in row.paths), row.id
        assert (row.format is not None) == (row.reader == "instructions"), row.id
        assert row.format is None or row.format in instruction_files.FORMATS
    assert {row.client for row in clients.ROWS} == set(clients.CLIENTS)
    assert clients.NOT_READ and all(line.endswith(".") for line in clients.NOT_READ)


def test_every_client_has_a_row_on_every_system():
    for system in clients.SYSTEMS:
        assert {row.client for row in clients.rows_for(system)} == set(clients.CLIENTS), system
        # each client can be found by a path that only it reads: a `shared` directory alone shows no client (spec 11.2)
        assert {row.client for row in clients.rows_for(system) if not row.shared} == set(clients.CLIENTS), system


def test_vs_code_user_mcp_json_has_a_row_per_system_and_left_not_read():
    """Phase 3 batch 2c spec 11.3 and T-61 (F2): one row per system with the four paths, the `servers` dialect, the MCP
    reference as its source and the two pages its folder is derived from; "Not read" no longer names the files, and names the
    remote and WSL folders instead."""
    rows = {row.id: row for row in clients.ROWS}
    paths = ("Code/User/mcp.json", "Code/User/profiles/*/mcp.json", "Code - Insiders/User/mcp.json",
             "Code - Insiders/User/profiles/*/mcp.json")
    for system, base in (("linux", "$XDG_CONFIG_HOME"), ("macos", "~/Library/Application Support"), ("windows", "%APPDATA%")):
        row = rows[f"vscode/{system}"]
        assert (row.client, row.systems, row.base, row.paths, row.reader) == ("vscode", (system,), base, paths, "mcp")
        assert row.reads == "MCP servers (`servers`)" and row.checked == "2026-11-15" and not row.shared
        assert row.source == "https://code.visualstudio.com/docs/copilot/reference/mcp-configuration"
        assert row.path_from == ("https://code.visualstudio.com/docs/configure/settings",
                                 "https://code.visualstudio.com/docs/configure/profiles")
    assert not any("Code/User/mcp.json" in line for line in clients.NOT_READ)
    assert any("remote and WSL" in line and "~/.vscode-server/" in line for line in clients.NOT_READ)
    assert any(line.startswith("VS Code's user instruction files") for line in clients.NOT_READ)
    # Engine 1.20.0 (7.9, 7.17): the Devin folder's rows (a pair per file but the MCP one) take their folder from another page too
    assert sum(1 for row in clients.ROWS if row.path_from) == 3 + sum(
        1 for row in clients.ROWS if row.client == "windsurf" and row.path_from == (
            "https://docs.devin.ai/desktop/devin-local/customizations",))
    text = README.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert ("or names the file while the pages in the row give its folder (VS Code's user and profile `mcp.json`, and the Devin "
            "Desktop folder of the Windsurf rows)") in " ".join(text.split())


NEW_ROWS = ("claude-code/commands", "claude-code/agents", "claude-code/output-styles", "cursor/skills", "cursor/agents-skills",
            "cursor/claude-skills", "cursor/codex-skills", "cursor/agents", "cursor/claude-agents", "cursor/codex-agents",
            "cursor/plugins", "vscode/instructions", "vscode/instruction-files", "vscode/agents", "vscode/hooks",
            "vscode/settings", "vscode/plugins", "vscode/claude-rules", "vscode/claude-memory", "vscode/claude-agents",
            "windsurf/agents-md", "windsurf/agents", "windsurf/config", "windsurf/codeium-mcp", "windsurf/codeium-skills",
            "windsurf/codex-skills", "windsurf/copilot-skills", "codex/prompts", "codex/plugins", "gemini-cli/agents")
CHANGED_ROWS = ("claude-code/rules", "claude-code/plugins", "windsurf/mcp", "windsurf/skills", "windsurf/global-rules",
                "windsurf/rules", "windsurf/agents-skills", "gemini-cli/extensions")


def test_every_new_or_changed_row_was_checked_on_2026_11_23():
    """Engine 1.20.0 (C38): a new or changed row carries the date its page was read; a Devin row has a Windows twin."""
    rows = {row.id: row for row in clients.ROWS}
    assert clients.CHECKED_SELECTION == "2026-11-23"
    for row_id in (*NEW_ROWS, *CHANGED_ROWS):
        for found in (row_id, f"{row_id}-windows"):
            if found in rows:
                assert rows[found].checked == "2026-11-23", found
    for row_id in ("windsurf/mcp", "windsurf/skills", "windsurf/agents-md", "windsurf/agents", "windsurf/config"):
        if row_id in rows:
            linux, windows = rows[row_id], rows[f"{row_id}-windows"]
            assert (linux.systems, linux.base, windows.systems, windows.base) == (
                ("linux", "macos"), "$XDG_CONFIG_HOME", ("windows",), "%APPDATA%")
            assert (linux.paths, linux.reader, linux.format) == (windows.paths, windows.reader, windows.format)
    assert not any(path.startswith(".config/devin/") for row in clients.ROWS for path in row.paths)


def test_the_not_read_list_says_what_1_20_0_still_does_not_read():
    """Engine 1.20.0 (7.13, C39): the ten lines in order, plus one per row a page no longer names; no line says a location is not
    read that a row reads."""
    starts = ("Windsurf's `~/.codeium/windsurf/memories/global_rules.md`", "Codex's `$CODEX_HOME/skills/` as Codex's own",
              "The `mcp.json` files of VS Code's remote and WSL servers", "VS Code's user instruction files",
              "Claude Code's plugins when `CLAUDE_CODE_PLUGIN_CACHE_DIR`", "System-wide managed files",
              "Cursor's `~/.cursor/rules/`", "Claude Desktop extensions", "Windsurf's global workflows",
              "Files that need a parser or a rule the scanner does not have")
    lines = clients.NOT_READ
    assert len(lines) >= 10 and all(line.startswith(start) for line, start in zip(lines, starts, strict=False))
    text = " ".join(lines)
    for gone in ("`~/.codeium/windsurf/mcp_config.json`", "The files of installed Codex plugins",
                 "Skills inside Gemini CLI extensions", "Claude Code subagents, commands and output styles"):
        assert gone not in text, gone
    assert "Cursor and Devin Desktop document loading `~/.codex/skills/`, so it is read as their directory" in lines[1]
    assert "Copilot's `$COPILOT_HOME/instructions/` and `$COPILOT_HOME/agents/` are read" in lines[3]


def test_rows_that_read_one_folder_give_its_files_one_format():
    """Engine 1.20.0 (7.12, C35): a file reached by two rows has the format of the first, so the rows of one folder agree."""
    import posixpath

    homes = {"$CLAUDE_CONFIG_DIR": "~/.claude", "$CODEX_HOME": "~/.codex", "$COPILOT_HOME": "~/.copilot", "~": "~"}
    formats: dict[str, set[str]] = {}
    for row in clients.ROWS:
        if row.format is None or row.base not in homes:
            continue
        for path in row.paths:
            folder = posixpath.dirname(path).split("/*")[0]
            formats.setdefault(f"{homes[row.base]}/{folder}".rstrip("/"), set()).add(row.format)
    assert {folder: found for folder, found in formats.items() if len(found) > 1} == {}
