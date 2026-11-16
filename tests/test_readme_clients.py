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
    assert sum(1 for row in clients.ROWS if row.path_from) == 3
    # the paragraph under the table no longer says that every row's source names the path
    text = README.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert "or names the file while the pages in the row give its folder (VS Code's user and profile `mcp.json`)" in text
