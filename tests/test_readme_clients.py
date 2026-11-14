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
