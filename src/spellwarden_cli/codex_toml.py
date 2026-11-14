"""Codex's `config.toml` as the engine's JSON values (phase 3 batch 2a spec 11.1, 11.2): `tomllib` reads the file, and every
table becomes an `Obj` and every array an `Arr` with the line of each key and item, found by a line scan of the text (the
header of a table, the line of a `key =`), so findings on a Codex server or hook point at its line as they do in a JSON file.
Dates and times become their ISO text. `agentconfig.parse_selected` then reads the servers and hooks of the tree.

Lines are best effort: a key whose line the scan cannot place gets its table's header line, and a key of the root table that
cannot be placed gets line 1. Values are never changed."""
from __future__ import annotations

import datetime
import re
import tomllib

from spellwarden_scan._json import Arr, Obj

_HEADER = re.compile(r"^\s*(\[\[?)\s*(.+?)\s*\]\]?\s*(?:#.*)?$")
_ONE_KEY = r"""(?:"(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)"""
_KEY = re.compile(rf"^\s*({_ONE_KEY}(?:\s*\.\s*{_ONE_KEY})*)\s*=")
_SEGMENT = re.compile(r""""((?:[^"\\]|\\.)*)"|'([^']*)'|([A-Za-z0-9_-]+)""")


def _segments(dotted: str) -> tuple[str, ...]:
    return tuple(match.group(1) if match.group(1) is not None else match.group(2) if match.group(2) is not None
                 else match.group(3) for match in _SEGMENT.finditer(dotted))


class _Lines:
    """Where each table starts and where each key of each table section is written. A section is `(table path, occurrence)`:
    occurrence 0 for a table, the element's index for an array of tables."""

    def __init__(self, text: str) -> None:
        self.headers: dict[tuple[tuple[str, ...], int], int] = {}
        self.keys: dict[tuple[tuple[str, ...], int], dict[tuple[str, ...], int]] = {((), 0): {}}
        counts: dict[tuple[str, ...], int] = {}
        section: tuple[tuple[str, ...], int] = ((), 0)
        for number, line in enumerate(text.splitlines(), start=1):
            header = _HEADER.match(line)
            if header is not None and not _KEY.match(line):
                path = _segments(header.group(2))
                occurrence = 0
                if header.group(1) == "[[":
                    occurrence = counts.get(path, 0)
                    counts[path] = occurrence + 1
                section = (path, occurrence)
                self.headers.setdefault(section, number)
                self.keys.setdefault(section, {})
                continue
            key = _KEY.match(line)
            if key is not None:
                self.keys[section].setdefault(_segments(key.group(1)), number)

    def line(self, table: tuple[str, ...], occurrence: int, key: str) -> int:
        """The line of `key` in the table section `(table, occurrence)`, else of the same dotted key written in an enclosing
        table, else the first header of a table at or below the key, else the section's header line, else 1."""
        full = (*table, key)
        found = self.keys.get((table, occurrence), {}).get((key,))
        if found is not None:
            return found
        for cut in range(len(table) - 1, -1, -1):
            found = self.keys.get((table[:cut], 0), {}).get(full[cut:])
            if found is not None:
                return found
        below = [number for (path, _), number in self.headers.items() if path[:len(full)] == full]
        if below:  # the key is a table of its own (`[mcp_servers.docs]`), or holds tables: its first header
            return min(below)
        return self.headers.get((table, occurrence), self.headers.get((table, 0), 1))


def _convert(value: object, table: tuple[str, ...], occurrence: int, lines: _Lines, line: int):
    if isinstance(value, dict):
        converted = Obj()
        converted.line, converted.lines = line, {}
        for key, item in value.items():
            at = lines.line(table, occurrence, key)
            converted.lines[key] = at
            if isinstance(item, list) and item and all(isinstance(entry, dict) for entry in item):
                converted[key] = _table_array(item, (*table, key), lines, at)
            else:
                converted[key] = _convert(item, (*table, key), 0, lines, at)
        return converted
    if isinstance(value, list):
        converted_list = Arr(_convert(item, table, 0, lines, line) for item in value)
        converted_list.line, converted_list.lines = line, [line] * len(value)
        return converted_list
    if isinstance(value, (datetime.date, datetime.time)):  # a datetime is a date
        return value.isoformat()
    return value


def _table_array(items: list, table: tuple[str, ...], lines: _Lines, line: int) -> Arr:
    """An array of tables: element `index` is the section `(table, index)` when it was written as `[[table]]`."""
    converted = Arr()
    converted.line, converted.lines = line, []
    for index, item in enumerate(items):
        at = lines.headers.get((table, index), line)
        converted.append(_convert(item, table, index, lines, at))
        converted.lines.append(at)
    return converted


def read(content: bytes) -> Obj:
    """The root table of `config.toml`. Raises ValueError (`UnicodeDecodeError`, `tomllib.TOMLDecodeError`) when the bytes are
    not UTF-8 TOML."""
    text = content.decode("utf-8")
    data = tomllib.loads(text)
    return _convert(data, (), 0, _Lines(text), 1)


__all__ = ["read"]
