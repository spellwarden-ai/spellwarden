"""SW-SKL-036: frontmatter pre-approves an unscoped shell or interpreter.

Read over the leading YAML frontmatter of every Markdown file in the package that has one (SKILL.md and the command
or agent files shipped beside it), key `allowed-tools` in any form: a comma- or space-separated string, a flow list or
a block list. An entry fires when it is, case-insensitively, a shell tool (`Bash`, `Shell`, `PowerShell`) with no
scope, with a wildcard scope (`Bash(*)`, `Bash(:*)`), or with a scope that is a general interpreter or launcher alone
(`Bash(python3:*)`, `Bash(node)`, `Bash(npx:*)`, ...). A shell scoped to one task-specific command
(`Bash(gh pr view:*)`) is quiet, and so is everything that is not the leading frontmatter's own `allowed-tools` key:
the body, a fenced example in an authoring guide, a subagent's `tools:` capability list, a nested key.

The finding is at the offending entry's line: the list item's line, or the `allowed-tools:` line for a one-line value.
Entries are cut out of the value with one forward scan and located by a cursor that only moves forward; an entry the
raw text does not contain (YAML unescaped it) costs one search to the end of the key block, so after a few such misses
the rest are placed on the key line without searching, and a long line is read in linear time. The module is registered by the rule set, not here."""
from __future__ import annotations

from collections.abc import Iterator

from spellwarden_scan.evidence import excerpt, fingerprint
from spellwarden_scan.frontmatter import FrontmatterError, parse_frontmatter
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.package import Package, TextFile

RULE_ID = "SW-SKL-036"
TITLE = "Frontmatter pre-approves an unscoped shell or interpreter"
SEVERITY = "medium"
OWASP = ("ASI02", "ASI03")
NIST = ("AC-6", "CM-7")
MALICIOUS = False

_KEY = "allowed-tools"
_PER_FILE = 5
_PER_PACKAGE = 10
_MISSES = 8  # entries the raw text does not contain (YAML escapes) that may be searched for before the key line is used

_SHELL_TOOLS = frozenset({"bash", "shell", "powershell"})
_WILDCARDS = frozenset({"*", ":*"})
_INTERPRETERS = frozenset({
    "python", "python3", "node", "deno", "bun", "ruby", "perl", "bash", "sh", "zsh", "pwsh", "powershell", "npx", "uvx",
    "pip", "source", "eval",
})
_SEPARATORS = " \t\r\n,"


def _entries(value: object) -> Iterator[str]:
    """The entries of a string, flow list or block list value, in text order. Parentheses keep a scope's spaces."""
    if isinstance(value, str):
        yield from _split(value)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                yield from _split(item)


def _split(text: str) -> Iterator[str]:
    """Cut at commas and white space outside parentheses; one forward scan, an unclosed `(` runs to the end."""
    size = len(text)
    i = 0
    while i < size:
        if text[i] in _SEPARATORS:
            i += 1
            continue
        start = i
        while i < size and text[i] not in _SEPARATORS and text[i] != "(":
            i += 1
        if i < size and text[i] == "(":
            close = text.find(")", i)
            i = size if close == -1 else close + 1
        yield text[start:i]


def _unscoped(entry: str) -> bool:
    """A shell tool with no scope, a wildcard scope or a general interpreter as its scope."""
    entry = entry.strip().strip("\"'").strip()
    name, paren, rest = entry.partition("(")
    name = name.strip().lower()
    if name not in _SHELL_TOOLS:
        return False
    if not paren:
        return True
    scope, closed, _ = rest.partition(")")
    if not closed:
        return False
    scope = scope.strip().lower()
    if scope in _WILDCARDS:
        return True
    for suffix in (":*", " *"):
        if scope.endswith(suffix):
            scope = scope[: -len(suffix)].rstrip()
            break
    return scope in _INTERPRETERS


def _frontmatter_lines(unit: TextFile) -> tuple[int, int] | None:
    """`(first, end)`: the 0-based range of the lines between the opening and the closing `---`, or `None`."""
    lines = unit.lines
    if not lines or lines[0].lstrip("﻿").rstrip("\r\n") != "---":
        return None
    for index in range(1, len(lines)):
        if lines[index].rstrip("\r\n") == "---":
            return 1, index
    return None


def _key_block(lines: tuple[str, ...], first: int, end: int) -> tuple[int, int] | None:
    """The 0-based `(key line, end)` of the last top-level `allowed-tools` key (YAML keeps the last duplicate) and the
    lines that belong to it, up to the next top-level key."""
    found: int | None = None
    for index in range(first, end):
        line = lines[index]
        if line[:1] in ("", " ", "\t", "-", "#"):
            continue
        name = line.partition(":")[0].strip().strip("\"'")
        if ":" in line and name == _KEY:
            found = index
    if found is None:
        return None
    stop = end
    for index in range(found + 1, end):
        line = lines[index]
        if line[:1] not in ("", " ", "\t", "-", "#") and ":" in line:
            stop = index
            break
    return found, stop


def _located(lines: tuple[str, ...], key_line: int, stop: int, entries: Iterator[str]) -> Iterator[tuple[str, int]]:
    """`(entry, 1-based line)` for each entry, found with a cursor that never moves back; the key line when not found.
    Only `_MISSES` failed searches are made, each reads the rest of the block; later entries are not searched for."""
    row, col = key_line, lines[key_line].find(":") + 1
    misses = 0
    for entry in entries:
        line = key_line
        probe_row, probe_col = row, col
        while probe_row < stop and misses < _MISSES:
            at = lines[probe_row].find(entry, probe_col) if entry else -1
            if at != -1:
                line, row, col = probe_row, probe_row, at + len(entry)
                break
            probe_row, probe_col = probe_row + 1, 0
        else:
            if misses < _MISSES:
                misses += 1
        yield entry, line + 1


def detect(package: Package) -> Iterator[Finding]:
    reported = 0
    for unit in package.instructions():
        span = _frontmatter_lines(unit)
        if span is None:
            continue
        block = _key_block(unit.lines, *span)
        if block is None:
            continue
        try:
            mapping, _ = parse_frontmatter(unit.text)
        except FrontmatterError:
            continue
        if _KEY not in mapping:
            continue
        key_line, stop = block
        seen: set[str] = set()
        in_file = 0
        for entry, line in _located(unit.lines, key_line, stop, _entries(mapping[_KEY])):
            if not _unscoped(entry) or entry in seen:
                continue
            seen.add(entry)
            matched = f"{_KEY}: {entry}"
            yield Finding(RULE_ID, SEVERITY, TITLE, Location(unit.path, line), excerpt(matched),
                          fingerprint(RULE_ID, unit.path, matched), MALICIOUS)
            in_file += 1
            reported += 1
            if in_file >= _PER_FILE or reported >= _PER_PACKAGE:
                break
        if reported >= _PER_PACKAGE:
            return
