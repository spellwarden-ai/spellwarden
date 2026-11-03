"""SW-SKL-036: frontmatter pre-approves an unscoped shell or interpreter.

Read over the leading YAML frontmatter of SKILL.md and of the Markdown files in a `commands/` or `agents/` directory of
the package (the command and agent files an agent loads; a reference document with frontmatter is not read), key `allowed-tools` in any form: a comma- or space-separated string, a flow list or
a block list. An entry fires when it is, case-insensitively, a shell tool (`Bash`, `Shell`, `PowerShell`) with no
scope, with a wildcard scope (`Bash(*)`, `Bash(:*)`), or with a scope that is a general interpreter or launcher alone
(`Bash(python3:*)`, `Bash(node)`, `Bash(npx:*)`, ...). A shell scoped to one task-specific command
(`Bash(gh pr view:*)`) is quiet, and so is everything that is not the leading frontmatter's own `allowed-tools` key:
the body, a fenced example in an authoring guide, a subagent's `tools:` capability list, a nested key.

The finding is at the offending entry's line: the list item's line, or the `allowed-tools:` line for a one-line value.
Whether the key is there and what it holds come from the parsed frontmatter; the text is read only to place a finding.
Entries are cut out of the value with one forward scan, and only the entries that will be reported (at most five per
file) are located, each by a forward search for the whole entry from the previous one; an entry the raw text does not
contain (YAML unescaped it), or a key the text does not show plainly, is placed on the key line, or on the
frontmatter's first line. A long line is therefore read in linear time. The module is registered by the rule set, not
here."""
from __future__ import annotations

import re
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

_SHELL_TOOLS = frozenset({"bash", "shell", "powershell"})
_WILDCARDS = frozenset({"*", ":*"})
_INTERPRETERS = frozenset({
    "python", "python3", "node", "deno", "bun", "ruby", "perl", "bash", "sh", "zsh", "pwsh", "powershell", "npx", "uvx",
    "pip", "pip3", "source", "eval",
})
# Launchers run whatever follows them: alone, or followed by an interpreter, they are as general as the interpreter.
_LAUNCHERS = frozenset({"env", "xargs", "exec", "command", "sudo", "nohup", "time"})
_INLINE_CODE = frozenset({"-c", "-e", "--eval", "-"})
_VERSIONED = re.compile(r"^(python|ruby|perl|node|pip|pwsh)[0-9][0-9.]*$")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_BOUNDARY_BEFORE = " \t,[-\"'"
_BOUNDARY_AFTER = " \t,]\"'#\r\n"
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
    return _general(scope.split())


def _program(word: str) -> str:
    """`/usr/bin/python3.12` -> `python3`: the base name, without `.exe` and without a version after the name."""
    name = word.replace("\\", "/").rsplit("/", 1)[-1]
    name = name.removesuffix(".exe")
    versioned = _VERSIONED.match(name)
    if versioned:
        major = name[len(versioned.group(1)):].split(".", 1)[0]
        return versioned.group(1) + ("3" if major == "3" and versioned.group(1) in ("python", "pip") else "")
    return name


def _general(words: list[str]) -> bool:
    """A scope that runs anything: an interpreter or launcher alone, an interpreter given inline code (`-c`, `-e`,
    `--eval`, `-`) or `-m` with no module, or a launcher (`env`, `xargs`, ...) followed by one of those."""
    while words and _ASSIGNMENT.match(words[0]):
        words = words[1:]
    if not words:
        return False
    program = _program(words[0])
    if program == "command":
        options = []
        for word in words[1:]:
            if not word.startswith("-"):
                break
            options.append(word)
        if "-v" in options or "-V" in options:
            return False  # `command -v x` only looks a program up; `command -p bash -v` still runs bash
    if program in _LAUNCHERS:
        rest = [word for word in words[1:] if not word.startswith("-")]
        return not rest or _general(rest)
    if program not in _INTERPRETERS:
        return False
    # `python3 -m pytest` is one module; `python3 -m` alone, or inline code, runs anything.
    return len(words) == 1 or words[1] in _INLINE_CODE or (words[1] == "-m" and len(words) == 2)


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


def _find_entry(lines: tuple[str, ...], entry: str, row: int, col: int, stop: int) -> tuple[int, int] | None:
    """The first whole occurrence of `entry` at or after `(row, col)` before line `stop`: `(row, column after it)`.
    One forward pass over the block: each line is searched once, occurrence after occurrence."""
    while row < stop:
        line = lines[row]
        at = line.find(entry, col)
        while at != -1:
            end = at + len(entry)
            before = line[at - 1] if at > 0 else " "
            after = line[end] if end < len(line) else "\n"
            if before in _BOUNDARY_BEFORE and (after in _BOUNDARY_AFTER or entry.endswith(")")) and after != "(":
                return row, end
            at = line.find(entry, at + 1)
        row, col = row + 1, 0
    return None


def _loaded(path: str) -> bool:
    """SKILL.md (or `skill.md`), or a Markdown file inside a `commands/` or `agents/` directory of the package."""
    parts = path.replace("\\", "/").split("/")
    return parts[-1].lower() == "skill.md" or any(part.lower() in ("commands", "agents") for part in parts[:-1])


def detect(package: Package) -> Iterator[Finding]:
    reported = 0
    for unit in package.instructions():
        if not _loaded(unit.path):
            continue
        span = _frontmatter_lines(unit)
        if span is None:
            continue
        try:
            mapping, _ = parse_frontmatter(unit.text)
        except FrontmatterError:
            continue
        if not isinstance(mapping, dict) or _KEY not in mapping:
            continue
        # The parsed mapping decides; the text only places the finding. A key the text does not show plainly (quoted
        # oddly, a flow mapping) is placed on the frontmatter's first line.
        block = _key_block(unit.lines, *span)
        key_line, stop = block if block is not None else (span[0], span[1])
        row, col = key_line, max(unit.lines[key_line].find(":") + 1, 0)
        seen: set[str] = set()
        in_file = 0
        for entry in _entries(mapping[_KEY]):
            if not _unscoped(entry) or entry in seen:
                continue
            seen.add(entry)
            found = _find_entry(unit.lines, entry, row, col, stop) if entry else None
            line = key_line + 1
            if found is not None:
                row, col = found
                line = row + 1
            matched = f"{_KEY}: {entry}"
            yield Finding(RULE_ID, SEVERITY, TITLE, Location(unit.path, line), excerpt(matched),
                          fingerprint(RULE_ID, unit.path, matched), MALICIOUS)
            in_file += 1
            reported += 1
            if in_file >= _PER_FILE or reported >= _PER_PACKAGE:
                break
        if reported >= _PER_PACKAGE:
            return
