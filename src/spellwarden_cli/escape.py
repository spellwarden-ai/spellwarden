"""Output escaping per sink (spec 6.13). Every string that comes from the
scanned revision or a probed server passes through one of these before it
reaches a terminal, a report, a comment or a CI output file."""
from __future__ import annotations

import re
import unicodedata

# The characters SW-SKL-002 treats as hidden (bidirectional controls, zero-width and invisible characters, the tag
# block and the variation selectors), plus every other format character: shown as \u{NNNN}, never passed through.
_INVISIBLE = re.compile("[͏ᅟ᠋-᠏​-‏  ‪-‮⁠-⁤⁦-⁩"
                        "ㅤ︀-️﻿ﾠ￹-￻\U000e0000-\U000e007f\U000e0100-\U000e01ef]")
_MARKDOWN_BACKSLASH = frozenset("\\`*_[]|#")
_MARKDOWN_ENTITY = {"<": "&lt;", ">": "&gt;", "&": "&amp;"}
_BACKTICKS = re.compile(r"`+")
# A line whose first non-blank characters are `::` (blank: any whitespace but a line break, as a CI runner trims it).
_WORKFLOW_COMMAND = re.compile(r"^([^\S\n]*):(?=:)", re.MULTILINE)


def _hidden(char: str) -> bool:
    return bool(_INVISIBLE.match(char)) or unicodedata.category(char) == "Cf"


def terminal(text: str, *, single_line: bool = True) -> str:
    """C0 and C1 controls and DEL as \\xNN, hidden characters as \\u{NNNN}; in a single-line field tab and
    newline become \\t and \\n (a multi-line field keeps them)."""
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\t" and single_line:
            out.append("\\t")
        elif char == "\n" and single_line:
            out.append("\\n")
        elif char in "\t\n":
            out.append(char)
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        elif _hidden(char):
            out.append(f"\\u{{{code:04X}}}")
        else:
            out.append(char)
    return "".join(out)


def log_lines(text: str) -> str:
    """A CI log reads a line whose first non-blank characters are `::` as a workflow command (GitHub Actions'
    `::error::`, `::add-mask::`, `::stop-commands::`), so in a report that may be printed to a log such a line has
    its first colon written as \\x3a. Only a line that starts with text from the scanned revision can match."""
    return _WORKFLOW_COMMAND.sub(r"\1\\x3a", text)


def markdown(text: str) -> str:
    """The terminal rules, then Markdown punctuation backslash-escaped and `<`, `>`, `&` entity-encoded, so a
    path or a name can neither format, link, inject HTML nor break a table cell."""
    out: list[str] = []
    for char in terminal(text):
        if char in _MARKDOWN_BACKSLASH:
            out.append("\\" + char)
        else:
            out.append(_MARKDOWN_ENTITY.get(char, char))
    return "".join(out)


def code_span(text: str, *, table: bool = False) -> str:
    """A code span whose fence is longer than any backtick run inside; in a table cell `|` is also escaped
    (GitHub ends a cell at `|` even inside a code span)."""
    inner = terminal(text)
    if table:
        inner = inner.replace("|", "\\|")
    longest = max((len(run) for run in _BACKTICKS.findall(inner)), default=0)
    fence = "`" * (longest + 1)
    if inner.startswith(("`", " ")) or inner.endswith(("`", " ")) or not inner:
        inner = f" {inner} "
    return f"{fence}{inner}{fence}"


def message(text: str) -> str:
    """SARIF `message.text` and other JSON strings shown to people: the JSON encoder escapes C0; C1 controls
    and hidden characters are written as \\u{NNNN} here so no viewer renders them."""
    out: list[str] = []
    for char in text:
        code = ord(char)
        if 0x7F <= code <= 0x9F or _hidden(char):
            out.append(f"\\u{{{code:04X}}}")
        else:
            out.append(char)
    return "".join(out)


codequality = terminal

__all__ = ["code_span", "codequality", "markdown", "message", "terminal"]
