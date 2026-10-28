"""The Zuplo export (Zuplo export spec 4.3). This module holds `zuplo_part`, the JavaScript form of one part of an org
pattern: the Zuplo guard runs the engine's patterns as JavaScript regular expressions."""
from __future__ import annotations

import re

JS_REASON = "its pattern cannot be written for JavaScript"
_PUNCTUATION = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ")
_CLASS_ESCAPES = frozenset("sSdDwW")
_ESCAPES = _CLASS_ESCAPES | {"b"}
_QUANTIFIER = re.compile(r"\{[0-9]{1,3}(?:,[0-9]{1,3})?\}")


def _js_char(char: str, *, in_class: bool) -> str | None:
    """One literal character as JavaScript source without the `u` flag: ASCII as it is, any other character of the BMP
    as `\\uXXXX`, an astral character as its surrogate pair (never inside a class, where a pair would be two members)."""
    code = ord(char)
    if code < 0x80:
        return char
    if code <= 0xFFFF:
        return f"\\u{code:04X}"
    if in_class:
        return None
    code -= 0x10000
    return f"\\u{0xD800 + (code >> 10):04X}\\u{0xDC00 + (code & 0x3FF):04X}"


def _class(text: str, at: int) -> tuple[str, int] | None:
    """A bracket class starting at `text[at]`: its JavaScript source and the index after it."""
    out = ["["]
    index = at + 1
    if text[index:index + 1] == "^":
        out.append("^")
        index += 1
    members = 0
    while index < len(text):
        char = text[index]
        if char == "]":
            return ("".join(out) + "]", index + 1) if members else None
        if char == "[":
            return None
        if char == "\\":
            escaped = text[index + 1:index + 2]
            if escaped in _CLASS_ESCAPES or (escaped and escaped in _PUNCTUATION):
                out.append("\\" + escaped)
                index += 2
                members += 1
                continue
            return None
        if char == "-":
            out.append("-")
            index += 1
            members += 1
            continue
        piece = _js_char(char, in_class=True)
        if piece is None:
            return None
        out.append(piece)
        index += 1
        members += 1
    return None


def zuplo_part(source: str) -> str | None:
    """The JavaScript form of one emitted part of a pattern (`part.pattern`), or None when the part holds anything the
    token grammar of the spec does not name. Tokens: an escape (`\\` and ASCII punctuation or a space, or one of
    `\\s \\S \\d \\D \\w \\W \\b`), `.`, `^` first, `$` last, a bracket class, a quantifier (`*`, `+`, `?`, `{m}`,
    `{m,n}`; never two in a row), a group `(` or `(?:` with alternatives separated by `|`, and any other single
    character as a literal. A non-ASCII character is written as `\\uXXXX`; an astral character outside a class as its
    surrogate pair, inside a group of its own when a quantifier follows it, so that the quantifier repeats the character
    and not its second half."""
    out: list[str] = []
    depth = 0
    after_atom = False
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char == "\\":
            escaped = source[index + 1:index + 2]
            if escaped in _ESCAPES or (escaped and escaped in _PUNCTUATION):
                out.append("\\" + escaped)
                after_atom = escaped != "b"
                index += 2
                continue
            return None
        if char == "^":
            if index != 0:
                return None
            out.append("^")
            index += 1
            continue
        if char == "$":
            if index != length - 1:
                return None
            out.append("$")
            index += 1
            continue
        if char == "[":
            parsed = _class(source, index)
            if parsed is None:
                return None
            out.append(parsed[0])
            index = parsed[1]
            after_atom = True
            continue
        if char == "(":
            if source.startswith("(?", index):
                if not source.startswith("(?:", index):
                    return None
                out.append("(?:")
                index += 3
            else:
                out.append("(")
                index += 1
            depth += 1
            after_atom = False
            continue
        if char == ")":
            if depth == 0:
                return None
            depth -= 1
            out.append(")")
            index += 1
            after_atom = True
            continue
        if char == "|":
            if depth == 0:
                return None
            out.append("|")
            index += 1
            after_atom = False
            continue
        if char in "*+?":
            if not after_atom:
                return None
            out.append(char)
            index += 1
            after_atom = False
            continue
        if char == "{":
            match = _QUANTIFIER.match(source, index)
            if match is None or not after_atom:
                return None
            out.append(match.group(0))
            index = match.end()
            after_atom = False
            continue
        if char in "}]":
            return None
        piece = _js_char(char, in_class=False)
        if piece is None:
            return None
        if ord(char) > 0xFFFF:
            following = source[index + 1:index + 2]
            if following and (following in "*+?" or following == "{"):
                piece = "(?:" + piece + ")"
        out.append(piece)
        after_atom = True
        index += 1
    return "".join(out) if depth == 0 else None


__all__ = ["JS_REASON", "zuplo_part"]
