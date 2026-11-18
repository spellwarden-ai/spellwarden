"""The text rules of Phase C spec 5.4 (review item 8): what a pack name, a pack description, an org rule title or an
eval label may hold, and how a value is written into a generated comment. A value accepted here can never start a
new line, a new key or a reversed run of text in a generated file or a response header."""
from __future__ import annotations

import re
import unicodedata

# Cc: every control character (CR, LF, NUL, tab, ...); Cf: format characters (the bidirectional controls, zero-width
# joiners, the tag block); Zl and Zp: U+2028 and U+2029; Cs: a lone surrogate, which no UTF-8 encoder accepts (plan
# decision P-TXT-1 adds it to spec 5.4's list).
_REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_TAGS = ("\U000e0000", "\U000e007f")


def _clean(text: str, *, allow_lf: bool) -> bool:
    for char in text:
        if allow_lf and char == "\n":
            continue
        if unicodedata.category(char) in _REFUSED_CATEGORIES or _TAGS[0] <= char <= _TAGS[1]:
            return False
    return True


def valid_line(s: object, max_len: int) -> bool:
    """True when `s` is a string of 1 to `max_len` characters after stripping that holds no character of the
    categories Cc, Cf, Cs, Zl or Zp and none of U+E0000 to U+E007F (checked over the whole string, stripped part included)."""
    return isinstance(s, str) and 1 <= len(s.strip()) <= max_len and _clean(s, allow_lf=False)


def valid_block(s: object, max_len: int) -> bool:
    """`valid_line` that also allows LF (a description of several lines); CR stays refused."""
    return isinstance(s, str) and 1 <= len(s.strip()) <= max_len and _clean(s, allow_lf=True)


def _escaped(char: str) -> str:
    if " " <= char <= "~":
        return char
    code = ord(char)
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def comment_safe(s: str, max_len: int = 120) -> str:
    """`s` for a generated comment or Markdown line: every character outside printable ASCII written as `\\uXXXX`
    (`\\UXXXXXXXX` above U+FFFF), then cut to at most `max_len` characters without splitting an escape."""
    out: list[str] = []
    length = 0
    for char in str(s):
        piece = _escaped(char)
        if length + len(piece) > max_len:
            break
        out.append(piece)
        length += len(piece)
    return "".join(out)


# 1.18.0: a lone surrogate, the code points U+D800 to U+DFFF on their own. JSON allows them as `\uD800` escapes and
# Python's `json` decodes such an escape to that code point, but no UTF-8 encoder accepts one, so remote text that holds one
# would make every later hash or file write raise. A pair written as two escapes is decoded to one character and is not one.
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def replace_lone_surrogates(text: str) -> str:
    """`text` with each lone surrogate replaced by U+FFFD; any other text is returned unchanged."""
    return _LONE_SURROGATE.sub("\ufffd", text)


def utf8(text: str) -> bytes:
    """The UTF-8 bytes every hash of the engine takes of a text: `replace_lone_surrogates` first, so a caller's text that holds a
    lone surrogate hashes as its U+FFFD form instead of raising, and any other text gives exactly `text.encode("utf-8")`."""
    return replace_lone_surrogates(text).encode("utf-8")


def replace_lone_surrogates_in_json(value: object) -> object:
    """A value as `json.loads` returns it, with `replace_lone_surrogates` applied to every string in it, keys included. Lists and
    objects are changed in place (the caller owns what it just parsed) and walked with a loop, not a recursion, so any depth
    `json.loads` accepted is handled. Two keys that become equal keep the later value, as a repeated JSON key does."""
    if isinstance(value, str):
        return replace_lone_surrogates(value)
    pending = [value] if isinstance(value, (dict, list)) else []
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            for index, item in enumerate(node):
                if isinstance(item, str):
                    node[index] = replace_lone_surrogates(item)
                elif isinstance(item, (dict, list)):
                    pending.append(item)
            continue
        entries = list(node.items())
        node.clear()
        for key, item in entries:
            if isinstance(item, str):
                item = replace_lone_surrogates(item)
            elif isinstance(item, (dict, list)):
                pending.append(item)
            node[replace_lone_surrogates(key) if isinstance(key, str) else key] = item
    return value


__all__ = ["comment_safe", "replace_lone_surrogates", "replace_lone_surrogates_in_json", "utf8", "valid_block",
           "valid_line"]
