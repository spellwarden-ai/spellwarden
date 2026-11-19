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
# Python's `json` decodes such an escape to that code point; PyYAML does the same with a double-quoted escape, and leaves a pair
# written as two escapes as two code points. No UTF-8 encoder accepts one, so text that holds one would make every later hash
# or file write raise. A high surrogate followed by a low one is a pair: it is joined into the character it encodes.
_SURROGATE = re.compile("([\ud800-\udbff][\udc00-\udfff])|[\ud800-\udfff]")


def _replaced(match: re.Match) -> str:
    pair = match.group(1)
    if pair is None:
        return "\ufffd"
    return chr(0x10000 + ((ord(pair[0]) - 0xD800) << 10) + (ord(pair[1]) - 0xDC00))


def replace_lone_surrogates(text: str) -> str:
    """`text` with each pair of surrogates joined into its character and each lone surrogate replaced by U+FFFD; any other text
    is returned unchanged."""
    return _SURROGATE.sub(_replaced, text)


def utf8(text: str) -> bytes:
    """The UTF-8 bytes every hash of the engine takes of a text: `replace_lone_surrogates` first, so a caller's text that holds a
    lone surrogate hashes as its U+FFFD form instead of raising, and any other text gives exactly `text.encode("utf-8")`."""
    return replace_lone_surrogates(text).encode("utf-8")


class _Walk:
    """The state of one walk: the lists and mappings still to clean, the ids of those already queued (a YAML alias is the same
    object at every reference, so a few hundred bytes can reference one list billions of times: each is cleaned once, in place,
    which serves every reference), and each tuple or set already rebuilt, by id, so it too is rebuilt once."""

    def __init__(self) -> None:
        self.pending: list = []
        self.queued: set[int] = set()
        self.rebuilt: dict[int, object] = {}

    def safe(self, item: object) -> object:
        """One member: a string made safe, a list or mapping queued once (changed in place), a tuple or set (PyYAML's `!!omap`
        pairs and `!!set`) rebuilt once with its members made safe; anything else as it is."""
        if isinstance(item, str):
            return replace_lone_surrogates(item)
        if isinstance(item, (dict, list)):
            if id(item) not in self.queued:
                self.queued.add(id(item))
                self.pending.append(item)
            return item
        if isinstance(item, (tuple, set, frozenset)):
            if id(item) not in self.rebuilt:
                self.rebuilt[id(item)] = type(item)(self.safe(member) for member in item)
            return self.rebuilt[id(item)]
        return item


def replace_lone_surrogates_in_json(value: object) -> object:
    """A value as `json.loads` or a YAML safe loader returns it, with `replace_lone_surrogates` applied to every string in it,
    keys included. Lists and mappings are changed in place (the caller owns what it just parsed) and walked with a loop, not a
    recursion, so any depth the parser accepted is handled. No value is ever lost: a cleaned key equal to a key already in the
    cleaned mapping (two keys that clean to the same text, or one that already held U+FFFD) is kept under a distinct name, the
    later key in the document's order as `base + U+FFFD + n` with n counted per base from 2, skipping a name the mapping
    already holds, so a server cannot hide one value behind another. The last n of each base is kept, so the work and the key
    text stay linear in the input however many keys collide. A mapping without lone surrogates comes back with the same keys
    in the same order. Each list, mapping, tuple and set is cleaned once however many references it has (`_Walk`), so the work
    is linear in the number of distinct objects, not in the size of the value they expand to."""
    walk = _Walk()
    value = walk.safe(value)
    while walk.pending:
        node = walk.pending.pop()
        if isinstance(node, list):
            for index, item in enumerate(node):
                node[index] = walk.safe(item)
            continue
        entries = list(node.items())
        node.clear()
        last: dict[str, int] = {}  # per base name, the last n given: each candidate is tried once, O(1) amortised
        for key, item in entries:
            key = walk.safe(key)
            if isinstance(key, str) and key in node:
                base, n = key, last.get(key, 1)
                while True:
                    n += 1
                    key = f"{base}\ufffd{n}"
                    if key not in node:
                        break
                last[base] = n
            node[key] = walk.safe(item)
    return value


__all__ = ["comment_safe", "replace_lone_surrogates", "replace_lone_surrogates_in_json", "utf8", "valid_block",
           "valid_line"]
