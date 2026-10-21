"""The text rules of Phase C spec 5.4 (review item 8): what a pack name, a pack description, an org rule title or an
eval label may hold, and how a value is written into a generated comment. A value accepted here can never start a
new line, a new key or a reversed run of text in a generated file or a response header."""
from __future__ import annotations

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


__all__ = ["comment_safe", "valid_block", "valid_line"]
