"""Disguised content (P6-4 spec 6.5): the steps that give the skill rules a normalised reading of a line. Pure functions over one
line, linear in its length; no I/O. A fold step changes a line in place and never adds or removes a line break (`fold`); the
decode step reads extra text out of a line (`payloads`). `scan_skill_package` reads the rules of `RULES` through these steps
and keeps a finding only where the text as written has none; the original line stays what a finding quotes (`EVIDENCE_PREFIX`).
Unicode folding follows the interpreter's Unicode version."""
from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from collections.abc import Collection

FOLD_STEPS = ("entities", "invisible", "compat", "lookalike", "spaces")
DECODE_STEPS = ("base64",)
# Every step built, in the order they apply; `STEPS` is the subset the release ships (spec 6.6), the default of
# `scan_skill_package(normalise=True)`.
CANDIDATE_STEPS = FOLD_STEPS + DECODE_STEPS
STEPS = CANDIDATE_STEPS
MAX_LAYERS = 3
EVIDENCE_PREFIX = "Matched after normalising: "
# The skill rules that read through the normalised views (spec 6.5.3): every skill rule but SW-SKL-002 (it reports the raw
# characters the views remove), SW-SKL-010 (paths and binary files), SW-SKL-011 (a credential in look-alike letters is not a
# usable one, and decoded evidence would carry the encoded secret) and SW-SKL-015, SW-SKL-031 and SW-SKL-036 (the front matter,
# which the views do not change).
RULES = frozenset({"SW-SKL-001", "SW-SKL-003", "SW-SKL-004", "SW-SKL-005", "SW-SKL-006", "SW-SKL-007", "SW-SKL-008", "SW-SKL-009",
                   "SW-SKL-012", "SW-SKL-013", "SW-SKL-014", "SW-SKL-019", "SW-SKL-032", "SW-SKL-037"})

# Every format character and the soft hyphen, removed before the injection phrases are matched (SW-SKL-001,
# SW-MCP-011): `ig\u00adnore previous instructions` reads as the phrase to an agent. Moved here from `rules/skill.py` in 1.22.0,
# unchanged; `rules.skill` imports `visible` under the same name.
_INVISIBLE = re.compile("[\u00ad\u034f\u115f\u180b-\u180f\u200b-\u200f\u2060-\u2064\u202a-\u202e\u2066-\u2069\u3164\ufeff"
                        "\uffa0\ufe00-\ufe0f\ufff9-\ufffb]|[\U000e0000-\U000e007f]|[\U000e0100-\U000e01ef]")


def visible(text: str) -> str:
    """`text` without the characters `_INVISIBLE` names and without every other format character (`Cf`: U+061C,
    U+1BCA0 and the rest), as an agent reads it."""
    text = _INVISIBLE.sub("", text)
    if text.isascii():
        return text
    return "".join(char for char in text if unicodedata.category(char) != "Cf")


# --- the fold steps --------------------------------------------------------------------------------------------------------

# The character references `html.unescape` reads, with the digits bounded so that a reference never feeds `int` more than
# seven digits (a longer run is read as its first digits, as an out-of-range reference: U+FFFD).
_REFERENCE = re.compile(r"&(?:#[0-9]{1,7};?|#[xX][0-9a-fA-F]{1,6};?|[^\t\n\f <&#;]{1,32};?)")


def _reference(match: re.Match) -> str:
    written = match.group(0)
    character = html.unescape(written)
    if any(unicodedata.category(char) == "Cc" for char in character):
        return written  # `&#10;`, `&#13;`, `&NewLine;`: a line break or other control character stays as written
    return character


def _entities(line: str) -> str:
    return line if "&" not in line else _REFERENCE.sub(_reference, line)


def _compat(line: str) -> str:
    """Unicode NFKC of the line, or, when that would be longer than three times the line (characters such as U+FDFA, 18
    characters under NFKC), each character folded alone with every character whose own NFKC form is longer than three characters
    left as written, so the folded line is never longer than three times the line."""
    if line.isascii() or unicodedata.is_normalized("NFKC", line):
        return line
    forms: dict[str, str] = {}
    total = 0
    for char in line:
        form = forms.get(char)
        if form is None:
            form = forms[char] = unicodedata.normalize("NFKC", char)
        total += len(form)
    if total <= 3 * len(line):  # composition only shortens, so the whole line's form is at most `total` long
        return unicodedata.normalize("NFKC", line)
    return "".join(forms[char] if len(forms[char]) <= 3 else char for char in line)


# Written by hand from the code charts (not copied from a Unicode data file): single characters of the Cyrillic, Greek,
# Armenian and Latin extended (IPA) blocks whose glyph is an ASCII letter's. It covers the generator's map
# (benchmarks/disguise.py) by design, which benchmarks/README.md says.
LOOKALIKES = {
    # Cyrillic, small
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u04bb": "h", "\u0456": "i", "\u0458": "j", "\u043e": "o", "\u0440": "p",
    "\u051b": "q", "\u0455": "s", "\u051d": "w", "\u0445": "x", "\u0443": "y", "\u0501": "d", "\u04cf": "l",
    # Cyrillic, capital
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E", "\u041d": "H", "\u0406": "I", "\u0408": "J", "\u041a": "K",
    "\u041c": "M", "\u041e": "O", "\u0420": "P", "\u051a": "Q", "\u0405": "S", "\u0422": "T", "\u051c": "W", "\u0425": "X",
    "\u0423": "Y", "\u04c0": "I",
    # Greek, small
    "\u03bf": "o", "\u03b1": "a", "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03c1": "p", "\u03c5": "u", "\u03c7": "x",
    # Greek, capital
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    # Armenian, small
    "\u0585": "o", "\u057d": "u", "\u0570": "h", "\u0578": "n", "\u0581": "g", "\u0566": "q",
    # Latin extended and IPA
    "\u0251": "a", "\u0261": "g", "\u0269": "i", "\u0131": "i",
}


def _word_char(char: str) -> bool:
    return char.isalnum() or unicodedata.category(char) in ("Mn", "Mc", "Me")


def _fold_word(word: str) -> str:
    """A word (letters, digits and combining marks) with its table characters folded when it holds an ASCII letter or when
    every letter in it is a table character; a real Russian or Greek word holds a letter outside the table and is kept."""
    letters = [char for char in word if char.isalpha()]
    if not any(char in LOOKALIKES for char in letters):
        return word
    if any(char.isascii() for char in letters) or all(char in LOOKALIKES for char in letters):
        return "".join(LOOKALIKES.get(char, char) for char in word)
    return word


def _lookalike(line: str) -> str:
    if line.isascii():
        return line
    out: list[str] = []
    start = None
    for index, char in enumerate(line):
        if _word_char(char):
            if start is None:
                start = index
            continue
        if start is not None:
            out.append(_fold_word(line[start:index]))
            start = None
        out.append(char)
    if start is not None:
        out.append(_fold_word(line[start:]))
    return "".join(out)


_INDENT = re.compile(r"[ \t]*")
_RUNS = re.compile(r"[ \t]{2,}|\t")


def _spaces(line: str) -> str:
    """Every run of spaces and tabs after the first non-space character that is not one single space (two or more, or one
    tab) becomes one space; the leading indentation is kept."""
    indent = _INDENT.match(line).end()
    return line[:indent] + _RUNS.sub(" ", line[indent:])


_FOLDERS = {"entities": _entities, "invisible": visible, "compat": _compat, "lookalike": _lookalike, "spaces": _spaces}


def fold(line: str, steps: Collection[str] = STEPS) -> str:
    """`line` through the fold steps of `steps`, in the order of `FOLD_STEPS`. The line holds no line break, and neither does
    the result."""
    for step in FOLD_STEPS:
        if step in steps:
            line = _FOLDERS[step](line)
    return line


_BREAK = re.compile(r"(\r\n|\r|\n)")


def fold_text(text: str, steps: Collection[str] = STEPS) -> str:
    """Text of several lines folded line by line, its line breaks kept as written."""
    parts = _BREAK.split(text)
    return "".join(part if index % 2 else fold(part, steps) for index, part in enumerate(parts))


# --- the decode step -------------------------------------------------------------------------------------------------------

_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_ALLOWED_CONTROLS = frozenset("\t\n\r")
_WHITESPACE = re.compile(r"[ \t\r\n]")


def decoded_text(token: str) -> str | None:
    """The text a base64 token decodes to (standard or URL-safe alphabet, not both; up to two `=` and a length that is a multiple
    of four once padded), when it is strict UTF-8 of at least 8 characters with no control character but tab, line feed and
    carriage return; None otherwise."""
    body = token.rstrip("=")
    padding = len(token) - len(body)
    missing = -len(body) % 4
    if missing == 3 or (padding and padding != missing):
        return None
    standard, url_safe = ("+" in body or "/" in body), ("-" in body or "_" in body)
    if standard and url_safe:
        return None
    try:
        data = base64.b64decode(body + "=" * missing, altchars=b"-_" if url_safe else None, validate=True)
        text = data.decode("utf-8")
    except (binascii.Error, ValueError):  # UnicodeDecodeError is a ValueError
        return None
    if len(text) < 8 or any(unicodedata.category(char) == "Cc" and char not in _ALLOWED_CONTROLS for char in text):
        return None
    return text


def payloads(line: str, steps: Collection[str] = STEPS) -> tuple[str, ...]:
    """The payloads of a line (spec 6.5.1 step 6), in the order they appear: every decoded text that holds a space, tab or line
    break, folded with the fold steps of `steps`. Every decoded text, payload or not, is searched for tokens again, up to
    `MAX_LAYERS` decodings counted from the line: text encoded once, twice or three times is reached, four times is not. Empty
    without the step `base64` in `steps`."""
    if "base64" not in steps:
        return ()
    found: list[str] = []

    def search(text: str, depth: int) -> None:
        for match in _TOKEN.finditer(text):
            decoded = decoded_text(match.group(0))
            if decoded is None:
                continue
            decoded = fold_text(decoded, steps)
            if _WHITESPACE.search(decoded):
                found.append(decoded)
            if depth + 1 < MAX_LAYERS:
                search(decoded, depth + 1)

    search(line, 0)
    return tuple(found)


__all__ = ["CANDIDATE_STEPS", "DECODE_STEPS", "EVIDENCE_PREFIX", "FOLD_STEPS", "LOOKALIKES", "MAX_LAYERS", "RULES", "STEPS",
           "decoded_text", "fold", "fold_text", "payloads", "visible"]
