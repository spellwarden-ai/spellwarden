"""The 1.23.0 text of `visible`, `_word_char`, `_fold_word` and `_lookalike` of `spellwarden_scan.normalise`, copied unchanged, so
that tests/test_normalise_speed.py can hold the faster 1.24.0 functions to them on every input (speed and deadline spec 11.2, claim
T4). Test code: nothing imports it but the tests, and it is never changed. Only `_INVISIBLE` and `LOOKALIKES`, which 1.24.0 left as
they were, come from the module."""
from __future__ import annotations

import unicodedata

from spellwarden_scan.normalise import _INVISIBLE, LOOKALIKES


def visible(text: str) -> str:
    text = _INVISIBLE.sub("", text)
    if text.isascii():
        return text
    return "".join(char for char in text if unicodedata.category(char) != "Cf")


def _word_char(char: str) -> bool:
    return char.isalnum() or unicodedata.category(char) in ("Mn", "Mc", "Me")


def _fold_word(word: str) -> str:
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
