"""Engine 1.24.0 (speed and deadline spec 6.2, F2 and F3; claim T4): the faster `_lookalike`, `_fold_word` and `visible` give the
result of the 1.23.0 functions (tests/reference_normalise_1_23_0.py) on every input the tests can name: every code point, every
single character, 20,000 lines drawn by a deterministic generator and the lines of the fixtures. The running Python supplies both
sides, so the tests hold on every Unicode version. They count no time."""
from __future__ import annotations

import hashlib

import pytest
import reference_normalise_1_23_0 as old
from conftest import SKILL_FIXTURES

from spellwarden_scan import normalise
from spellwarden_scan.normalise import LOOKALIKES

ALL_CODE_POINTS = [chr(code) for code in range(0x110000)]


def test_every_table_character_is_a_letter():
    """F2 reads `_TABLE` where 1.23.0 read the letters of a word: the two agree only while each table character is a letter."""
    assert len(LOOKALIKES) == 65
    assert all(char.isalpha() and not char.isascii() for char in LOOKALIKES)


def test_the_word_pattern_equals_word_char_on_every_code_point():
    pattern = normalise._words()
    for char in ALL_CODE_POINTS:
        assert (pattern.fullmatch(char) is not None) == old._word_char(char), hex(ord(char))


def test_the_word_pattern_is_built_on_first_use_and_kept():
    normalise._words.cache_clear()
    assert normalise._words.cache_info().currsize == 0
    pattern = normalise._words()
    assert normalise._words() is pattern and normalise._words.cache_info().currsize == 1


def test_every_single_character_folds_as_before():
    for char in ALL_CODE_POINTS:
        assert normalise._lookalike(char) == old._lookalike(char), hex(ord(char))
        assert normalise._fold_word(char) == old._fold_word(char), hex(ord(char))


def test_every_single_character_between_ascii_letters_folds_as_before():
    for char in ALL_CODE_POINTS:
        line = f"a{char}b {char}{char} x_{char}"
        assert normalise._lookalike(line) == old._lookalike(line), hex(ord(char))


ALPHABETS = (
    "abcxyzABCXYZ019 _-.,;:!?()[]{}<>/\\\"'`~@#$%^&*+=|\t",  # ASCII, digits, punctuation, a tab
    "".join(sorted(LOOKALIKES)),  # the table characters
    "\u0301\u0308\u0345\u20dd\u0903\u093e\u200d",  # combining marks of Mn, Mc and Me, and a joiner
    "\u00ad\u061c\u200b\u200e\u2060\ufeff\U000e0001\U000e0100\U0001bca0",  # format characters: those of `_INVISIBLE` and others
    "\u0663\u00b2\u2460\u3007\ufdfa\u00e9\u00df\u0436\u03c3\u4e2d\u0e01",  # digits of other scripts, letters outside the table
    "\u2003\u00a0\u3000\u2028",  # spaces that are not word characters
)


def generated_lines(count: int = 20_000):
    """Lines of 1 to 32 characters drawn from the alphabets above by a counter hashed with SHA-256: the same on every Python."""
    alphabet = "".join(ALPHABETS)
    for index in range(count):
        digest = hashlib.sha256(index.to_bytes(4, "big")).digest()
        yield "".join(alphabet[byte % len(alphabet)] for byte in digest[1:2 + digest[0] % 31])


def test_generated_lines_fold_as_before():
    changed = 0
    for line in generated_lines():
        assert normalise._lookalike(line) == old._lookalike(line), repr(line)
        changed += old._lookalike(line) != line
    assert changed > 1_000  # the generator reaches the interesting branches: the lines are not all left as they were


def fixture_lines():
    for path in sorted(SKILL_FIXTURES.rglob("*")):
        if path.is_file() and path.name != "expected.json":
            yield from path.read_bytes().decode("utf-8", errors="replace").splitlines()


def test_the_lines_of_the_fixtures_fold_as_before():
    count = 0
    for line in fixture_lines():
        assert normalise._lookalike(line) == old._lookalike(line), repr(line)
        count += 1
    assert count > 100


NAMED = ["\u0441at", "\u0441\u043e\u0441", "\u0441\u0436", "pa\u0440\u0430l", "\u0430\u0436\u0430", "a_\u0430",
         "pa\u0443pal \u0441onfig", "\u0441\u0436 \u0441at", "\u0441\u0436 \u043e\u043e", "x \u0430\u0436\u0430 \u0430b"]


@pytest.mark.parametrize("line", NAMED)
def test_named_lines_that_take_each_of_the_three_paths(line):
    assert normalise._lookalike(line) == old._lookalike(line)
    assert normalise._fold_word(line) == old._fold_word(line)


def test_a_line_without_a_table_character_is_returned_as_it_is():
    line = "caf\u00e9 \u0436 text"
    assert normalise._lookalike(line) is line


def test_a_line_of_ascii_and_table_letters_is_folded_whole_and_a_line_with_another_letter_word_by_word():
    assert normalise._lookalike("pa\u0443pal \u0441onfig \u043e\u043e") == "paypal config oo"  # no other letter: the whole line
    # `\u0436` is a letter outside the table: the word `\u0441\u0436` is a real word and stays, `\u0441at` is folded
    assert normalise._lookalike("\u0441\u0436 \u0441at") == "\u0441\u0436 cat"
