"""Zuplo export spec 4.3 ("JavaScript sources") and claim E6, the pure half: `zuplo_part` writes the JavaScript form of one
emitted part of a pattern and answers None for what the token grammar does not name."""
from __future__ import annotations

import pytest

from spellwarden_scan.exports import zuplo as Z
from spellwarden_scan.rules.patterns import INJECTION


def test_e6_every_injection_expression_passes():
    for pattern in INJECTION:
        assert Z.zuplo_part(pattern.pattern) is not None, pattern.pattern


@pytest.mark.parametrize(("source", "expected"), [
    ("abc", "abc"),
    ("^ab$", "^ab$"),
    ("café", "caf\\u00E9"),
    ("a\\ b\\-c\\&d\\~e\\#f", "a\\ b\\-c\\&d\\~e\\#f"),
    ("[a-z\\d_]+x", "[a-z\\d_]+x"),
    ("[^à-ÿ]{1,3}", "[^\\u00E0-\\u00FF]{1,3}"),
    ("(?:ab|cd)?e", "(?:ab|cd)?e"),
    ("(ab|cd)e", "(ab|cd)e"),
    ("\\bfoo\\b", "\\bfoo\\b"),
    ("a.b", "a.b"),
    ("x\U0001F600y", "x\\uD83D\\uDE00y"),
    ("x\U0001F600+y", "x(?:\\uD83D\\uDE00)+y"),
])
def test_e6_zuplo_part_writes_the_javascript_form(source, expected):
    assert Z.zuplo_part(source) == expected


@pytest.mark.parametrize("source", [
    "(?i)abc", "(?P<n>a)", "(?=a)b", "(a)\\1", "\\Aab", "ab\\Z", "a\\u00e9", "a\\x41", "a\\N{DASH}", "a\\012", "a\\0",
    "[a\U0001F600]", "[\\b]", "a\\", "a**", "*a", "a{,3}", "a{2", "a}", "a]", "(ab", "ab)", "a|b", "a^b", "a$b", "ab\\\tcd", "[]a]",
])
def test_e6_zuplo_part_answers_none_for_what_the_grammar_does_not_name(source):
    assert Z.zuplo_part(source) is None
