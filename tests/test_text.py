"""Phase C spec 5.4 (review item 8): the text rules for names, descriptions, titles and labels, and the comment form."""
from __future__ import annotations

import json

import pytest

from spellwarden_scan.text import (comment_safe, replace_lone_surrogates, replace_lone_surrogates_in_json, valid_block,
                                   valid_line)


@pytest.mark.parametrize("value", ["Ops prod", 'Ops "prod"', "x: y", "- z", "Équipe sécurité", "运维团队", "Launch \U0001f680",
                                   "  padded  ", "x" * 80])
def test_valid_line_accepts_printable_text_of_any_script(value):
    assert valid_line(value, 80) is True


@pytest.mark.parametrize("value", ["", "   ", "a\nb", "a\rb", "a\tb", "a\x00b", "a\U00002028b", "a\U00002029b", "a\U0000202eb",
                                   "a\U00002066b", "a\U0000200db", "a\U0000feffb", "a\U000e0041b", "x" * 81, None, 7, ["x"], "line\n"])
def test_valid_line_refuses_controls_format_and_separator_characters_and_wrong_types(value):
    assert valid_line(value, 80) is False


def test_valid_block_allows_line_feeds_only():
    assert valid_block("First line.\nSecond line.", 500) is True
    assert valid_block("First line.\r\nSecond line.", 500) is False
    assert valid_block("Bidi \U0000202e inside", 500) is False
    assert valid_block("x" * 501, 500) is False
    assert valid_block("\n\n", 500) is False


def test_comment_safe_escapes_everything_outside_printable_ascii():
    assert comment_safe('Pack "x"\n- y: z') == 'Pack "x"\\u000a- y: z'
    assert comment_safe("Équipe \U0001f680") == "\\u00c9quipe \\U0001f680"
    assert comment_safe("a\U00002028b\U0000202ec") == "a\\u2028b\\u202ec"


def test_comment_safe_cuts_without_splitting_an_escape():
    assert comment_safe("x" * 200) == "x" * 120
    cut = comment_safe("x" * 117 + "é" + "y")
    assert cut == "x" * 117 and len(cut) <= 120
    assert comment_safe("abc", max_len=2) == "ab"


# --- 1.18.0: lone surrogates ---------------------------------------------------------------------------------------------

def test_a_lone_surrogate_becomes_the_replacement_character_and_other_text_is_unchanged():
    assert replace_lone_surrogates("a\udc80b\ud800\udfff") == "a\ufffdb\ufffd\ufffd"
    for text in ("", "plain", "Équipe \U0001F600 运维", "\ufffd", "\uffff\U00010000"):
        assert replace_lone_surrogates(text) is text or replace_lone_surrogates(text) == text
    assert replace_lone_surrogates(json.loads('"\\ud83d\\ude00"')) == "\U0001F600"  # a pair of escapes is one character


def test_every_string_of_a_parsed_json_value_is_made_safe_keys_included():
    value = json.loads('{"a\\udc80": ["x\\ud800", {"k": "v\\udfff", "n": 1, "t": true, "z": null}], "b": "\\ud83d\\ude00"}')
    assert replace_lone_surrogates_in_json(value) == {"a\ufffd": ["x\ufffd", {"k": "v\ufffd", "n": 1, "t": True, "z": None}],
                                                      "b": "\U0001F600"}
    assert list(value) == ["a\ufffd", "b"]  # the key order is kept
    assert replace_lone_surrogates_in_json("\udc80") == "\ufffd" and replace_lone_surrogates_in_json(7) == 7


def test_a_deep_json_value_is_walked_without_recursion():
    depth = 5000
    value: object = "\udc80"
    for _ in range(depth):
        value = [value]
    replace_lone_surrogates_in_json(value)
    for _ in range(depth):
        value = value[0]
    assert value == "\ufffd"
