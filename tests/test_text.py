"""Phase C spec 5.4 (review item 8): the text rules for names, descriptions, titles and labels, and the comment form."""
from __future__ import annotations

import json
import os
import time
from itertools import islice, product

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

# Wall-clock budgets scale with SPELLWARDEN_SPEED_FACTOR when it is set (CI sets 3), as in tests/test_growth_skl_037.py.
SPEED_FACTOR = float(os.environ.get("SPELLWARDEN_SPEED_FACTOR", "1"))


# --- 1.18.0: lone surrogates ---------------------------------------------------------------------------------------------

def test_a_lone_surrogate_becomes_the_replacement_character_and_other_text_is_unchanged():
    assert replace_lone_surrogates("a\udc80b\udfff\ud800c\ud800") == "a\ufffdb\ufffd\ufffdc\ufffd"  # a low before a high: two
    for text in ("", "plain", "\u00c9quipe \U0001F600 \u8fd0\u7ef4", "\ufffd", "\uffff\U00010000"):
        assert replace_lone_surrogates(text) == text
    assert replace_lone_surrogates(json.loads('"\\ud83d\\ude00"')) == "\U0001F600"  # json joins a pair of escapes itself
    # PyYAML leaves a pair of escapes as two code points: a high followed by a low is joined into the character it encodes
    assert replace_lone_surrogates("x\ud83d\ude00y\ud800\udfff") == "x\U0001F600y\U000103FF"


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


def test_keys_that_become_equal_are_all_kept_the_later_with_a_distinct_name():
    """1.18.0: cleaning keys never loses a value. A cleaned key equal to one already in the cleaned object (another cleaned key,
    or a key that was U+FFFD already) gets U+FFFD and a number from 2 appended; the earlier key in the document keeps its name."""
    assert replace_lone_surrogates_in_json(json.loads('{"a\\udc80": 1, "a\\udc81": 2}')) == {"a\ufffd": 1, "a\ufffd\ufffd2": 2}
    assert list(replace_lone_surrogates_in_json(json.loads('{"a\\ufffd": 0, "a\\udc80": 1, "a\\udc81": 2}')).items()) == [
        ("a\ufffd", 0), ("a\ufffd\ufffd2", 1), ("a\ufffd\ufffd3", 2)]
    assert list(replace_lone_surrogates_in_json(json.loads('{"a\\udc80": 1, "a\\ufffd": 0}')).items()) == [
        ("a\ufffd", 1), ("a\ufffd\ufffd2", 0)]
    nested = '{"p": {"x\\udc80": {"d": "one"}, "x\\udc81": {"d": "two"}}, "q": [{"k\\ud800": 1, "k\\udbff": 2}]}'
    first, second = (replace_lone_surrogates_in_json(json.loads(nested)) for _ in range(2))
    assert first == second == {"p": {"x\ufffd": {"d": "one"}, "x\ufffd\ufffd2": {"d": "two"}},
                               "q": [{"k\ufffd": 1, "k\ufffd\ufffd2": 2}]}
    assert [list(first["p"]), list(first["q"][0])] == [list(second["p"]), list(second["q"][0])]


def test_an_object_without_lone_surrogates_keeps_its_keys_in_their_order():
    text = '{"z": 1, "a": {"y": 2, "b": [{"x": 3, "\\ufffd": 4, "\\ufffd\\ufffd": 5}]}, "m": "\\ud83d\\ude00"}'
    value = replace_lone_surrogates_in_json(json.loads(text))
    assert value == json.loads(text)
    assert list(value) == ["z", "a", "m"] and list(value["a"]["b"][0]) == ["x", "\ufffd", "\ufffd\ufffd"]


def test_a_name_the_document_already_holds_is_skipped():
    value = replace_lone_surrogates_in_json(json.loads('{"a\\ufffd": 0, "a\\ufffd\\ufffd2": 9, "a\\udc80": 1, "a\\udc81": 2}'))
    assert list(value.items()) == [("a\ufffd", 0), ("a\ufffd\ufffd2", 9), ("a\ufffd\ufffd3", 1), ("a\ufffd\ufffd4", 2)]


def test_many_keys_that_all_collide_cost_linear_time_and_key_text():
    """200,000 keys that differ only in which two low surrogates they hold (a low surrogate never starts a pair) all clean to
    `name\ufffd\ufffd`: the names given are numbered, so the work and the text of the keys grow with the input, not with its square."""
    lows = [chr(code) for code in range(0xDC00, 0xE000)]
    keys = ["name" + first + second for first, second in islice(product(lows, repeat=2), 200_000)]
    value = dict.fromkeys(keys, 1)
    started = time.perf_counter()
    cleaned = replace_lone_surrogates_in_json(value)
    elapsed = time.perf_counter() - started
    assert elapsed < 3.0 * SPEED_FACTOR, elapsed
    assert len(cleaned) == 200_000 and sum(cleaned.values()) == 200_000  # no value lost
    names = list(cleaned)
    assert names[:3] == ["name\ufffd\ufffd", "name\ufffd\ufffd\ufffd2", "name\ufffd\ufffd\ufffd3"] and names[-1] == "name\ufffd\ufffd\ufffd200000"
    assert sum(map(len, names)) < 3 * sum(map(len, keys))

