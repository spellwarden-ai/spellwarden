"""O4 spec 5.1 and claims J2 and J3: the shared reader's strict mode (agent cards) refuses a comment, a trailing comma and
a leading byte-order mark and bounds the depth at a parameter; its lenient mode (configuration files) is the 1.2.1 reader."""
from __future__ import annotations

import json

import pytest

from spellwarden_scan import parse_mcp_config
from spellwarden_scan._json import Arr, Obj, Refused, load_json


def refused(content: bytes, **options) -> str:
    with pytest.raises(Refused) as caught:
        load_json(content, **options)
    return caught.value.code


def nested(levels: int) -> str:
    """`levels` nested objects, the innermost empty: the deepest container sits at depth `levels`."""
    return '{"a":' * (levels - 1) + "{}" + "}" * (levels - 1)


def card_with_params(levels: int) -> bytes:
    """A card whose `capabilities.extensions[0].params` nests `levels` objects: the root is depth 1, `capabilities` 2,
    `extensions` 3, its element 4, `params` and what is inside it 5 and deeper."""
    return ('{"capabilities":{"extensions":[{"uri":"x","params":' + nested(levels) + "}]}}").encode()


def test_j2_a_card_nested_128_levels_parses_and_129_is_too_deep():
    deepest = 4 + 124  # params of 124 nested objects ends at depth 128
    assert isinstance(load_json(card_with_params(124), strict=True, max_depth=128), Obj)
    assert deepest == 128
    assert refused(card_with_params(125), strict=True, max_depth=128) == "too_deep"


def test_the_default_depth_is_the_configuration_files_32():
    assert isinstance(load_json(nested(32).encode()), Obj)
    assert refused(nested(33).encode()) == "too_deep"


@pytest.mark.parametrize(("content", "code"), [
    (b'// c\n{"a": 1}', "not_json"),            # a comment
    (b'{"a": 1 /* c */}', "not_json"),
    (b'{"a": 1,}', "not_json"),                 # a trailing comma in an object
    (b'{"a": [1,]}', "not_json"),               # and in an array
    (b'\xef\xbb\xbf{"a": 1}', "bom"),           # a leading byte-order mark
    (b'{"a": 1, "a": 2}', "duplicate_key"),
    (b'{"a": "\\ud800"}', "not_json"),          # a lone surrogate
    (b"\xff{}", "not_utf8"),
])
def test_j3_strict_mode_refuses_what_lenient_mode_accepts_or_both_refuse(content, code):
    assert refused(content, strict=True) == code


@pytest.mark.parametrize("content", [b'// c\n{"a": 1}', b'{"a": 1 /* c */}', b'{"a": 1,}', b'{"a": [1,]}', b'\xef\xbb\xbf{"a": 1}'])
def test_j3_lenient_mode_accepts_the_same_bytes(content):
    assert isinstance(load_json(content), Obj)


def test_j3_an_mcp_json_with_all_three_parses_exactly_as_in_1_2_1():
    content = (b'\xef\xbb\xbf// a comment\n{\n  /* block */ "mcpServers": {"docs": {"url": "https://docs.example.com/mcp",},},\n}\n')
    document = parse_mcp_config(".mcp.json", content)
    assert document.error is None and [server.name for server in document.servers] == ["docs"]
    # recorded from the 1.2.1 reader before the extraction
    assert document.sha256 == "186c2e37c600e3e5313e2ce8a80b118c9222d58bcc92f00480705e8fdfdfe94e"
    assert document.servers[0].raw_sha256 == "2a2be174e61d1f3c95acf8f91c4e5d38481bcf98e09ec594dae96af455ff79cc"
    assert document.servers[0].line == 3


def test_lines_are_recorded_for_keys_and_array_items():
    value = load_json(b'{\n "a": [\n  1,\n  2\n ],\n "b": {\n  "c": 3\n }\n}', strict=True)
    assert isinstance(value, Obj) and isinstance(value["a"], Arr)
    assert (value.line, value.lines) == (1, {"a": 2, "b": 6})
    assert (value["a"].line, value["a"].lines, value["b"].lines) == (2, [3, 4], {"c": 7})


def test_the_size_limit_is_a_parameter():
    assert refused(b'{"a":"' + b"x" * 100 + b'"}', max_bytes=50) == "too_large"
    assert load_json(b'{"a":1}', max_bytes=7) == {"a": 1}


def test_numbers_keep_their_python_types_and_exponents_read_as_floats():
    value = load_json(b'{"i": 12, "f": 1.5, "e": 1E3, "big": 9007199254740993}', strict=True)
    assert [type(value[name]) for name in ("i", "f", "e", "big")] == [int, float, float, int]
    assert value["big"] == 9007199254740993 and json.dumps(value["e"]) == "1000.0"
