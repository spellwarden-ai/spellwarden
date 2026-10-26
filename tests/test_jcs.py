"""O4 spec 5.5 and claim J1: `jcs_canonicalize` reproduces RFC 8785's number vectors (Appendix B) and its 3.2.3 example
byte for byte, sorts members by UTF-16 code units, and refuses the two values the scanner does not canonicalise."""
from __future__ import annotations

import struct

import pytest

from spellwarden_scan._json import load_json
from spellwarden_scan.jcs import JcsError, jcs_canonicalize

# RFC 8785 Appendix B: the IEEE 754 bit pattern of a double and the text ECMAScript writes for it.
APPENDIX_B = (
    ("0000000000000000", "0"), ("8000000000000000", "0"), ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"), ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"), ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"), ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"), ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"), ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"), ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"), ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"), ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"), ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"), ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
)

RFC_3_2_3_INPUT = """{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\"\\/",
  "literals": [null, true, false]
}"""
RFC_3_2_3_OUTPUT = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                    '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')


@pytest.mark.parametrize(("bits", "expected"), APPENDIX_B, ids=[bits for bits, _ in APPENDIX_B])
def test_the_appendix_b_number_vectors(bits, expected):
    value = struct.unpack(">d", bytes.fromhex(bits))[0]
    assert jcs_canonicalize(value) == expected.encode()


def test_the_section_3_2_3_example_is_reproduced_byte_for_byte():
    assert jcs_canonicalize(load_json(RFC_3_2_3_INPUT.encode(), strict=True)) == RFC_3_2_3_OUTPUT.encode("utf-8")


def test_members_sort_by_utf16_code_units_not_by_code_points():
    # U+1F600 is the surrogate pair D83D DE00, which sorts before U+FF21 although its code point is larger.
    assert jcs_canonicalize({"Ａ": 1, "\U0001f600": 2, "b": 3, "a": 4}) == '{"a":4,"b":3,"\U0001f600":2,"Ａ":1}'.encode()


def test_control_characters_use_lower_case_u_escapes_and_the_rest_stays_literal():
    assert jcs_canonicalize("\x00\x1f\x7f ") == '"\\u0000\\u001f\x7f "'.encode()
    assert jcs_canonicalize("\b\t\n\f\r\"\\") == b'"\\b\\t\\n\\f\\r\\"\\\\"'


def test_integers_are_plain_digits_and_minus_zero_is_zero():
    assert jcs_canonicalize([0, -7, 2**53, -(2**53)]) == b"[0,-7,9007199254740992,-9007199254740992]"
    assert jcs_canonicalize(-0.0) == b"0" and jcs_canonicalize(1.0) == b"1" and jcs_canonicalize(1e21) == b"1e+21"


@pytest.mark.parametrize("value", [2**53 + 1, -(2**53) - 1, float("inf"), float("-inf"), float("nan")])
def test_a_number_outside_the_range_is_refused(value):
    with pytest.raises(JcsError) as caught:
        jcs_canonicalize({"n": value})
    assert caught.value.args == ("number",)


def test_an_out_of_range_exponent_reads_as_infinity_and_is_refused():
    with pytest.raises(JcsError):
        jcs_canonicalize(load_json(b'{"n": 1e400}', strict=True))


def test_a_value_that_is_not_json_is_refused():
    with pytest.raises(JcsError) as caught:
        jcs_canonicalize({"n": object()})
    assert caught.value.args == ("type",)
