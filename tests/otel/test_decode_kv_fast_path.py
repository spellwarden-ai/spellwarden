"""The KeyValue fast path of the protobuf decoder (10,000-span production check, code runtime traces spec 18): for
every layout it answers what the field-by-field reader answers, and only the usual layout takes it."""
from __future__ import annotations

import pytest

from spellwarden_scan.otel import otlp
from spellwarden_scan.otel.otlp import OtlpError, OtlpLimits
from spellwarden_scan.otel.wire import len_field, varint_field


def any_string(text: bytes) -> bytes:
    return len_field(1, text)


LAYOUTS = [
    len_field(1, b"gen_ai.tool.name") + len_field(2, any_string(b"search_orders")),          # the usual layout
    len_field(1, b"") + len_field(2, any_string(b"")),                                         # empty key and value
    len_field(1, b"k" * 127) + len_field(2, any_string(b"v" * 125)),                           # the largest one-byte sizes
    len_field(1, b"k" * 128) + len_field(2, any_string(b"v")),                                 # a two-byte key length
    len_field(1, b"k") + len_field(2, any_string(b"v" * 200)),                                 # a two-byte value length
    len_field(1, b"k") + len_field(2, varint_field(3, 42)),                                    # an int value
    len_field(1, b"k") + len_field(2, any_string(b"a") + any_string(b"b")),                    # the last string wins
    len_field(1, b"k") + len_field(2, any_string(b"v")) + len_field(1, b"k2"),                 # the last key wins
    len_field(2, any_string(b"v")) + len_field(1, b"k"),                                       # fields in either order
    len_field(1, b"k") + len_field(2, any_string(b"v")) + varint_field(9, 1),                  # an unknown field after
    len_field(1, b"\xff\xfe") + len_field(2, any_string(b"\xc3")),                             # invalid UTF-8 replaced
]


@pytest.mark.parametrize("data", LAYOUTS, ids=[f"layout-{n}" for n in range(len(LAYOUTS))])
@pytest.mark.parametrize("limits", [OtlpLimits(), OtlpLimits(max_value_bytes=2)], ids=["default-limits", "values-cut-at-2"])
def test_the_fast_path_answers_what_the_field_reader_answers(data, limits):
    fast, slow = otlp._Context(limits), otlp._Context(limits)
    assert otlp._pb_kv(memoryview(data), fast, 1) == otlp._pb_kv_fields(memoryview(data), slow, 1)
    assert fast.values_cut == slow.values_cut


def test_the_depth_limit_holds_on_the_usual_layout():
    data = memoryview(LAYOUTS[0])
    with pytest.raises(OtlpError):
        otlp._pb_kv_fields(data, otlp._Context(OtlpLimits(max_depth=0)), 1)
    with pytest.raises(OtlpError):
        otlp._pb_kv(data, otlp._Context(OtlpLimits(max_depth=0)), 1)
