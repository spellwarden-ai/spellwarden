"""Spec 4.1: the protobuf wire reader. Varints of at most 10 bytes, every wire type, groups refused, lengths checked."""
from __future__ import annotations

import struct

import pytest

from spellwarden_scan.otel.wire import WireError, double, fields, len_field, read_varint, signed64, varint_bytes, varint_field


def _read(data: bytes) -> tuple[int, int]:
    return read_varint(memoryview(data), 0, len(data))


def test_varints_of_one_to_ten_bytes():
    assert _read(b"\x00") == (0, 1)
    assert _read(b"\x96\x01") == (150, 2)
    assert _read(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01") == ((1 << 64) - 1, 10)
    assert varint_bytes((1 << 64) - 1) == b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"
    assert varint_bytes(-1) == varint_bytes((1 << 64) - 1)


def test_a_tenth_byte_past_64_bits_is_cut_as_protobuf_does():
    assert _read(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f")[0] == (1 << 64) - 1


def test_an_overlong_varint_is_refused():
    with pytest.raises(WireError):
        _read(b"\x80" * 10 + b"\x01")


def test_a_truncated_varint_is_refused():
    with pytest.raises(WireError):
        _read(b"\x96")


def test_every_wire_type():
    body = (varint_field(1, 150) + bytes([2 << 3 | 1]) + struct.pack("<d", 1.5) + len_field(3, b"abc")
            + bytes([4 << 3 | 5]) + struct.pack("<I", 7))
    got = [(number, wire, bytes(value) if isinstance(value, memoryview) else value) for number, wire, value in fields(memoryview(body))]
    assert got[0] == (1, 0, 150)
    assert got[1][:2] == (2, 1) and double(got[1][2]) == 1.5
    assert got[2] == (3, 2, b"abc")
    assert got[3] == (4, 5, 7)


@pytest.mark.parametrize("wire", [3, 4, 6, 7])
def test_groups_and_unused_wire_types_are_refused(wire):
    with pytest.raises(WireError):
        list(fields(memoryview(bytes([1 << 3 | wire, 0]))))


def test_field_number_zero_is_refused():
    with pytest.raises(WireError):
        list(fields(memoryview(b"\x00\x00")))


@pytest.mark.parametrize("body", [b"\x0a\x05abc", b"\x09\x00\x00\x00", b"\x0d\x00\x00", b"\x08"])
def test_lengths_past_the_end_are_refused(body):
    with pytest.raises(WireError):
        list(fields(memoryview(body)))


def test_signed64():
    assert signed64((1 << 64) - 1) == -1
    assert signed64(5) == 5


# --- the one-byte fast paths (10,000-span production check, code runtime traces spec 18) --------------------------

def _field(number: int, wire: int) -> bytes:
    return varint_bytes(number << 3 | wire)


@pytest.mark.parametrize("data", [
    len_field(1, b"k" * 127) + varint_field(2, 127),
    len_field(1, b"k" * 128) + varint_field(2, 128) + varint_field(17, 1 << 40),
    len_field(300, b"") + len_field(1, b"x" * 70_000),
    varint_field(1, 0) + struct.pack("<B", 1 << 3 | 1) + b"\x01" * 8 + struct.pack("<B", 2 << 3 | 5) + b"\x02" * 4,
], ids=["one-byte-sizes", "two-byte-sizes", "long-key-number-and-70000-bytes", "fixed64-and-fixed32"])
# Short ids: pytest exports the id as PYTEST_CURRENT_TEST, and Windows refuses a variable over 32,767 characters.
def test_one_byte_keys_and_lengths_read_as_the_long_form_does(data):
    reference = []
    pos, end, buf = 0, len(data), memoryview(data)
    while pos < end:
        key, pos = read_varint(buf, pos, end)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = read_varint(buf, pos, end)
        elif wire == 2:
            length, pos = read_varint(buf, pos, end)
            value, pos = bytes(buf[pos:pos + length]), pos + length
        elif wire == 1:
            value, pos = struct.unpack_from("<Q", buf, pos)[0], pos + 8
        else:
            value, pos = struct.unpack_from("<I", buf, pos)[0], pos + 4
        reference.append((number, wire, value))
    assert [(n, w, bytes(v) if isinstance(v, memoryview) else v) for n, w, v in fields(buf)] == reference


@pytest.mark.parametrize("data, message", [
    (_field(1, 2), "truncated varint"),
    (_field(1, 0), "truncated varint"),
    (_field(1, 2) + b"\x05abc", "length past the end"),
    (b"\x00", "field number 0"),
], ids=["truncated-length", "truncated-varint", "length-past-the-end", "field-number-0"])
def test_the_fast_paths_refuse_what_the_long_form_refuses(data, message):
    with pytest.raises(WireError, match=message):
        list(fields(memoryview(data)))
