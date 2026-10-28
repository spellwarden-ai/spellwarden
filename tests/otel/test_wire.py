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
