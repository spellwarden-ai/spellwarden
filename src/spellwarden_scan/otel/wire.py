"""The protobuf wire format, read by hand (runtime traces spec 4.1): varints of at most 10 bytes, fixed32, fixed64 and
length-delimited fields. Groups (wire types 3 and 4) and the unused wire types 6 and 7 are refused, and every length is
checked against the bytes that remain, so a hostile body costs at most one pass over its bytes. Standard library only."""
from __future__ import annotations

import struct
from collections.abc import Iterator

VARINT, FIXED64, LEN, START_GROUP, END_GROUP, FIXED32 = 0, 1, 2, 3, 4, 5
_MASK64 = (1 << 64) - 1
_DOUBLE = struct.Struct("<d")
_U64 = struct.Struct("<Q")
_U32 = struct.Struct("<I")


class WireError(ValueError):
    """The bytes are not a well-formed protobuf message; `otlp` turns it into `OtlpError("malformed")`."""


def read_varint(buf: memoryview, pos: int, end: int) -> tuple[int, int]:
    """`(value, next position)`: at most 10 bytes, the value cut to 64 bits as protobuf does."""
    result = 0
    shift = 0
    while True:
        if pos >= end:
            raise WireError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result & _MASK64, pos
        shift += 7
        if shift >= 70:
            raise WireError("varint longer than 10 bytes")


def fields(buf: memoryview, start: int = 0, end: int | None = None) -> Iterator[tuple[int, int, object]]:
    """Every `(field number, wire type, value)` of the message in `buf[start:end]`, in order. The value is an `int`
    for varint, fixed32 and fixed64 fields (fixed ones unsigned, little-endian) and a `memoryview` for
    length-delimited ones."""
    if end is None:
        end = len(buf)
    pos = start
    # Keys and lengths under 128 are one byte, read inline; longer ones, and every error, go through read_varint.
    while pos < end:
        key = buf[pos]
        if key < 0x80:
            pos += 1
        else:
            key, pos = read_varint(buf, pos, end)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise WireError("field number 0")
        if wire == LEN:
            if pos < end and buf[pos] < 0x80:
                length = buf[pos]
                pos += 1
            else:
                length, pos = read_varint(buf, pos, end)
            if length > end - pos:
                raise WireError("length past the end")
            yield number, wire, buf[pos:pos + length]
            pos += length
        elif wire == VARINT:
            if pos < end and buf[pos] < 0x80:
                value = buf[pos]
                pos += 1
            else:
                value, pos = read_varint(buf, pos, end)
            yield number, wire, value
        elif wire == FIXED64:
            if end - pos < 8:
                raise WireError("truncated fixed64")
            yield number, wire, _U64.unpack_from(buf, pos)[0]
            pos += 8
        elif wire == FIXED32:
            if end - pos < 4:
                raise WireError("truncated fixed32")
            yield number, wire, _U32.unpack_from(buf, pos)[0]
            pos += 4
        else:
            raise WireError(f"wire type {wire}")


def signed64(value: int) -> int:
    """An int64 (or a negative enum or int32, which protobuf writes as 10-byte varints) from its unsigned varint."""
    return value - (1 << 64) if value >= 1 << 63 else value


def double(value: int) -> float:
    """A double from the unsigned 64-bit value of its fixed64 field."""
    return _DOUBLE.unpack(_U64.pack(value))[0]


# --- writing, for the two answers of `otlp.encode_success` and `otlp.encode_status` ---------------------------------

def varint_bytes(value: int) -> bytes:
    value &= _MASK64
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def varint_field(number: int, value: int) -> bytes:
    return varint_bytes(number << 3 | VARINT) + varint_bytes(value)


def len_field(number: int, payload: bytes) -> bytes:
    return varint_bytes(number << 3 | LEN) + varint_bytes(len(payload)) + payload
