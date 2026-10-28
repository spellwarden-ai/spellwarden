"""Spec 4.3 and claim E3: each limit at and past its value; `decompress` bounds its output."""
from __future__ import annotations

import gzip
import time
import zlib

import pytest

from otel_support import build_request, json_bytes, reference_protobuf
from spellwarden_scan.otel import DEFAULT_LIMITS, OtlpError, OtlpLimits, decode, decompress
from spellwarden_scan.otel.otlp import CutText


def _spans(count: int, **span) -> dict:
    return build_request({"signal": "traces", "resource": {"service.name": "a"}, "items": [{"name": "s", **span}] * count})


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_max_records_at_and_past(encoding):
    limits = OtlpLimits(max_records=5)
    def body(n):
        return json_bytes(_spans(n)) if encoding == "json" else reference_protobuf(_spans(n), "traces")
    assert decode(body(5), signal="traces", encoding=encoding, limits=limits).record_count == 5
    with pytest.raises(OtlpError) as raised:
        decode(body(6), signal="traces", encoding=encoding, limits=limits)
    assert raised.value.reason == "too_many_records"


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_max_attributes_skips_and_counts(encoding):
    attributes = {f"a{n}": n for n in range(DEFAULT_LIMITS.max_attributes + 3)}
    document = _spans(1, attributes=attributes)
    body = json_bytes(document) if encoding == "json" else reference_protobuf(document, "traces")
    request = decode(body, signal="traces", encoding=encoding)
    assert len(request.resources[0].scopes[0].spans[0].attributes) == DEFAULT_LIMITS.max_attributes
    assert request.attributes_skipped == 3


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_max_events_skips_and_counts(encoding):
    document = _spans(1, events=[{"name": f"e{n}"} for n in range(DEFAULT_LIMITS.max_events + 2)])
    body = json_bytes(document) if encoding == "json" else reference_protobuf(document, "traces")
    request = decode(body, signal="traces", encoding=encoding)
    assert len(request.resources[0].scopes[0].spans[0].events) == DEFAULT_LIMITS.max_events
    assert request.events_skipped == 2


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_max_value_bytes_cuts_and_marks(encoding):
    limits = OtlpLimits(max_value_bytes=12)
    document = _spans(1, attributes={"short": "012345678901", "long": "012345678901X"})
    body = json_bytes(document) if encoding == "json" else reference_protobuf(document, "traces")
    request = decode(body, signal="traces", encoding=encoding, limits=limits)
    attributes = request.resources[0].scopes[0].spans[0].attributes
    assert attributes["short"] == "012345678901" and not isinstance(attributes["short"], CutText)
    assert attributes["long"] == "012345678901" and isinstance(attributes["long"], CutText)
    assert request.values_cut == 1


def test_default_limits_are_the_spec_s():
    assert DEFAULT_LIMITS == OtlpLimits(max_records=20_000, max_depth=16, max_attributes=512, max_events=256, max_value_bytes=1 << 20)


def test_decompress_identity_and_unsupported_encodings():
    assert decompress(b"abc", None, max_bytes=1) == b"abc"
    assert decompress(b"abc", "", max_bytes=1) == b"abc"
    assert decompress(b"abc", "identity", max_bytes=1) == b"abc"
    for encoding in ("deflate", "zstd", "br", "gzip, br"):
        with pytest.raises(OtlpError) as raised:
            decompress(b"abc", encoding, max_bytes=100)
        assert raised.value.reason == "unsupported_encoding"


def test_decompress_at_and_past_max_bytes():
    assert decompress(gzip.compress(b"x" * 1000), "gzip", max_bytes=1000) == b"x" * 1000
    with pytest.raises(OtlpError) as raised:
        decompress(gzip.compress(b"x" * 1001), "gzip", max_bytes=1000)
    assert raised.value.reason == "too_large"


def test_a_gzip_bomb_stops_at_the_bound():
    deflater = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    chunk = bytes(1 << 20)
    bomb = b"".join(deflater.compress(chunk) for _ in range(1024)) + deflater.flush()  # 1 GiB of zeros
    started = time.monotonic()
    with pytest.raises(OtlpError) as raised:
        decompress(bomb, "gzip", max_bytes=16 << 20)
    assert raised.value.reason == "too_large"
    assert time.monotonic() - started < 5


def test_concatenated_members_inflate_and_other_trailing_bytes_are_malformed():
    assert decompress(gzip.compress(b"ab") + gzip.compress(b"cd"), "GZIP", max_bytes=10) == b"abcd"
    with pytest.raises(OtlpError) as raised:
        decompress(gzip.compress(b"ab") + gzip.compress(b"cd"), "gzip", max_bytes=3)
    assert raised.value.reason == "too_large"
    for body in (gzip.compress(b"ab") + b"junk", gzip.compress(b"abc")[:-3], b"not gzip", b""):
        with pytest.raises(OtlpError) as raised:
            decompress(body, "gzip", max_bytes=100)
        assert raised.value.reason == "malformed", body
