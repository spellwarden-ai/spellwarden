"""Claim E12, first part: `count_records` equals the decoded record count on every fixture, protobuf and JSON."""
from __future__ import annotations

import pytest

from otel_support import fixture_bodies
from spellwarden_scan.otel import OtlpError, count_records, decode

BODIES = fixture_bodies()


@pytest.mark.parametrize(("name", "signal", "encoding", "body"), BODIES, ids=[item[0] for item in BODIES])
def test_count_records_equals_the_decoded_count(name, signal, encoding, body):  # noqa: ARG001 -- the id
    assert count_records(body, signal=signal, encoding=encoding) == decode(body, signal=signal, encoding=encoding).record_count


def test_count_records_refuses_what_decode_refuses():
    for body, encoding in ((b"\x0a\x05abc", "protobuf"), (b"{", "json")):
        with pytest.raises(OtlpError) as raised:
            count_records(body, signal="logs", encoding=encoding)
        assert raised.value.reason == "malformed"
