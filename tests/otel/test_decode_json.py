"""Spec 4.2 and claim E2: OTLP/JSON. Hex ids of either case, 64-bit integers as strings or numbers, enums as integers,
unknown keys ignored, snake_case accepted, the depth pre-scan, invalid UTF-8 refused."""
from __future__ import annotations

import json

import pytest

from otel_support import FIXTURES, json_bytes, reference_protobuf
from spellwarden_scan.otel import OtlpError, decode


def _one_span(span: dict, **top) -> bytes:
    return json_bytes({"resourceSpans": [{"resource": {"attributes": []}, "scopeSpans": [{"spans": [span]}]}], **top})


def _span(body: bytes):
    return decode(body, signal="traces", encoding="json").resources[0].scopes[0].spans[0]


def test_hex_ids_of_either_case_are_lower_case():
    span = _span(_one_span({"traceId": "5B8EFFF798038103D269B633813FC60C", "spanId": "EEE19B7EC3C1B174", "parentSpanId": ""}))
    assert (span.trace_id, span.span_id, span.parent_span_id) == ("5b8efff798038103d269b633813fc60c", "eee19b7ec3c1b174", "")


@pytest.mark.parametrize("trace_id", ["5b8efff798038103d269b633813fc60", "W4jv95gDgQPSabYzgT/GDA==", "zz8efff798038103d269b633813fc60c"])
def test_ids_that_are_not_hex_of_the_right_length_are_malformed(trace_id):
    with pytest.raises(OtlpError) as raised:
        decode(_one_span({"traceId": trace_id}), signal="traces", encoding="json")
    assert raised.value.reason == "malformed"


def test_a_body_the_reference_json_parser_misreads_decodes_right():
    """`json_format` reads `traceId` as base64: 32 hex digits are valid base64 of 24 bytes, so it decodes a different id
    without an error. The engine reads hex."""
    from google.protobuf import json_format
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

    hex_id = "5b8efff798038103d269b633813fc60c"
    body = _one_span({"traceId": hex_id, "name": "x"})
    misread = json_format.Parse(body.decode(), ExportTraceServiceRequest())
    assert misread.resource_spans[0].scope_spans[0].spans[0].trace_id.hex() != hex_id
    assert _span(body).trace_id == hex_id


def test_int64_as_strings_or_numbers_and_enums_as_integers():
    span = _span(_one_span({"startTimeUnixNano": "1761600000000000001", "endTimeUnixNano": 1761600000000000002, "kind": 3,
                            "attributes": [{"key": "a", "value": {"intValue": "-9007199254740993"}},
                                           {"key": "b", "value": {"intValue": 12}},
                                           {"key": "c", "value": {"doubleValue": "NaN"}}],
                            "status": {"code": 2}}))
    assert (span.start_time_unix_nano, span.end_time_unix_nano, span.kind, span.status.code) == (1761600000000000001, 1761600000000000002, 3, 2)
    assert span.attributes["a"] == -9007199254740993 and span.attributes["b"] == 12
    assert span.attributes["c"] != span.attributes["c"]


def test_unknown_keys_are_ignored_and_snake_case_is_accepted():
    body = json_bytes({"resource_spans": [{"resource": {"attributes": [{"key": "service.name", "value": {"string_value": "svc"}}]},
                                           "scope_spans": [{"scope": {"name": "s"}, "spans": [
                                               {"trace_id": "5b8efff798038103d269b633813fc60c", "name": "x", "start_time_unix_nano": "5",
                                                "futureField": {"anything": [1, 2]}}]}]}],
                       "somethingNew": True})
    request = decode(body, signal="traces", encoding="json")
    assert request.resources[0].attributes == {"service.name": "svc"}
    span = request.resources[0].scopes[0].spans[0]
    assert (span.trace_id, span.name, span.start_time_unix_nano) == ("5b8efff798038103d269b633813fc60c", "x", 5)


def test_json_and_protobuf_of_one_document_decode_alike():
    for path in sorted((FIXTURES / "synthetic").glob("*.json")):
        fixture = json.loads(path.read_text())
        from_json = decode(json_bytes(fixture["body"]), signal=fixture["signal"], encoding="json")
        from_pb = decode(reference_protobuf(fixture["body"], fixture["signal"]), signal=fixture["signal"], encoding="protobuf")
        assert from_json == from_pb, path.name


def test_the_depth_prescan_refuses_a_deep_body_without_recursion():
    body = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(OtlpError) as raised:
        decode(body, signal="traces", encoding="json")
    assert raised.value.reason == "too_deep"


def test_brackets_inside_strings_do_not_count():
    deep_text = "[" * 500 + '"\\' + "{" * 500  # json_bytes writes the quote and the backslash escaped
    body = _one_span({"name": deep_text})
    assert _span(body).name == deep_text


def test_values_nested_past_max_depth_are_too_deep():
    value: dict = {"stringValue": "leaf"}
    for _ in range(16):
        value = {"arrayValue": {"values": [value]}}
    with pytest.raises(OtlpError) as raised:
        decode(_one_span({"events": [{"name": "e", "attributes": [{"key": "k", "value": value}]}]}), signal="traces", encoding="json")
    assert raised.value.reason == "too_deep"


def test_values_at_max_depth_decode_even_in_an_event_kvlist():
    value: dict = {"kvlistValue": {"values": []}}
    for _ in range(15):
        value = {"kvlistValue": {"values": [{"key": "k", "value": value}]}}
    span = _span(_one_span({"events": [{"name": "e", "attributes": [{"key": "k", "value": value}]}]}))
    assert "k" in span.events[0].attributes


def test_invalid_utf8_and_non_json_are_malformed():
    for body in (b'{"resourceSpans": [{"x": "\xff"}]}', b"not json", b"[]", b'{"resourceSpans": {}}'):
        with pytest.raises(OtlpError) as raised:
            decode(body, signal="traces", encoding="json")
        assert raised.value.reason == "malformed", body


def test_the_synthetic_zuplo_fixture_is_json_only_and_decodes():
    fixture = json.loads((FIXTURES / "synthetic" / "zuplo.json").read_text())
    assert fixture["encoding"] == "json"
    request = decode(json_bytes(fixture["body"]), signal="traces", encoding="json")
    assert request.record_count == 3
