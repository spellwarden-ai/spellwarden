"""Spec 4.9 and claim E1: every protobuf body decodes as the reference decoder (opentelemetry-proto 1.45.1 with
protobuf, dev dependencies only) decodes it, for every field the model keeps, and the field-number table equals the
reference descriptors. The package is generated from proto v1.10.0; no trace or log field changed between v1.10.0
and v1.11.1, the version `otlp.py` names."""
from __future__ import annotations

import math

import pytest

from otel_support import fixture_bodies, reference_decode
from spellwarden_scan.otel import decode
from spellwarden_scan.otel.otlp import FIELDS

PROTOBUF = [(name, signal, body) for name, signal, encoding, body in fixture_bodies() if encoding == "protobuf"]


def _value(value):
    """A reference `AnyValue` as the engine's model holds it."""
    which = value.WhichOneof("value")
    if which is None:
        return None
    if which == "array_value":
        return tuple(_value(item) for item in value.array_value.values)
    if which == "kvlist_value":
        out = {}
        for item in value.kvlist_value.values:
            out.setdefault(item.key, _value(item.value))
        return out
    return getattr(value, which)


def _attributes(items):
    out = {}
    for item in items:
        out.setdefault(item.key, _value(item.value))
    return out


def _same(left, right):
    if isinstance(left, float) and isinstance(right, float) and math.isnan(left) and math.isnan(right):
        return True
    return left == right


def compare(engine, reference, signal):
    resources = reference.resource_spans if signal == "traces" else reference.resource_logs
    assert len(engine.resources) == len(resources)
    for mine, theirs in zip(engine.resources, resources, strict=True):
        assert mine.attributes == _attributes(theirs.resource.attributes)
        scopes = theirs.scope_spans if signal == "traces" else theirs.scope_logs
        assert len(mine.scopes) == len(scopes)
        for scope, ref_scope in zip(mine.scopes, scopes, strict=True):
            assert (scope.name, scope.version) == (ref_scope.scope.name, ref_scope.scope.version)
            if signal == "traces":
                assert len(scope.spans) == len(ref_scope.spans)
                for span, ref in zip(scope.spans, ref_scope.spans, strict=True):
                    assert (span.trace_id, span.span_id, span.parent_span_id) == (ref.trace_id.hex(), ref.span_id.hex(), ref.parent_span_id.hex())
                    assert (span.name, span.kind) == (ref.name, ref.kind)
                    assert (span.start_time_unix_nano, span.end_time_unix_nano) == (ref.start_time_unix_nano, ref.end_time_unix_nano)
                    assert all(_same(span.attributes.get(k), v) for k, v in _attributes(ref.attributes).items())
                    assert span.attributes.keys() == _attributes(ref.attributes).keys()
                    assert [(e.name, e.time_unix_nano, e.attributes) for e in span.events] == [
                        (e.name, e.time_unix_nano, _attributes(e.attributes)) for e in ref.events]
                    assert (span.status.code, span.status.message) == (ref.status.code, ref.status.message)
            else:
                assert len(scope.log_records) == len(ref_scope.log_records)
                for log, ref in zip(scope.log_records, ref_scope.log_records, strict=True):
                    assert (log.time_unix_nano, log.observed_time_unix_nano, log.severity_number) == (
                        ref.time_unix_nano, ref.observed_time_unix_nano, ref.severity_number)
                    assert log.body == (_value(ref.body) if ref.HasField("body") else None)
                    assert log.attributes == _attributes(ref.attributes)
                    assert (log.trace_id, log.span_id, log.event_name) == (ref.trace_id.hex(), ref.span_id.hex(), ref.event_name)


@pytest.mark.parametrize(("name", "signal", "body"), PROTOBUF, ids=[name for name, _, _ in PROTOBUF])
def test_the_engine_decodes_as_the_reference_does(name, signal, body):  # noqa: ARG001 -- the id
    compare(decode(body, signal=signal, encoding="protobuf"), reference_decode(body, signal), signal)


def test_a_body_with_every_value_type_and_unknown_fields():
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
    from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue

    request = ExportTraceServiceRequest()
    resource = request.resource_spans.add()
    resource.schema_url = "https://opentelemetry.io/schemas/1.30.0"
    resource.resource.attributes.add(key="service.name", value=AnyValue(string_value="svc"))
    resource.resource.dropped_attributes_count = 3
    scope = resource.scope_spans.add()
    scope.scope.name, scope.scope.version = "lib", "2.0"
    scope.scope.attributes.add(key="scope.attr", value=AnyValue(int_value=1))
    span = scope.spans.add(trace_id=bytes(range(16)), span_id=bytes(range(8)), name="s", kind=3, start_time_unix_nano=1,
                           end_time_unix_nano=2, trace_state="k=v", flags=1, dropped_attributes_count=1)
    span.attributes.extend([
        KeyValue(key="str", value=AnyValue(string_value="café")), KeyValue(key="bool", value=AnyValue(bool_value=True)),
        KeyValue(key="int", value=AnyValue(int_value=-5)), KeyValue(key="double", value=AnyValue(double_value=2.5)),
        KeyValue(key="bytes", value=AnyValue(bytes_value=b"\x00\x01")),
        KeyValue(key="array", value=AnyValue(array_value={"values": [AnyValue(int_value=1), AnyValue(string_value="x")]})),
        KeyValue(key="kvlist", value=AnyValue(kvlist_value={"values": [KeyValue(key="a", value=AnyValue(bool_value=False))]})),
        KeyValue(key="empty", value=AnyValue()),
    ])
    span.events.add(name="e", time_unix_nano=3).attributes.add(key="k", value=AnyValue(string_value="v"))
    span.links.add(trace_id=bytes(16), span_id=bytes(8))
    span.status.code, span.status.message = 2, "bad"
    body = request.SerializeToString()
    engine = decode(body, signal="traces", encoding="protobuf")
    compare(engine, reference_decode(body, "traces"), "traces")
    assert engine.resources[0].scopes[0].spans[0].attributes["array"] == (1, "x")


def _field(number: int, payload: bytes) -> bytes:
    """A length-delimited field (numbers under 16, payloads under 128 bytes per length byte, as here)."""
    length, out = len(payload), bytearray()
    while True:
        out.append((length & 0x7F) | (0x80 if length > 0x7F else 0))
        length >>= 7
        if not length:
            break
    return bytes([number << 3 | 2]) + bytes(out) + payload


def test_a_message_field_written_twice_is_merged_as_the_reference_merges_it():
    from opentelemetry.proto.common.v1.common_pb2 import AnyValue, InstrumentationScope
    from opentelemetry.proto.resource.v1.resource_pb2 import Resource
    from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans, ScopeSpans, Span, Status

    def resource(**attributes):
        message = Resource()
        for key, value in attributes.items():
            message.attributes.add(key=key, value=AnyValue(string_value=value))
        return message

    # Concatenated serialisations are one message with each field written twice: legal, and merged by protobuf.
    span = (Span(trace_id=bytes(range(16)), span_id=bytes(range(8)), name="s", status=Status(code=2)).SerializeToString()
            + Span(status=Status(message="bad")).SerializeToString())
    scope = (ScopeSpans(scope=InstrumentationScope(name="lib")).SerializeToString()
             + ScopeSpans(scope=InstrumentationScope(version="2.0")).SerializeToString() + _field(2, span))
    resource_spans = (ResourceSpans(resource=resource(**{"service.name": "claude-code"})).SerializeToString()
                      + ResourceSpans(resource=resource(**{"service.version": "2.0", "service.name": "other"})).SerializeToString()
                      + _field(2, scope))
    body = _field(1, resource_spans)
    engine = decode(body, signal="traces", encoding="protobuf")
    compare(engine, reference_decode(body, "traces"), "traces")
    decoded = engine.resources[0]
    assert decoded.attributes == {"service.name": "claude-code", "service.version": "2.0"}
    assert (decoded.scopes[0].name, decoded.scopes[0].version) == ("lib", "2.0")
    assert (decoded.scopes[0].spans[0].status.code, decoded.scopes[0].spans[0].status.message) == (2, "bad")


def test_invalid_utf8_is_replaced():
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

    request = ExportLogsServiceRequest()
    request.resource_logs.add().scope_logs.add().log_records.add(event_name="ok")
    body = request.SerializeToString().replace(b"\x62\x02ok", b"\x62\x02o\xff")
    log = decode(body, signal="logs", encoding="protobuf").resources[0].scopes[0].log_records[0]
    assert log.event_name == "o�"


def test_the_field_table_equals_the_reference_descriptors():
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
    from opentelemetry.proto.collector.trace.v1 import trace_service_pb2
    from opentelemetry.proto.common.v1 import common_pb2
    from opentelemetry.proto.logs.v1 import logs_pb2
    from opentelemetry.proto.resource.v1 import resource_pb2
    from opentelemetry.proto.trace.v1 import trace_pb2

    from otel_support import rpc_status_class

    descriptors = {
        "ExportTraceServiceRequest": trace_service_pb2.ExportTraceServiceRequest,
        "ExportLogsServiceRequest": logs_service_pb2.ExportLogsServiceRequest,
        "ResourceSpans": trace_pb2.ResourceSpans, "ResourceLogs": logs_pb2.ResourceLogs, "Resource": resource_pb2.Resource,
        "ScopeSpans": trace_pb2.ScopeSpans, "ScopeLogs": logs_pb2.ScopeLogs,
        "InstrumentationScope": common_pb2.InstrumentationScope, "Span": trace_pb2.Span, "Span.Event": trace_pb2.Span.Event,
        "Status": trace_pb2.Status, "LogRecord": logs_pb2.LogRecord, "KeyValue": common_pb2.KeyValue,
        "AnyValue": common_pb2.AnyValue, "ArrayValue": common_pb2.ArrayValue, "KeyValueList": common_pb2.KeyValueList,
        "ExportTracePartialSuccess": trace_service_pb2.ExportTracePartialSuccess,
        "ExportLogsPartialSuccess": logs_service_pb2.ExportLogsPartialSuccess,
        "ExportTraceServiceResponse": trace_service_pb2.ExportTraceServiceResponse,
        "ExportLogsServiceResponse": logs_service_pb2.ExportLogsServiceResponse,
        "google.rpc.Status": rpc_status_class(),
    }
    assert set(FIELDS) == set(descriptors)
    for message, numbers in FIELDS.items():
        by_name = descriptors[message].DESCRIPTOR.fields_by_name
        assert {name: by_name[name].number for name in numbers} == numbers, message
