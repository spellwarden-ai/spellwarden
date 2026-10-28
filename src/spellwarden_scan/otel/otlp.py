"""OTLP over HTTP, decoded without a protobuf library (runtime traces spec 4.2, 4.3): `decompress`, `decode` for traces
and logs in protobuf or JSON, `count_records`, the data model the normaliser reads, and the two answers a receiver
sends (`encode_success`, `encode_status`). Pure: bytes in, values out.

The field numbers are those of the `.proto` files of opentelemetry-proto v1.11.1, in the table `FIELDS` below, which the
decoder reads and `tests/otel/test_decode_reference.py` compares with the reference package's descriptors. Every field
the table does not name is skipped by its wire type: `schema_url`, the dropped counts, `trace_state`, `flags`, links,
`severity_text`, a scope's attributes, `Resource.entity_refs = 3`, `KeyValue.key_strindex = 3` and
`AnyValue.string_value_strindex = 8` (profiles only).
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import zlib
from dataclasses import dataclass
from typing import Literal

from spellwarden_scan.otel.wire import FIXED64, LEN, VARINT, WireError, double, fields, len_field, signed64, varint_field

Signal = Literal["traces", "logs"]
Encoding = Literal["protobuf", "json"]
REASONS = ("malformed", "too_large", "too_many_records", "too_deep", "unsupported_encoding")

# The table above as data: the decoder reads these numbers, and the reference test compares them with the descriptors.
FIELDS: dict[str, dict[str, int]] = {
    "ExportTraceServiceRequest": {"resource_spans": 1},
    "ExportLogsServiceRequest": {"resource_logs": 1},
    "ResourceSpans": {"resource": 1, "scope_spans": 2},
    "ResourceLogs": {"resource": 1, "scope_logs": 2},
    "Resource": {"attributes": 1},
    "ScopeSpans": {"scope": 1, "spans": 2},
    "ScopeLogs": {"scope": 1, "log_records": 2},
    "InstrumentationScope": {"name": 1, "version": 2},
    "Span": {"trace_id": 1, "span_id": 2, "parent_span_id": 4, "name": 5, "kind": 6, "start_time_unix_nano": 7,
             "end_time_unix_nano": 8, "attributes": 9, "events": 11, "status": 15},
    "Span.Event": {"time_unix_nano": 1, "name": 2, "attributes": 3},
    "Status": {"message": 2, "code": 3},  # a span's status; field 1 is reserved
    "LogRecord": {"time_unix_nano": 1, "severity_number": 2, "body": 5, "attributes": 6, "trace_id": 9, "span_id": 10,
                  "observed_time_unix_nano": 11, "event_name": 12},
    "KeyValue": {"key": 1, "value": 2},
    "AnyValue": {"string_value": 1, "bool_value": 2, "int_value": 3, "double_value": 4, "array_value": 5,
                 "kvlist_value": 6, "bytes_value": 7},
    "ArrayValue": {"values": 1},
    "KeyValueList": {"values": 1},
    "ExportTracePartialSuccess": {"rejected_spans": 1, "error_message": 2},
    "ExportLogsPartialSuccess": {"rejected_log_records": 1, "error_message": 2},
    "ExportTraceServiceResponse": {"partial_success": 1},
    "ExportLogsServiceResponse": {"partial_success": 1},
    "google.rpc.Status": {"code": 1, "message": 2},  # the body of an error answer, not a span's Status
}


class OtlpError(ValueError):
    """A request refused whole; `reason` is one of `REASONS`."""

    def __init__(self, reason: str, detail: str = "") -> None:
        if reason not in REASONS:
            raise ValueError(f"unknown reason {reason!r}")
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class OtlpLimits:
    """Spec 4.3. Hard limits refuse the request (`max_records`, `max_depth`); soft ones skip and count."""
    max_records: int = 20_000
    max_depth: int = 16
    max_attributes: int = 512
    max_events: int = 256
    max_value_bytes: int = 1 << 20


DEFAULT_LIMITS = OtlpLimits()


class CutText(str):
    """A string value cut at `max_value_bytes`; the normaliser marks content made from it as cut."""


class CutBytes(bytes):
    """A bytes value cut at `max_value_bytes`."""


Value = str | bool | int | float | bytes | tuple | dict | None


@dataclass(frozen=True, slots=True)
class SpanEvent:
    name: str
    time_unix_nano: int
    attributes: dict


@dataclass(frozen=True, slots=True)
class SpanStatus:
    code: int = 0
    message: str = ""


@dataclass(frozen=True, slots=True)
class Span:
    trace_id: str
    span_id: str
    parent_span_id: str
    name: str
    kind: int
    start_time_unix_nano: int
    end_time_unix_nano: int
    attributes: dict
    events: tuple[SpanEvent, ...]
    status: SpanStatus


@dataclass(frozen=True, slots=True)
class LogRecord:
    time_unix_nano: int
    observed_time_unix_nano: int
    severity_number: int
    body: Value
    attributes: dict
    trace_id: str
    span_id: str
    event_name: str


@dataclass(frozen=True, slots=True)
class Scope:
    name: str
    version: str
    spans: tuple[Span, ...] = ()
    log_records: tuple[LogRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class Resource:
    attributes: dict
    scopes: tuple[Scope, ...]


@dataclass(frozen=True, slots=True)
class OtlpRequest:
    signal: Signal
    resources: tuple[Resource, ...]
    attributes_skipped: int = 0
    events_skipped: int = 0
    values_cut: int = 0

    @property
    def record_count(self) -> int:
        """The spans (traces) or log records (logs) of the request."""
        return sum(len(scope.spans) + len(scope.log_records) for resource in self.resources for scope in resource.scopes)


@dataclass
class _Context:
    limits: OtlpLimits
    records: int = 0
    attributes_skipped: int = 0
    events_skipped: int = 0
    values_cut: int = 0

    def record(self) -> None:
        self.records += 1
        if self.records > self.limits.max_records:
            raise OtlpError("too_many_records", f"more than {self.limits.max_records} records")

    def text(self, raw: memoryview | bytes) -> str:
        limit = self.limits.max_value_bytes
        if len(raw) > limit:
            self.values_cut += 1
            return CutText(bytes(raw[:limit]).decode("utf-8", "replace"))
        return bytes(raw).decode("utf-8", "replace")

    def blob(self, raw: memoryview | bytes) -> bytes:
        limit = self.limits.max_value_bytes
        if len(raw) > limit:
            self.values_cut += 1
            return CutBytes(bytes(raw[:limit]))
        return bytes(raw)

    def json_text(self, value: str) -> str:
        limit = self.limits.max_value_bytes
        if not value.isascii():
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                # A lone `\ud800`-style escape: protobuf strings decode with errors=replace, so the JSON path does too.
                value = value.encode("utf-8", "surrogatepass").decode("utf-8", "replace")
        if len(value) * 4 > limit:
            raw = value.encode("utf-8", "surrogatepass")
            if len(raw) > limit:
                self.values_cut += 1
                return CutText(raw[:limit].decode("utf-8", "replace"))
        return value


# --- decompress -----------------------------------------------------------------------------------------------------

_GZIP_MAGIC = b"\x1f\x8b"
_GZIP_WINDOW = 1024


def decompress(body: bytes, content_encoding: str | None, *, max_bytes: int) -> bytes:
    """The body as the exporter meant it: `None`, `""` and `identity` return it; `gzip` inflates every member
    (RFC 1952 allows several) with never more than `max_bytes + 1` bytes of output. Anything else is
    `unsupported_encoding`; a corrupt stream or trailing bytes that do not start a member are `malformed`."""
    encoding = (content_encoding or "").strip().lower()
    if encoding in ("", "identity"):
        return body
    if encoding != "gzip":
        raise OtlpError("unsupported_encoding", encoding)
    out = bytearray()
    view = memoryview(body)
    if not len(view):
        raise OtlpError("malformed", "empty gzip body")
    # The inflater copies whatever it did not consume into `unused_data`, so it is fed a window at a time and the
    # position moves by offset: one copy of the whole remainder per member would be quadratic in the member count.
    position = 0
    while position < len(view):
        if position and bytes(view[position : position + 2]) != _GZIP_MAGIC:
            raise OtlpError("malformed", "trailing bytes after the gzip stream")
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        while not inflater.eof:
            if position >= len(view):
                raise OtlpError("malformed", "truncated gzip stream")
            window = view[position : position + _GZIP_WINDOW]
            try:
                out += inflater.decompress(window, max_bytes + 1 - len(out))
            except zlib.error as exc:
                raise OtlpError("malformed", "corrupt gzip stream") from exc
            if len(out) > max_bytes:
                raise OtlpError("too_large", f"more than {max_bytes} bytes uncompressed")
            position += len(window) - len(inflater.unused_data)
    return bytes(out)


# --- protobuf -------------------------------------------------------------------------------------------------------

def _pb_id(raw: memoryview, size: int) -> str:
    if len(raw) == 0:
        return ""
    if len(raw) != size:
        raise OtlpError("malformed", f"an id of {len(raw)} bytes")
    return bytes(raw).hex()


def _pb_any(buf: memoryview, ctx: _Context, depth: int) -> Value:
    if depth > ctx.limits.max_depth:
        raise OtlpError("too_deep", f"values nested deeper than {ctx.limits.max_depth}")
    value: Value = None
    for number, wire, raw in fields(buf):
        if number == 1 and wire == LEN:
            value = ctx.text(raw)
        elif number == 2 and wire == VARINT:
            value = raw != 0
        elif number == 3 and wire == VARINT:
            value = signed64(raw)
        elif number == 4 and wire == FIXED64:
            value = double(raw)
        elif number == 5 and wire == LEN:
            value = tuple(_pb_any(item, ctx, depth + 1) for n, w, item in fields(raw) if n == 1 and w == LEN)
        elif number == 6 and wire == LEN:
            value = _pb_kvlist(raw, ctx, depth + 1)
        elif number == 7 and wire == LEN:
            value = ctx.blob(raw)
    return value


def _pb_kv(buf: memoryview, ctx: _Context, depth: int) -> tuple[str, Value]:
    key = ""
    value: Value = None
    for number, wire, raw in fields(buf):
        if number == 1 and wire == LEN:
            key = ctx.text(raw)
        elif number == 2 and wire == LEN:
            value = _pb_any(raw, ctx, depth)
    return key, value


def _pb_kvlist(buf: memoryview, ctx: _Context, depth: int) -> dict:
    out: dict = {}
    for number, wire, raw in fields(buf):
        if number == 1 and wire == LEN:
            key, value = _pb_kv(raw, ctx, depth)
            out.setdefault(key, value)
    return out


class _Attributes:
    """Collects one owner's attributes: the first `max_attributes` entries, the first value of a repeated key."""
    __slots__ = ("ctx", "seen", "values")

    def __init__(self, ctx: _Context) -> None:
        self.ctx = ctx
        self.seen = 0
        self.values: dict = {}

    def add_pb(self, raw: memoryview) -> None:
        self.seen += 1
        if self.seen > self.ctx.limits.max_attributes:
            self.ctx.attributes_skipped += 1
            return
        key, value = _pb_kv(raw, self.ctx, 1)
        self.values.setdefault(key, value)

    def add_json(self, item: object) -> None:
        self.seen += 1
        if self.seen > self.ctx.limits.max_attributes:
            self.ctx.attributes_skipped += 1
            return
        key, value = _json_kv(item, self.ctx, 1)
        self.values.setdefault(key, value)


# A singular message field written more than once is merged, as protobuf merges it: a resource's attributes collect
# into one `_Attributes`, and a scope's or a status's fields keep the earlier value unless a later copy sets them.
def _pb_resource(buf: memoryview, attributes: _Attributes) -> None:
    for number, wire, raw in fields(buf):
        if number == 1 and wire == LEN:
            attributes.add_pb(raw)


def _pb_scope_info(buf: memoryview, ctx: _Context, name: str, version: str) -> tuple[str, str]:
    for number, wire, raw in fields(buf):
        if number == 1 and wire == LEN:
            name = ctx.text(raw)
        elif number == 2 and wire == LEN:
            version = ctx.text(raw)
    return name, version


def _pb_event(buf: memoryview, ctx: _Context) -> SpanEvent:
    name = ""
    time = 0
    attributes = _Attributes(ctx)
    for number, wire, raw in fields(buf):
        if number == 1 and wire == FIXED64:
            time = raw
        elif number == 2 and wire == LEN:
            name = ctx.text(raw)
        elif number == 3 and wire == LEN:
            attributes.add_pb(raw)
    return SpanEvent(name, time, attributes.values)


def _pb_status(buf: memoryview, ctx: _Context, status: SpanStatus) -> SpanStatus:
    code, message = status.code, status.message
    for number, wire, raw in fields(buf):
        if number == 2 and wire == LEN:
            message = ctx.text(raw)
        elif number == 3 and wire == VARINT:
            code = signed64(raw)
    return SpanStatus(code, message)


def _pb_span(buf: memoryview, ctx: _Context) -> Span:
    ctx.record()
    trace_id = span_id = parent = name = ""
    kind = start = end = 0
    attributes = _Attributes(ctx)
    events: list[SpanEvent] = []
    status = SpanStatus()
    for number, wire, raw in fields(buf):
        if wire == LEN:
            if number == 9:
                attributes.add_pb(raw)
            elif number == 5:
                name = ctx.text(raw)
            elif number == 1:
                trace_id = _pb_id(raw, 16)
            elif number == 2:
                span_id = _pb_id(raw, 8)
            elif number == 4:
                parent = _pb_id(raw, 8)
            elif number == 11:
                if len(events) >= ctx.limits.max_events:
                    ctx.events_skipped += 1
                else:
                    events.append(_pb_event(raw, ctx))
            elif number == 15:
                status = _pb_status(raw, ctx, status)
        elif wire == FIXED64:
            if number == 7:
                start = raw
            elif number == 8:
                end = raw
        elif wire == VARINT and number == 6:
            kind = signed64(raw)
    return Span(trace_id, span_id, parent, name, kind, start, end, attributes.values, tuple(events), status)


def _pb_log(buf: memoryview, ctx: _Context) -> LogRecord:
    ctx.record()
    time = observed = severity = 0
    body: Value = None
    attributes = _Attributes(ctx)
    trace_id = span_id = event_name = ""
    for number, wire, raw in fields(buf):
        if wire == LEN:
            if number == 6:
                attributes.add_pb(raw)
            elif number == 5:
                body = _pb_any(raw, ctx, 1)
            elif number == 9:
                trace_id = _pb_id(raw, 16)
            elif number == 10:
                span_id = _pb_id(raw, 8)
            elif number == 12:
                event_name = ctx.text(raw)
        elif wire == FIXED64:
            if number == 1:
                time = raw
            elif number == 11:
                observed = raw
        elif wire == VARINT and number == 2:
            severity = signed64(raw)
    return LogRecord(time, observed, severity, body, attributes.values, trace_id, span_id, event_name)


def _pb_scope(buf: memoryview, ctx: _Context, signal: Signal) -> Scope:
    name = version = ""
    items: list = []
    for number, wire, raw in fields(buf):
        if number == 1 and wire == LEN:
            name, version = _pb_scope_info(raw, ctx, name, version)
        elif number == 2 and wire == LEN:
            items.append(_pb_span(raw, ctx) if signal == "traces" else _pb_log(raw, ctx))
    if signal == "traces":
        return Scope(name, version, spans=tuple(items))
    return Scope(name, version, log_records=tuple(items))


def _pb_request(body: bytes, ctx: _Context, signal: Signal) -> tuple[Resource, ...]:
    resources: list[Resource] = []
    for number, wire, raw in fields(memoryview(body)):
        if number != 1 or wire != LEN:
            continue
        attributes = _Attributes(ctx)
        scopes: list[Scope] = []
        for inner, inner_wire, part in fields(raw):
            if inner == 1 and inner_wire == LEN:
                _pb_resource(part, attributes)
            elif inner == 2 and inner_wire == LEN:
                scopes.append(_pb_scope(part, ctx, signal))
        resources.append(Resource(attributes.values, tuple(scopes)))
    return tuple(resources)


# --- JSON -----------------------------------------------------------------------------------------------------------

_STRING = re.compile(rb'"(?:[^"\\]|\\.)*"', re.DOTALL)
_NOT_BRACKETS = bytes(byte for byte in range(256) if byte not in b"[]{}")
_HEX32 = re.compile(r"[0-9a-fA-F]{32}")
_HEX16 = re.compile(r"[0-9a-fA-F]{16}")
_INT = re.compile(r"-?[0-9]{1,20}")


def json_depth_limit(limits: OtlpLimits) -> int:
    """The deepest OTLP/JSON a request within `max_depth` can hold: an event attribute's value sits 12 levels deep
    (request, resourceSpans, a resource, scopeSpans, a scope, spans, a span, events, an event, attributes, a key-value,
    the value), each nested kvlist adds 4 (`kvlistValue`, `values`, a key-value, the value) and an empty container at
    the deepest value adds 2."""
    return 4 * limits.max_depth + 10


def _depth_within(body: bytes, limit: int) -> bool:
    if body.count(b"[") + body.count(b"{") <= limit:
        return True
    depth = 0
    for byte in _STRING.sub(b"", body).translate(None, _NOT_BRACKETS):
        if byte == 0x5B or byte == 0x7B:
            depth += 1
            if depth > limit:
                return False
        else:
            depth -= 1
    return True


def parse_json(body: bytes, limits: OtlpLimits = DEFAULT_LIMITS, *, depth_limit: int | None = None) -> object:
    """`json.loads` behind the depth pre-scan: `too_deep` past the limit (default `json_depth_limit(limits)`) or on a
    `RecursionError`, `malformed` for anything that is not UTF-8 JSON."""
    raw = bytes(body)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OtlpError("malformed", "the JSON body is not UTF-8") from exc
    limit = json_depth_limit(limits) if depth_limit is None else depth_limit
    if not _depth_within(raw, limit):
        raise OtlpError("too_deep", f"JSON nested deeper than {limit}")
    try:
        return json.loads(text)
    except RecursionError as exc:
        raise OtlpError("too_deep", "JSON nested too deeply") from exc
    except ValueError as exc:
        raise OtlpError("malformed", "the body is not JSON") from exc


def _get(obj: dict, camel: str, snake: str) -> object:
    """OTLP/JSON's lowerCamelCase key, or (a leniency) the original snake_case name; null reads as absent."""
    value = obj.get(camel)
    if value is None:
        value = obj.get(snake)
    return value


def _list(value: object) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise OtlpError("malformed", "an array was expected")
    return value


def _dict(value: object) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise OtlpError("malformed", "an object was expected")
    return value


def _json_int(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        raise OtlpError("malformed", "a boolean where an integer was expected")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and _INT.fullmatch(value):
        return int(value)
    raise OtlpError("malformed", "an integer was expected")


def _json_str(value: object, ctx: _Context) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise OtlpError("malformed", "a string was expected")
    return ctx.json_text(value)


def _json_id(value: object, pattern: re.Pattern) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise OtlpError("malformed", "an id is not hex of the right length")
    return value.lower()


def _json_double(value: object) -> float:
    if isinstance(value, bool):
        raise OtlpError("malformed", "a boolean where a number was expected")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            pass
    raise OtlpError("malformed", "a number was expected")


def _json_any(value: object, ctx: _Context, depth: int) -> Value:
    if depth > ctx.limits.max_depth:
        raise OtlpError("too_deep", f"values nested deeper than {ctx.limits.max_depth}")
    obj = _dict(value)
    if "stringValue" in obj or "string_value" in obj:
        return _json_str(_get(obj, "stringValue", "string_value"), ctx)
    if "boolValue" in obj or "bool_value" in obj:
        flag = _get(obj, "boolValue", "bool_value")
        if not isinstance(flag, bool):
            raise OtlpError("malformed", "boolValue is not a boolean")
        return flag
    if "intValue" in obj or "int_value" in obj:
        return _json_int(_get(obj, "intValue", "int_value"))
    if "doubleValue" in obj or "double_value" in obj:
        return _json_double(_get(obj, "doubleValue", "double_value"))
    if "arrayValue" in obj or "array_value" in obj:
        values = _list(_dict(_get(obj, "arrayValue", "array_value")).get("values"))
        return tuple(_json_any(item, ctx, depth + 1) for item in values)
    if "kvlistValue" in obj or "kvlist_value" in obj:
        out: dict = {}
        for item in _list(_dict(_get(obj, "kvlistValue", "kvlist_value")).get("values")):
            key, inner = _json_kv(item, ctx, depth + 1)
            out.setdefault(key, inner)
        return out
    if "bytesValue" in obj or "bytes_value" in obj:
        encoded = _get(obj, "bytesValue", "bytes_value")
        if not isinstance(encoded, str):
            raise OtlpError("malformed", "bytesValue is not a string")
        try:
            return ctx.blob(base64.b64decode(encoded, validate=False))
        except (binascii.Error, ValueError) as exc:
            raise OtlpError("malformed", "bytesValue is not base64") from exc
    return None


def _json_kv(item: object, ctx: _Context, depth: int) -> tuple[str, Value]:
    obj = _dict(item)
    return _json_str(obj.get("key"), ctx), _json_any(obj.get("value"), ctx, depth)


def _json_attributes(owner: dict, ctx: _Context) -> dict:
    attributes = _Attributes(ctx)
    for item in _list(owner.get("attributes")):
        attributes.add_json(item)
    return attributes.values


def _json_span(obj: dict, ctx: _Context) -> Span:
    ctx.record()
    events: list[SpanEvent] = []
    for item in _list(obj.get("events")):
        if len(events) >= ctx.limits.max_events:
            ctx.events_skipped += 1
            continue
        event = _dict(item)
        events.append(SpanEvent(_json_str(event.get("name"), ctx), _json_int(_get(event, "timeUnixNano", "time_unix_nano")),
                                _json_attributes(event, ctx)))
    status = _dict(obj.get("status"))
    return Span(
        trace_id=_json_id(_get(obj, "traceId", "trace_id"), _HEX32),
        span_id=_json_id(_get(obj, "spanId", "span_id"), _HEX16),
        parent_span_id=_json_id(_get(obj, "parentSpanId", "parent_span_id"), _HEX16),
        name=_json_str(obj.get("name"), ctx),
        kind=_json_int(obj.get("kind")),
        start_time_unix_nano=_json_int(_get(obj, "startTimeUnixNano", "start_time_unix_nano")),
        end_time_unix_nano=_json_int(_get(obj, "endTimeUnixNano", "end_time_unix_nano")),
        attributes=_json_attributes(obj, ctx),
        events=tuple(events),
        status=SpanStatus(_json_int(status.get("code")), _json_str(status.get("message"), ctx)),
    )


def _json_log(obj: dict, ctx: _Context) -> LogRecord:
    ctx.record()
    return LogRecord(
        time_unix_nano=_json_int(_get(obj, "timeUnixNano", "time_unix_nano")),
        observed_time_unix_nano=_json_int(_get(obj, "observedTimeUnixNano", "observed_time_unix_nano")),
        severity_number=_json_int(_get(obj, "severityNumber", "severity_number")),
        body=_json_any(obj.get("body"), ctx, 1) if obj.get("body") is not None else None,
        attributes=_json_attributes(obj, ctx),
        trace_id=_json_id(_get(obj, "traceId", "trace_id"), _HEX32),
        span_id=_json_id(_get(obj, "spanId", "span_id"), _HEX16),
        event_name=_json_str(_get(obj, "eventName", "event_name"), ctx),
    )


_JSON_KEYS = {
    "traces": (("resourceSpans", "resource_spans"), ("scopeSpans", "scope_spans"), ("spans", "spans")),
    "logs": (("resourceLogs", "resource_logs"), ("scopeLogs", "scope_logs"), ("logRecords", "log_records")),
}


def _json_request(body: bytes, ctx: _Context, signal: Signal) -> tuple[Resource, ...]:
    document = parse_json(body, ctx.limits)
    if not isinstance(document, dict):
        raise OtlpError("malformed", "the body is not a JSON object")
    top, middle, leaf = _JSON_KEYS[signal]
    resources: list[Resource] = []
    for item in _list(_get(document, *top)):
        entry = _dict(item)
        attributes = _json_attributes(_dict(entry.get("resource")), ctx)
        scopes: list[Scope] = []
        for scope_item in _list(_get(entry, *middle)):
            scope_entry = _dict(scope_item)
            info = _dict(scope_entry.get("scope"))
            items = [_json_span(_dict(x), ctx) if signal == "traces" else _json_log(_dict(x), ctx)
                     for x in _list(_get(scope_entry, *leaf))]
            name, version = _json_str(info.get("name"), ctx), _json_str(info.get("version"), ctx)
            scopes.append(Scope(name, version, spans=tuple(items)) if signal == "traces"
                          else Scope(name, version, log_records=tuple(items)))
        resources.append(Resource(attributes, tuple(scopes)))
    return tuple(resources)


# --- the public entry points ----------------------------------------------------------------------------------------

def _check(signal: str, encoding: str) -> None:
    if signal not in ("traces", "logs"):
        raise ValueError(f"signal must be traces or logs, not {signal!r}")
    if encoding not in ("protobuf", "json"):
        raise ValueError(f"encoding must be protobuf or json, not {encoding!r}")


def decode(body: bytes, *, signal: Signal, encoding: Encoding, limits: OtlpLimits = DEFAULT_LIMITS) -> OtlpRequest:
    """An `ExportTraceServiceRequest` or `ExportLogsServiceRequest` (opentelemetry-proto v1.11.1) as an `OtlpRequest`,
    or `OtlpError`."""
    _check(signal, encoding)
    ctx = _Context(limits)
    if encoding == "protobuf":
        try:
            resources = _pb_request(bytes(body), ctx, signal)
        except WireError as exc:
            raise OtlpError("malformed", str(exc)) from exc
    else:
        resources = _json_request(body, ctx, signal)
    return OtlpRequest(signal, resources, ctx.attributes_skipped, ctx.events_skipped, ctx.values_cut)


def count_records(body: bytes, *, signal: Signal, encoding: Encoding, limits: OtlpLimits = DEFAULT_LIMITS) -> int:
    """The spans or log records of a request, without reading their attributes (the `drop` pause, spec 6.3 step 6)."""
    _check(signal, encoding)
    if encoding == "json":
        document = parse_json(body, limits)
        if not isinstance(document, dict):
            raise OtlpError("malformed", "the body is not a JSON object")
        top, middle, leaf = _JSON_KEYS[signal]
        return sum(len(_list(_get(_dict(scope), *leaf)))
                   for resource in _list(_get(document, *top)) for scope in _list(_get(_dict(resource), *middle)))
    count = 0
    try:
        for number, wire, resource in fields(memoryview(bytes(body))):
            if number != 1 or wire != LEN:
                continue
            for inner, inner_wire, scope in fields(resource):
                if inner != 2 or inner_wire != LEN:
                    continue
                count += sum(1 for leaf, leaf_wire, _ in fields(scope) if leaf == 2 and leaf_wire == LEN)
    except WireError as exc:
        raise OtlpError("malformed", str(exc)) from exc
    return count


def encode_success(signal: Signal, encoding: Encoding, *, rejected: int = 0, message: str = "") -> bytes:
    """The 200 answer: the empty `Export*ServiceResponse` when nothing is rejected and there is no message, otherwise
    one with `partial_success`."""
    _check(signal, encoding)
    if not rejected and not message:
        return b"" if encoding == "protobuf" else b"{}"
    if encoding == "json":
        key = "rejectedSpans" if signal == "traces" else "rejectedLogRecords"
        return json.dumps({"partialSuccess": {key: str(rejected), "errorMessage": message}},
                          separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    inner = (varint_field(1, rejected) if rejected else b"") + (len_field(2, message.encode("utf-8")) if message else b"")
    return len_field(1, inner)


def encode_status(encoding: Encoding, *, code: int, message: str) -> bytes:
    """The body of every 4xx and 5xx answer: a `google.rpc.Status`."""
    _check("traces", encoding)
    if encoding == "json":
        return json.dumps({"code": code, "message": message}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return (varint_field(1, code) if code else b"") + (len_field(2, message.encode("utf-8")) if message else b"")
