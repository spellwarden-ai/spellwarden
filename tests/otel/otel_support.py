"""Shared helpers of the OTLP tests (runtime traces spec 4.9): the vector format of `tests/vectors/otel/` (its README
says it again for the hosted side), OTLP/JSON built from it, protobuf built by the reference package, and the fixture
directories. The reference package (`opentelemetry-proto`, a dev dependency) is imported inside the functions that
need it, never by the engine (`tests/test_pure.py`)."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
VECTORS = TESTS / "vectors" / "otel"
FIXTURES = TESTS / "fixtures" / "otel"
TRACE_ID = "5b8efff798038103d269b633813fc60c"
BASE_NS = 1_761_600_000_000_000_000


def any_value(value: object) -> dict:
    """A plain JSON value as an OTLP/JSON `AnyValue`: str, bool, int, float, list (array) and dict (kvlist);
    `{"$bytes": "<base64>"}` is a bytes value and None the empty value."""
    if value is None:
        return {}
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, list):
        return {"arrayValue": {"values": [any_value(item) for item in value]}}
    if isinstance(value, dict) and set(value) == {"$bytes"}:
        return {"bytesValue": value["$bytes"]}
    if isinstance(value, dict):
        return {"kvlistValue": {"values": [{"key": key, "value": any_value(item)} for key, item in value.items()]}}
    raise TypeError(type(value))


def attributes(values: dict | None) -> list[dict]:
    return [{"key": key, "value": any_value(value)} for key, value in (values or {}).items()]


def _span(index: int, item: dict) -> dict:
    start = item.get("start", BASE_NS + index * 1_000_000_000)
    span = {
        "traceId": item.get("trace_id", TRACE_ID), "spanId": item.get("span_id", f"{index + 1:016x}"),
        "name": item.get("name", ""), "kind": item.get("kind", 1), "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(item.get("end", start + 250_000_000)), "attributes": attributes(item.get("attributes")),
    }
    if "parent_span_id" in item:
        span["parentSpanId"] = item["parent_span_id"]
    if "status" in item:
        span["status"] = item["status"]
    if "events" in item:
        span["events"] = [{"name": event["name"], "timeUnixNano": str(event.get("time", start)),
                           "attributes": attributes(event.get("attributes"))} for event in item["events"]]
    return span


def _log(index: int, item: dict) -> dict:
    log = {"timeUnixNano": str(item.get("time", BASE_NS + index * 1_000_000_000)),
           "attributes": attributes(item.get("attributes")), "severityNumber": item.get("severity", 9)}
    for key, name in (("event_name", "eventName"), ("trace_id", "traceId"), ("span_id", "spanId")):
        if key in item:
            log[name] = item[key]
    if "observed" in item:
        log["observedTimeUnixNano"] = str(item["observed"])
    if "body" in item:
        log["body"] = any_value(item["body"])
    return log


def build_request(vector: dict) -> dict:
    """The OTLP/JSON request of a vector: one resource, one scope (`vector["scope"]`, default `test`), its items."""
    scope = {"name": vector.get("scope", "test"), "version": "1.0.0"}
    resource = {"attributes": attributes(vector.get("resource"))}
    if vector["signal"] == "traces":
        spans = [_span(index, item) for index, item in enumerate(vector["items"])]
        return {"resourceSpans": [{"resource": resource, "scopeSpans": [{"scope": scope, "spans": spans}]}]}
    logs = [_log(index, item) for index, item in enumerate(vector["items"])]
    return {"resourceLogs": [{"resource": resource, "scopeLogs": [{"scope": scope, "logRecords": logs}]}]}


def json_bytes(document: dict) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def vectors(name: str) -> list[dict]:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def matches(expected: dict, actual: dict) -> list[str]:
    """The differences between an expected record (a subset of `Record.to_dict(content=True)`, with `$absent` naming
    fields that must be absent) and the actual one; [] when it matches."""
    problems = [f"{key}: expected {value!r}, got {actual.get(key)!r}"
                for key, value in expected.items() if key != "$absent" and actual.get(key) != value]
    problems += [f"{key}: expected absent, got {actual[key]!r}" for key in expected.get("$absent", ()) if key in actual]
    return problems


# --- the reference package ------------------------------------------------------------------------------------------

_ID_KEYS = ("traceId", "spanId", "parentSpanId")


def _ids_to_base64(node: object) -> object:
    """OTLP/JSON writes ids as hex; proto3 JSON (`json_format`) reads bytes as base64."""
    if isinstance(node, dict):
        return {key: (base64.b64encode(bytes.fromhex(value)).decode("ascii") if key in _ID_KEYS and isinstance(value, str)
                      else _ids_to_base64(value)) for key, value in node.items()}
    if isinstance(node, list):
        return [_ids_to_base64(item) for item in node]
    return node


def request_class(signal: str):
    if signal == "traces":
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
        return ExportTraceServiceRequest
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
    return ExportLogsServiceRequest


def reference_protobuf(document: dict, signal: str) -> bytes:
    """The protobuf bytes of an OTLP/JSON document, as the reference encoder writes them."""
    from google.protobuf import json_format

    message = request_class(signal)()
    json_format.ParseDict(_ids_to_base64(copy.deepcopy(document)), message)
    return message.SerializeToString()


def reference_decode(body: bytes, signal: str):
    return request_class(signal).FromString(body)


def rpc_status_class():
    """`google.rpc.Status` (code = 1, message = 2, details = 3), built from a descriptor: the reference package does
    not ship it."""
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

    pool = descriptor_pool.DescriptorPool()
    any_file = descriptor_pb2.FileDescriptorProto(name="any_for_status.proto", package="google.protobuf", syntax="proto3")
    any_message = any_file.message_type.add(name="Any")
    any_message.field.add(name="type_url", number=1, type=9, label=1)
    any_message.field.add(name="value", number=2, type=12, label=1)
    pool.Add(any_file)
    status_file = descriptor_pb2.FileDescriptorProto(name="status_for_test.proto", package="google.rpc", syntax="proto3",
                                                     dependency=["any_for_status.proto"])
    status = status_file.message_type.add(name="Status")
    status.field.add(name="code", number=1, type=5, label=1)
    status.field.add(name="message", number=2, type=9, label=1)
    status.field.add(name="details", number=3, type=11, label=3, type_name=".google.protobuf.Any")
    pool.Add(status_file)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName("google.rpc.Status"))


# --- fixtures -------------------------------------------------------------------------------------------------------

def synthetic_fixtures() -> list[Path]:
    return sorted((FIXTURES / "synthetic").glob("*.json"))


def recorded_bodies() -> list[Path]:
    """Every recorded body of the release gate (spec 7.1): `<producer>/<name>.pb` or `.json`, with its signal in the
    name (`*.traces.pb`, `*.logs.json`)."""
    root = FIXTURES / "recorded"
    return sorted(path for path in root.rglob("*") if path.suffix in (".pb", ".json") and not path.name.endswith(".expected.json"))


def recorded_signal(path: Path) -> str:
    return "traces" if ".traces." in path.name else "logs"


def recorded_encoding(path: Path) -> str:
    return "protobuf" if path.suffix == ".pb" else "json"


def fixture_bodies() -> list[tuple[str, str, str, bytes]]:
    """`(name, signal, encoding, body)` of every synthetic fixture (its JSON body, and the reference protobuf of it
    when the fixture's producer sends protobuf) and every recorded body."""
    out = []
    for path in synthetic_fixtures():
        fixture = json.loads(path.read_text(encoding="utf-8"))
        out.append((path.stem + ".json", fixture["signal"], "json", json_bytes(fixture["body"])))
        if fixture["encoding"] == "protobuf":
            out.append((path.stem + ".pb", fixture["signal"], "protobuf", reference_protobuf(fixture["body"], fixture["signal"])))
    for path in recorded_bodies():
        out.append((path.relative_to(FIXTURES).as_posix(), recorded_signal(path), recorded_encoding(path), path.read_bytes()))
    return out
