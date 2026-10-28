"""Claim E8: the answers decode with the reference package, partial success included."""
from __future__ import annotations

import json

from otel_support import rpc_status_class
from spellwarden_scan.otel import encode_status, encode_success


def test_empty_success():
    assert encode_success("traces", "protobuf") == b""
    assert encode_success("logs", "json") == b"{}"


def test_partial_success_decodes_with_the_reference_package():
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceResponse
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceResponse

    traces = ExportTraceServiceResponse.FromString(encode_success("traces", "protobuf", rejected=7, message="over quota"))
    assert (traces.partial_success.rejected_spans, traces.partial_success.error_message) == (7, "over quota")
    logs = ExportLogsServiceResponse.FromString(encode_success("logs", "protobuf", rejected=0, message="ignored"))
    assert logs.HasField("partial_success") and logs.partial_success.error_message == "ignored"
    assert logs.partial_success.rejected_log_records == 0


def test_partial_success_in_json():
    assert json.loads(encode_success("traces", "json", rejected=3, message="m")) == {"partialSuccess": {"rejectedSpans": "3", "errorMessage": "m"}}
    assert json.loads(encode_success("logs", "json", rejected=2, message="")) == {"partialSuccess": {"rejectedLogRecords": "2", "errorMessage": ""}}


def test_status_decodes_as_google_rpc_status():
    status = rpc_status_class().FromString(encode_status("protobuf", code=8, message="Spellwarden is paused – later"))
    assert (status.code, status.message) == (8, "Spellwarden is paused – later")
    assert json.loads(encode_status("json", code=3, message="bad")) == {"code": 3, "message": "bad"}
