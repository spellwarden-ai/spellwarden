"""Spec 4.8 and P13: `spellwarden otel normalise` on a file: the JSON it prints, `--content`, gzip input, the bounds,
`--signal` required for protobuf, the exit codes. It reads a file and sends nothing."""
from __future__ import annotations

import gzip
import json
from pathlib import Path

ZUPLO = Path(__file__).resolve().parents[1] / "fixtures" / "otel" / "synthetic" / "zuplo.json"


def _protobuf_traces() -> bytes:
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
    from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue

    request = ExportTraceServiceRequest()
    resource = request.resource_spans.add()
    resource.resource.attributes.add(key="service.name", value=AnyValue(string_value="shop-agent"))
    span = resource.scope_spans.add().spans.add(trace_id=bytes(range(1, 17)), span_id=bytes(range(1, 9)), name="chat gpt-4o",
                                                 start_time_unix_nano=1, end_time_unix_nano=2_000_001)
    span.attributes.extend([KeyValue(key="gen_ai.operation.name", value=AnyValue(string_value="chat")),
                            KeyValue(key="gen_ai.provider.name", value=AnyValue(string_value="openai")),
                            KeyValue(key="gen_ai.input.messages", value=AnyValue(string_value="hello there")),
                            KeyValue(key="user.email", value=AnyValue(string_value="dana@example.com"))])
    return request.SerializeToString()


def _json_logs() -> bytes:
    return json.dumps({"resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "claude-code"}}]},
                                         "scopeLogs": [{"logRecords": [{"eventName": "claude_code.tool_result", "timeUnixNano": "5",
                                                                        "attributes": [{"key": "tool_name", "value": {"stringValue": "Read"}}]}]}]}]}).encode()


def test_protobuf_with_signal_prints_the_records_without_content(run_cli, tmp_path):
    path = tmp_path / "traces.pb"
    path.write_bytes(_protobuf_traces())
    code, out, err = run_cli(["otel", "normalise", str(path), "--signal", "traces"])
    assert (code, err) == (0, "")
    printed = json.loads(out)
    assert set(printed) == {"stats", "resources", "records"}
    assert printed["records"][0]["kind"] == "model" and "content" not in printed["records"][0]
    assert "hello there" not in out and "dana@example.com" not in out
    assert printed["resources"] == [{"service_name": "shop-agent"}]


def test_content_prints_the_content_items(run_cli, tmp_path):
    path = tmp_path / "traces.pb"
    path.write_bytes(_protobuf_traces())
    code, out, _ = run_cli(["otel", "normalise", str(path), "--signal", "traces", "--content"])
    assert code == 0
    assert json.loads(out)["records"][0]["content"] == [{"kind": "input", "text": "hello there", "cut": False}]
    assert "dana@example.com" not in out


def test_gzip_input_and_json_without_signal(run_cli, tmp_path):
    path = tmp_path / "logs.json.gz"
    path.write_bytes(gzip.compress(_json_logs()))
    code, out, _ = run_cli(["otel", "normalise", str(path)])
    assert code == 0
    assert json.loads(out)["records"][0]["tool_name"] == "Read"


def test_the_zuplo_fixture_keeps_nothing(run_cli, tmp_path):
    path = tmp_path / "zuplo.json"
    path.write_text(json.dumps(json.loads(ZUPLO.read_text())["body"]))
    code, out, _ = run_cli(["otel", "normalise", str(path), "--encoding", "json"])
    assert code == 0
    assert json.loads(out)["stats"]["kept"] == 0 and json.loads(out)["stats"]["ignored"] == 3


def test_signal_is_required_for_protobuf(run_cli, tmp_path):
    path = tmp_path / "traces.pb"
    path.write_bytes(_protobuf_traces())
    code, out, err = run_cli(["otel", "normalise", str(path)])
    assert (code, out) == (2, "")
    assert "--signal" in err


def test_malformed_protobuf_names_the_signal_flag(run_cli, tmp_path):
    path = tmp_path / "bad.pb"
    path.write_bytes(b"\x0a\x05abc")
    code, _, err = run_cli(["otel", "normalise", str(path), "--signal", "logs"])
    assert code == 2 and "malformed" in err and "--signal" in err


def test_auto_does_not_take_a_protobuf_tag_for_a_blank_byte(run_cli, tmp_path):
    """A protobuf request starts with the tag byte 0x0a, which is also a newline, and a 123-byte first message puts
    `{` (0x7b) right behind it; `--encoding auto` must still read the body as protobuf."""
    path = tmp_path / "tag.pb"
    path.write_bytes(b"\x0a\x7b" + b"\xff" * 123)
    code, _, err = run_cli(["otel", "normalise", str(path), "--signal", "traces"])
    assert code == 2 and "malformed" in err and "--signal" in err


def test_the_bounds(run_cli, tmp_path):
    path = tmp_path / "traces.pb"
    path.write_bytes(_protobuf_traces())
    code, _, err = run_cli(["otel", "normalise", str(path), "--signal", "traces", "--max-bytes", "10"])
    assert code == 2 and "too_large" in err
    big = tmp_path / "big.gz"
    big.write_bytes(gzip.compress(b"{" + b" " * 5000 + b"}"))
    code, _, err = run_cli(["otel", "normalise", str(big), "--max-bytes", "1000"])
    assert code == 2 and "too_large" in err
    many = tmp_path / "many.json"
    many.write_text(json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "s"}] * 3}]}]}))
    code, _, err = run_cli(["otel", "normalise", str(many), "--max-records", "2"])
    assert code == 2 and "too_many_records" in err


def test_usage_errors_exit_two(run_cli, tmp_path):
    assert run_cli(["otel", "normalise", str(tmp_path / "missing.pb"), "--signal", "traces"])[0] == 2
    assert run_cli(["otel", "normalise"])[0] == 2
    assert run_cli(["otel", "normalise", "x", "--max-records", "0"])[0] == 2
    assert run_cli(["otel"])[0] == 2
