"""Spec 4.4, 4.5 and claim E7: Claude Code. String booleans and integers, the `safety_event` fold (absent fields only,
the disagreeing pair kept apart), the unpaired `safety_event`, the placeholders, every shape of the event name: the
vectors of `tests/vectors/otel/claude_code.json`, in both encodings."""
from __future__ import annotations

import pytest

from otel_support import build_request, json_bytes, matches, reference_protobuf, vectors
from spellwarden_scan.otel import decode, normalise

CASES = vectors("claude_code.json")


@pytest.mark.parametrize("vector", CASES, ids=[vector["name"] for vector in CASES])
@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_vector(vector, encoding):
    document = build_request(vector)
    body = json_bytes(document) if encoding == "json" else reference_protobuf(document, vector["signal"])
    result = normalise(decode(body, signal=vector["signal"], encoding=encoding), content=vector.get("content", False))
    records = [record.to_dict(content=True) for record in result.records]
    assert len(records) == len(vector["expect"]), records
    for index, (expected, actual) in enumerate(zip(vector["expect"], records, strict=True)):
        assert matches(expected, actual) == [], (index, actual)
    stats = result.stats.to_dict()
    for key, value in vector.get("stats", {}).items():
        assert stats[key] == value, (key, stats)


def test_claude_code_spans_never_count_and_events_do():
    """Claim E7: a tool call reported as a `tool_result` event and as a `claude_code.tool` span counts once."""
    spans = build_request({"signal": "traces", "resource": {"service.name": "claude-code"},
                           "items": [{"name": "claude_code.tool", "attributes": {"tool_name": "Read", "tool_use_id": "toolu_1"}}]})
    logs = build_request({"signal": "logs", "resource": {"service.name": "claude-code"},
                          "items": [{"event_name": "claude_code.tool_result", "attributes": {"tool_name": "Read", "tool_use_id": "toolu_1"}}]})
    counted = [normalise(decode(json_bytes(doc), signal=signal, encoding="json"), content=False).stats.counted
               for doc, signal in ((spans, "traces"), (logs, "logs"))]
    assert counted == [0, 1]
