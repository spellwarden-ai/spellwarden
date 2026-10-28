"""Spec 4.4, 4.6 and claim E12: content records are bounded by `max_records` and the content cuts only, `other`
records by `max(100, 2 x counted)`, and content items by 32 KiB each and 128 KiB a record."""
from __future__ import annotations

from otel_support import build_request, json_bytes
from spellwarden_scan.otel import decode, normalise


def _normalised(vector: dict, content: bool):
    return normalise(decode(json_bytes(build_request(vector)), signal=vector["signal"], encoding="json"), content=content)


def test_a_logs_only_genai_body_keeps_every_content_record():
    items = [{"event_name": "gen_ai.client.inference.operation.details", "attributes": {"gen_ai.input.messages": f"m{n}"}}
             for n in range(500)]
    result = _normalised({"signal": "logs", "resource": {"service.name": "a"}, "items": items}, True)
    assert result.stats.kept == 500 and result.stats.counted == 0
    assert {record.kind for record in result.records} == {"content"}


def test_other_records_past_the_floor_are_ignored():
    items = [{"name": "chain", "attributes": {"openinference.span.kind": "CHAIN"}}] * 150
    result = _normalised({"signal": "traces", "resource": {"service.name": "a"}, "items": items}, False)
    assert (result.stats.kept, result.stats.ignored) == (100, 50)


def test_content_cut_counts_the_kept_records_only():
    big = "x" * 40_000  # over the 32 KiB of one item: each record cuts one
    items = [{"name": "chain", "attributes": {"openinference.span.kind": "CHAIN", "input.value": big}}] * 150
    result = _normalised({"signal": "traces", "resource": {"service.name": "a"}, "items": items}, True)
    assert (result.stats.kept, result.stats.ignored) == (100, 50)
    assert result.stats.content_items == 100 and result.stats.content_cut == 100


def test_other_records_scale_with_the_counted_ones():
    chains = [{"name": "chain", "attributes": {"openinference.span.kind": "CHAIN"}}] * 200
    tools = [{"name": "tool", "attributes": {"openinference.span.kind": "TOOL"}}] * 60
    result = _normalised({"signal": "traces", "resource": {"service.name": "a"}, "items": chains + tools}, False)
    assert result.stats.counted == 60
    assert sum(1 for record in result.records if record.kind == "other") == 120
    assert result.stats.ignored == 80


def test_content_items_are_cut_at_32_kib_and_a_record_at_128_kib():
    big = "é" * 40_000  # 80,000 bytes of UTF-8
    attributes = {"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai", "gen_ai.system_instructions": big,
                  "gen_ai.input.messages": big, "gen_ai.output.messages": big, "gen_ai.tool.call.arguments": big,
                  "gen_ai.tool.call.result": big}
    result = _normalised({"signal": "traces", "resource": {"service.name": "a"}, "items": [{"name": "chat", "attributes": attributes}]}, True)
    items = result.records[0].content
    sizes = [len(item.text.encode("utf-8")) for item in items]
    assert len(items) == 4 and all(item.cut for item in items)
    assert sizes[:3] == [32_768, 32_768, 32_768] and sum(sizes) <= 131_072
    assert result.stats.content_cut == 5 and result.stats.content_items == 4


def test_a_value_cut_by_the_decoder_marks_its_content_cut():
    from spellwarden_scan.otel import OtlpLimits

    body = json_bytes(build_request({"signal": "traces", "resource": {"service.name": "a"},
                                     "items": [{"name": "c", "attributes": {"gen_ai.operation.name": "chat", "gen_ai.input.messages": "x" * 50}}]}))
    request = decode(body, signal="traces", encoding="json", limits=OtlpLimits(max_value_bytes=40))
    (item,) = normalise(request, content=True).records[0].content
    assert item.cut and item.text == "x" * 40
