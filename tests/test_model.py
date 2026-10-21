"""Spec 5.2: every data class is frozen, JSON-serialisable and round-trips."""
from __future__ import annotations

import dataclasses
import json

import pytest

from spellwarden_scan import model


def test_every_data_class_is_frozen_and_round_trips():
    probe = model.ProbeResult(endpoint="https://mcp.example/mcp", reachable=True, discover={"supportedVersions": ["2026-07-28"]},
                              tools=(model.ToolInfo("search", "Searches.", {"longRunning": True}),),
                              auth_server_metadata=model.AuthServerMetadata(issuer="https://auth.example"))
    as_json = json.dumps(probe.to_dict())
    assert model.ProbeResult.from_dict(json.loads(as_json)) == probe
    with pytest.raises(dataclasses.FrozenInstanceError):
        probe.reachable = False  # type: ignore[misc]
    finding = model.Finding("SW-SKL-001", "high", "t", model.Location("SKILL.md", 3), "e", "f" * 64)
    assert model.Finding.from_dict(json.loads(json.dumps(finding.to_dict()))) == finding
    meta = model.Metadata("n", "d", None, None, None, frozenset({"name", "description"}), True, ())
    back = model.Metadata.from_dict(json.loads(json.dumps(meta.to_dict())))
    assert back == meta and sorted(meta.to_dict()["present"]) == ["description", "name"]
    inputs = model.CurationInputs((finding,), (), 3)
    assert model.CurationInputs.from_dict(json.loads(json.dumps(inputs.to_dict()))) == inputs
    mixed = model.CurationInputs((finding, "low"), ("medium",), 3)
    assert model.CurationInputs.from_dict(json.loads(json.dumps(mixed.to_dict()))) == mixed
    result = model.McpScanResult((finding,), 0, "2026-07-28", "streamable-http", "oauth-cimd", (), "ready", (), "r", "s",
                                 list_meta_missing=True, long_running_tools=("export",), tasks_supported=False, issuer_problem=True)
    assert model.McpScanResult.from_dict(json.loads(json.dumps(result.to_dict()))) == result
    assert model.McpScanResult.from_dict({"findings": [], "truncated": 0, "spec_version": None, "transport": "stdio", "auth_mode": "unknown",
                                          "deprecated_features": [], "migration_status": "not_probeable", "checklist": [],
                                          "rules_version": "r", "scanner_version": "s"}).long_running_tools == ()


def test_probe_result_has_a_default_for_every_field():
    empty = model.ProbeResult()
    assert empty.reachable is False and empty.tools == () and empty.capabilities == {}
    assert model.ProbeResult.from_dict({}) == empty


def test_from_dict_ignores_unknown_keys_and_fills_missing_defaults():
    probe = model.ProbeResult.from_dict({"endpoint": "https://x.example/mcp", "future_field": 1})
    assert probe.endpoint == "https://x.example/mcp" and probe.probed_at is None


def test_tool_info_input_schema_is_optional_and_round_trips():
    # Phase C spec 5.6 and claim E9: an additive field; a 1.0.0 dict without it still loads.
    plain = model.ToolInfo("search", "Searches.")
    assert plain.input_schema is None
    assert model.ToolInfo.from_dict({"name": "search", "description": "Searches.", "annotations": {}}) == plain
    schema = {"type": "object", "properties": {"q": {"type": "string", "description": "What to look for."}},
              "required": ["q"]}
    with_schema = model.ToolInfo("search", "Searches.", {}, schema)
    as_json = json.loads(json.dumps(with_schema.to_dict()))
    assert as_json["input_schema"] == schema
    assert model.ToolInfo.from_dict(as_json) == with_schema


def test_every_1_0_0_probe_fixture_still_loads_and_round_trips():
    from conftest import PROBE_FIXTURES

    paths = sorted(PROBE_FIXTURES.rglob("*.json"))
    assert len(paths) >= 20
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        probe = model.ProbeResult.from_dict(document["probe"])
        assert all(tool.input_schema is None for tool in probe.tools), path.name
        assert model.ProbeResult.from_dict(json.loads(json.dumps(probe.to_dict()))) == probe, path.name
