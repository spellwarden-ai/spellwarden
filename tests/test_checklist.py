"""Spec 5.8: the 12 items, their order and their conditions."""
from __future__ import annotations

from spellwarden_scan.checklist import ITEMS, migration_checklist
from spellwarden_scan.model import AuthServerMetadata, ProbeResult, ToolInfo
from spellwarden_scan.probe import evaluate_probe
from spellwarden_scan.rules import RuleSet

RULES = RuleSet.baseline()
ENDPOINT = "https://mcp.example/mcp"


def keys(probe: ProbeResult) -> list[str]:
    result = evaluate_probe(probe, RULES)
    assert migration_checklist(result) == result.checklist
    return [item.key for item in result.checklist]


def test_the_twelve_items_in_order():
    assert [key for key, _ in ITEMS] == ["streamable_http", "server_discover", "remove_sessions", "meta_version", "sampling_to_mrtr",
                                         "logging_to_meta", "tasks_extension", "oauth_cimd", "validate_iss", "list_ttl", "traceparent", "rescan"]
    assert ITEMS[1][1] == "Add `server/discover`"


def test_ci_logs_matches_product_spec_screen_3():
    ci_logs = ProbeResult(endpoint=ENDPOINT, reachable=True, post_status=200, post_content_type="application/json",
                          initialize={"protocolVersion": "2025-11-25", "capabilities": {"tools": {}, "sampling": {}}},
                          negotiated_version="2025-11-25", capabilities={"tools": {}, "sampling": {}}, unauthenticated_status=200,
                          tools=(ToolInfo("logs", "Reads CI logs."),), tools_source="probe")
    assert keys(ci_logs) == ["server_discover", "meta_version", "sampling_to_mrtr", "oauth_cimd", "validate_iss", "list_ttl", "traceparent", "rescan"]


def test_ready_servers_get_only_rescan_and_stdio_nothing():
    asm = AuthServerMetadata(issuer="https://auth.example", metadata_url="https://auth.example/.well-known/oauth-authorization-server", client_id_metadata_document_supported=True)
    ready = ProbeResult(endpoint=ENDPOINT, reachable=True, post_status=200, post_content_type="application/json",
                        discover={"supportedVersions": ["2026-07-28"]}, capabilities={"tools": {}}, unauthenticated_status=401,
                        resource_metadata={"resource": ENDPOINT, "authorization_servers": ["https://auth.example"]}, auth_server_metadata=asm)
    assert keys(ready) == ["rescan"]
    assert keys(ProbeResult(repository="https://github.com/x/y")) == []


def test_tasks_and_list_ttl_conditions():
    base = dict(endpoint=ENDPOINT, reachable=True, post_status=200, post_content_type="application/json",
                discover={"supportedVersions": ["2026-07-28"]}, capabilities={"tools": {}}, unauthenticated_status=200, tools_source="probe")
    long_running = ProbeResult(**base, tools=(ToolInfo("export", "Exports the warehouse. This may take several minutes."),))
    assert "tasks_extension" in keys(long_running)
    annotated = ProbeResult(**base, tools=(ToolInfo("export", "Exports.", {"longRunning": True}),))
    assert "tasks_extension" in keys(annotated)
    with_tasks = ProbeResult(**{**base, "capabilities": {"tools": {}, "io.modelcontextprotocol/tasks": {}}}, tools=(ToolInfo("export", "Exports.", {"longRunning": True}),))
    assert "tasks_extension" not in keys(with_tasks)
    assert "list_ttl" in keys(ProbeResult(**base, list_result_meta={"ttlMs": 60000}))
    assert "list_ttl" not in keys(ProbeResult(**base, list_result_meta={"ttlMs": 60000, "cacheScope": "private"}))
    assert "list_ttl" not in keys(ProbeResult(**base))
