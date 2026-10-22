"""Spec 6.8 and claim C14 (ported from the hosted backend's N3 tests, `code/backend/tests/test_probe.py` at
`b83c500`): the probe sequence against recorded exchanges. Pure: the fetcher is the fake. The edits to the ported
file are the imports, one unused name, and the `on_event` test at the end."""
from __future__ import annotations

import json

import pytest

from fake_net import FakeFetcher, load_exchanges
from spellwarden_cli import probe as probe_module
from spellwarden_cli.probe import probe

ENDPOINT = "https://mcp.example/mcp"


def run(name: str):
    fetcher = FakeFetcher(load_exchanges(name))
    return probe(fetcher, ENDPOINT, release="test-release", now_iso="2026-10-18T10:00:00Z"), fetcher.requests


def posts(requests):
    return [r for r in requests if r["method"] == "POST"]


def test_cimd_discover_then_metadata():
    result, requests = run("probe_cimd")
    assert result.reachable and result.discover["supportedVersions"] == ["2025-11-25", "2026-07-28"]
    assert result.unauthenticated_status == 401 and result.resource_metadata["resource"] == ENDPOINT
    assert result.auth_server_metadata.client_id_metadata_document_supported is True
    assert result.auth_server_metadata.metadata_url == "https://auth.example/.well-known/oauth-authorization-server"
    assert result.initialize is None and result.session_id_seen is False and result.probed_at == "2026-10-18T10:00:00Z"
    first = posts(requests)[0]
    assert first["headers"]["MCP-Protocol-Version"] == "2026-07-28"
    assert first["headers"]["Mcp-Method"] == "server/discover" and first["headers"]["Mcp-Name"] == probe_module.PROBE_NAME
    assert first["body"]["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    for request in requests:
        assert "Authorization" not in request["headers"] and "authorization" not in {k.lower() for k in request["headers"]}
    assert [r["headers"]["Mcp-Method"] for r in posts(requests)] == ["server/discover", "tools/list"]
    assert len(requests) <= probe_module.MAX_REQUESTS


def test_dcr_falls_back_to_initialize_sends_initialized_and_walks_both_metadata_locations():
    result, requests = run("probe_dcr")
    assert result.discover is None and result.initialize["protocolVersion"] == "2025-11-25"
    assert result.negotiated_version == "2025-11-25"
    assert [r["headers"]["Mcp-Method"] for r in posts(requests)] == ["server/discover", "initialize", "notifications/initialized", "tools/list"]
    assert "id" not in posts(requests)[2]["body"]
    assert result.resource_metadata["resource"] == "https://mcp.example"
    assert result.auth_server_metadata.registration_endpoint == "https://auth.example/register"
    assert result.auth_server_metadata.client_id_metadata_document_supported is False
    gets = [r["url"] for r in requests if r["method"] == "GET"]
    assert gets == ["https://mcp.example/.well-known/oauth-protected-resource/mcp", "https://mcp.example/.well-known/oauth-protected-resource",
                    "https://auth.example/.well-known/oauth-authorization-server"]
    assert len(requests) == 7


def test_xaa_reads_the_openid_document_when_the_oauth_one_is_missing():
    result, requests = run("probe_xaa")
    assert "urn:ietf:params:oauth:grant-type:jwt-bearer" in result.auth_server_metadata.grant_types_supported
    assert result.auth_server_metadata.metadata_url == "https://auth.example/.well-known/openid-configuration"
    assert result.auth_server_metadata.registration_endpoint is None


def test_static_key_has_no_metadata_anywhere():
    result, requests = run("probe_static")
    assert result.unauthenticated_status == 403 and result.resource_metadata is None and result.auth_server_metadata is None
    assert len(requests) == 4


def test_none_lists_tools_with_their_meta():
    result, requests = run("probe_none")
    assert result.unauthenticated_status == 200 and [tool.name for tool in result.tools] == ["tail_logs", "ignore_me"]
    assert result.tools_source == "probe" and result.list_result_meta == {"ttlMs": 60000, "cacheScope": "public"}
    assert result.capabilities == {"tools": {}, "sampling": {}}
    assert len(requests) == 2


def test_sse_is_found_through_the_get_after_both_posts_fail():
    result, requests = run("probe_sse")
    assert result.post_status == 405 and result.get_content_type == "text/event-stream" and result.sse_endpoint_event is True
    get = [r for r in requests if r["method"] == "GET"][0]
    assert get["headers"]["Accept"] == "text/event-stream"


def test_initialize_only_echoes_the_session_on_the_notification_and_the_list():
    result, requests = run("probe_initialize_only")
    assert result.session_id_seen is True and result.negotiated_version == "2025-06-18"
    assert result.capabilities == {"tools": {}, "logging": {}}
    methods = [r["headers"]["Mcp-Method"] for r in posts(requests)]
    assert methods.index("notifications/initialized") < methods.index("tools/list")
    assert posts(requests)[2]["headers"]["Mcp-Session-Id"] == "sess-1" and posts(requests)[3]["headers"]["Mcp-Session-Id"] == "sess-1"
    assert "Mcp-Session-Id" not in posts(requests)[0]["headers"]


def test_sessions_are_noticed_on_discover():
    result, _ = run("probe_sessions")
    assert result.session_id_seen is True and [tool.name for tool in result.tools] == ["query"]


def test_unreachable_and_http_endpoints():
    result, requests = run("probe_unreachable")
    assert result.reachable is False and result.error == "unreachable" and result.tools == ()
    assert requests == [] or all(r["url"].startswith(ENDPOINT) for r in requests)
    fetcher = FakeFetcher([])
    plain = probe(fetcher, "http://mcp.example/mcp", release="r", now_iso="2026-10-18T10:00:00Z")
    assert (plain.reachable, plain.error, fetcher.requests) == (False, "not_https", [])


def test_a_redirected_discover_is_not_followed_and_the_probe_stays_on_its_origin():
    """Spec 6.5 and 6.6: the fetcher never follows a POST redirect (Task 7), so a `server/discover`
    answered 302 to another origin is a status without a result; the probe carries on with
    `initialize` on the original URL and no request, header or session ever reaches the other origin."""
    result, requests = run("probe_redirect")
    assert result.discover is None and result.initialize["protocolVersion"] == "2025-11-25"
    assert all(r["url"].startswith(ENDPOINT) for r in requests)
    assert [r["headers"]["Mcp-Method"] for r in posts(requests)] == ["server/discover", "initialize", "notifications/initialized", "tools/list"]


def test_an_answer_that_is_neither_json_nor_an_event_stream_carries_no_result():
    exchanges = load_exchanges("probe_none")
    exchanges[0]["headers"] = {"Content-Type": "text/plain"}
    result = probe(FakeFetcher(exchanges), ENDPOINT, release="r", now_iso="t")
    assert result.discover is None and result.initialize is None
    # The text/plain body was a JSON-RPC result, ignored for its content type; the later
    # `tools/list` answer (200, application/json) is what the transport fields record (spec 6.6 step 4).
    assert result.post_status == 200 and result.post_content_type == "application/json"


def test_the_tool_cap_and_description_cut():
    exchanges = load_exchanges("probe_none")
    exchanges[1]["body"]["result"]["tools"] = [{"name": f"t{i}", "description": "x" * 1500} for i in range(250)]
    result, _ = probe(FakeFetcher(exchanges), ENDPOINT, release="r", now_iso="t"), None
    assert len(result.tools) == 200 and len(result.tools[0].description) == 1000


@pytest.mark.parametrize("name", ["probe_cimd", "probe_dcr", "probe_xaa", "probe_static", "probe_none", "probe_sse",
                                  "probe_initialize_only", "probe_sessions"])
def test_every_recorded_probe_round_trips_to_dict(name):
    result, _ = run(name)
    assert type(result).from_dict(result.to_dict()) == result


def test_a_probe_that_raises_is_a_result_and_an_event():
    class Broken:
        def post_json(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    events: list[tuple[str, dict]] = []
    result = probe(Broken(), ENDPOINT, release="r", now_iso="t", on_event=lambda name, fields: events.append((name, fields)))
    assert (result.reachable, result.error, result.probed_at) == (False, "unreachable", "t")
    assert events == [("probe_failed", {"error_class": "RuntimeError"})]


def _schema_of_size(size: int) -> dict:
    """A JSON object whose canonical JSON (sorted keys, no spaces, UTF-8) is exactly `size` bytes."""
    base = {"type": "object", "properties": {"q": {"type": "string", "description": ""}}}
    overhead = len(json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    base["properties"]["q"]["description"] = "x" * (size - overhead)
    return base


def test_the_prober_records_input_schemas_up_to_16_kib():
    # Phase C spec 5.6 and claim E9: kept at 10 KiB and at exactly 16 384 bytes, dropped at 16 385 and at 20 KiB;
    # anything that is not a JSON object, or cannot be written as UTF-8, is no schema.
    exchanges = load_exchanges("probe_none")
    schemas = {"ten": _schema_of_size(10 * 1024), "edge": _schema_of_size(16384), "over": _schema_of_size(16385),
               "twenty": _schema_of_size(20 * 1024), "list": ["not", "an", "object"], "text": "object",
               "surrogate": {"type": "object", "description": "\ud800"}}
    exchanges[1]["body"]["result"]["tools"] = [{"name": name, "description": "d", "inputSchema": schema}
                                               for name, schema in schemas.items()] + [{"name": "none", "description": "d"}]
    result = probe(FakeFetcher(exchanges), ENDPOINT, release="r", now_iso="t")
    recorded = {tool.name: tool.input_schema for tool in result.tools}
    assert recorded["ten"] == schemas["ten"] and recorded["edge"] == schemas["edge"]
    assert [name for name, value in recorded.items() if value is None] == ["over", "twenty", "list", "text", "surrogate", "none"]
    assert probe_module.MAX_SCHEMA_BYTES == 16384
    assert type(result).from_dict(result.to_dict()) == result


def test_after_initialize_every_request_carries_the_negotiated_protocol_version():
    """A server that negotiates an older version than the probe's refuses the probe's own on `tools/list` (the AWS
    MCP server on 2026-10-22: 400 "Unsupported protocol version: 2025-11-25"); the header follows the negotiation."""
    fetcher = FakeFetcher()
    fetcher.add("POST", ENDPOINT, status=400, body={"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no discover"}}, queue=True)
    fetcher.add("POST", ENDPOINT, status=200, headers={"Mcp-Session-Id": "s1"},
                body={"jsonrpc": "2.0", "id": 2, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                                           "serverInfo": {"name": "older", "version": "1"}}}, queue=True)
    fetcher.add("POST", ENDPOINT, status=202, body=b"", queue=True)
    fetcher.add("POST", ENDPOINT, status=200, body={"jsonrpc": "2.0", "id": 4, "result": {"tools": [
        {"name": "list_regions", "description": "Lists regions.", "inputSchema": {"type": "object"}}]}}, queue=True)
    result = probe(fetcher, ENDPOINT, release="test-release", now_iso="2026-10-22T13:00:00Z")
    sent = posts(fetcher.requests)
    assert [r["headers"]["Mcp-Method"] for r in sent] == ["server/discover", "initialize", "notifications/initialized", "tools/list"]
    assert [r["headers"]["MCP-Protocol-Version"] for r in sent] == ["2026-07-28", "2025-11-25", "2025-06-18", "2025-06-18"]
    assert sent[3]["headers"]["Mcp-Session-Id"] == "s1"
    assert result.negotiated_version == "2025-06-18" and result.tools_source == "probe"
    assert [tool.name for tool in result.tools] == ["list_regions"] and result.unauthenticated_status == 200
