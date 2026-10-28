"""Zuplo export spec claims T1 to T3: the local MCP test server serves every planted answer of the release gate, the OAuth
client completes the flow against the local fake (metadata, dynamic registration, PKCE S256, the `resource` parameter, the
consent form, the token) and holds one token for each route, and neither tool is run by the checks against a real project.
Everything here runs on loopback."""
from __future__ import annotations

import gzip
import json
import urllib.request
from pathlib import Path

import pytest
import zuplo_client as C
from fake_zuplo_oauth import CONSENT_FIELDS, ROUTES, FakeGateway, s256
from zuplo_upstream import BIG_BYTES, ORG_PHRASE, PHRASE, TOOLS, Upstream

ROOT = Path(__file__).resolve().parents[1]


def post(url: str, message: dict) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, data=json.dumps(message).encode("utf-8"), method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": "test"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()


def call(url: str, name: str) -> tuple[int, dict[str, str], str]:
    status, headers, body = post(url, {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": name}})
    if headers.get("content-encoding") == "gzip":
        body = gzip.decompress(body)
    return status, headers, body.decode("utf-8")


@pytest.fixture(scope="module")
def upstream():
    with Upstream() as server:
        yield server


def test_t1_every_planted_answer_is_served(upstream):
    for name in TOOLS:
        status, headers, body = call(upstream.url + "/", name)
        assert status == (500 if name == "error500" else 200), name
        if name in ("clean", "phrase", "zwsp", "error500", "blob", "big", "phrase_gzip", "big_gzip", "mib", "mib_dense"):
            assert headers["content-type"] == "application/json", name
        else:
            assert headers["content-type"] == "text/event-stream", name
    assert "sunny" in call(upstream.url, "clean")[2] and PHRASE not in call(upstream.url, "clean")[2]
    assert "notifications/progress" in call(upstream.url, "clean_sse")[2]
    assert PHRASE in call(upstream.url, "phrase")[2] and PHRASE in call(upstream.url, "phrase_sse")[2]
    status, headers, body = call(upstream.url, "phrase_gzip")
    assert headers["content-encoding"] == "gzip" and PHRASE in body
    assert "Ignore\\u200b previous" in call(upstream.url, "zwsp")[2]
    assert "sampling/createMessage" in call(upstream.url, "sampling")[2]
    assert '"blob"' in call(upstream.url, "blob")[2] and PHRASE not in call(upstream.url, "blob")[2]
    assert PHRASE in call(upstream.url, "error500")[2]
    assert len(call(upstream.url, "big")[2]) > BIG_BYTES
    assert 1_000_000 < len(call(upstream.url, "mib")[2]) < 1_048_576 and 1_000_000 < len(call(upstream.url, "mib_dense")[2]) < 1_048_576
    assert PHRASE not in call(upstream.url, "mib_dense")[2]
    assert call(upstream.url, "big_gzip")[1]["content-encoding"] == "gzip"


def test_t1_prompts_tools_list_initialize_and_get(upstream):
    _, _, body = post(upstream.url, {"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {"name": "org_phrase"}})
    assert ORG_PHRASE in body.decode("utf-8")
    plain = json.loads(post(upstream.url + "/", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})[2])["result"]["tools"]
    hidden = json.loads(post(upstream.url + "/b", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})[2])["result"]["tools"]
    assert [tool["name"] for tool in plain] == ["visible_tool"]
    assert [tool["name"] for tool in hidden] == ["hidden_tool", "visible_tool"] and hidden[0]["description"] == PHRASE
    assert hidden[1]["description"] != PHRASE
    shown = json.loads(post(upstream.url + "/b", {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": "visible-phrase"}})[2])
    assert [(tool["name"], tool["description"]) for tool in shown["result"]["tools"]] == [("visible_tool", PHRASE)]
    init = json.loads(post(upstream.url, {"jsonrpc": "2.0", "id": 3, "method": "initialize"})[2])["result"]
    assert init["protocolVersion"] == "2025-11-25"
    request = urllib.request.Request(upstream.url, method="GET")
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(request, timeout=10)
    assert caught.value.code == 405


def test_t2_the_client_completes_the_flow_and_holds_one_token_per_route():
    with FakeGateway() as fake:
        client = C.GatewayClient(fake.base)
        try:
            reply = client.call(ROUTES[0], {"jsonrpc": "2.0", "id": 5, "method": "ping"})
            assert reply.status == 200 and reply.json() == {"jsonrpc": "2.0", "id": 5, "result": {"route": "/mcp/a"}}
            assert set(client.tokens) == {"/mcp/a"}
            other = client.call(ROUTES[1], {"jsonrpc": "2.0", "id": 6, "method": "ping"})
            assert other.json()["result"] == {"route": "/mcp/b"}
            assert set(client.tokens) == {"/mcp/a", "/mcp/b"} and client.tokens["/mcp/a"] != client.tokens["/mcp/b"]
            assert fake.calls.count(("POST", "/oauth/register")) == 1, "one registration for both routes"
            assert fake.calls.count(("POST", "/oauth/token")) == 2
            assert client.call(ROUTES[0], {"jsonrpc": "2.0", "id": 7, "method": "ping"}).status == 200
            assert fake.calls.count(("POST", "/oauth/token")) == 2, "a token is reused"
        finally:
            client.close()


def test_t2_a_token_is_bound_to_its_route_and_pkce_is_checked():
    with FakeGateway() as fake:
        client = C.GatewayClient(fake.base)
        try:
            token = client.token_for(ROUTES[0])
            bound = urllib.request.Request(fake.base + ROUTES[1], data=b"{}", method="POST", headers={"Authorization": f"Bearer {token}"})
            with pytest.raises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(bound, timeout=10)
            assert caught.value.code == 401 and "resource_metadata" in caught.value.headers["WWW-Authenticate"]
            request = next(iter(fake.requests.values()))
            assert request["code_challenge_method"] == "S256" and request["resource"] == fake.resource(ROUTES[0])
            assert s256("x") == C.pkce("x")
        finally:
            client.close()


def test_t2_the_consent_form_is_read_from_the_page():
    form = C._Form()
    form.feed('<form method="post" action="/c"><input type="hidden" name="a" value="1"><button type="submit" name="d" value="no">Deny</button>'
              '<button type="submit" name="d" value="yes">Allow access</button></form>')
    assert (form.action, form.method, form.hidden) == ("/c", "post", {"a": "1"})
    assert form.buttons == [("d", "no", "Deny"), ("d", "yes", "Allow access")]
    assert set(CONSENT_FIELDS) == {"state", "decision"}
    assert C.metadata_url("https://auth.example/tenant") == "https://auth.example/.well-known/oauth-authorization-server/tenant"
    assert C.metadata_url("http://127.0.0.1:9000") == "http://127.0.0.1:9000/.well-known/oauth-authorization-server"


def test_t2_the_playwright_step_says_what_is_missing(monkeypatch):
    import builtins
    real = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise ImportError(name)
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    with pytest.raises(C.GatewayError, match="Playwright is not installed"):
        C.playwright_consent("http://127.0.0.1:1/authorize", "http://127.0.0.1:2/callback")


def test_t3_no_check_runs_the_gate_tools():
    names = ("zuplo_client", "zuplo_upstream", "fake_zuplo_oauth")
    for path in [ROOT / "Makefile", *sorted((ROOT / ".github").rglob("*.yml"))]:
        text = path.read_text(encoding="utf-8")
        assert not any(name in text for name in names), path
    for name in names:
        source = (ROOT / "tests" / f"{name}.py").read_text(encoding="utf-8")
        assert "0.0.0.0" not in source, name  # the servers bind to loopback only
