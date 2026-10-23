"""O3 spec 6.3 and claim E7: the API client over scripted answers. Nothing here opens a socket: the opener, the
resolver and the clock are `FakeApi`'s (`tests/cli/fake_api.py`), and the client waits with the clock's `sleep`."""
from __future__ import annotations

import base64
import io
import json
import ssl

import pytest
from conftest import credential
from fake_api import PUBLIC_IP, FakeApi, FakeClock

from spellwarden_cli import api, net
from spellwarden_cli.secret import Secret

BASE = "https://dash.spellwarden.ai/api"
ORGS = "/api/v1/orgs"
AUDIENCE = "https://dash.spellwarden.ai/ci/acme"
SESSION = {"token": "", "expires_at": "2026-10-23T10:15:00Z", "org": {"slug": "acme", "name": "Acme", "plan": "team"},
           "run": {"identity": "github:github.com/acme/tools", "scope": "", "kind": "request", "event": "pull_request"}}


def build(base=BASE, key=None, **kwargs):
    clock = kwargs.pop("clock", None) or FakeClock()
    fake = FakeApi(clock)
    events: list[tuple[str, dict]] = []
    client = api.ApiClient(base, key, release="1.2.0", opener=kwargs.pop("opener", fake.opener),
                           resolver=kwargs.pop("resolver", fake.resolver), clock=clock,
                           on_event=lambda name, fields: events.append((name, fields)), **kwargs)
    return fake, clock, client, events


def unavailable(call, *args, **kwargs) -> api.ApiError:
    with pytest.raises(api.ApiError) as caught:
        call(*args, **kwargs)
    return caught.value


def test_https_only_and_public_addresses_for_the_api_origin():
    fake, _, client, _ = build("http://dash.spellwarden.ai/api")
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable" and fake.requests == []
    fake, _, client, _ = build(resolver=lambda _host: ["10.0.0.5"])
    error = unavailable(client.get, "/v1/orgs")
    assert error.code == "connected_unavailable" and fake.requests == []
    fake, _, client, _ = build(resolver=lambda _host: [PUBLIC_IP, "169.254.169.254"])
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable" and fake.requests == []
    # loopback HTTP only under the test hook, and only for a loopback host
    fake, _, client, _ = build("http://127.0.0.1:8123/api", loopback=True)
    fake.script("GET", ORGS, 200, {"orgs": []})
    assert client.get("/v1/orgs") == {"orgs": []}
    fake, _, client, _ = build("http://127.0.0.1:8123/api")
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable" and fake.requests == []
    fake, _, client, _ = build("http://dash.spellwarden.ai/api", loopback=True)
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable" and fake.requests == []


def test_the_api_origin_is_pinned_to_the_checked_address_and_keeps_the_host():
    seen: list[tuple] = []
    fake = FakeApi()

    def opener(host, ip, port, timeout, **options):
        seen.append((host, ip, port, options))
        return fake.opener(host, ip, port, timeout, **options)

    client = api.ApiClient(BASE, None, release="1.2.0", opener=opener, resolver=fake.resolver, clock=FakeClock())
    fake.script("GET", ORGS, 200, {})
    client.get("/v1/orgs")
    assert seen == [("dash.spellwarden.ai", PUBLIC_IP, 443, {})]
    assert fake.requests[0][2]["Host"] == "dash.spellwarden.ai"


def test_the_token_endpoint_allows_private_addresses_but_needs_https():
    fake = FakeApi()
    url = fake.token_endpoint(200, {"value": "provider.jwt"})
    private = lambda _host: ["10.1.2.3"]  # noqa: E731 -- a GitHub Enterprise Server instance on a private network
    token = api.github_id_token({}, Secret(url), Secret("rt"), AUDIENCE, opener=fake.opener, resolver=private,
                                clock=FakeClock())
    assert token.value == "provider.jwt"
    fake = FakeApi()
    fake.script("GET", "/idtoken", 200, {"value": "x"})
    error = unavailable(api.github_id_token, {}, Secret("http://token.actions.example/idtoken?api-version=2.0"),
                        Secret("rt"), AUDIENCE, opener=fake.opener, resolver=private, clock=FakeClock())
    assert error.code == "connected_unavailable" and fake.requests == []
    for refused in ("169.254.169.254", "fd00:ec2::254"):  # the cloud metadata addresses stay refused
        error = unavailable(api.github_id_token, {}, Secret(url), Secret("rt"), AUDIENCE, opener=fake.opener,
                            resolver=lambda _host, refused=refused: [refused], clock=FakeClock())
        assert error.code == "connected_unavailable" and fake.requests == []
    # loopback HTTP is honoured under the hook only
    fake = FakeApi()
    fake.script("GET", "/idtoken", 200, {"value": "loop.jwt"})
    loop = Secret("http://127.0.0.1:8124/idtoken?api-version=2.0")
    assert api.github_id_token({}, loop, Secret("rt"), AUDIENCE, opener=fake.opener, resolver=fake.resolver,
                               clock=FakeClock(), loopback=True).value == "loop.jwt"
    assert unavailable(api.github_id_token, {}, loop, Secret("rt"), AUDIENCE, opener=fake.opener,
                       resolver=fake.resolver, clock=FakeClock()).code == "connected_unavailable"


def test_no_redirect_is_followed():
    resolved: list[str] = []
    fake = FakeApi()

    def resolver(host):
        resolved.append(host)
        return fake.resolver(host)

    client = api.ApiClient(BASE, None, release="1.2.0", opener=fake.opener, resolver=resolver, clock=FakeClock())
    fake.script("GET", ORGS, 302, "", headers={"Location": "https://evil.example/steal"})
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable"
    assert resolved == ["dash.spellwarden.ai"] and len(fake.requests) == 1


def test_request_deadline_and_run_budget():
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 200, {}, delay=11.0)
    started = clock()
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable"
    assert clock() - started == api.REQUEST_TIMEOUT_SECONDS  # 10 s, not the 11 s the answer would have taken
    # P50: the budget is time inside requests and retry waits; 200 s of idle clock between requests is free
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 200, {"n": 1}, times=2)
    assert client.get("/v1/orgs") == {"n": 1}
    clock.advance(200.0)
    assert client.get("/v1/orgs") == {"n": 1}
    # 150 s spent inside requests make the next one connected_unavailable without a connection
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 200, {}, delay=9.0, times=30)
    for _ in range(16):  # 144 s
        client.get("/v1/orgs")
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable"  # 6 s left: the 9 s answer is cut at 6
    assert len(fake.requests) == 17
    error = unavailable(client.get, "/v1/orgs")
    assert error.code == "connected_unavailable" and len(fake.requests) == 17


def test_retry_waits_count_against_the_run_budget():
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 200, {}, delay=7.0, times=20)  # 140 s inside requests
    for _ in range(20):
        client.get("/v1/orgs")
    fake.script("GET", ORGS, 503, {})
    fake.script("GET", ORGS, 200, {"ok": 1}, delay=7.0)
    assert client.get("/v1/orgs") == {"ok": 1} and clock.slept == [2.0]  # 140 + the 2 s wait + 7 s: 149 s spent
    fake.script("GET", ORGS, 200, {}, delay=7.0)
    before = clock()
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable"
    assert clock() - before == 1.0  # one second was left: the request was cut there


def test_token_lifetime_limit():
    fake, clock, client, _ = build()
    fake.script("POST", "/api/public/ci/token", 201, {**SESSION, "token": credential("swt")})
    fake.script("GET", ORGS, 200, {"n": 1}, times=3)
    client.exchange("acme", Secret("provider.jwt"), {"scope": ""})
    clock.advance(839.0)
    assert client.get("/v1/orgs") == {"n": 1}
    assert client.token_age(clock) == pytest.approx(839.0)
    clock.advance(2.0)
    error = unavailable(client.get, "/v1/orgs")
    assert error.code == "connected_unavailable" and "fifteen minutes" in error.message
    assert len(fake.requests) == 2  # the exchange and one get; the late one never connected


def test_body_cap_2_mib():
    fake, _, client, _ = build()
    shell = b'{"pad":""}'
    fake.script("GET", ORGS, 200, b'{"pad":"' + b"a" * (api.RESPONSE_MAX - len(shell)) + b'"}')
    assert len(client.get("/v1/orgs")["pad"]) == api.RESPONSE_MAX - len(shell)
    fake.script("GET", ORGS, 200, b'{"pad":"' + b"a" * (api.RESPONSE_MAX - len(shell) + 1) + b'"}')
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable"


def test_retry_matrix():
    # a 429 is retried once after Retry-After
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 429, {"error": "rate_limited", "message": "slow down"}, headers={"Retry-After": "3"})
    fake.script("GET", ORGS, 200, {"ok": True})
    assert client.get("/v1/orgs") == {"ok": True} and clock.slept == [3.0] and len(fake.requests) == 2
    # capped at 20 seconds
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 429, {"error": "rate_limited"}, headers={"Retry-After": "3000"})
    fake.script("GET", ORGS, 200, {})
    client.get("/v1/orgs")
    assert clock.slept == [float(api.RETRY_AFTER_MAX)]
    # and by the time left in the budget: with 10 s left a 20 s wait is not taken at all
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 200, {}, delay=7.0, times=20)  # 140 s
    for _ in range(20):
        client.get("/v1/orgs")
    fake.script("GET", ORGS, 429, {"error": "rate_limited", "message": "later"}, headers={"Retry-After": "20"})
    assert unavailable(client.get, "/v1/orgs").code == "connected_rate_limited" and clock.slept == []
    # a second 429 is connected_rate_limited with the server's message
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 429, {"error": "rate_limited", "message": "A limit, not an outage"}, times=2)
    error = unavailable(client.get, "/v1/orgs")
    assert error.code == "connected_rate_limited" and error.message == "A limit, not an outage" and len(fake.requests) == 2
    # a 5xx is retried once after 2 s
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 503, {})
    fake.script("GET", ORGS, 200, {"ok": 1})
    assert client.get("/v1/orgs") == {"ok": 1} and clock.slept == [2.0]
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 500, {}, times=2)
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable" and len(fake.requests) == 2
    # a connection failure before the request was sent is retried once after 2 s
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 0, None)
    fake.script("GET", ORGS, 200, {"ok": 2})
    assert client.get("/v1/orgs") == {"ok": 2} and clock.slept == [2.0]
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 0, None, times=2)
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable" and clock.slept == [2.0]
    assert fake.requests == []  # both connections failed before a request was sent
    # a 4xx is never retried; neither is a timeout
    for status in (400, 401, 403, 404, 409):
        fake, clock, client, _ = build()
        fake.script("GET", ORGS, status, {"error": "x"}, times=2)
        unavailable(client.get, "/v1/orgs")
        assert len(fake.requests) == 1 and clock.slept == []
    fake, clock, client, _ = build()
    fake.script("GET", ORGS, 200, {}, delay=30.0, times=2)
    unavailable(client.get, "/v1/orgs")
    assert len(fake.requests) == 1 and clock.slept == []


def test_a_post_without_retry_is_retried_only_for_429_and_a_connection_failure_before_sending():
    path = "/api/v1/orgs/acme/ci/scans"
    fake, clock, client, _ = build()
    fake.script("POST", path, 200, {}, delay=30.0, times=2)  # a timed-out upload may still be running
    unavailable(client.post, "/v1/orgs/acme/ci/scans", {"a": 1}, retry=False)
    assert len(fake.requests) == 1 and clock.slept == []
    fake, clock, client, _ = build()
    fake.script("POST", path, 503, {}, times=2)
    unavailable(client.post, "/v1/orgs/acme/ci/scans", {"a": 1}, retry=False)
    assert len(fake.requests) == 1
    fake, clock, client, _ = build()
    fake.script("POST", path, 429, {"error": "rate_limited"}, headers={"Retry-After": "1"})
    fake.script("POST", path, 200, {"ok": 1})
    assert client.post("/v1/orgs/acme/ci/scans", {"a": 1}, retry=False) == {"ok": 1}
    fake, clock, client, _ = build()
    fake.script("POST", path, 0, None)
    fake.script("POST", path, 200, {"ok": 2})
    assert client.post("/v1/orgs/acme/ci/scans", {"a": 1}, retry=False) == {"ok": 2}
    fake, clock, client, _ = build()  # with retry (the default) a 5xx is retried
    fake.script("POST", path, 502, {})
    fake.script("POST", path, 200, {"ok": 3})
    assert client.post("/v1/orgs/acme/ci/scans", {"a": 1}) == {"ok": 3}


def test_headers():
    key = Secret(credential("swk"))
    fake, _, client, _ = build(key=key)
    fake.script("GET", ORGS, 200, {})
    fake.script("POST", "/api/v1/orgs/acme/ci/scans", 200, {})
    client.get("/v1/orgs", {"scanner": "1.2.0"})
    client.post("/v1/orgs/acme/ci/scans", {"x": 1})
    (get_method, get_path, get_headers, _), (_, _, post_headers, post_body) = fake.requests
    assert (get_method, get_path) == ("GET", f"{ORGS}?scanner=1.2.0")
    assert get_headers["Authorization"] == f"Bearer {key.value}" and get_headers["Accept"] == "application/json"
    assert get_headers["User-Agent"] == net.USER_AGENT and "Content-Type" not in get_headers
    assert post_headers["Content-Type"] == "application/json" and post_headers["Authorization"] == f"Bearer {key.value}"
    assert post_body == {"x": 1}
    # the exchange carries no Authorization, even from a client that holds a credential
    fake, _, client, _ = build(key=key)
    fake.script("POST", "/api/public/ci/token", 201, {**SESSION, "token": credential("swt")})
    client.exchange("acme", Secret("provider.jwt"), {"scope": ""})
    assert "Authorization" not in fake.requests[0][2] and fake.requests[0][2]["User-Agent"] == net.USER_AGENT
    # the token endpoint gets its own bearer and never the API credential
    fake = FakeApi()
    url = fake.token_endpoint(200, {"value": "provider.jwt"})
    api.github_id_token({}, Secret(url), Secret("runner-request-token"), AUDIENCE, opener=fake.opener,
                        resolver=fake.resolver, clock=FakeClock())
    assert fake.requests[0][2]["Authorization"] == "bearer runner-request-token"
    assert fake.requests[0][2]["Host"] == "token.actions.example"


STATUS_TABLE = [
    (400, "token_invalid", "connected_auth"), (400, "token_replayed", "connected_auth"),
    (401, "api_key_invalid", "connected_auth"), (401, "api_key_expired", "connected_auth"),
    (402, "subscription_required", "connected_subscription"),
    (403, "connection_not_found", "connected_auth"), (403, "repository_not_allowed", "connected_auth"),
    (403, "owner_changed", "connected_auth"), (403, "project_pending_approval", "connected_auth"),
    (403, "shape_mismatch", "connected_auth"), (403, "fork_pipeline_unsupported", "connected_auth"),
    (403, "audience_mismatch", "connected_auth"),
    (403, "ci_key_required", "connected_ci_key_required"),
    (403, "permission_denied", "connected_forbidden"), (403, "ci_credential_not_allowed", "connected_forbidden"),
    (403, "scope_mismatch", "connected_forbidden"),
    (404, "pack_not_found", "policy_not_found"), (404, "pack_version_not_found", "policy_not_found"),
    (404, "pack_not_allowed", "policy_not_found"),
    (404, "org_not_found", "connected_auth"), (404, "not_found", "connected_unavailable"),
    (409, "scope_limit", "connected_auth"),
    (500, "internal", "connected_unavailable"), (503, "unavailable", "connected_unavailable"),
    (302, "", "connected_unavailable"),
]


@pytest.mark.parametrize(("status", "server_code", "expected"), STATUS_TABLE)
def test_error_mapping_table(status, server_code, expected):
    fake, _, client, _ = build()
    body = {"error": server_code, "message": f"server says {server_code}", "request_id": "req-1"}
    fake.script("GET", ORGS, status, body, times=2, headers={"Location": "https://dash.spellwarden.ai/elsewhere"}
                if status == 302 else None)
    error = unavailable(client.get, "/v1/orgs")
    assert error.code == expected and error.status == status
    if status < 300 or status >= 400:
        assert error.request_id == "req-1" and error.body == body
    if expected not in ("connected_unavailable",):
        assert error.message == f"server says {server_code}"


def test_a_missing_route_is_connected_unavailable_with_the_invariant_11_message():
    fake, _, client, _ = build()
    fake.script("GET", ORGS, 404, {"error": "not_found", "message": "No such route"})
    error = unavailable(client.get, "/v1/orgs")
    assert error.code == "connected_unavailable" and error.message == "Connected mode is not available yet on this server"


@pytest.mark.parametrize("body", [b"<html>nope</html>", b"[1, 2]", b'"text"', b"\xff\xfe"])
def test_an_unparseable_or_non_object_success_body_is_connected_unavailable(body):
    fake, _, client, _ = build()
    fake.script("GET", ORGS, 200, body)
    assert unavailable(client.get, "/v1/orgs").code == "connected_unavailable"


def test_an_error_body_that_is_not_json_still_maps_by_status():
    fake, _, client, _ = build()
    fake.script("GET", ORGS, 402, b"payment required")
    assert unavailable(client.get, "/v1/orgs").code == "connected_subscription"
    fake, _, client, _ = build()
    fake.script("GET", ORGS, 401, b"")
    assert unavailable(client.get, "/v1/orgs").code == "connected_auth"


def test_exchange_sends_schema_org_token_and_client_and_sets_the_credential():
    fake, _, client, _ = build()
    swt = credential("swt")
    fake.script("POST", "/api/public/ci/token", 201, {**SESSION, "token": swt})
    fake.script("GET", ORGS, 200, {"orgs": []})
    client_fields = {"scope": "services/agent", "request_number": 7, "head_sha": "a" * 40, "default_branch": "main"}
    session = client.exchange("acme", Secret("provider.jwt"), client_fields)
    method, path, _, body = fake.requests[0]
    assert (method, path) == ("POST", "/api/public/ci/token")
    assert body == {"schema": 1, "org": "acme", "token": "provider.jwt", "client": client_fields}
    assert isinstance(session, api.Session) and session.token == Secret(swt) and session.credential == "oidc"
    assert session.expires_at == SESSION["expires_at"] and session.org["slug"] == "acme"
    assert session.run == SESSION["run"]
    client.get("/v1/orgs")
    assert fake.requests[1][2]["Authorization"] == f"Bearer {swt}"
    assert swt not in repr(session) and swt not in repr(client)


def test_the_exchange_is_not_retried_after_a_server_error():
    fake, clock, client, _ = build()  # the first try may have consumed the provider token's jti
    fake.script("POST", "/api/public/ci/token", 503, {}, times=2)
    assert unavailable(client.exchange, "acme", Secret("provider.jwt"), {"scope": ""}).code == "connected_unavailable"
    assert len(fake.requests) == 1 and clock.slept == []


@pytest.mark.parametrize("answer", [{}, {"token": "not-a-ci-token", "expires_at": "x", "org": {}},
                                    {"token": "swt_" + "a" * 40, "expires_at": "x"}])
def test_an_exchange_answer_that_is_not_a_session_is_connected_unavailable(answer):
    fake, _, client, _ = build()
    fake.script("POST", "/api/public/ci/token", 201, answer)
    assert unavailable(client.exchange, "acme", Secret("provider.jwt"), {"scope": ""}).code == "connected_unavailable"


def test_github_id_token_request():
    fake = FakeApi()
    url = fake.token_endpoint(200, {"value": "provider.jwt", "count": 1})
    token = api.github_id_token({}, Secret(url), Secret("runner-token"), AUDIENCE, opener=fake.opener,
                                resolver=fake.resolver, clock=FakeClock())
    assert isinstance(token, Secret) and token.value == "provider.jwt"
    method, path, headers, _ = fake.requests[0]
    assert (method, path) == ("GET", "/idtoken?api-version=2.0&audience=https://dash.spellwarden.ai/ci/acme")
    assert headers["Authorization"] == "bearer runner-token" and headers["User-Agent"] == net.USER_AGENT
    # a URL without a query gets one
    fake = FakeApi()
    fake.script("GET", "/plain", 200, {"value": "p.jwt"})
    api.github_id_token({}, Secret("https://token.actions.example/plain"), Secret("t"), AUDIENCE, opener=fake.opener,
                        resolver=fake.resolver, clock=FakeClock())
    assert fake.requests[0][1] == "/plain?audience=https://dash.spellwarden.ai/ci/acme"


@pytest.mark.parametrize(("status", "body"), [(403, {"message": "no"}), (500, {}), (200, {}), (200, {"value": ""}),
                                              (200, {"value": 7}), (302, "")])
def test_a_failing_token_request_is_connected_unavailable_and_names_no_url(status, body):
    fake = FakeApi()
    url = fake.token_endpoint(status, body)
    error = unavailable(api.github_id_token, {}, Secret(url), Secret("runner-token"), AUDIENCE, opener=fake.opener,
                        resolver=fake.resolver, clock=FakeClock())
    assert error.code == "connected_unavailable" and "idtoken" not in error.message and "runner-token" not in error.message


def test_proxy_for_reads_the_environment():
    env = {"HTTPS_PROXY": "http://user:p%40ss@proxy.corp:3128"}
    proxy = api.proxy_for(env, "dash.spellwarden.ai")
    assert proxy == api.ProxyConfig("proxy.corp", 3128, Secret("user:p@ss"))
    assert api.proxy_for({"https_proxy": "http://proxy.corp:8080"}, "x.example") == api.ProxyConfig("proxy.corp", 8080, None)
    assert api.proxy_for({"https_proxy": "proxy.corp:8080"}, "x.example") == api.ProxyConfig("proxy.corp", 8080, None)
    assert api.proxy_for({"HTTPS_PROXY": "http://proxy.corp"}, "x.example").port == 80
    assert api.proxy_for({}, "dash.spellwarden.ai") is None
    assert api.proxy_for({"HTTPS_PROXY": ""}, "dash.spellwarden.ai") is None
    assert api.proxy_for({"HTTPS_PROXY": "socks5://proxy.corp:1080"}, "dash.spellwarden.ai") is None  # not a proxy we speak to
    for no_proxy in ("dash.spellwarden.ai", ".spellwarden.ai", "spellwarden.ai", "*", "other.example, .spellwarden.ai",
                     "*.spellwarden.ai", "DASH.SPELLWARDEN.AI"):
        assert api.proxy_for({**env, "NO_PROXY": no_proxy}, "dash.spellwarden.ai") is None, no_proxy
        assert api.proxy_for({**env, "no_proxy": no_proxy}, "dash.spellwarden.ai") is None, no_proxy
    assert api.proxy_for({**env, "NO_PROXY": "other.example,10.0.0.0/8"}, "dash.spellwarden.ai") is not None
    assert api.proxy_for({**env, "NO_PROXY": "10.0.0.0/8"}, "10.1.2.3") is None
    assert "p@ss" not in repr(proxy)  # the password is a Secret


def test_a_proxy_is_used_for_the_api_origin_and_the_token_endpoint_without_checking_the_proxy_or_resolving_the_target():
    proxy = api.ProxyConfig("proxy.corp", 3128, Secret("user:pw"))
    resolved: list[str] = []
    calls: list[tuple] = []
    fake = FakeApi()

    def opener(host, ip, port, timeout, **options):
        calls.append((host, ip, port, options))
        return fake.opener(host, ip, port, timeout, **options)

    def resolver(host):
        resolved.append(host)
        return ["10.9.9.9"]  # the proxy's own network: would be refused as a target, is not checked as a proxy

    client = api.ApiClient(BASE, None, release="1.2.0", opener=opener, resolver=resolver, clock=FakeClock(), proxy=proxy)
    fake.script("GET", ORGS, 200, {"ok": 1})
    assert client.get("/v1/orgs") == {"ok": 1}
    assert calls == [("dash.spellwarden.ai", None, 443, {"proxy": proxy})] and resolved == []
    url = fake.token_endpoint(200, {"value": "provider.jwt"})
    token = api.github_id_token({}, Secret(url), Secret("t"), AUDIENCE, opener=opener, resolver=resolver,
                                clock=FakeClock(), proxy=proxy)
    assert token.value == "provider.jwt" and calls[1][3] == {"proxy": proxy} and resolved == []
    # the environment is the fallback of the token request, with NO_PROXY honoured
    url = fake.token_endpoint(200, {"value": "provider.jwt"})
    github = api.github_id_token({"HTTPS_PROXY": "http://proxy.corp:3128", "NO_PROXY": "token.actions.example"},
                                 Secret(url), Secret("t"), AUDIENCE, opener=opener, resolver=fake.resolver, clock=FakeClock())
    assert github.value == "provider.jwt" and calls[2][3] == {} and calls[2][1] == PUBLIC_IP


class _FakeSocket:
    def __init__(self) -> None:
        self.sent = b""
        self.timeout = None

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def makefile(self, _mode: str = "rb", *_args, **_kwargs):
        return io.BytesIO(b"HTTP/1.1 200 Connection established\r\n\r\n")

    def settimeout(self, seconds) -> None:
        self.timeout = seconds

    def setsockopt(self, *_args) -> None:
        return None

    def close(self) -> None:
        return None


class _FakeTls:
    # the attributes http.client.HTTPSConnection reads from a context on Python 3.11
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True
    post_handshake_auth = None

    def __init__(self) -> None:
        self.wrapped: list[tuple] = []

    def wrap_socket(self, sock, server_hostname=None, **_kwargs):
        self.wrapped.append((sock, server_hostname))
        return sock


def test_proxy_connect_and_tls_to_target(monkeypatch):
    plain = _FakeSocket()
    dialled: list[tuple] = []
    monkeypatch.setattr(api.socket, "create_connection", lambda address, *_a, **_k: (dialled.append(address), plain)[1])
    tls = _FakeTls()
    proxy = api.ProxyConfig("proxy.corp", 3128, Secret("user:pw"))
    connection = api.tunnel_connection("dash.spellwarden.ai", 443, proxy, 10.0, context=tls)
    connection.connect()
    assert dialled == [("proxy.corp", 3128)]  # the proxy by name: its address is not pinned or checked
    first_line = plain.sent.split(b"\r\n", 1)[0]
    # the protocol version of the request line is the standard library's: HTTP/1.0 up to Python 3.11, HTTP/1.1 after
    assert first_line in (b"CONNECT dash.spellwarden.ai:443 HTTP/1.0", b"CONNECT dash.spellwarden.ai:443 HTTP/1.1")
    assert b"Proxy-Authorization: Basic " + base64.b64encode(b"user:pw") in plain.sent
    assert tls.wrapped == [(plain, "dash.spellwarden.ai")]  # TLS is verified against the target, end to end
    no_auth = _FakeSocket()
    monkeypatch.setattr(api.socket, "create_connection", lambda *_a, **_k: no_auth)
    api.tunnel_connection("dash.spellwarden.ai", 443, api.ProxyConfig("proxy.corp", 3128, None), 10.0,
                          context=_FakeTls()).connect()
    assert b"Proxy-Authorization" not in no_auth.sent


def test_the_default_opener_builds_a_pinned_tls_connection_a_tunnel_or_a_plain_loopback_one():
    direct = api.open_connection("dash.spellwarden.ai", PUBLIC_IP, 443, 10.0)
    assert direct.host == "dash.spellwarden.ai" and direct.pinned_ip == PUBLIC_IP
    tunnel = api.open_connection("dash.spellwarden.ai", None, 443, 10.0, proxy=api.ProxyConfig("p.corp", 3128, None))
    assert (tunnel.host, tunnel.port) == ("p.corp", 3128) and tunnel._tunnel_host == "dash.spellwarden.ai"
    loop = api.open_connection("127.0.0.1", "127.0.0.1", 8123, 10.0, tls=False)
    assert (loop.host, loop.port) == ("127.0.0.1", 8123)


@pytest.mark.parametrize(("raw", "expected"), [
    ("http://127.0.0.1:8123/api", ("http://127.0.0.1:8123/api", True)),
    ("http://[::1]:8123/api", ("http://[::1]:8123/api", True)),
    ("http://localhost:8123/api", ("http://127.0.0.1:8123/api", True)),
    ("http://localhost:8123/", ("http://127.0.0.1:8123/", True)),
])
def test_api_url_rule_honours_loopback_http(raw, expected):
    lines: list[str] = []
    assert api.api_url({"SPELLWARDEN_API_URL": raw}, lines.append) == expected and lines == []


@pytest.mark.parametrize("raw", ["https://example.com/api", "http://169.254.169.254/", "http://10.0.0.1/api",
                                 "http://localhost.example.com:80/", "http://127.0.0.1/", "http://127.0.0.1:0/",
                                 "http://127.0.0.1:8123@evil.example/", "http://127.0.0.1:8123/?next=x",
                                 "http://127.0.0.1:99999/", "ftp://127.0.0.1:21/"])
def test_api_url_rule_ignores_everything_else_with_a_verbose_line(raw):
    lines: list[str] = []
    assert api.api_url({"SPELLWARDEN_API_URL": raw}, lines.append) == (api.DEFAULT_API_URL, False)
    assert lines == ["SPELLWARDEN_API_URL ignored: it is honoured for loopback HTTP only (127.0.0.1, [::1] or localhost)"]


def test_api_url_default_when_unset_or_empty():
    lines: list[str] = []
    assert api.api_url({}, lines.append) == (api.DEFAULT_API_URL, False)
    assert api.api_url({"SPELLWARDEN_API_URL": ""}, lines.append) == (api.DEFAULT_API_URL, False) and lines == []
    assert api.DEFAULT_API_URL == "https://dash.spellwarden.ai/api"


def test_audience_is_per_organisation():
    assert api.audience_for("acme") == AUDIENCE


def test_no_credential_in_repr_or_events():
    swk, swt, provider = credential("swk"), credential("swt"), "provider-" + "p" * 20
    fake, _, client, events = build(key=Secret(swk))
    fake.script("POST", "/api/public/ci/token", 201, {**SESSION, "token": swt})
    fake.script("GET", ORGS, 200, {})
    fake.script("GET", ORGS, 503, {"error": "internal", "message": "boom"}, times=2)
    session = client.exchange("acme", Secret(provider), {"scope": ""})
    client.get("/v1/orgs")
    error = unavailable(client.get, "/v1/orgs")
    everything = json.dumps(events) + repr(client) + repr(session) + repr(error) + str(error)
    for secret in (swk, swt, provider):
        assert secret not in everything
    assert events and events[0][0] == "api_request" and {"host", "method", "status", "ms", "path"} <= set(events[0][1])
    assert events[0][1]["path"] == "/public/ci/token" and "?" not in json.dumps(events)


def test_the_module_constants():
    assert (api.RUN_BUDGET_SECONDS, api.REQUEST_TIMEOUT_SECONDS, api.RESPONSE_MAX, api.RETRY_AFTER_MAX) == (
        150.0, 10.0, 2 * 1024 * 1024, 20)
