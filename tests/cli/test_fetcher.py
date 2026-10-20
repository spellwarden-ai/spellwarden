"""Spec 6.8 and claim C14 (ported from the hosted backend's N1 tests, `code/backend/tests/test_net.py` at `b83c500`):
every request goes to a checked address over HTTPS, with at most 5 re-checked redirects, a byte cap enforced while
reading, a deadline, and never an Authorization header. No socket is opened here: the opener, the resolver and the
clock are injected. The edits to the ported file are the import, the `Net` helper's new parameters, the clock seam
of the drip test and the `on_event` test that replaces the backend's log test."""
from __future__ import annotations

import json
import time

import pytest

from spellwarden_cli import net
from spellwarden_cli.net import FetchError, Fetcher

PUBLIC_IP = "8.8.8.8"


class ScriptedConnection:
    """What the real `pinned_connection` returns, scripted: `answers` maps
    `(host, path)` to `(status, headers, body)`; `body` may be a list of chunks."""

    def __init__(self, host, ip, port, timeout, answers, calls):
        self.host, self.ip, self.port, self.timeout = host, ip, port, timeout
        self._answers, self._calls = answers, calls
        self._pending = None

    def request(self, method, path, body=None, headers=None):
        self._calls.append({"method": method, "host": self.host, "ip": self.ip, "path": path, "body": body,
                            "headers": dict(headers or {})})
        bare = path.split("?", 1)[0]  # an answer may be scripted with or without the query string
        self._pending = self._answers.get((self.host, path)) or self._answers.get((self.host, bare), (404, {}, b"not scripted"))

    def getresponse(self):
        status, headers, body = self._pending
        chunks = list(body) if isinstance(body, list) else [body]
        return (getattr(self, "response_class", None) or ScriptedResponse)(status, headers, chunks)

    def close(self):
        pass


class ScriptedResponse:
    def __init__(self, status, headers, chunks):
        self.status = status
        self._headers = headers
        self._chunks = chunks

    def getheaders(self):
        return list(self._headers.items())

    def read(self, amt=None):
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if amt is not None and len(chunk) > amt:
            self._chunks.insert(0, chunk[amt:])
            return chunk[:amt]
        return chunk

    def read1(self, amt=None):  # what `http.client.HTTPResponse` offers: at most one read of the stream
        return self.read(amt)


class Net:
    """A `Fetcher` over scripted answers and a scripted resolver."""

    def __init__(self, answers=None, addresses=None, response_class=None, clock=None, allow_private=False):
        self.calls: list[dict] = []
        self.events: list[tuple[str, dict]] = []
        self.resolved: list[str] = []
        self._addresses = addresses or {}

        def resolver(host):
            self.resolved.append(host)
            return self._addresses.get(host, [PUBLIC_IP])

        def opener(host, ip, port, timeout):
            connection = ScriptedConnection(host, ip, port, timeout, answers or {}, self.calls)
            connection.response_class = response_class  # a test may script how the body is read (an open stream, for one)
            return connection

        # The backend's adapter sends this exact header (spec 8.1); the public default names the scanner version.
        self.fetcher = Fetcher(release="test-release", resolver=resolver, opener=opener, clock=clock,
                               allow_private=allow_private, user_agent="Spellwarden/test-release (+https://spellwarden.ai)",
                               on_event=lambda name, fields: self.events.append((name, fields)))


def test_a_non_https_url_is_refused_before_any_lookup():
    net_ = Net()
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get("http://example.com/a.zip", max_bytes=100)
    assert caught.value.code == "not_https"
    assert net_.resolved == [] and net_.calls == []


@pytest.mark.parametrize("host", ["localhost", "db.local", "api.internal", "me.localhost", "LOCALHOST"])
def test_local_names_are_refused_without_a_lookup(host):
    net_ = Net()
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get(f"https://{host}/x", max_bytes=100)
    assert caught.value.code == "private_address"
    assert net_.resolved == []


@pytest.mark.parametrize("literal", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "[::1]", "[fd00::1]",
                                     "[::ffff:10.0.0.1]", "192.168.1.1", "172.16.0.9", "0.0.0.0", "[fe80::1]", "224.0.0.1"])
def test_private_literals_are_refused(literal):
    net_ = Net()
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get(f"https://{literal}/x", max_bytes=100)
    assert caught.value.code == "private_address"
    assert net_.calls == []


def test_a_name_resolving_to_a_private_address_is_refused():
    net_ = Net(addresses={"evil.example": [PUBLIC_IP, "10.0.0.1"]})
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get("https://evil.example/x", max_bytes=100)
    assert caught.value.code == "private_address"
    assert net_.resolved == ["evil.example"] and net_.calls == []


def test_is_private_address_table():
    for ip in ("127.0.0.1", "10.1.2.3", "172.31.0.1", "192.168.0.1", "169.254.1.1", "100.64.0.1", "100.127.255.254",
               "224.0.0.1", "240.0.0.1", "0.0.0.0", "::1", "fd12::1", "fe80::1", "::ffff:192.168.0.1", "::", "not an ip",
               "203.0.113.10", "198.51.100.1", "192.0.2.1"):  # the TEST-NET ranges are documentation space, refused too
        assert net.is_private_address(ip), ip
    for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "100.128.0.1", "2606:4700::1111"):
        assert not net.is_private_address(ip), ip


def test_a_public_host_is_fetched_at_its_checked_address_with_the_spellwarden_headers():
    net_ = Net(answers={("files.example", "/a.zip?x=1"): (200, {"Content-Type": "application/zip"}, b"PK...")})
    response = net_.fetcher.get("https://files.example/a.zip?x=1", max_bytes=100, accept="application/zip")
    assert (response.status, response.body, response.url) == (200, b"PK...", "https://files.example/a.zip?x=1")
    assert response.header("content-type") == "application/zip"
    call = net_.calls[0]
    assert (call["host"], call["ip"], call["path"], call["method"]) == ("files.example", PUBLIC_IP, "/a.zip?x=1", "GET")
    assert call["headers"]["User-Agent"] == "Spellwarden/test-release (+https://spellwarden.ai)"
    assert call["headers"]["Accept"] == "application/zip"
    assert "Authorization" not in call["headers"] and "Cookie" not in call["headers"]


def test_a_redirect_is_followed_and_re_checked():
    net_ = Net(
        answers={
            ("a.example", "/one"): (302, {"Location": "https://b.example/two"}, b""),
            ("b.example", "/two"): (200, {}, b"done"),
        },
        addresses={"a.example": ["1.1.1.1"], "b.example": ["9.9.9.9"]},
    )
    response = net_.fetcher.get("https://a.example/one", max_bytes=100)
    assert response.body == b"done" and response.url == "https://b.example/two"
    assert net_.resolved == ["a.example", "b.example"]
    assert [call["ip"] for call in net_.calls] == ["1.1.1.1", "9.9.9.9"]


def test_a_cross_origin_redirect_drops_the_mcp_headers_and_a_same_origin_one_keeps_them():
    net_ = Net(answers={
        ("a.example", "/one"): (302, {"Location": "https://b.example/two"}, b""),
        ("b.example", "/two"): (200, {}, b"done"),
        ("a.example", "/same"): (302, {"Location": "https://a.example/same2"}, b""),
        ("a.example", "/same2"): (200, {}, b"same"),
    })
    sent = {"Mcp-Session-Id": "sess", "MCP-Protocol-Version": "2026-07-28", "Mcp-Name": "probe", "X-Other": "kept"}
    assert net_.fetcher.get("https://a.example/one", max_bytes=100, headers=sent).body == b"done"
    first, second = net_.calls[0]["headers"], net_.calls[1]["headers"]
    assert first["Mcp-Session-Id"] == "sess" and first["Mcp-Name"] == "probe"
    assert not any(name.lower().startswith("mcp") for name in second) and second["X-Other"] == "kept"
    net_.calls.clear()
    assert net_.fetcher.get("https://a.example/same", max_bytes=100, headers=sent).body == b"same"
    assert net_.calls[1]["headers"]["Mcp-Session-Id"] == "sess"


def test_a_post_never_follows_a_redirect():
    net_ = Net(answers={("mcp.example", "/mcp"): (307, {"Location": "https://other.example/mcp"}, b""),
                        ("other.example", "/mcp"): (200, {}, b"should not be reached")})
    response = net_.fetcher.post_json("https://mcp.example/mcp", {"jsonrpc": "2.0"}, {"Mcp-Session-Id": "sess"})
    assert response.status == 307 and response.header("location") == "https://other.example/mcp"
    assert [call["host"] for call in net_.calls] == ["mcp.example"]


def test_a_redirect_to_a_private_address_or_plain_http_is_refused():
    net_ = Net(answers={("a.example", "/p"): (301, {"Location": "https://169.254.169.254/latest"}, b""),
                        ("a.example", "/h"): (301, {"Location": "http://a.example/h2"}, b"")})
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get("https://a.example/p", max_bytes=100)
    assert caught.value.code == "private_address"
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get("https://a.example/h", max_bytes=100)
    assert caught.value.code == "not_https"


def test_more_than_five_redirects_are_refused():
    answers = {("a.example", f"/r{i}"): (302, {"Location": f"https://a.example/r{i + 1}"}, b"") for i in range(7)}
    net_ = Net(answers=answers)
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get("https://a.example/r0", max_bytes=100)
    assert caught.value.code == "too_many_redirects"
    assert len(net_.calls) == net.MAX_REDIRECTS + 1


def test_the_byte_cap_is_enforced_while_reading():
    net_ = Net(answers={("a.example", "/big"): (200, {}, [b"x" * 60, b"y" * 60, b"z" * 60])})
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get("https://a.example/big", max_bytes=100)
    assert caught.value.code == "too_large"
    ok = Net(answers={("a.example", "/big"): (200, {}, [b"x" * 60, b"y" * 30])})
    assert len(ok.fetcher.get("https://a.example/big", max_bytes=100).body) == 90


def test_post_json_sends_json_and_the_given_headers_but_never_authorization():
    net_ = Net(answers={("mcp.example", "/mcp"): (200, {"Content-Type": "application/json"}, b'{"ok": true}')})
    response = net_.fetcher.post_json("https://mcp.example/mcp", {"jsonrpc": "2.0"},
                                      {"Mcp-Method": "server/discover", "Authorization": "Bearer x", "cookie": "a=b"})
    assert json.loads(response.body) == {"ok": True}
    call = net_.calls[0]
    assert call["method"] == "POST" and json.loads(call["body"]) == {"jsonrpc": "2.0"}
    assert call["headers"]["Content-Type"] == "application/json"
    assert call["headers"]["Mcp-Method"] == "server/discover"
    assert not any(name.lower() in ("authorization", "cookie") for name in call["headers"])


def test_get_stream_head_reads_at_most_4096_bytes():
    net_ = Net(answers={("sse.example", "/events"): (200, {"Content-Type": "text/event-stream"},
                                                      [b"event: endpoint\n" + b"d" * 5000, b"more"])})
    response = net_.fetcher.get_stream_head("https://sse.example/events")
    assert response.status == 200 and len(response.body) == net.STREAM_HEAD_MAX
    assert response.body.startswith(b"event: endpoint")
    assert net_.calls[0]["headers"]["Accept"] == "text/event-stream"


def test_a_stream_head_never_asks_for_more_than_its_cap():
    """An SSE stream stays open: a read of 64 KiB would block until the timeout. The head reader asks for
    at most what is left of `STREAM_HEAD_MAX` and stops exactly there, with the stream still open."""
    asked: list[int] = []

    class OpenStream(ScriptedResponse):
        def read(self, amt=None):  # a full read would block: the head reader must never call it
            raise AssertionError("read() on an open stream")

        def read1(self, amt=None):
            asked.append(amt)
            assert amt is not None and amt <= net.STREAM_HEAD_MAX
            return b"d" * amt  # never ends, like a real event stream

    net_ = Net(answers={("sse.example", "/events"): (200, {"Content-Type": "text/event-stream"}, b"")}, response_class=OpenStream)
    response = net_.fetcher.get_stream_head("https://sse.example/events")
    assert len(response.body) == net.STREAM_HEAD_MAX and sum(asked) == net.STREAM_HEAD_MAX


def test_an_event_stream_answer_stops_at_the_first_event_whatever_the_method():
    """A POST answered with `text/event-stream` (a streamed JSON-RPC answer, spec 6.6 step 2) is read as a head:
    `read1` for what arrived, stopped at the first blank line, never the 1 MiB body path that would wait."""
    first = b'event: message\ndata: {"jsonrpc": "2.0", "id": 1, "result": {}}\n\n'

    class OneEventThenOpen(ScriptedResponse):
        def read(self, amt=None):
            raise AssertionError("read() on an open stream")

        def read1(self, amt=None):
            if self._chunks:
                return self._chunks.pop(0)
            raise AssertionError("a second read would block on the open stream")

    net_ = Net(answers={("mcp.example", "/mcp"): (200, {"Content-Type": "text/event-stream"}, [first])},
               response_class=OneEventThenOpen)
    response = net_.fetcher.post_json("https://mcp.example/mcp", {"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, {})
    assert response.status == 200 and response.body == first


def test_an_event_boundary_split_across_reads_or_spelled_crlf_ends_the_head_and_a_smaller_cap_holds():
    """The blank line that ends an event may arrive in two reads, or as `\\r\\n\\r\\n`: the head reader sees both and
    never reads on into the open stream. A caller's cap below `STREAM_HEAD_MAX` holds for a stream too."""
    split = [b"event: endpoint\ndata: /messages\n", b"\n", b"event: never\n"]
    crlf = [b"event: endpoint\r\ndata: /messages\r\n\r\n", b"event: never\r\n"]
    net_ = Net(answers={("sse.example", "/split"): (200, {"Content-Type": "text/event-stream"}, list(split)),
                        ("sse.example", "/crlf"): (200, {"Content-Type": "text/event-stream"}, list(crlf)),
                        ("sse.example", "/long"): (200, {"Content-Type": "text/event-stream"}, [b"d" * net.STREAM_HEAD_MAX])})
    assert net_.fetcher.get_stream_head("https://sse.example/split").body == b"".join(split[:2])
    assert net_.fetcher.get_stream_head("https://sse.example/crlf").body == crlf[0]
    capped = net_.fetcher.post_json("https://sse.example/long", {"jsonrpc": "2.0", "id": 1, "method": "ping"}, {}, max_bytes=64)
    assert len(capped.body) == 64


def test_a_malformed_redirect_is_fetch_failed_and_a_body_is_read_one_byte_past_its_cap():
    net_ = Net(answers={("a.example", "/x"): (302, {"Location": "https://b.example:99999/y"}, b""),
                        ("a.example", "/exact"): (200, {}, [b"12345", b""])})
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get("https://a.example/x", max_bytes=10)
    assert caught.value.code == "fetch_failed"
    assert net_.fetcher.get("https://a.example/exact", max_bytes=5).body == b"12345"  # exactly the cap is not too large


def test_caller_headers_never_override_host_or_the_json_rpc_content_headers():
    net_ = Net(answers={("mcp.example", "/mcp"): (200, {"Content-Type": "application/json"}, b"{}")})
    net_.fetcher.post_json("https://mcp.example/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                           {"Host": "evil.example", "content-type": "text/plain", "accept": "text/html", "Mcp-Name": "probe",
                            "Transfer-Encoding": "chunked", "User-Agent": "other"})
    sent = net_.calls[0]["headers"]
    assert "Host" not in sent and "Transfer-Encoding" not in sent
    assert sent["Content-Type"] == "application/json" and sent["Accept"] == "application/json, text/event-stream"
    assert [name for name in sent if name.lower() in ("content-type", "accept")] == ["Content-Type", "Accept"]  # one of each
    assert sent["Mcp-Name"] == "probe" and sent["User-Agent"].startswith("Spellwarden/")


def test_a_server_that_drips_bytes_hits_the_request_deadline():
    """Run-2 review r0:F4: `TIMEOUT_SECONDS` bounds the whole request, not each read: a body that arrives one byte
    at a time, each inside the socket timeout, ends `fetch_failed` once the deadline passes. The deadline clock is
    the `clock` the fetcher was given (spec 6.8)."""
    clock = [0.0]

    class Drip(ScriptedResponse):
        def read(self, amt=None):
            clock[0] += 4.0  # every byte arrives within the socket timeout; the whole never does
            return b"x"

        def read1(self, amt=None):
            return self.read(amt)

    for get in (lambda f: f.get("https://slow.example/mcp", max_bytes=1000), lambda f: f.get_stream_head("https://slow.example/mcp")):
        clock[0] = 0.0
        net_ = Net(answers={("slow.example", "/mcp"): (200, {"Content-Type": "application/json"}, b"")}, response_class=Drip,
                   clock=lambda: clock[0])
        with pytest.raises(net.FetchError) as caught:
            get(net_.fetcher)
        assert caught.value.code == "fetch_failed" and clock[0] <= net.TIMEOUT_SECONDS + 4.0


def test_the_watchdog_ends_a_read_that_blocks_inside_one_call():
    """Security review of 1899753: a single `read` may span many receives, each within the socket timeout; the
    watchdog shuts the socket at the deadline whatever call is blocked."""
    import threading as _threading

    shut = _threading.Event()

    class Sock:
        def settimeout(self, seconds):
            pass

        def shutdown(self, how):
            shut.set()

    class Blocking(ScriptedResponse):
        def read(self, amt=None):
            if not shut.wait(5):
                raise AssertionError("the watchdog never fired")
            raise OSError("socket shut down")

    net_ = Net(answers={("slow.example", "/mcp"): (200, {"Content-Type": "application/json"}, b"")}, response_class=Blocking)
    original = net_.fetcher._opener

    def opener(host, ip, port, timeout):
        connection = original(host, ip, port, timeout)
        connection.sock = Sock()
        return connection

    net_.fetcher._opener = opener
    net_.fetcher._timeout = 0.2
    started = time.monotonic()
    with pytest.raises(net.FetchError) as caught:
        net_.fetcher.get("https://slow.example/mcp", max_bytes=1000)
    assert (caught.value.code, caught.value.detail) == ("fetch_failed", "deadline") and time.monotonic() - started < 2


def test_a_transport_failure_is_fetch_failed():
    def opener(host, ip, port, timeout):  # noqa: ARG001
        raise OSError("connection refused")

    fetcher = Fetcher(resolver=lambda host: [PUBLIC_IP], opener=opener)
    with pytest.raises(FetchError) as caught:
        fetcher.get("https://a.example/x", max_bytes=10)
    assert caught.value.code == "fetch_failed"


def test_a_non_2xx_status_is_an_answer_not_an_error():
    net_ = Net(answers={("mcp.example", "/mcp"): (401, {"WWW-Authenticate": 'Bearer resource_metadata="https://mcp.example/.well-known/oauth-protected-resource"'}, b"")})
    response = net_.fetcher.post_json("https://mcp.example/mcp", {}, {})
    assert response.status == 401 and response.header("www-authenticate").startswith("Bearer ")


def test_a_request_is_reported_through_on_event_without_its_body():
    net_ = Net(answers={("a.example", "/secret"): (200, {}, b"the body")})
    net_.fetcher.get("https://a.example/secret?token=abc", max_bytes=100)
    (name, fields), = net_.events
    assert name == "net_request" and sorted(fields) == ["bytes", "host", "method", "ms", "status"]
    assert (fields["host"], fields["method"], fields["status"], fields["bytes"]) == ("a.example", "GET", 200, 8)
    assert "the body" not in repr(fields) and "abc" not in repr(fields)


def test_the_default_user_agent_names_the_scanner_version():
    from spellwarden_cli import __version__

    calls: list[dict] = []
    fetcher = Fetcher(resolver=lambda _host: [PUBLIC_IP],
                      opener=lambda host, ip, port, timeout: ScriptedConnection(host, ip, port, timeout, {}, calls))
    fetcher.get("https://a.example/x", max_bytes=100)
    assert calls[0]["headers"]["User-Agent"] == f"Spellwarden/{__version__} (+https://spellwarden.ai)"


@pytest.mark.parametrize("literal", ["10.0.0.1", "127.0.0.1", "[fd00::1]"])
def test_allow_private_lets_a_private_address_through_and_nothing_else(literal):
    net_ = Net(answers={(literal.strip("[]"), "/mcp"): (200, {}, b"ok")}, allow_private=True)
    assert net_.fetcher.get(f"https://{literal}/mcp", max_bytes=100).body == b"ok"
    assert net_.calls[0]["ip"] == literal.strip("[]")
    resolved = Net(answers={("intranet.example", "/mcp"): (200, {}, b"ok")}, addresses={"intranet.example": ["10.1.2.3"]},
                   allow_private=True)
    assert resolved.fetcher.get("https://intranet.example/mcp", max_bytes=100).body == b"ok"
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get(f"http://{literal}/mcp", max_bytes=100)  # plain HTTP stays refused (spec D13)
    assert caught.value.code == "not_https"
    net_.fetcher.post_json(f"https://{literal}/mcp", {}, {"Authorization": "Bearer x", "Cookie": "a=b"})
    assert not any(name.lower() in ("authorization", "cookie") for name in net_.calls[-1]["headers"])


def test_without_allow_private_the_same_addresses_are_refused():
    net_ = Net(addresses={"intranet.example": ["10.1.2.3"]})
    for url in ("https://10.0.0.1/mcp", "https://intranet.example/mcp"):
        with pytest.raises(FetchError) as caught:
            net_.fetcher.get(url, max_bytes=100)
        assert caught.value.code == "private_address"
    assert net_.calls == []


def test_the_gate_runs_before_every_connection_and_can_refuse_one():
    net_ = Net(answers={("a.example", "/one"): (302, {"Location": "https://a.example/two"}, b""),
                        ("a.example", "/two"): (200, {}, b"done")})
    opened: list[int] = []

    def gate():
        opened.append(1)
        if len(opened) > 1:
            raise FetchError("budget")

    net_.fetcher._gate = gate
    with pytest.raises(FetchError) as caught:
        net_.fetcher.get("https://a.example/one", max_bytes=100)
    assert caught.value.code == "budget" and len(net_.calls) == 1  # the redirect hop was not opened


def test_the_default_resolver_and_opener_exist_and_the_real_opener_pins_the_address():
    connection = net.pinned_connection("files.example", PUBLIC_IP, 443, 10.0)
    assert connection.host == "files.example" and connection.pinned_ip == PUBLIC_IP and connection.port == 443
    assert callable(net.default_resolver)
