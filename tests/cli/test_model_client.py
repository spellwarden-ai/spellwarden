"""Phase 4 batch B spec 11.3, D26 and claim E-7: the model client's address rules (`https` for any host, `http` for a loopback
address only, private addresses for the configured endpoint's origin only, never a redirect), its bounds (120 s to read, 1 MiB
of answer) and its errors (status plus a masked, bounded message, never the key). Every server here is a local fake on a
loopback address."""
from __future__ import annotations

import json
import socket
import time

import pytest
from fake_model import FakeModel, completion

from spellwarden_cli import model_client
from spellwarden_cli.model_client import ModelClient, ModelError
from spellwarden_cli.net import FetchError
from spellwarden_cli.secret import Secret

KEY = "sk-test-" + "k" * 40


@pytest.fixture
def fake():
    servers: list[FakeModel] = []

    def start(answer):
        server = FakeModel(answer)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


@pytest.mark.parametrize("url", ["https://api.example.com/v1", "https://10.0.0.5:8443/v1", "http://127.0.0.1:4000/v1",
                                 "http://[::1]:11434/v1", "http://localhost:11434", "https://gw.example/v1/chat/completions"])
def test_accepted_endpoints(url):
    assert model_client.endpoint_problem(url) is None


@pytest.mark.parametrize("url, words", [
    ("http://api.example.com/v1", "loopback"), ("http://10.0.0.5/v1", "loopback"), ("ftp://x.example", "https://"),
    ("https://user:pw@api.example.com/v1", "user name"), ("https://api.example.com/v1?key=x", "query"),
    ("https://api.example.com/v1#x", "fragment"), ("https://api.example.com:99999/v1", "not a URL"), ("api.example.com", "https://"),
])
def test_refused_endpoints(url, words):
    assert words in model_client.endpoint_problem(url)


def test_the_completions_url():
    assert model_client.completions_url("https://a.example/v1") == "https://a.example/v1/chat/completions"
    assert model_client.completions_url("https://a.example/v1/") == "https://a.example/v1/chat/completions"
    assert model_client.completions_url("https://a.example/v1/chat/completions") == "https://a.example/v1/chat/completions"


def test_one_chat_completion_with_the_bearer_key(fake):
    server = fake(lambda _h, _b: (200, {"Content-Type": "application/json"}, completion("the answer")))
    client = ModelClient(server.url, "my-model", Secret(KEY))
    assert client.complete("system text", "user text", max_tokens=4096) == "the answer"
    ((path, headers, body),) = server.requests
    assert path == "/v1/chat/completions"
    assert headers["authorization"] == f"Bearer {KEY}" and headers["user-agent"].startswith("Spellwarden/")
    assert body == {"model": "my-model", "max_tokens": 4096, "temperature": 0,
                    "messages": [{"role": "system", "content": "system text"}, {"role": "user", "content": "user text"}]}
    assert KEY not in repr(client)


def test_text_parts_are_joined_and_no_key_sends_no_authorization(fake):
    server = fake(lambda _h, _b: (200, {}, completion([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}])))
    assert ModelClient(server.url, "m").complete("s", "u", max_tokens=1) == "ab"
    assert "authorization" not in server.requests[0][1]


def test_an_error_status_carries_a_masked_bounded_message_never_the_key(fake):
    body = json.dumps({"error": {"message": f"invalid key {KEY} for token=abcdef123456 " + "x" * 400}}).encode()
    server = fake(lambda _h, _b: (401, {}, body))
    with pytest.raises(ModelError) as caught:
        ModelClient(server.url, "m", Secret(KEY)).complete("s", "u", max_tokens=1)
    error = caught.value
    assert (error.code, error.status) == ("endpoint_status", 401)
    assert KEY not in error.message and KEY not in str(error) and "abcdef123456" not in error.message
    assert len(error.message) <= model_client.MESSAGE_MAX and error.message.startswith("invalid key ***")


def test_a_redirect_is_never_followed(fake):
    other = fake(lambda _h, _b: (200, {}, completion("from elsewhere")))
    server = fake(lambda _h, _b: (307, {"Location": other.url + "/chat/completions"}, b""))
    with pytest.raises(ModelError) as caught:
        ModelClient(server.url, "m", Secret(KEY)).complete("s", "u", max_tokens=1)
    assert (caught.value.code, caught.value.status) == ("endpoint_redirect", 307)
    assert other.requests == []


def test_an_answer_past_one_mebibyte_is_refused(fake):
    big = completion("x" * model_client.ANSWER_MAX)
    server = fake(lambda _h, _b: (200, {}, big))
    with pytest.raises(ModelError) as caught:
        ModelClient(server.url, "m").complete("s", "u", max_tokens=1)
    assert caught.value.code == "answer_too_large" and model_client.ANSWER_MAX == 2**20


def test_an_answer_that_is_not_a_chat_completion_is_invalid(fake):
    server = fake(lambda _h, _b: (200, {}, b'{"choices": []}'))
    with pytest.raises(ModelError) as caught:
        ModelClient(server.url, "m").complete("s", "u", max_tokens=1)
    assert caught.value.code == "answer_invalid"


def test_a_body_nested_too_deep_is_an_error_of_the_call_never_a_crash(fake):
    """The endpoint is a remote party: a body that exhausts the JSON reader's stack (a RecursionError, which is no
    ValueError) is an invalid answer or an unread error message, never an exception that ends the scan."""
    server = fake(lambda _h, _b: (200, {}, b"[" * 200_000))
    with pytest.raises(ModelError) as caught:
        ModelClient(server.url, "m").complete("s", "u", max_tokens=1)
    assert caught.value.code == "answer_invalid"
    refusing = fake(lambda _h, _b: (500, {}, b"[" * 8192))
    with pytest.raises(ModelError) as caught:
        ModelClient(refusing.url, "m").complete("s", "u", max_tokens=1)
    assert (caught.value.code, caught.value.status) == ("endpoint_status", 500)
    assert caught.value.message.startswith("[[[") and len(caught.value.message) <= model_client.MESSAGE_MAX


def test_a_slow_answer_is_a_timeout(fake):
    def slow(_h, _b):
        time.sleep(1.5)
        return 200, {}, completion("late")

    server = fake(slow)
    started = time.monotonic()
    with pytest.raises(ModelError) as caught:
        ModelClient(server.url, "m", read_timeout=0.3, connect_timeout=0.3).complete("s", "u", max_tokens=1)
    assert caught.value.code == "timeout" and time.monotonic() - started < 1.4
    assert (model_client.CONNECT_TIMEOUT_SECONDS, model_client.READ_TIMEOUT_SECONDS) == (10.0, 120.0)


def test_a_closed_port_is_unreachable():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(ModelError) as caught:
        ModelClient(f"http://127.0.0.1:{port}/v1", "m").complete("s", "u", max_tokens=1)
    assert caught.value.code == "endpoint_unreachable"


class _Refused(OSError):
    pass


def _recording_opener(seen: list):
    def opener(host, ip, port, _timeout, *, tls):
        seen.append((host, ip, port, tls))
        raise _Refused("no connection in this test")

    return opener


def test_a_private_address_is_allowed_for_the_configured_origin():
    seen: list = []
    client = ModelClient("https://llm.internal.example/v1", "m", resolver=lambda _host: ["10.0.0.5"], opener=_recording_opener(seen))
    with pytest.raises(ModelError) as caught:
        client.complete("s", "u", max_tokens=1)
    assert caught.value.code == "endpoint_unreachable" and seen == [("llm.internal.example", "10.0.0.5", 443, True)]


@pytest.mark.parametrize("address", ["169.254.169.254", "fd00:ec2::254", "0.0.0.0", "224.0.0.1", "::ffff:10.0.0.5"])
def test_addresses_no_connection_may_reach_stay_refused(address):
    seen: list = []
    client = ModelClient("https://llm.example/v1", "m", resolver=lambda _host: [address], opener=_recording_opener(seen))
    with pytest.raises(ModelError) as caught:
        client.complete("s", "u", max_tokens=1)
    assert caught.value.code == "endpoint_refused" and seen == []


def test_a_name_that_does_not_resolve_is_unreachable_not_refused():
    def no_such_host(_host):
        raise FetchError("fetch_failed", "resolve gaierror")

    seen: list = []
    for resolver in (no_such_host, lambda _host: []):
        client = ModelClient("https://llm.example/v1", "m", resolver=resolver, opener=_recording_opener(seen))
        with pytest.raises(ModelError) as caught:
            client.complete("s", "u", max_tokens=1)
        assert caught.value.code == "endpoint_unreachable" and seen == []


def test_http_reaches_a_loopback_address_only():
    seen: list = []
    with pytest.raises(ModelError) as caught:
        ModelClient("http://10.0.0.5/v1", "m", opener=_recording_opener(seen)).complete("s", "u", max_tokens=1)
    assert caught.value.code == "endpoint_invalid" and seen == []
    with pytest.raises(ModelError):
        ModelClient("http://localhost:4000/v1", "m", opener=_recording_opener(seen)).complete("s", "u", max_tokens=1)
    assert seen == [("localhost", "127.0.0.1", 4000, False)]


def test_clean_message_reads_error_message_and_masks():
    assert model_client.clean_message(b'{"error": "plain"}', None) == "plain"
    assert model_client.clean_message(b"<html>  bad\n gateway </html>", None) == "<html> bad gateway </html>"
    assert model_client.clean_message(KEY.encode(), Secret(KEY)) == "***"
