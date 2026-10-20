"""The test double of `spellwarden_cli.net.Fetcher` behaves as `tests/recorded/README.md` says:
a JSON-RPC POST answers from `url#<method>` before the bare url, a stream head from
`url#stream`, exchanges of one key answer in order, and the refusals of the real
fetcher are kept."""
from __future__ import annotations

import pytest

import inspect

from fake_net import FakeFetcher
from spellwarden_cli import net
from spellwarden_cli.net import FetchError

URL = "https://mcp.example/mcp"


@pytest.mark.parametrize("method", ["get", "post_json", "get_stream_head"])
def test_the_fake_has_the_signature_of_the_real_fetcher(method):
    """What the steps call on `clients["net"]` must exist on both with the same parameters, kinds and defaults."""
    def shape(function):
        return [(p.name, p.kind, p.default) for p in inspect.signature(function).parameters.values() if p.name != "self"]
    assert shape(getattr(FakeFetcher, method)) == shape(getattr(net.Fetcher, method))


def test_post_json_prefers_the_method_key_then_the_bare_url():
    fake = FakeFetcher()
    fake.add("POST", f"{URL}#tools/list", body={"json": {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}})
    fake.add("POST", URL, status=404, body=b"not here")
    listed = fake.post_json(URL, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, {})
    other = fake.post_json(URL, {"jsonrpc": "2.0", "id": 2, "method": "server/discover"}, {})
    assert listed.status == 200 and b"tools" in listed.body
    assert other.status == 404 and other.body == b"not here"
    assert [request["body"]["method"] for request in fake.requests] == ["tools/list", "server/discover"]


def test_get_stream_head_prefers_the_stream_key_and_cuts_at_4096():
    fake = FakeFetcher()
    fake.add("GET", f"{URL}#stream", headers={"Content-Type": "text/event-stream"}, body=b"event: endpoint\n" + b"x" * 5000)
    fake.add("GET", URL, status=405, body=b"")
    head = fake.get_stream_head(URL)
    assert head.status == 200 and len(head.body) == 4096 and head.body.startswith(b"event: endpoint")
    assert fake.get(URL, max_bytes=10).status == 405


def test_exchanges_of_one_key_answer_in_order_and_the_last_repeats():
    fake = FakeFetcher([{"method": "GET", "url": URL, "status": 500, "body": b"first"},
                        {"method": "GET", "url": URL, "status": 200, "body": b"second"}])
    assert [fake.get(URL, max_bytes=10).body for _ in range(3)] == [b"first", b"second", b"second"]


def test_the_refusals_of_the_real_fetcher_hold():
    fake = FakeFetcher()
    with pytest.raises(FetchError) as caught:
        fake.get("http://mcp.example/mcp", max_bytes=10)
    assert caught.value.code == "not_https"
    with pytest.raises(FetchError) as caught:
        fake.get("https://nowhere.example/", max_bytes=10)
    assert caught.value.code == "unreachable"
    fake.add("GET", URL, body=b"x" * 11)
    with pytest.raises(FetchError) as caught:
        fake.get(URL, max_bytes=10)
    assert caught.value.code == "too_large"
