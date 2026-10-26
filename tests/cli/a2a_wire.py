"""A scripted wire for the agent card tests: the real `net.Fetcher` (its address rules, redirect rules, byte caps and header
rules) runs over a resolver and an opener that open no socket. Routes are `https://host/path` to `(status, headers, body)`;
anything else answers 404. Every connection is recorded with its host, address, method, path, headers and body."""
from __future__ import annotations

import threading

from spellwarden_cli import net

PUBLIC_IP = "8.8.8.8"


class _Answer:
    def __init__(self, status: int, headers: dict, body: bytes) -> None:
        self.status, self._headers, self._body = status, headers, body

    def getheaders(self):
        return list(self._headers.items())

    def read(self, amt=None):
        chunk, self._body = (self._body, b"") if amt is None else (self._body[:amt], self._body[amt:])
        return chunk

    read1 = read


class Wire:
    def __init__(self, monkeypatch, routes: dict[str, tuple[int, dict, bytes]] | None = None, *,
                 addresses: dict[str, str] | None = None) -> None:
        self.routes = dict(routes or {})
        self.calls: list[dict] = []
        self.lock = threading.Lock()
        self.addresses = addresses or {}
        monkeypatch.setattr(net, "default_resolver", lambda host: [self.addresses.get(host, PUBLIC_IP)])
        monkeypatch.setattr(net, "pinned_connection", self.open)

    def open(self, host, ip, port, timeout):  # noqa: ARG002 -- the opener's shape
        wire = self

        class Connection:
            def request(self, method, path, body=None, headers=None):
                with wire.lock:
                    wire.calls.append({"host": host, "ip": ip, "method": method, "path": path, "headers": dict(headers or {}),
                                       "body": body, "url": f"https://{host}{path}"})
                self.answer = _Answer(*wire.routes.get(f"https://{host}{path}", (404, {}, b"")))

            def getresponse(self):
                return self.answer

            def close(self):
                pass

        return Connection()

    @property
    def urls(self) -> list[str]:
        return [call["url"] for call in self.calls]
