"""The test double of the connected API (O3 spec 6.3, plan Task 6): a scripted answer table behind the `opener`
and `resolver` seams of `spellwarden_cli.api.ApiClient`, so no test opens a socket. It records every request,
the token endpoint's and the exchange's included, as `(method, path, headers, body)`: `path` is the request target
as sent (query string included), `headers` is a copy of what the client sent plus the `Host` that `http.client`
adds, `body` is the decoded JSON body or None.

`script(method, path, status, body, ...)` answers requests whose path, without its query, equals `path`, `times`
times in a row (an unscripted request fails the test with an AssertionError, never a connection). `status=0`
scripts a connection that fails before the request is sent (it is not recorded as a request). `delay` is the time the answer takes on the injected
clock: past the request's timeout it is a timeout. `FakeClock` is the clock to inject; its `sleep` is what the
client waits with, so a retry costs no real time."""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

PUBLIC_IP = "93.184.216.34"
TOKEN_HOST = "token.actions.example"


class FakeClock:
    """`clock()` is the time; `sleep(seconds)` moves it; `advance` moves it without a wait (time passing elsewhere)."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class _Answer:
    method: str
    path: str
    status: int
    body: object
    headers: dict[str, str]
    delay: float
    left: int


def _bytes_of(body: object) -> bytes:
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return json.dumps(body).encode("utf-8")


class _Response:
    def __init__(self, status: int, headers: dict[str, str], data: bytes) -> None:
        self.status = status
        self._headers = headers
        self._data = data

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self._headers.items())

    def read(self, amt: int | None = None) -> bytes:
        take = self._data if amt is None else self._data[:amt]
        self._data = self._data[len(take):]
        return take


class _Connection:
    sock = None  # the watchdog looks for a socket to shut; there is none

    def __init__(self, api: FakeApi, host: str, ip: str | None, port: int, timeout: float, options: dict) -> None:
        self._api = api
        self.host, self.ip, self.port, self.timeout, self.options = host, ip, port, timeout, options
        self._answer: _Answer | None = None
        self._sent: object = None

    def connect(self) -> None:
        """A status-0 answer fails the connection that is opened while it is the first answer not yet used."""
        for answer in self._api._answers:
            if answer.left > 0:
                if answer.status == 0:
                    answer.left -= 1
                    raise ConnectionRefusedError("scripted: refused before the request was sent")
                break

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> None:
        sent = dict(headers or {})
        sent.setdefault("Host", self.host if self.port in (80, 443) else f"{self.host}:{self.port}")
        self._sent = json.loads(body) if body else None
        self._api.requests.append((method, path, sent, self._sent))
        bare = path.split("?", 1)[0]
        for answer in self._api._answers:
            if answer.method == method and answer.path == bare and answer.left > 0 and answer.status != 0:
                answer.left -= 1
                self._answer = answer
                return
        raise AssertionError(f"unscripted request {method} {path}")

    def getresponse(self) -> _Response:
        answer = self._answer
        assert answer is not None
        clock = self._api._clock
        if answer.delay >= self.timeout:
            clock.advance(self.timeout)
            raise TimeoutError("timed out")
        clock.advance(answer.delay)
        headers = {"Content-Type": "application/json", **answer.headers}
        content = answer.body(self._sent) if callable(answer.body) else answer.body
        return _Response(answer.status, headers, _bytes_of(content))

    def close(self) -> None:
        return None


class FakeApi:
    def __init__(self, clock: FakeClock | None = None) -> None:
        self.requests: list[tuple[str, str, dict[str, str], object]] = []
        self._answers: list[_Answer] = []
        self._clock = clock or FakeClock()

    def script(self, method: str, path: str, status: int, body: object = None, headers: dict[str, str] | None = None,
               delay: float = 0.0, times: int = 1) -> None:
        self._answers.append(_Answer(method.upper(), path, status, {} if body is None else body, dict(headers or {}),
                                     delay, times))

    def token_endpoint(self, status: int, body: object) -> str:
        """Scripts the GitHub token endpoint and returns the request URL a runner would hold in
        `ACTIONS_ID_TOKEN_REQUEST_URL` (it carries a query already, as GitHub's does)."""
        self.script("GET", "/idtoken", status, body)
        return f"https://{TOKEN_HOST}/idtoken?api-version=2.0"

    @property
    def opener(self) -> Callable[..., _Connection]:
        def open_connection(host: str, ip: str | None, port: int, timeout: float, **options) -> _Connection:
            return _Connection(self, host, ip, port, timeout, options)

        return open_connection

    @property
    def resolver(self) -> Callable[[str], list[str]]:
        return lambda _host: [PUBLIC_IP]
