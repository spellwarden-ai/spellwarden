"""The model client of `spellwarden scan --analyze` (Phase 4 batch B spec 11.3): one OpenAI-compatible chat completion per
skill, sent to the endpoint the user names, with the user's key. Spellwarden's own service is never involved.

Rules for the endpoint (spec 11.3, D26): `https` for any host; `http` only for a loopback address (127.0.0.0/8, ::1 or
`localhost`); no user name, password, query or fragment in the URL. The host is resolved and the connection pinned to the
checked address as `net.check_host` does, with private addresses allowed, because the endpoint is the configured origin (the
user's own machine or runner); the addresses no connection may reach (link-local, the cloud metadata addresses, multicast,
unspecified, reserved) stay refused. Only that origin is ever contacted: no redirect is followed (a 3xx is the error
`endpoint_redirect`). 10 s to connect, then 120 s to read the answer; the answer is cut off past 1 MiB (`answer_too_large`).
A proxy is not used.

The key comes from `SPELLWARDEN_MODEL_KEY` only (`main.py` takes it out of the environment), travels as a `Secret`, and is
sent as `Authorization: Bearer` and nowhere else; without a key no `Authorization` header is sent (a local server may need
none). An error carries the endpoint's status and its message masked with `mask_credentials`, with the key's own value
replaced by `***`, and cut to 200 characters: never the key, never the request.

The fifth module of `spellwarden_cli` that may reach the network (`tests/test_network_boundary.py`): it imports `socket` and
`http.client`, and nothing from `urllib.request`. Imported only under `--analyze` (`analysis.py`)."""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from spellwarden_scan import mask_credentials

from spellwarden_cli.net import USER_AGENT, FetchError, check_host, default_resolver, pinned_connection
from spellwarden_cli.secret import Secret

CONNECT_TIMEOUT_SECONDS = 10.0
READ_TIMEOUT_SECONDS = 120.0
ANSWER_MAX = 2**20
MESSAGE_MAX = 200
COMPLETIONS_PATH = "/chat/completions"
ERROR_CODES = ("endpoint_invalid", "endpoint_refused", "endpoint_unreachable", "timeout", "endpoint_redirect",
               "endpoint_status", "answer_too_large", "answer_invalid")
_CHUNK = 65536
_LOOPBACK_NAMES = ("localhost",)


class ModelError(Exception):
    """A call that gave no answer text: `code` from `ERROR_CODES`, `status` the HTTP status when there was one, `message` the
    endpoint's message masked and cut (empty when it sent none). The text holds no key and no request."""

    def __init__(self, code: str, *, status: int | None = None, message: str = "") -> None:
        super().__init__(f"{code} {status}" if status is not None else code)
        self.code = code
        self.status = status
        self.message = message


def _loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def endpoint_problem(url: str) -> str | None:
    """Why `url` cannot be the endpoint (a usage error of `--model-endpoint`), or None. Checked before any request."""
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 -- a port out of range raises here
    except ValueError:
        return "--model-endpoint is not a URL"
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("https", "http") or not host:
        return "--model-endpoint must be an https:// URL (http:// only for a loopback address)"
    if parts.scheme == "http" and not _loopback(host):
        return "--model-endpoint may use http:// only for a loopback address (127.0.0.1, [::1] or localhost)"
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        return "--model-endpoint must hold no user name, password, query or fragment: the key comes from SPELLWARDEN_MODEL_KEY"
    return None


def completions_url(endpoint: str) -> str:
    """The URL the request is posted to: the endpoint as given when it already ends in `/chat/completions`, else the
    endpoint (an OpenAI-compatible base URL such as `https://api.example.com/v1`) with `/chat/completions` added."""
    base = endpoint.rstrip("/")
    return base if base.endswith(COMPLETIONS_PATH) else base + COMPLETIONS_PATH


def clean_message(raw: bytes, key: Secret | None) -> str:
    """An endpoint's error text for a report: `error.message` of a JSON body (else the body), the key's value replaced by
    `***`, masked with `mask_credentials`, whitespace collapsed, cut to `MESSAGE_MAX` characters."""
    text = raw[:8192].decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):  # RecursionError: a body nested deeper than the JSON reader's stack
        parsed = None
    if isinstance(parsed, dict):
        error = parsed.get("error")
        inner = error.get("message") if isinstance(error, dict) else error
        if isinstance(inner, str):
            text = inner
    if key is not None and key.value:
        text = text.replace(key.value, "***")
    text = " ".join(mask_credentials(text).split())
    return text if len(text) <= MESSAGE_MAX else text[:MESSAGE_MAX - 3] + "..."


def answer_text(body: bytes) -> str:
    """The text of an OpenAI chat completion: `choices[0].message.content`, a string or a list of `{"type": "text", "text"}`
    parts joined. Anything else is `ModelError("answer_invalid")`, a body nested deeper than the JSON reader's stack
    included: the endpoint is a remote party, and nothing it sends may end the scan."""
    try:
        document = json.loads(body.decode("utf-8"))
        content = document["choices"][0]["message"]["content"]
    except (ValueError, UnicodeDecodeError, KeyError, IndexError, TypeError, RecursionError):
        raise ModelError("answer_invalid") from None
    if isinstance(content, str):
        return content
    if isinstance(content, list) and all(isinstance(part, dict) and isinstance(part.get("text"), str) for part in content):
        return "".join(part["text"] for part in content)
    raise ModelError("answer_invalid")


def _abort(connection) -> None:
    sock = getattr(connection, "sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def _open(host: str, ip: str, port: int, timeout: float, *, tls: bool):
    if not tls:
        return http.client.HTTPConnection(ip, port, timeout=timeout)
    return pinned_connection(host, ip, port, timeout)


@dataclass
class ModelClient:
    """`complete(system, user, max_tokens)` posts one chat completion and returns the answer's text, or raises `ModelError`.
    `resolver`, `opener` and `clock` are the seams of the tests; the defaults are the real ones."""
    endpoint: str
    model: str
    key: Secret | None = field(default=None, repr=False)
    resolver: Callable[[str], list[str]] = default_resolver
    opener: Callable[..., object] = _open
    clock: Callable[[], float] = time.monotonic
    read_timeout: float = READ_TIMEOUT_SECONDS
    connect_timeout: float = CONNECT_TIMEOUT_SECONDS

    def complete(self, system: str, user: str, *, max_tokens: int) -> str:
        if endpoint_problem(self.endpoint) is not None:
            raise ModelError("endpoint_invalid")
        url = completions_url(self.endpoint)
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        tls = parts.scheme == "https"
        port = parts.port or (443 if tls else 80)
        if tls:
            try:
                ip = check_host(host, self.resolver, allow_private=True)
            except FetchError as error:  # a name that does not resolve is unreachable; only a refused address is refused
                raise ModelError("endpoint_refused" if error.code == "private_address" else "endpoint_unreachable") from None
        else:
            ip = "127.0.0.1" if host == "localhost" else host
        body = json.dumps({"model": self.model, "max_tokens": max_tokens, "temperature": 0,
                           "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": USER_AGENT}
        if self.key is not None and self.key.value:
            headers["Authorization"] = f"Bearer {self.key.value}"
        status, data = self._send(host, ip, port, tls, parts.path or "/", body, headers)
        if 300 <= status < 400:
            raise ModelError("endpoint_redirect", status=status)
        if status != 200:
            raise ModelError("endpoint_status", status=status, message=clean_message(data, self.key))
        return answer_text(data)

    def _send(self, host: str, ip: str, port: int, tls: bool, target: str, body: bytes,
              headers: dict[str, str]) -> tuple[int, bytes]:
        deadline = self.clock() + self.connect_timeout + self.read_timeout
        fired = threading.Event()
        connection = None
        watchdog = None
        try:
            connection = self.opener(host, ip, port, self.connect_timeout, tls=tls)

            def fire(target_connection=connection) -> None:
                fired.set()
                _abort(target_connection)

            watchdog = threading.Timer(self.connect_timeout + self.read_timeout, fire)
            watchdog.daemon = True
            watchdog.start()
            connection.connect()
            if getattr(connection, "sock", None) is not None:
                connection.sock.settimeout(self.read_timeout)
            connection.request("POST", target, body, headers)
            raw = connection.getresponse()
            status = int(raw.status)
            chunks: list[bytes] = []
            total = 0
            while True:
                if self.clock() >= deadline:
                    raise ModelError("timeout")
                chunk = raw.read(min(_CHUNK, ANSWER_MAX + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > ANSWER_MAX:
                    raise ModelError("answer_too_large", status=status)
            return status, b"".join(chunks)
        except ModelError:
            raise
        except (OSError, http.client.HTTPException, ValueError) as exc:
            late = fired.is_set() or self.clock() >= deadline or isinstance(exc, TimeoutError)
            raise ModelError("timeout" if late else "endpoint_unreachable") from None
        finally:
            if watchdog is not None:
                watchdog.cancel()
            if connection is not None:
                connection.close()


__all__ = ["ANSWER_MAX", "CONNECT_TIMEOUT_SECONDS", "ERROR_CODES", "MESSAGE_MAX", "READ_TIMEOUT_SECONDS", "ModelClient",
           "ModelError", "answer_text", "clean_message", "completions_url", "endpoint_problem"]
