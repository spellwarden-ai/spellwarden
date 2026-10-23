"""The connected API client (O3 spec 6.3): the exchange of the pipeline's identity for a CI token, the GitHub token
request, and the authenticated `GET` and `POST` of the v1 routes, over the rules of `net.py` where they apply and
nowhere else.

Rules for the API origin: HTTPS only (loopback HTTP under the test hook), the host resolved and every address
checked and pinned as `net.check_host` does, no redirect, one deadline of 10 s per request including the body, the
answer capped at 2 MiB, `Authorization: Bearer <credential>` (absent on the exchange), the User-Agent of `net.py`. The
run budget of 150 s is the time spent inside requests and retry waits, not wall time (P50); a request started more
than 840 s after the exchange is refused (the CI token lives 15 minutes). Retries: a 429 once after `Retry-After`
(at most 20 s and less than the budget left), a 5xx or a connection failure before the request was sent once after
2 s; nothing else. `post(retry=False)` skips the 5xx retry (a timed-out upload may still be running).

The GitHub token request goes to the address the job's own runner set: HTTPS (loopback HTTP under the hook), no
public-address check (a GitHub Enterprise Server may answer on a private network), the fixed set of addresses no fetch
may reach still refused, no redirect.

A proxy (`HTTPS_PROXY`, `NO_PROXY`) is honoured by this module only: `CONNECT` to the target and TLS verified end to
end against the target host. The proxy resolves the target, so the target is not resolved here and the proxy's own
address is not checked. Probes and the ping ignore it.

Credentials are `Secret`s and no message, event or repr holds one. `clock` is a callable returning seconds; its
optional `sleep(seconds)` is how the client waits (the tests' clock moves instead of waiting).

One of the four modules of `spellwarden_cli` that may reach the network (`tests/test_network_boundary.py`); it imports
`socket`, `ssl` and `http.client`, and nothing from `urllib.request`."""
from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlencode, urlsplit

from spellwarden_cli.net import USER_AGENT, FetchError, check_host, default_resolver, pinned_connection
from spellwarden_cli.secret import Secret

DEFAULT_API_URL = "https://dash.spellwarden.ai/api"
RUN_BUDGET_SECONDS = 150.0
REQUEST_TIMEOUT_SECONDS = 10.0
RESPONSE_MAX = 2 * 1024 * 1024
RETRY_AFTER_MAX = 20
TOKEN_LIFETIME_SECONDS = 840.0  # the CI token lives 900 s; a request later than this may outlive it
RETRY_WAIT_SECONDS = 2.0
NOT_YET_AVAILABLE = "Connected mode is not available yet on this server"
_CHUNK = 65536
_LOOPBACK = re.compile(r"http://(127\.0\.0\.1|\[::1\]|localhost):([0-9]{1,5})(/[A-Za-z0-9._~/-]*)?")
_LOOPBACK_HOSTS = ("127.0.0.1", "::1")
_MESSAGE_MAX = 300


def loopback_url(raw: str) -> str | None:
    """`raw` in the form of the test hooks (Phase O spec D25): `http://127.0.0.1:<port>/<path>`,
    `http://[::1]:<port>/<path>` or `http://localhost:<port>/<path>` (written with 127.0.0.1); None for anything
    else. `SPELLWARDEN_PING_URL` and `SPELLWARDEN_API_URL` follow the same rule."""
    match = _LOOPBACK.fullmatch(raw)
    if match is None or not 1 <= int(match.group(2)) <= 65535:
        return None
    host = "127.0.0.1" if match.group(1) == "localhost" else match.group(1)
    return f"http://{host}:{int(match.group(2))}{match.group(3) or '/'}"


def api_url(env: Mapping[str, str], log: Callable[[str], None]) -> tuple[str, bool]:
    """The API base URL and whether `SPELLWARDEN_API_URL` overrode the default. The override is honoured for loopback
    HTTP only (the acceptance rule of `SPELLWARDEN_PING_URL`); anything else is ignored with one `--verbose` line."""
    raw = env.get("SPELLWARDEN_API_URL")
    if not raw:
        return DEFAULT_API_URL, False
    url = loopback_url(raw)
    if url is None:
        log("SPELLWARDEN_API_URL ignored: it is honoured for loopback HTTP only (127.0.0.1, [::1] or localhost)")
        return DEFAULT_API_URL, False
    return url, True


def audience_for(org: str) -> str:
    return f"https://dash.spellwarden.ai/ci/{org}"


@dataclass(frozen=True)
class ProxyConfig:
    host: str
    port: int
    auth: Secret | None  # `user:password`; sent as `Proxy-Authorization: Basic`


def _no_proxy(entries: str, host: str) -> bool:
    host = host.lower()
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    for raw in entries.split(","):
        entry = raw.strip().lower()
        if not entry:
            continue
        if entry == "*":
            return True
        if "/" in entry and address is not None:
            try:
                if address in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
            continue
        if entry.count(":") == 1:  # `host:port`
            entry = entry.split(":", 1)[0]
        entry = entry.removeprefix("*").lstrip(".")
        if entry and (host == entry or host.endswith("." + entry)):
            return True
    return False


def proxy_for(env: Mapping[str, str], target_host: str) -> ProxyConfig | None:
    """The proxy for HTTPS requests to `target_host`: `HTTPS_PROXY` (or `https_proxy`) unless `NO_PROXY` names the
    host. Only an `http://` proxy (or a bare `host:port`) is spoken to; anything else is no proxy."""
    raw = (env.get("HTTPS_PROXY") or env.get("https_proxy") or "").strip()
    if not raw or _no_proxy(env.get("NO_PROXY") or env.get("no_proxy") or "", target_host):
        return None
    text = raw if "://" in raw else f"http://{raw}"
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "http" or not parts.hostname:
        return None
    auth = Secret(f"{unquote(parts.username)}:{unquote(parts.password or '')}") if parts.username else None
    return ProxyConfig(parts.hostname, port or 80, auth)


class ApiError(Exception):
    """An answer or a failure mapped to a report error code (6.3). `message` is the server's own message when it
    sent one (never a credential: the server never echoes one), else this module's description; `body` is the parsed
    JSON of an error answer."""

    def __init__(self, code: str, message: str = "", *, status: int | None = None, request_id: str | None = None,
                 body: dict | None = None) -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.status = status
        self.message = message
        self.request_id = request_id
        self.body = body


@dataclass(frozen=True)
class Session:
    token: Secret
    expires_at: str
    org: dict
    run: dict | None
    credential: str  # "oidc" | "key"


# --- connections ---------------------------------------------------------------------------------------------------


class _TunnelConnection(http.client.HTTPSConnection):
    """A connection to the proxy that `CONNECT`s to the target and then speaks TLS to the target's name."""

    def __init__(self, host: str, port: int, proxy: ProxyConfig, timeout: float, context=None) -> None:
        super().__init__(proxy.host, proxy.port, timeout=timeout, context=context or ssl.create_default_context())
        headers = {}
        if proxy.auth is not None:
            headers["Proxy-Authorization"] = "Basic " + base64.b64encode(proxy.auth.value.encode("utf-8")).decode("ascii")
        self.set_tunnel(host, port, headers)


def tunnel_connection(host: str, port: int, proxy: ProxyConfig, timeout: float, *, context=None) -> _TunnelConnection:
    return _TunnelConnection(host, port, proxy, timeout, context=context)


def open_connection(host: str, ip: str | None, port: int, timeout: float, *, tls: bool = True,
                    proxy: ProxyConfig | None = None):
    """The default opener. `ip` is the checked address of a direct TLS connection; with a proxy it is None."""
    if not tls:
        return http.client.HTTPConnection(ip or host, port, timeout=timeout)
    if proxy is not None:
        return tunnel_connection(host, port, proxy, timeout)
    return pinned_connection(host, ip, port, timeout)


def _abort(connection) -> None:
    """The deadline watchdog (as `net.py`): shuts the socket down, which ends a blocked connect, handshake, send or
    receive at once."""
    sock = getattr(connection, "sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class _Unreachable(Exception):
    """A failure of the exchange of bytes. `sent` is False when the request cannot have reached the server."""

    def __init__(self, reason: str, *, sent: bool) -> None:
        super().__init__(reason)
        self.reason = reason
        self.sent = sent


class _Wire:
    """One request over the rules above; knows nothing of budgets, credentials or retries."""

    def __init__(self, *, opener, resolver, clock, proxy: ProxyConfig | None, loopback: bool, on_event) -> None:
        self._opener = opener or open_connection
        self._resolver = resolver or default_resolver
        self._clock = clock or time.monotonic
        self._proxy = proxy
        self._loopback = loopback
        self._on_event = on_event

    def send(self, method: str, url: str, body: bytes | None, headers: dict[str, str], *, public: bool, timeout: float,
             label: str | None) -> tuple[int, dict[str, str], bytes]:
        """`label` is the path an event may carry (None: the URL is itself a secret, nothing of it is reported)."""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            raise _Unreachable("bad_url", sent=False) from None
        if not host:
            raise _Unreachable("bad_url", sent=False)
        options: dict = {}
        proxy = None
        if parts.scheme == "https":
            port = port or 443
            proxy = self._proxy
            if proxy is not None:
                ip = None
                options["proxy"] = proxy
            else:
                try:
                    ip = check_host(host, self._resolver, allow_private=not public)
                except FetchError as exc:
                    raise _Unreachable(exc.detail or exc.code, sent=False) from None
        elif parts.scheme == "http" and self._loopback and host in _LOOPBACK_HOSTS:
            port = port or 80
            ip = host
            options["tls"] = False
        else:
            raise _Unreachable("https_required", sent=False)
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        started = self._clock()
        deadline = started + timeout
        connection = None
        watchdog = None
        fired = threading.Event()
        sent = False
        try:
            connection = self._opener(host, ip, port, timeout, **options)

            def fire(target_connection=connection) -> None:
                fired.set()
                _abort(target_connection)

            watchdog = threading.Timer(max(0.0, timeout), fire)
            watchdog.daemon = True
            watchdog.start()
            connection.connect()
            sent = True  # from here on the request may have reached the server
            connection.request(method, target, body, headers)
            raw = connection.getresponse()
            status = int(raw.status)
            response_headers = {str(name): str(value) for name, value in raw.getheaders()}
            data = self._read(raw, deadline, getattr(connection, "sock", None))
        except _Unreachable:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
            late = fired.is_set() or self._clock() >= deadline or isinstance(exc, TimeoutError)
            raise _Unreachable("timeout" if late else type(exc).__name__, sent=sent) from None
        finally:
            if watchdog is not None:
                watchdog.cancel()
            if connection is not None:
                connection.close()
        if self._on_event is not None:
            fields = {"host": host, "method": method, "status": status, "bytes": len(data),
                      "ms": int((self._clock() - started) * 1000)}
            if label is not None:
                fields["path"] = label
            self._on_event("api_request", fields)
        return status, response_headers, data

    def _read(self, raw, deadline: float, sock) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            left = deadline - self._clock()
            if left <= 0:
                raise _Unreachable("timeout", sent=True)
            if sock is not None:
                sock.settimeout(left)
            chunk = raw.read(min(_CHUNK, RESPONSE_MAX + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > RESPONSE_MAX:
                raise _Unreachable("too_large", sent=True)
        return b"".join(chunks)


# --- the client ----------------------------------------------------------------------------------------------------

_AUTH_403 = frozenset(("connection_not_found", "repository_not_allowed", "owner_changed", "project_pending_approval",
                       "shape_mismatch", "fork_pipeline_unsupported", "audience_mismatch"))
_POLICY_404 = frozenset(("pack_not_found", "pack_version_not_found", "pack_not_allowed"))
_DEFAULT_MESSAGES = {
    "connected_auth": "the organisation did not accept the request",
    "connected_subscription": "the organisation's subscription is not active",
    "connected_ci_key_required": "the credential is not a CI key",
    "connected_forbidden": "the credential is not allowed to do this",
    "connected_rate_limited": "a limit stopped the call",
    "policy_not_found": "the pack was not found",
    "connected_unavailable": "the Spellwarden service did not answer as expected",
}


def _text(value: object) -> str:
    """A server message, one line and at most 300 characters; empty when it is not a string."""
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:_MESSAGE_MAX]


def _classify(status: int, code: str) -> str:
    if status == 400 and code in ("token_invalid", "token_replayed"):
        return "connected_auth"
    if status == 401:
        return "connected_auth"
    if status == 402:
        return "connected_subscription"
    if status == 403:
        if code == "ci_key_required":
            return "connected_ci_key_required"
        return "connected_auth" if code in _AUTH_403 else "connected_forbidden"
    if status == 404:
        if code in _POLICY_404:
            return "policy_not_found"
        return "connected_auth" if code == "org_not_found" else "connected_unavailable"
    if status == 409 and code == "scope_limit":
        return "connected_auth"
    if status == 429:
        return "connected_rate_limited"
    return "connected_unavailable"


def _unavailable(message: str, *, status: int | None = None) -> ApiError:
    return ApiError("connected_unavailable", message, status=status)


class ApiClient:
    """`get` and `post` against `base_url`, `exchange` for a CI token. Every failure is an `ApiError` whose `code` is
    a report error code; whether it ends the run is `connected.py`'s decision."""

    def __init__(self, base_url: str, credential: Secret | None, *, release: str, opener=None, resolver=None, clock=None,
                 on_event=None, proxy: ProxyConfig | None = None, loopback: bool = False) -> None:
        self._base = base_url.rstrip("/")
        self._credential = credential
        self._release = release
        self._clock = clock or time.monotonic
        self._sleep = getattr(self._clock, "sleep", None) or time.sleep
        self._wire = _Wire(opener=opener, resolver=resolver, clock=self._clock, proxy=proxy, loopback=loopback,
                           on_event=on_event)
        self._spent = 0.0  # seconds inside requests and retry waits (P50)
        self._exchanged_at: float | None = None

    def get(self, path: str, params: dict[str, str] | None = None) -> dict:
        return self._request("GET", path, params, None, retry=True)

    def post(self, path: str, body: dict, *, retry: bool = True) -> dict:
        return self._request("POST", path, None, body, retry=retry)

    def exchange(self, org: str, provider_token: Secret, client: dict) -> Session:
        """`POST /public/ci/token`; afterwards the CI token is this client's credential. Never retried after a 5xx: the
        first try may have consumed the provider token."""
        answer = self._request("POST", "/public/ci/token", None, {"schema": 1, "org": org, "token": provider_token.value,
                                                                   "client": client}, retry=False, auth=False)
        token, expires_at, organisation, run = (answer.get("token"), answer.get("expires_at"), answer.get("org"),
                                                answer.get("run"))
        if not (isinstance(token, str) and token.startswith("swt_") and isinstance(expires_at, str)
                and isinstance(organisation, dict) and (run is None or isinstance(run, dict))):
            raise _unavailable("the exchange did not answer a session")
        self._credential = Secret(token)
        self._exchanged_at = self._clock()
        return Session(Secret(token), expires_at, organisation, run, "oidc")

    def token_age(self, clock: Callable[[], float] | None = None) -> float:
        """Seconds since the exchange (0.0 before it)."""
        if self._exchanged_at is None:
            return 0.0
        return (clock or self._clock)() - self._exchanged_at

    # -- internals --

    def _url(self, path: str, params: dict[str, str] | None) -> str:
        query = f"?{urlencode(params, quote_via=quote, safe='@')}" if params else ""
        return f"{self._base}{path}{query}"

    def _left(self) -> float:
        return RUN_BUDGET_SECONDS - self._spent

    def _admit(self) -> float:
        """The timeout of the next request; `connected_unavailable` when the budget is spent or the token is old."""
        if self._left() <= 0:
            raise _unavailable("the time allowed for connected calls in one run (150 seconds) is spent")
        if self._exchanged_at is not None and self._clock() - self._exchanged_at > TOKEN_LIFETIME_SECONDS:
            raise _unavailable("the CI token's fifteen minutes are over")
        return min(REQUEST_TIMEOUT_SECONDS, self._left())

    def _wait(self, seconds: float) -> None:
        self._sleep(seconds)
        self._spent += seconds

    def _can_wait(self, seconds: float) -> bool:
        return self._left() - seconds > 0

    @staticmethod
    def _retry_after(headers: dict[str, str]) -> float:
        for name, value in headers.items():
            if name.lower() == "retry-after":
                try:
                    return max(0.0, float(value))
                except ValueError:
                    break
        return 1.0

    def _request(self, method: str, path: str, params: dict[str, str] | None, body: dict | None, *, retry: bool,
                 auth: bool = True) -> dict:
        url = self._url(path, params)
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if auth and self._credential is not None:
            headers["Authorization"] = f"Bearer {self._credential.value}"
        retried = {"connect": False, "429": False, "5xx": False}
        while True:
            timeout = self._admit()
            begin = self._clock()
            try:
                status, response_headers, payload = self._wire.send(method, url, data, headers, public=True,
                                                                     timeout=timeout, label=path)
            except _Unreachable as failure:
                self._spent += self._clock() - begin
                if not failure.sent and not retried["connect"] and self._can_wait(RETRY_WAIT_SECONDS):
                    retried["connect"] = True
                    self._wait(RETRY_WAIT_SECONDS)
                    continue
                raise _unavailable(f"the Spellwarden service could not be reached ({failure.reason})") from None
            self._spent += self._clock() - begin
            if status == 429 and not retried["429"]:
                wait = min(self._retry_after(response_headers), float(RETRY_AFTER_MAX), self._left())
                if self._can_wait(wait):
                    retried["429"] = True
                    self._wait(wait)
                    continue
            elif status >= 500 and retry and not retried["5xx"] and self._can_wait(RETRY_WAIT_SECONDS):
                retried["5xx"] = True
                self._wait(RETRY_WAIT_SECONDS)
                continue
            return self._answer(status, payload)

    @staticmethod
    def _parse(payload: bytes) -> dict | None:
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def _answer(self, status: int, payload: bytes) -> dict:
        body = self._parse(payload)
        if 200 <= status < 300:
            if body is None:
                raise _unavailable("the answer was not a JSON object", status=status)
            return body
        if 300 <= status < 400:
            raise _unavailable(f"the service answered {status}: redirects are not followed", status=status)
        code = body.get("error") if body is not None and isinstance(body.get("error"), str) else ""
        mapped = _classify(status, code)
        request_id = body.get("request_id") if body is not None and isinstance(body.get("request_id"), str) else None
        message = _text(body.get("message")) if body is not None else ""
        if status == 404 and code == "not_found":
            message = NOT_YET_AVAILABLE
        elif mapped == "connected_unavailable" and not message:
            message = f"the Spellwarden service answered {status}"
        raise ApiError(mapped, message or _DEFAULT_MESSAGES[mapped], status=status, request_id=request_id, body=body)


def github_id_token(env: Mapping[str, str], request_url: Secret, request_token: Secret, audience: str, *, opener=None,
                    resolver=None, clock=None, proxy: ProxyConfig | None = None, loopback: bool = False) -> Secret:
    """The OIDC token of a GitHub Actions job: `GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=<audience>` with
    `Authorization: bearer <request token>`. `proxy`, else `HTTPS_PROXY` and `NO_PROXY` of `env`. A failure is
    `connected_unavailable` and names neither the URL nor the token."""
    raw = request_url.value
    parts = urlsplit(raw)
    if proxy is None and parts.scheme == "https" and parts.hostname:
        proxy = proxy_for(env, parts.hostname)
    url = f"{raw}{'&' if '?' in raw else '?'}audience={quote(audience, safe=':/')}"
    wire = _Wire(opener=opener, resolver=resolver, clock=clock, proxy=proxy, loopback=loopback, on_event=None)
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT,
               "Authorization": f"bearer {request_token.value}"}
    try:
        status, _, payload = wire.send("GET", url, None, headers, public=False, timeout=REQUEST_TIMEOUT_SECONDS, label=None)
    except _Unreachable as failure:
        raise _unavailable(f"the GitHub token request failed ({failure.reason})") from None
    body = ApiClient._parse(payload) if status == 200 else None
    value = body.get("value") if body is not None else None
    if not isinstance(value, str) or not value:
        raise _unavailable(f"the GitHub token request failed ({status})" if status != 200
                           else "the GitHub token request did not answer a token")
    return Secret(value)
