"""The fetcher of the MCP probe (spec 6.8; moved from the hosted backend's `spellwarden/net.py`, Phase B spec 6.5,
behaviour unchanged): HTTPS fetches with the SSRF rules applied before every connection and again on every redirect.

Rules: `https` only; the host is resolved and every resolved address must be
public (loopback, private, link-local, CGNAT, multicast, reserved, unspecified
and IPv4-mapped forms of those are refused; `localhost` and `.local`,
`.internal`, `.localhost` names are refused without a lookup); the connection
is opened to the checked address with the hostname kept for SNI and the `Host`
header, so a second resolution cannot swap the address; at most 5 redirects,
each re-checked; a 10 s deadline per request, redirects included; `max_bytes`
enforced while reading; never an `Authorization` header, never a cookie. A POST
never follows a redirect (its 3xx answer is returned); a GET that is redirected
to another origin (scheme, host, port) loses every `Mcp-*` and `MCP-*` header,
so no session state issued by one server reaches another.

Additive to the backend's version (spec 6.8): `on_event(name, fields)` receives
what the backend logged (`net_request`), `clock` is the deadline clock,
`user_agent` the header sent, and `private_origins` (URLs; only their scheme,
host and port count) are the origins of the configured servers that may be
private (`--probe-private` on a trusted run). A request, or a redirect hop,
to one of those origins skips the blocked names and the private-address test,
but every address its host resolves to must still be outside the
always-refused set (link-local, the fixed cloud metadata addresses,
multicast, unspecified, reserved, every IPv4-mapped address, and a 6to4,
Teredo or NAT64 address embedding one of these); any other URL, whoever
supplied it (a probed server's `resource_metadata` or `authorization_servers`,
a `Location`), gets the full rules. `allow_private=False` is accepted with its old meaning; the old global
`allow_private=True` is refused. `_gate`, when set, is called before every
connection (the probe phase's request budget, `probing.py`) and may raise
`FetchError`.

One of the three modules of `spellwarden_cli` that may reach the network
(`tests/test_network_boundary.py`). Python 3.11 or newer.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from spellwarden_scan.version import __version__

MAX_REDIRECTS = 5
ARCHIVE_MAX = 20 * 2**20
JSON_MAX = 2**20
STREAM_HEAD_MAX = 4096
TIMEOUT_SECONDS = 10.0  # per request, redirects included: a deadline, not only a per-read socket timeout
_CHUNK = 65536
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_BLOCKED_NAMES = ("localhost",)
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
# Never sent from a caller: credentials, and the headers this module or `http.client` owns (a caller-supplied `Host`
# would address another virtual host at the checked address).
_FORBIDDEN_HEADERS = ("authorization", "cookie", "proxy-authorization", "host", "content-length", "transfer-encoding",
                      "connection", "user-agent")
_ORIGIN_BOUND_PREFIX = "mcp"


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return value
        return None


class FetchError(Exception):
    """`code` is one of `not_https`, `private_address`, `too_large`,
    `fetch_failed`, `too_many_redirects` (and `budget` from the probe phase's
    gate); `detail` never holds a body."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _abort(connection) -> None:
    """The deadline watchdog: shuts the connection's socket down, which ends any blocked connect, handshake, send
    or receive at once (a socket timeout bounds one operation, never a server that drips bytes)."""
    sock = getattr(connection, "sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def is_private_address(ip: str) -> bool:
    """True for every address a fetch must not reach; an unparsable string counts as private."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if parsed.version == 4 and parsed in _CGNAT:
        return True
    return bool(parsed.is_loopback or parsed.is_private or parsed.is_link_local or parsed.is_multicast
                or parsed.is_reserved or parsed.is_unspecified)


# The documented fixed cloud metadata addresses outside 169.254.0.0/16 (r2:F11): AWS IMDS over IPv6, Alibaba Cloud
# ECS, Oracle Compute Cloud@Customer. GCP, Azure, OCI, OpenStack and most others use 169.254.169.254 (link-local).
# Compared by value, so a zone id (`fd00:ec2::254%eth0`) does not hide one.
_METADATA_ADDRESSES = frozenset((address.version, int(address)) for address in map(ipaddress.ip_address, (
    "fd00:ec2::254", "100.100.100.200", "192.0.0.192")))
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _refused_as_such(parsed: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool((parsed.version, int(parsed)) in _METADATA_ADDRESSES or parsed.is_link_local or parsed.is_multicast
                or parsed.is_unspecified or parsed.is_reserved)


def is_always_refused_address(ip: str) -> bool:
    """True for every address no fetch may reach, a configured private origin included: link-local (the cloud
    metadata address), the other fixed cloud metadata addresses, multicast, unspecified, reserved, every IPv4-mapped
    form, and a 6to4, Teredo (server or client) or NAT64 (`64:ff9b::/96`) address whose embedded IPv4 address is one
    of these; an unparsable string counts."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if parsed.version == 6:
        if parsed.ipv4_mapped is not None:
            return True
        embedded = list(parsed.teredo or ())
        if parsed.sixtofour is not None:
            embedded.append(parsed.sixtofour)
        if parsed.scope_id is None and parsed in _NAT64:
            embedded.append(ipaddress.IPv4Address(int(parsed) & 0xFFFFFFFF))
        if any(_refused_as_such(address) for address in embedded):
            return True
    return _refused_as_such(parsed)


def default_resolver(host: str) -> list[str]:
    """Every address `host` resolves to (A and AAAA), as strings."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise FetchError("fetch_failed", f"resolve {type(exc).__name__}") from None
    return sorted({info[4][0] for info in infos})


def check_host(host: str, resolver: Callable[[str], list[str]], *, allow_private: bool = False) -> str:
    """The address to connect to, after the rules of the module docstring; raises
    `FetchError("private_address")`. `allow_private` is for the host of a
    configured private origin only (the fetcher decides per request): the
    blocked names and the public-address test are skipped, the always-refused
    set, the lookup and the pinning are not."""
    name = host.strip("[]").lower()
    if not name:
        raise FetchError("private_address", "blocked name")
    if not allow_private and (name in _BLOCKED_NAMES or name.endswith(_BLOCKED_SUFFIXES)):
        raise FetchError("private_address", "blocked name")
    try:
        ipaddress.ip_address(name)
        literal = True
    except ValueError:
        literal = False
    addresses = [name] if literal else resolver(name)
    if not addresses:
        raise FetchError("fetch_failed", "no address")
    refused = is_always_refused_address if allow_private else is_private_address
    for address in addresses:
        if refused(address):
            raise FetchError("private_address", "resolved to a private address")
    return addresses[0]


class _PinnedConnection(http.client.HTTPSConnection):
    """An HTTPS connection to `pinned_ip` that keeps `host` for SNI and `Host`."""

    def __init__(self, host: str, pinned_ip: str, port: int, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.pinned_ip = pinned_ip
        self._ssl_context = ssl.create_default_context()

    def connect(self) -> None:
        sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        # The TLS socket takes over the descriptor of `sock`: it is exposed as `self.sock` before the handshake, so the
        # deadline watchdog (`_abort`) can shut it while a slow server drags the handshake out.
        self.sock = self._ssl_context.wrap_socket(sock, server_hostname=self.host, do_handshake_on_connect=False)
        self.sock.do_handshake()


def pinned_connection(host: str, ip: str, port: int, timeout: float) -> _PinnedConnection:
    """The default opener."""
    return _PinnedConnection(host, ip, port, timeout)


def _clean_headers(headers: dict[str, str] | None) -> dict[str, str]:
    return {name: value for name, value in (headers or {}).items() if name.lower() not in _FORBIDDEN_HEADERS}


def without(headers: dict[str, str] | None, *names: str) -> dict[str, str]:
    """`headers` without `names`, compared without case (`content-type` and `Content-Type` are one header)."""
    dropped = {name.lower() for name in names}
    return {name: value for name, value in (headers or {}).items() if name.lower() not in dropped}


def is_event_stream(content_type: str | None) -> bool:
    return (content_type or "").split(";", 1)[0].strip().lower() == "text/event-stream"


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    return parts.scheme, (parts.hostname or "").lower(), parts.port or 443


def _origins(urls: Iterable[str]) -> frozenset[tuple[str, str, int]]:
    """The origins of `urls`; a URL that does not parse is left out (it pins nothing)."""
    origins = set()
    for url in urls:
        try:
            origins.add(_origin(url))
        except ValueError:
            continue
    return frozenset(origins)


def _without_mcp_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name: value for name, value in headers.items() if not name.lower().startswith(_ORIGIN_BOUND_PREFIX)}


class Fetcher:
    """`get`, `post_json` and `get_stream_head` over the rules above. The
    `resolver`, the `opener` and the `clock` are injectable so tests open no
    socket and wait for nothing."""

    def __init__(self, *, release: str = "dev", resolver: Callable[[str], list[str]] | None = None, opener=None,
                 timeout: float = TIMEOUT_SECONDS, on_event: Callable[[str, dict], None] | None = None,
                 clock: Callable[[], float] | None = None, user_agent: str | None = None,
                 allow_private: bool = False, private_origins: Iterable[str] = ()) -> None:
        if allow_private:  # the global exemption let a probed server's URLs reach any private address (spec 6.8)
            raise ValueError("allow_private=True is replaced by private_origins: the configured URLs that may be private")
        self._release = release
        self._resolver = resolver or default_resolver
        self._opener = opener or pinned_connection
        self._timeout = timeout
        self._on_event = on_event
        self._clock = clock or time.monotonic
        self._user_agent = user_agent or f"Spellwarden/{__version__} (+https://spellwarden.ai)"
        self._private_origins = _origins(private_origins)
        self._gate: Callable[[], None] | None = None

    def get(self, url: str, *, max_bytes: int, accept: str = "*/*", headers: dict[str, str] | None = None) -> Response:
        return self._request("GET", url, None, {**without(headers, "Accept"), "Accept": accept}, max_bytes)

    def post_json(self, url: str, body: dict, headers: dict[str, str], *, max_bytes: int = JSON_MAX) -> Response:
        # The content headers of a JSON-RPC POST are this module's, whatever the caller's spelling; a caller adds
        # `Mcp-*` headers, nothing else wins. An event-stream answer is read as a head.
        sent = {**without(headers, "Content-Type", "Accept"), "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"}
        return self._request("POST", url, json.dumps(body).encode("utf-8"), sent, max_bytes)

    def get_stream_head(self, url: str) -> Response:
        return self._request("GET", url, None, {"Accept": "text/event-stream"}, STREAM_HEAD_MAX, head_only=True)

    def _left(self, deadline: float | None, default: float | None) -> float | None:
        """Seconds until `deadline` (`default` without one); `fetch_failed` once it has passed."""
        if deadline is None:
            return default
        left = deadline - self._clock()
        if left <= 0:
            raise FetchError("fetch_failed", "deadline")
        return left

    def _request(self, method: str, url: str, body: bytes | None, headers: dict[str, str], max_bytes: int,
                 *, head_only: bool = False) -> Response:
        current = url
        sent = dict(headers)
        deadline = self._clock() + self._timeout  # a server that drips bytes cannot hold a request past it
        for hop in range(MAX_REDIRECTS + 1):
            response, location = self._one(method, current, body, sent, max_bytes, head_only, deadline)
            if location is None or method == "POST":
                return response
            if hop == MAX_REDIRECTS:
                raise FetchError("too_many_redirects")
            try:
                following = urljoin(current, location)
                changed = _origin(following) != _origin(current)
            except ValueError as exc:  # an unparsable Location (a bad port, a malformed netloc) is a failed fetch, never a traceback
                raise FetchError("fetch_failed", f"redirect {type(exc).__name__}") from None
            if changed:
                sent = _without_mcp_headers(sent)
            current = following
        raise FetchError("too_many_redirects")

    def _one(self, method: str, url: str, body: bytes | None, headers: dict[str, str], max_bytes: int,
             head_only: bool, deadline: float | None = None) -> tuple[Response, str | None]:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise FetchError("not_https")
        if self._gate is not None:  # the probe phase's budget: no new lookup or connection once it is spent
            self._gate()
        host = parts.hostname or ""
        ip = check_host(host, self._resolver, allow_private=self._is_private_origin(url))
        port = parts.port or 443
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        sent = _clean_headers(headers)
        sent["User-Agent"] = self._user_agent
        started = time.monotonic()
        connection = None
        watchdog = None
        try:
            connection = self._opener(host, ip, port, self._left(deadline, self._timeout))
            if deadline is not None:  # the connection connects inside `request`: the watchdog covers it all
                watchdog = threading.Timer(max(0.0, deadline - self._clock()), _abort, (connection,))
                watchdog.daemon = True
                watchdog.start()
            connection.request(method, path, body, sent)
            raw = connection.getresponse()
            status = int(raw.status)
            response_headers = {str(name): str(value) for name, value in raw.getheaders()}
            content_type = next((value for name, value in response_headers.items() if name.lower() == "content-type"), None)
            stream = head_only or is_event_stream(content_type)  # an event stream stays open: only its head is read
            data = self._read(raw, min(max_bytes, STREAM_HEAD_MAX) if stream else max_bytes, stream, deadline=deadline,
                              sock=getattr(connection, "sock", None))
        except FetchError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
            late = deadline is not None and self._clock() >= deadline  # the watchdog shut the socket
            raise FetchError("fetch_failed", "deadline" if late else type(exc).__name__) from None
        finally:
            if watchdog is not None:
                watchdog.cancel()
            if connection is not None:
                connection.close()
        if self._on_event is not None:
            self._on_event("net_request", {"host": host, "method": method, "status": status, "bytes": len(data),
                                           "ms": int((time.monotonic() - started) * 1000)})
        response = Response(status, response_headers, data, url)
        location = response.header("location") if status in _REDIRECT_STATUSES else None
        return response, location

    def _is_private_origin(self, url: str) -> bool:
        """True when `url` is on one of the configured private origins; decided for every hop, so a redirect that
        leaves the origin gets the full rules."""
        if not self._private_origins:
            return False
        try:
            return _origin(url) in self._private_origins
        except ValueError:
            return False

    def _read(self, raw, max_bytes: int, head_only: bool, *, deadline: float | None = None, sock=None) -> bytes:
        """Reads in chunks and stops as soon as `max_bytes` is exceeded: an
        over-long body is `too_large` (or cut, for a stream head). Before each
        read the request's `deadline` is checked and the socket's timeout cut
        to the time left: past it the fetch is `fetch_failed` (`deadline`)."""
        chunks: list[bytes] = []
        total = 0
        # Never ask the connection for more than the cap allows. A stream head is read with `read1` (what has
        # arrived, never a wait for a full chunk) and stops at the first complete event (a blank line, `\n\n` or
        # `\r\n\r\n`, found even when it straddles two reads) or at `max_bytes`: an open SSE stream would otherwise
        # block until the timeout fired. A body reads one byte past its cap, which is how an over-long one is told
        # apart from one that fits exactly.
        reader = getattr(raw, "read1", raw.read) if head_only else raw.read
        tail = b""
        while True:
            want = (max_bytes if head_only else max_bytes + 1) - total
            if want <= 0:
                break
            left = self._left(deadline, None)
            if sock is not None and left is not None:
                sock.settimeout(left)
            chunk = reader(min(_CHUNK, want))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if head_only:
                window = tail + chunk
                if b"\n\n" in window or b"\r\n\r\n" in window:
                    break
                tail = window[-3:]
        if total > max_bytes:
            raise FetchError("too_large")
        return b"".join(chunks)
