"""The OAuth 2.1 client of Zuplo's MCP Gateway for the release gate (Zuplo export spec 7.1, "The test client"), following
https://zuplo.com/docs/mcp-gateway/how-it-works: POST to a route without a token and read the 401's `WWW-Authenticate`
`resource_metadata`; fetch the protected resource metadata (RFC 9728) and the authorization server metadata (RFC 8414);
register once by dynamic client registration (RFC 7591) with a loopback redirect URI; start the authorization with PKCE S256
and the `resource` parameter (RFC 8707); follow the redirect to the dev-login with a cookie jar; submit the consent form (its
fields read from the page); receive the code on a loopback listener; exchange it at the token endpoint. A token is bound to
one route, so this is done once for each route. Calls send `Accept: application/json, text/event-stream` and
`MCP-Protocol-Version: 2025-11-25`. The client sends its own User-Agent (Zuplo's API answers Python's default one with a
Cloudflare 403, error 1010). If the real consent page cannot be driven without a browser, `playwright_consent` does that one
step: Playwright is installed in the gate's own environment, never in `make check-node` and never as a dependency.

    python tests/zuplo_client.py call BASE ROUTE METHOD [--name NAME] [--arguments JSON] [--params JSON]
    python tests/zuplo_client.py call BASE ROUTE METHOD --manual    (prints the authorization URL, waits for the code)

Standard library only. The tests run it against `tests/fake_zuplo_oauth.py` on loopback, never against a real project."""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import re
import secrets
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

USER_AGENT = "spellwarden-zuplo-gate/1.6.0 (+https://spellwarden.ai)"
PROTOCOL_VERSION = "2025-11-25"
ACCEPT = "application/json, text/event-stream"
APPROVE = re.compile(r"allow|approve|authori[sz]e|accept|consent|yes|continue", re.I)
_RESOURCE_METADATA = re.compile(r'resource_metadata="([^"]+)"')


class GatewayError(Exception):
    pass


@dataclass
class Reply:
    status: int
    headers: dict[str, str]
    body: bytes

    def text(self) -> str:
        data = gzip.decompress(self.body) if self.headers.get("content-encoding") == "gzip" else self.body
        return data.decode("utf-8")

    def json(self):
        return json.loads(self.text())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class _Form(HTMLParser):
    """The first form of a page: its action, method, hidden fields and submit buttons."""

    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None
        self.method = "get"
        self.hidden: dict[str, str] = {}
        self.buttons: list[tuple[str, str, str]] = []
        self._open = False
        self._button: list | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        values = {name: value or "" for name, value in attrs}
        if tag == "form" and self.action is None:
            self.action, self.method, self._open = values.get("action", ""), values.get("method", "get").lower(), True
        elif self._open and tag == "input" and values.get("type") == "hidden":
            self.hidden[values.get("name", "")] = values.get("value", "")
        elif self._open and tag == "input" and values.get("type") == "submit":
            self.buttons.append((values.get("name", ""), values.get("value", ""), values.get("value", "")))
        elif self._open and tag == "button" and values.get("type", "submit") == "submit":
            self._button = [values.get("name", ""), values.get("value", ""), ""]

    def handle_data(self, data: str) -> None:
        if self._button is not None:
            self._button[2] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "button" and self._button is not None:
            self.buttons.append((self._button[0], self._button[1], self._button[2].strip()))
            self._button = None
        elif tag == "form":
            self._open = False


class _Listener:
    """The loopback redirect URI: it records the `code`, `state` and `error` of the one request it receives."""

    def __init__(self) -> None:
        listener = self
        self.got = threading.Event()
        self.query: dict[str, str] = {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:  # noqa: ARG002
                return

            def do_GET(self) -> None:  # noqa: N802
                listener.query = {key: values[0] for key, values in parse_qs(urlparse(self.path).query).items()}
                listener.got.set()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def uri(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/callback"

    def reset(self) -> None:
        self.got.clear()
        self.query = {}

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def pkce(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def metadata_url(issuer: str) -> str:
    """RFC 8414: the well-known path goes between the host and the path of the issuer."""
    parsed = urlparse(issuer)
    return f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-authorization-server{parsed.path.rstrip('/')}"


def playwright_consent(authorization_url: str, redirect_prefix: str) -> None:
    """Drives the real consent page with Playwright (the gate's own environment only) until the browser is sent to the
    loopback redirect URI. Raises GatewayError when Playwright is not installed."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise GatewayError("Playwright is not installed: install it in the gate's own environment, never as a dependency") from None
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(authorization_url)
        for label in ("Allow", "Approve", "Authorize", "Accept", "Continue"):
            button = page.get_by_role("button", name=re.compile(label, re.I))
            if button.count():
                button.first.click()
                break
        page.wait_for_url(re.compile("^" + re.escape(redirect_prefix)), timeout=60000)
        browser.close()


@dataclass
class GatewayClient:
    base: str
    user_agent: str = USER_AGENT
    consent: Callable[[str, str], None] | None = None
    timeout: float = 60.0
    tokens: dict[str, str] = field(default_factory=dict)
    client_id: str | None = None

    def __post_init__(self) -> None:
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPCookieProcessor(self.jar))
        self.listener = _Listener()

    def close(self) -> None:
        self.listener.close()

    def _open(self, method: str, url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None) -> Reply:
        request = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": self.user_agent, **(headers or {})})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return Reply(response.status, {name.lower(): value for name, value in response.headers.items()}, response.read())
        except urllib.error.HTTPError as error:
            return Reply(error.code, {name.lower(): value for name, value in error.headers.items()}, error.read())

    def _json(self, url: str, **kwargs) -> dict:
        reply = self._open("GET", url, **kwargs)
        if reply.status != 200:
            raise GatewayError(f"GET {url} answered {reply.status}")
        return reply.json()

    def metadata(self, route: str) -> dict:
        """Steps 1 to 3 of the flow: the 401, the resource metadata and the authorization server metadata."""
        probe = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}
        reply = self._open("POST", self.base + route, data=json.dumps(probe).encode("utf-8"),
                           headers={"Content-Type": "application/json", "Accept": ACCEPT})
        found = _RESOURCE_METADATA.search(reply.headers.get("www-authenticate", ""))
        if reply.status != 401 or found is None:
            raise GatewayError(f"POST {route} without a token answered {reply.status}, expected a 401 with resource_metadata")
        resource = self._json(found.group(1))
        server = self._json(metadata_url(resource["authorization_servers"][0]))
        if "S256" not in server.get("code_challenge_methods_supported", []):
            raise GatewayError("the authorization server does not offer PKCE S256")
        return {"resource": resource["resource"], **server}

    def register(self, server: dict) -> str:
        if self.client_id is None:
            body = {"client_name": "spellwarden-zuplo-gate", "redirect_uris": [self.listener.uri], "grant_types": ["authorization_code"],
                    "response_types": ["code"], "token_endpoint_auth_method": "none"}
            reply = self._open("POST", server["registration_endpoint"], data=json.dumps(body).encode("utf-8"),
                               headers={"Content-Type": "application/json"})
            if reply.status not in (200, 201):
                raise GatewayError(f"client registration answered {reply.status}")
            self.client_id = reply.json()["client_id"]
        return self.client_id

    def _submit_consent(self, page: Reply, url: str) -> Reply:
        form = _Form()
        form.feed(page.text())
        if form.action is None or form.method != "post":
            raise GatewayError("the consent page has no form that posts")
        chosen = next(((name, value) for name, value, text in form.buttons if APPROVE.search(f"{value} {text}")), None)
        if chosen is None:
            raise GatewayError(f"no button of the consent form reads as an approval: hidden fields {sorted(form.hidden)}, buttons {form.buttons}")
        fields = {**form.hidden, chosen[0]: chosen[1]}
        return self._open("POST", urljoin(url, form.action), data=urlencode(fields).encode("utf-8"),
                          headers={"Content-Type": "application/x-www-form-urlencoded"})

    def _drive(self, url: str) -> None:
        """Follows the authorization request to the loopback redirect, signing in and approving on the way."""
        for _ in range(10):
            reply = self._open("GET", url)
            while 300 <= reply.status < 400:
                url = urljoin(url, reply.headers["location"])
                if url.startswith(self.listener.uri):
                    self._open("GET", url)
                    return
                reply = self._open("GET", url)
            if reply.status != 200:
                raise GatewayError(f"the authorization flow answered {reply.status} at {url}")
            reply = self._submit_consent(reply, url)
            if 300 <= reply.status < 400:
                final = urljoin(url, reply.headers["location"])
                if final.startswith(self.listener.uri):
                    self._open("GET", final)
                    return
                url = final
                continue
            raise GatewayError(f"the consent form answered {reply.status}")
        raise GatewayError("the authorization flow did not reach the redirect URI")

    def token_for(self, route: str, *, manual: bool = False, wait: float = 600.0) -> str:
        """An access token for `route` (RFC 8707: bound to that route's resource), cached for the next call."""
        if route in self.tokens:
            return self.tokens[route]
        server = self.metadata(route)
        client_id = self.register(server)
        verifier, state = secrets.token_urlsafe(64), secrets.token_urlsafe(16)
        url = server["authorization_endpoint"] + "?" + urlencode({
            "response_type": "code", "client_id": client_id, "redirect_uri": self.listener.uri, "code_challenge": pkce(verifier),
            "code_challenge_method": "S256", "state": state, "resource": server["resource"]})
        self.listener.reset()
        if manual:
            print(f"Open this URL, sign in and approve:\n{url}", flush=True)
        elif self.consent is not None:
            self.consent(url, self.listener.uri)
        else:
            self._drive(url)
        if not self.listener.got.wait(wait):
            raise GatewayError("no redirect reached the loopback listener")
        if self.listener.query.get("state") != state or "code" not in self.listener.query:
            raise GatewayError(f"the redirect did not carry the code and the state: {sorted(self.listener.query)}")
        form = {"grant_type": "authorization_code", "code": self.listener.query["code"], "code_verifier": verifier, "client_id": client_id,
                "redirect_uri": self.listener.uri, "resource": server["resource"]}
        reply = self._open("POST", server["token_endpoint"], data=urlencode(form).encode("utf-8"),
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
        if reply.status != 200:
            raise GatewayError(f"the token endpoint answered {reply.status}")
        self.tokens[route] = reply.json()["access_token"]
        return self.tokens[route]

    def call(self, route: str, message: dict, *, manual: bool = False) -> Reply:
        token = self.token_for(route, manual=manual)
        return self._open("POST", self.base + route, data=json.dumps(message).encode("utf-8"), headers={
            "Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": ACCEPT, "MCP-Protocol-Version": PROTOCOL_VERSION})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Call a route of a Zuplo MCP Gateway as an OAuth client (the release gate).")
    parser.add_argument("action", choices=["call"])
    parser.add_argument("base")
    parser.add_argument("route")
    parser.add_argument("method")
    parser.add_argument("--name")
    parser.add_argument("--arguments", default="{}")
    parser.add_argument("--params", help="the whole params object, instead of --name and --arguments")
    parser.add_argument("--manual", action="store_true")
    parser.add_argument("--playwright", action="store_true")
    args = parser.parse_args(argv)
    params = json.loads(args.params) if args.params else {"name": args.name, "arguments": json.loads(args.arguments)} if args.name else {}
    client = GatewayClient(args.base, consent=playwright_consent if args.playwright else None)
    try:
        reply = client.call(args.route, {"jsonrpc": "2.0", "id": 1, "method": args.method, "params": params}, manual=args.manual)
    finally:
        client.close()
    print(reply.status)
    for name, value in sorted(reply.headers.items()):
        print(f"{name}: {value}")
    print()
    print(reply.text()[:4000])
    return 0 if reply.status == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
