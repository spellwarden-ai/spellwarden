"""A local fake of the endpoints of Zuplo's MCP Gateway that `tests/zuplo_client.py` talks to (Zuplo export spec 7.1,
claim T2): the 401 with `WWW-Authenticate: Bearer resource_metadata=...`, the protected resource metadata (RFC 9728), the
authorization server metadata (RFC 8414), dynamic client registration (RFC 7591), the authorization endpoint with PKCE S256
and the `resource` parameter (RFC 8707) that redirects to a dev-login and then to a consent page with a form, and the token
endpoint, plus two MCP routes `/mcp/a` and `/mcp/b` that accept only a token issued for their own resource. It follows the
flow of https://zuplo.com/docs/mcp-gateway/how-it-works as the spec records it; at the gate's first run the real consent
form's fields are compared with `CONSENT_FIELDS` and this file is corrected to match (the correction is recorded in the
spec's release gate record). Standard library only, loopback only."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

ROUTES = ("/mcp/a", "/mcp/b")
CONSENT_FIELDS = ("request_id", "state", "decision")


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


class FakeGateway:
    def __init__(self) -> None:
        self.clients: dict[str, dict] = {}
        self.requests: dict[str, dict] = {}
        self.codes: dict[str, dict] = {}
        self.tokens: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(self))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def resource(self, route: str) -> str:
        return self.base + route

    def __enter__(self) -> FakeGateway:
        self.thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.server.shutdown()
        self.server.server_close()


def _make_handler(gateway: FakeGateway):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args) -> None:  # noqa: ARG002
            return

        def send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None, kind: str = "application/json") -> None:
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            if body:
                self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def json(self, value: object, status: int = 200) -> None:
            self.send(status, json.dumps(value).encode("utf-8"))

        def redirect(self, location: str, headers: dict[str, str] | None = None) -> None:
            self.send(302, headers={"Location": location, **(headers or {})})

        def signed_in(self) -> bool:
            return "dev_session=1" in (self.headers.get("Cookie") or "")

        def body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length") or 0))

        def do_GET(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            query = {key: values[0] for key, values in parse_qs(url.query).items()}
            gateway.calls.append(("GET", url.path))
            if url.path.startswith("/.well-known/oauth-protected-resource"):
                route = url.path[len("/.well-known/oauth-protected-resource"):]
                if route not in ROUTES:
                    return self.send(404)
                return self.json({"resource": gateway.resource(route), "authorization_servers": [gateway.base],
                                  "bearer_methods_supported": ["header"]})
            if url.path == "/.well-known/oauth-authorization-server":
                return self.json({"issuer": gateway.base, "authorization_endpoint": gateway.base + "/oauth/authorize",
                                  "token_endpoint": gateway.base + "/oauth/token", "registration_endpoint": gateway.base + "/oauth/register",
                                  "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"],
                                  "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"]})
            if url.path == "/oauth/authorize":
                client = gateway.clients.get(query.get("client_id", ""))
                valid = (client is not None and query.get("response_type") == "code" and query.get("code_challenge_method") == "S256"
                         and query.get("redirect_uri") in client["redirect_uris"] and query.get("code_challenge")
                         and query.get("resource") in [gateway.resource(route) for route in ROUTES])
                if not valid:
                    return self.send(400, b'{"error":"invalid_request"}')
                request_id = secrets.token_hex(8)
                gateway.requests[request_id] = query
                return self.redirect("/__zuplo/oauth/dev-login?" + urlencode({"request_id": request_id}))
            if url.path == "/__zuplo/oauth/dev-login":
                return self.redirect("/oauth/consent?" + urlencode({"request_id": query.get("request_id", "")}),
                                     {"Set-Cookie": "dev_session=1; Path=/"})
            if url.path == "/oauth/consent":
                request = gateway.requests.get(query.get("request_id", ""))
                if request is None or not self.signed_in():
                    return self.send(403, b"not signed in", kind="text/plain")
                page = ('<html><body><h1>Allow access?</h1><form method="post" action="/oauth/consent">'
                        f'<input type="hidden" name="request_id" value="{query["request_id"]}">'
                        f'<input type="hidden" name="state" value="{request.get("state", "")}">'
                        '<button type="submit" name="decision" value="deny">Deny</button>'
                        '<button type="submit" name="decision" value="approve">Approve</button></form></body></html>')
                return self.send(200, page.encode("utf-8"), kind="text/html")
            return self.send(404)

        def do_POST(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            gateway.calls.append(("POST", url.path))
            raw = self.body()
            if url.path in ROUTES:
                token = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
                if gateway.tokens.get(token) != gateway.resource(url.path):
                    metadata = gateway.base + "/.well-known/oauth-protected-resource" + url.path
                    return self.send(401, b'{"error":"unauthorized"}', {"WWW-Authenticate": f'Bearer resource_metadata="{metadata}"'})
                message = json.loads(raw or b"{}")
                return self.json({"jsonrpc": "2.0", "id": message.get("id"), "result": {"route": url.path}})
            if url.path == "/oauth/register":
                data = json.loads(raw or b"{}")
                client_id = "client-" + secrets.token_hex(4)
                gateway.clients[client_id] = {"redirect_uris": data.get("redirect_uris", [])}
                return self.json({"client_id": client_id, "redirect_uris": data.get("redirect_uris", [])}, 201)
            if url.path == "/oauth/consent":
                form = {key: values[0] for key, values in parse_qs(raw.decode("utf-8")).items()}
                request = gateway.requests.get(form.get("request_id", ""))
                if request is None or not self.signed_in() or set(form) != set(CONSENT_FIELDS):
                    return self.send(400, b"bad consent form", kind="text/plain")
                target = request["redirect_uri"]
                if form["decision"] != "approve":
                    return self.redirect(target + "?" + urlencode({"error": "access_denied", "state": request.get("state", "")}))
                code = secrets.token_hex(8)
                gateway.codes[code] = request
                return self.redirect(target + "?" + urlencode({"code": code, "state": request.get("state", "")}))
            if url.path == "/oauth/token":
                form = {key: values[0] for key, values in parse_qs(raw.decode("utf-8")).items()}
                request = gateway.codes.pop(form.get("code", ""), None)
                if (request is None or form.get("grant_type") != "authorization_code" or form.get("redirect_uri") != request["redirect_uri"]
                        or form.get("client_id") != request["client_id"] or form.get("resource") != request["resource"]
                        or s256(form.get("code_verifier", "")) != request["code_challenge"]):
                    return self.json({"error": "invalid_grant"}, 400)
                token = secrets.token_urlsafe(24)
                gateway.tokens[token] = request["resource"]
                return self.json({"access_token": token, "token_type": "Bearer", "expires_in": 3600})
            return self.send(404)

    return Handler


if __name__ == "__main__":
    with FakeGateway() as fake:
        print("fake gateway on", fake.base, flush=True)
        threading.Event().wait()
