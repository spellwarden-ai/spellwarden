"""A loopback fake of the Spellwarden service for the connected e2e (O3 plan P23): python fixtures/ci/fake_api.py
--script FILE [--port 0] [--record FILE] [--ready FILE].

It plays the code host's token endpoint (`GET /idtoken`), the exchange and the routes the command calls
(`POST /api/public/ci/token`, `GET /api/v1/orgs`, `GET /api/v1/orgs/{slug}/ci/policy`, `POST .../ci/registry-check`,
`POST .../ci/scans`), from a script: `{"routes": [{"method", "path", "status", "body", "times"?}]}`. A request is answered
by the first route whose method and path (query ignored) match and that has answers left (`times`, default unlimited);
anything else is `404 {"error": "not_found"}` and is recorded with `"unscripted": true`. A body may be the directive
`{"$check": {"dashboard": URL, "refuse": [list names]}}`: the registry-check answer for the request it answers, every item
admitted except the first of each list named in `refuse`, which is not admitted and carries a request link under
`dashboard` (a template for servers). The string `{ci_token}` in a body is replaced by a CI token built here at run time,
so no credential-shaped value is written down in the repository.

`--record FILE` rewrites FILE after every request with the list of `{"method", "path", "headers", "body", "response":
{"status", "body"}}` in arrival order, headers as sent (a test fake: the values are fake). `--ready FILE` is written, once
the socket listens, with the port number. `--port 0` picks a free port. Standard library only, Python 3.11."""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlsplit

CI_TOKEN = "sw" + "t_" + "A" * 40
LISTS = ("skills", "servers", "stdio", "plugins", "marketplaces")


def _substitute(value: object) -> object:
    if isinstance(value, str):
        return value.replace("{ci_token}", CI_TOKEN)
    if isinstance(value, list):
        return [_substitute(item) for item in value]
    if isinstance(value, dict):
        return {key: _substitute(item) for key, item in value.items()}
    return value


def check_answer(directive: dict, request: object) -> dict:
    """The registry-check answer of the `$check` directive for `request`."""
    sent = request if isinstance(request, dict) else {}
    dashboard = str(directive.get("dashboard", "")).rstrip("/")
    refuse = set(directive.get("refuse", ()))
    answer: dict = {"schema": 1}
    for name in LISTS:
        items = []
        for index, item in enumerate(sent.get(name, [])):
            if name in refuse and index == 0:
                if name == "servers":
                    items.append({"path": item.get("path"), "admitted": False, "exported_name": None,
                                  "request_url_template": f"{dashboard}/mcp-servers?add=1&url="})
                elif name == "skills":
                    items.append({"path": item.get("path"), "admitted": False, "exported_name": None,
                                  "request_url": f"{dashboard}/skills?add=upload&name={quote(str(item.get('name')), safe='')}"})
                else:
                    items.append({"path": item.get("path"), "admitted": False, "exported_name": None,
                                  "request_url": f"{dashboard}/registry?allow={name}&identity={quote(str(item.get('identity')), safe='')}"})
            else:
                items.append({"path": item.get("path"), "admitted": True, "exported_name": None, "request_url": None})
        answer[name] = items
    return answer


class Fake:
    def __init__(self, script: dict, record: str | None) -> None:
        self.routes = [dict(route, left=route.get("times")) for route in script["routes"]]
        self.record = record
        self.requests: list[dict] = []
        self.lock = threading.Lock()

    def answer(self, method: str, path: str, body: object) -> tuple[int, object]:
        for route in self.routes:
            if route["method"] == method and route["path"] == path and (route["left"] is None or route["left"] > 0):
                if route["left"] is not None:
                    route["left"] -= 1
                payload = route.get("body")
                if isinstance(payload, dict) and "$check" in payload:
                    payload = check_answer(payload["$check"], body)
                return int(route.get("status", 200)), _substitute(payload)
        return 404, {"error": "not_found", "message": f"nothing is scripted for {method} {path}"}

    def log(self, entry: dict) -> None:
        with self.lock:
            self.requests.append(entry)
            if self.record:
                temporary = f"{self.record}.tmp"
                Path(temporary).write_text(json.dumps(self.requests, indent=2) + "\n", encoding="utf-8")
                os.replace(temporary, self.record)


def make_handler(fake: Fake) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _serve(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw) if raw else None
            except ValueError:
                body = {"unparsed": raw.decode("utf-8", "replace")}
            path = urlsplit(self.path).path
            status, payload = fake.answer(method, path, body)
            entry = {"method": method, "path": self.path, "headers": {key: value for key, value in self.headers.items()},
                     "body": body, "response": {"status": status, "body": payload}}
            if status == 404:
                entry["unscripted"] = True
            fake.log(entry)
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802 -- the http.server names
            self._serve("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._serve("POST")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- silence the access log
            return None

    return Handler


def serve(script: dict, *, port: int = 0, record: str | None = None) -> ThreadingHTTPServer:
    """A listening server (not yet serving): `server.server_address[1]` is the port; tests run `serve_forever` in a thread."""
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(Fake(script, record)))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--script", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--record")
    parser.add_argument("--ready")
    args = parser.parse_args(argv)
    script = json.loads(Path(args.script).read_text(encoding="utf-8"))
    server = serve(script, port=args.port, record=args.record)
    if args.record:
        Path(args.record).write_text("[]\n", encoding="utf-8")
    if args.ready:
        Path(args.ready).write_text(str(server.server_address[1]), encoding="utf-8")
    print(f"fake_api listening on 127.0.0.1:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
