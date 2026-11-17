"""A local fake of an OpenAI-compatible model endpoint for the analyzer's tests (Phase 4 batch B spec 11.3): an HTTP server on a
loopback address that answers each POST with what the test's `answer(handler, body)` returns and records every request. No test
reaches a real model."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeModel:
    """A loopback HTTP server: `answer(handler, body)` returns `(status, headers, bytes)`; every request is recorded as
    `(path, headers, body)`."""

    def __init__(self, answer) -> None:
        self.requests: list[tuple[str, dict, dict | None]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 -- the name http.server calls
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                body = json.loads(raw) if raw else None
                outer.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                status, headers, data = answer(self, body)
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except OSError:
                    pass

            def log_message(self, *_args) -> None:
                return None

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def completion(content) -> bytes:
    """An OpenAI chat completion whose first choice says `content` (a string or a list of text parts)."""
    return json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}], "model": "m"}).encode()
