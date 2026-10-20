"""A one-request loopback listener for the telemetry case (spec 7.4): python fixtures/ping_listener.py <port> <out>.

Listens on 127.0.0.1 only, writes `<out>.ready` once listening, stores the first POST body in <out>, answers
204, and stops after that request or after 300 seconds."""
from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

OUT = Path(sys.argv[2])


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 (the http.server name)
        length = min(int(self.headers.get("Content-Length") or 0), 65536)
        OUT.write_bytes(self.rfile.read(length))
        self.send_response(204)
        self.end_headers()
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 (the http.server signature)
        return


server = HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
timer = threading.Timer(300, server.shutdown)
timer.daemon = True
timer.start()
Path(f"{OUT}.ready").write_text("ready\n", encoding="utf-8")
server.serve_forever()
