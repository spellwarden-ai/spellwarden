"""The test double of `spellwarden_cli.net.Fetcher` (Phase B spec 6.12): answers
recorded exchanges keyed by method and URL, records every request, and keeps
the real fetcher's refusals (`http://`, the byte cap) so a test cannot pass a
request the product would refuse. An unknown URL is `FetchError("unreachable")`."""
from __future__ import annotations

import base64
import io
import json
import zipfile
from pathlib import Path

from spellwarden_cli.net import JSON_MAX, MAX_REDIRECTS, FetchError, Response, without

RECORDED = Path(__file__).resolve().parents[1] / "recorded"  # tests/recorded/ (spec 6.8)


def _body_bytes(body) -> tuple[bytes, str | None]:
    """The bytes of an exchange body and the content type it implies (an explicit header always wins): bytes are
    `application/octet-stream` (an archive), strings `text/plain` (what raw.githubusercontent.com serves), JSON values
    `application/json`; the steps check these types (spec 6.8a), so every exchange carries one."""
    if isinstance(body, bytes):
        return body, "application/octet-stream"
    if isinstance(body, str):
        return body.encode("utf-8"), "text/plain"
    if isinstance(body, dict) and set(body) == {"json"}:
        return json.dumps(body["json"]).encode("utf-8"), "application/json"
    if isinstance(body, dict) and set(body) == {"text"}:
        return body["text"].encode("utf-8"), "text/plain"
    if isinstance(body, dict) and set(body) == {"base64"}:
        return base64.b64decode(body["base64"]), "application/octet-stream"
    return json.dumps(body).encode("utf-8"), "application/json"


class FakeFetcher:
    def __init__(self, exchanges: list[dict] | None = None) -> None:
        self._routes: dict[tuple[str, str], list[dict]] = {}
        self.requests: list[dict] = []
        for exchange in exchanges or []:
            self.add(exchange["method"], exchange["url"], status=exchange.get("status", 200),
                     headers=exchange.get("headers"), body=exchange.get("body", b""), queue=True)

    def add(self, method: str, url: str, *, status: int = 200, headers: dict | None = None, body=b"", queue: bool = False) -> None:
        """Scripts one answer for `method url`, replacing what was scripted before; with `queue=True`
        the answer is appended and answers are served in order (a recorded sequence does the same)."""
        data, implied = _body_bytes(body)
        sent = dict(headers or {})
        if implied and not any(name.lower() == "content-type" for name in sent):
            sent["Content-Type"] = implied
        answer = {"status": status, "headers": sent, "body": data}
        if queue:
            self._routes.setdefault((method.upper(), url), []).append(answer)
        else:
            self._routes[(method.upper(), url)] = [answer]

    def _answer(self, method: str, url: str, headers: dict, body, max_bytes: int, *, key: str | None = None) -> Response:
        """`key` is the specific lookup (`url#<method>`, `url#stream`) tried before the bare `url`."""
        self.requests.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        if not url.startswith("https://"):
            raise FetchError("not_https")
        answers = self._routes.get((method, key)) if key is not None else None
        if not answers:
            answers = self._routes.get((method, url))
        if not answers:
            raise FetchError("unreachable", f"no recorded exchange for {method} {url}")
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        if len(answer["body"]) > max_bytes:
            raise FetchError("too_large")
        return Response(answer["status"], dict(answer["headers"]), answer["body"], url)

    def get(self, url: str, *, max_bytes: int, accept: str = "*/*", headers: dict[str, str] | None = None,
            redirects: int = MAX_REDIRECTS) -> Response:  # noqa: ARG002 -- the fake never redirects; the shape is the real one's
        return self._answer("GET", url, {**without(headers, "Accept"), "Accept": accept}, None, max_bytes)

    def post_json(self, url: str, body: dict, headers: dict[str, str], *, max_bytes: int = JSON_MAX) -> Response:
        sent = {**without(headers, "Content-Type", "Accept"), "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"}  # the real fetcher's override rule
        method = body.get("method") if isinstance(body, dict) else None
        return self._answer("POST", url, sent, body, max_bytes, key=f"{url}#{method}" if method else None)

    def get_stream_head(self, url: str) -> Response:
        response = self._answer("GET", url, {"Accept": "text/event-stream"}, None, 2**20, key=f"{url}#stream")
        return Response(response.status, response.headers, response.body[:4096], url)


def load_exchanges(name: str) -> list[dict]:
    """`tests/recorded/<name>.json`: a list of `{"method", "url", "status", "headers", "body"}`
    where `body` is `{"json": ...}`, `{"text": "..."}` or `{"base64": "..."}` (README)."""
    return json.loads((RECORDED / f"{name}.json").read_text())


def zip_of(files: dict[str, bytes], *, top: str | None = None) -> bytes:
    """A zip archive of `files` (POSIX paths to bytes), optionally under one top-level directory."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in sorted(files.items()):
            archive.writestr(f"{top}/{path}" if top else path, data)
    return buffer.getvalue()
