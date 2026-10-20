"""A recorded-exchange opener with the call shape of `urllib.request.urlopen(request, timeout=)`, for the comment
and ping tests: answers by method and full URL, raises `HTTPError` for a status of 400 or more as `urlopen` does,
records every request. An unrecorded request is a `URLError`, never a connection."""
from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message
from pathlib import Path

RECORDED = Path(__file__).resolve().parents[1] / "recorded"


def load(name: str, scenario: str) -> list[dict]:
    """`tests/recorded/<name>.json` holds `{scenario: [{"method", "url", "status", "body"}]}`."""
    return json.loads((RECORDED / f"{name}.json").read_text())[scenario]


class _Response:
    def __init__(self, status: int, data: bytes) -> None:
        self.status, self._data = status, data

    def read(self, amt: int | None = None) -> bytes:
        return self._data if amt is None else self._data[:amt]

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        return None


class RecordedOpener:
    def __init__(self, exchanges: list[dict]) -> None:
        self.routes: dict[tuple[str, str], list[dict]] = {}
        self.requests: list[dict] = []
        for exchange in exchanges:
            self.routes.setdefault((exchange["method"], exchange["url"]), []).append(exchange)

    def __call__(self, request, timeout=None):
        method, url = request.get_method(), request.full_url
        self.requests.append({"method": method, "url": url, "timeout": timeout,
                              "headers": {name.lower(): value for name, value in request.header_items()},
                              "body": json.loads(request.data) if request.data else None})
        answers = self.routes.get((method, url))
        if not answers:
            raise urllib.error.URLError(f"no recorded exchange for {method} {url}")
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        data = json.dumps(answer.get("body")).encode("utf-8") if "body" in answer else b""
        if answer["status"] >= 400:
            raise urllib.error.HTTPError(url, answer["status"], "recorded", Message(), io.BytesIO(data))
        return _Response(answer["status"], data)
