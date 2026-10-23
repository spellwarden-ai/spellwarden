"""The usage ping (spec 6.10): one POST per `spellwarden scan` in CI, at the end, with exactly five fields, so the
hosted backend can count organisations running the free scanner (kill criterion K2). Pseudonymous, not anonymous:
`org` is a hash of a public installation identity, which anyone who knows the identity can recompute.

Sent only in CI and only with telemetry on. Off with `--no-telemetry`, `SPELLWARDEN_TELEMETRY=off` (or `0`,
`false`, `no`), `DO_NOT_TRACK=1`, `telemetry: false` in `.spellwarden/config.yml`, or the wrappers' `telemetry`
input. Every error is swallowed and the request runs in a daemon thread that the scan waits for at most `wait`
seconds (plan decision P11: `urllib`'s timeout does not bound a hung DNS lookup), so the ping never changes the
outputs or the exit code; with `--verbose` it prints one line.

`SPELLWARDEN_PING_URL` is a test hook (spec 7.4, D25): honoured only for loopback HTTP
(`http://127.0.0.1:<port>/<path>`, `http://[::1]:<port>/<path>`, `http://localhost:<port>/<path>`, the last
connected to 127.0.0.1), ignored otherwise.

One of the three modules of `spellwarden_cli` that may reach the network (`tests/test_network_boundary.py`)."""
from __future__ import annotations

import json
import re
import threading
import urllib.request
from collections.abc import Callable, Mapping

from spellwarden_scan.version import RULES_VERSION, __version__

from spellwarden_cli.ci import CiContext, org_hash
from spellwarden_cli.settings import env_bool

DEFAULT_URL = "https://dash.spellwarden.ai/api/public/ping"
TIMEOUT_SECONDS = 2
_urlopen = urllib.request.urlopen  # tests replace it (tests/conftest.py keeps every test off the network)
_LOOPBACK = re.compile(r"http://(127\.0\.0\.1|\[::1\]|localhost):([0-9]{1,5})(/[A-Za-z0-9._~/-]*)?")


def ping_body(ctx: CiContext, *, version: str, rules_version: str) -> dict:
    """The five fields, and nothing else (spec 2 invariant 3)."""
    ci = ctx.provider if ctx.provider in ("github", "gitlab") else "other"
    return {"schema": 1, "version": version, "rules_version": rules_version, "ci": ci, "org": org_hash(ctx.identity)}


def loopback_url(raw: str) -> str | None:
    """`raw` in the form of the test hooks (D25): `http://127.0.0.1:<port>/<path>`, `http://[::1]:<port>/<path>` or
    `http://localhost:<port>/<path>` (written with 127.0.0.1); None for anything else. `SPELLWARDEN_API_URL` (O3
    spec 6.2) follows the same rule."""
    match = _LOOPBACK.fullmatch(raw)
    if match is None or not 1 <= int(match.group(2)) <= 65535:
        return None
    host = "127.0.0.1" if match.group(1) == "localhost" else match.group(1)
    return f"http://{host}:{int(match.group(2))}{match.group(3) or '/'}"


def ping_url(env: Mapping[str, str]) -> tuple[str, bool]:
    """The endpoint and whether a set `SPELLWARDEN_PING_URL` was ignored (it is honoured for loopback HTTP only)."""
    raw = env.get("SPELLWARDEN_PING_URL")
    if not raw:
        return DEFAULT_URL, False
    url = loopback_url(raw)
    return (DEFAULT_URL, True) if url is None else (url, False)


def telemetry_off(env: Mapping[str, str]) -> bool:
    """The environment's opt-outs, checked again here whatever the settings resolved."""
    return env_bool(env.get("SPELLWARDEN_TELEMETRY")) is False or env_bool(env.get("DO_NOT_TRACK")) is True


def send_ping(ctx: CiContext, *, telemetry: bool, env: Mapping[str, str], log: Callable[[str], None],
              opener: Callable[..., object] | None = None, wait: float = 2.5) -> None:
    """Spec 6.10. Never raises; returns after at most `wait` seconds whatever the network does."""
    try:
        if ctx.provider is None or not telemetry or telemetry_off(env):
            return
        url, ignored = ping_url(env)
        body = json.dumps(ping_body(ctx, version=__version__, rules_version=RULES_VERSION),
                          separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json", "User-Agent": f"Spellwarden/{__version__} (+https://spellwarden.ai)"})
        outcome: dict[str, str] = {}
        send = opener or _urlopen

        def worker() -> None:
            try:
                with send(request, timeout=TIMEOUT_SECONDS) as response:
                    outcome["status"] = str(getattr(response, "status", "sent"))
            except Exception as exc:  # noqa: BLE001 -- the ping never fails a scan
                outcome["error"] = type(exc).__name__

        thread = threading.Thread(target=worker, name="spellwarden-ping", daemon=True)
        thread.start()
        thread.join(wait)
        result = outcome.get("status") or outcome.get("error") or f"abandoned after {wait:g} s"
        note = " (SPELLWARDEN_PING_URL ignored: loopback HTTP only)" if ignored else ""
        log(f"ping: {result}{note}")
    except Exception:  # noqa: BLE001 -- nothing about the ping changes the outputs or the exit code
        return
