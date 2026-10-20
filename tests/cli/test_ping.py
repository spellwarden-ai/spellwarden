"""Spec 6.10 and claim C15: the usage ping. Only in CI, never with an opt-out, exactly five fields, bounded in time
(plan decision P11, Review Focus 5), and the loopback-only test hook."""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from spellwarden_cli import RULES_VERSION, __version__, ci, ping

GITHUB = ci.CiContext(provider="github", event="pull_request", is_request=True, request_number=7, fork=False,
                      dependabot=False, protected_ref=False, identity="github:github.com:1234567")


class Recorder:
    def __init__(self, fail: Exception | None = None) -> None:
        self.requests: list[urllib.request.Request] = []
        self.fail = fail

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        self.timeout = timeout
        if self.fail is not None:
            raise self.fail
        return _Ok()


class _Ok:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return None


def send(ctx=GITHUB, *, telemetry=True, env=None, opener=None, wait=2.5):
    lines: list[str] = []
    recorder = opener or Recorder()
    ping.send_ping(ctx, telemetry=telemetry, env=env or {}, log=lines.append, opener=recorder, wait=wait)
    return recorder, lines


def test_the_body_is_exactly_the_five_fields():
    recorder, lines = send()
    (request,) = recorder.requests
    body = json.loads(request.data)
    assert body == {"schema": 1, "version": __version__, "rules_version": RULES_VERSION, "ci": "github",
                    "org": "6ece64f2db0ecee34de1a73b2ad0effdf128e6b7a1a2babdb36203d72f61a785"}
    assert request.full_url == ping.DEFAULT_URL and request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/json" and recorder.timeout == 2
    assert lines == ["ping: 204"]


def test_ci_kind_and_a_missing_identity():
    other = ci.CiContext(provider="other", event=None, is_request=False, request_number=None, fork=False,
                         dependabot=False, protected_ref=False, identity=None)
    assert ping.ping_body(other, version="1.0.0", rules_version="2027.01.1") == {
        "schema": 1, "version": "1.0.0", "rules_version": "2027.01.1", "ci": "other", "org": None}


def test_nothing_is_sent_outside_ci():
    recorder, lines = send(ci.LOCAL)
    assert recorder.requests == [] and lines == []


@pytest.mark.parametrize("env", [{"SPELLWARDEN_TELEMETRY": value} for value in ("off", "0", "false", "no", "OFF")]
                         + [{"DO_NOT_TRACK": "1"}])
def test_every_environment_opt_out_holds(env):
    recorder, _ = send(env=env)
    assert recorder.requests == []


def test_telemetry_off_in_the_settings_or_the_flag_sends_nothing():
    recorder, _ = send(telemetry=False)
    assert recorder.requests == []


def test_an_error_is_swallowed_and_reported_on_one_verbose_line():
    recorder, lines = send(opener=Recorder(fail=OSError("unreachable")))
    assert len(recorder.requests) == 1 and lines == ["ping: OSError"]


def test_a_hanging_opener_is_abandoned_after_the_wait():
    """Review Focus 5: a resolver that never answers must not hold the job; `urllib`'s timeout does not bound DNS."""
    release = threading.Event()

    def hang(_request, timeout=None):  # noqa: ARG001 -- the shape of urlopen
        release.wait(30)
        raise OSError("released")

    started = time.monotonic()
    _, lines = send(opener=hang, wait=0.3)
    elapsed = time.monotonic() - started
    release.set()
    assert elapsed < 1.5 and lines == ["ping: abandoned after 0.3 s"]


@pytest.mark.parametrize(("raw", "expected"), [
    ("http://127.0.0.1:8123/ping", "http://127.0.0.1:8123/ping"),
    ("http://127.0.0.1:8123/", "http://127.0.0.1:8123/"),
    ("http://[::1]:8123/api/public/ping", "http://[::1]:8123/api/public/ping"),
    ("http://localhost:8123/ping", "http://127.0.0.1:8123/ping"),
])
def test_the_test_hook_is_honoured_for_loopback_http(raw, expected):
    assert ping.ping_url({"SPELLWARDEN_PING_URL": raw}) == (expected, False)


@pytest.mark.parametrize("raw", ["https://example.com/", "http://169.254.169.254/", "http://10.0.0.1/",
                                 "http://localhost.example.com/", "http://127.0.0.1/", "http://127.0.0.1:0/",
                                 "http://127.0.0.1:8123@evil.example/", "http://127.0.0.1:8123/?next=x",
                                 "http://127.0.0.1:99999/", "ftp://127.0.0.1:21/"])
def test_the_test_hook_is_ignored_for_anything_else(raw):
    assert ping.ping_url({"SPELLWARDEN_PING_URL": raw}) == (ping.DEFAULT_URL, True)
    recorder, lines = send(env={"SPELLWARDEN_PING_URL": raw})
    assert recorder.requests[0].full_url == ping.DEFAULT_URL
    assert lines == ["ping: 204 (SPELLWARDEN_PING_URL ignored: loopback HTTP only)"]


def test_a_real_loopback_listener_receives_exactly_the_five_fields():
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            return None

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = {"SPELLWARDEN_PING_URL": f"http://127.0.0.1:{server.server_port}/api/public/ping"}
        _, lines = send(env=env, opener=urllib.request.urlopen)
    finally:
        server.shutdown()
    assert lines == ["ping: 204"]
    assert [sorted(body) for body in received] == [["ci", "org", "rules_version", "schema", "version"]]


# --- through `spellwarden scan` (the autouse fixture `ping_requests` of tests/conftest.py records what is sent) ---

GITHUB_RUN = {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_SERVER_URL": "https://github.com",
              "GITHUB_REPOSITORY_OWNER_ID": "1234567"}


def scan_in_ci(monkeypatch, repo, *args: str, env: dict | None = None) -> tuple[int, bytes]:
    from spellwarden_cli.main import main

    # A readable push event: without one the run counts as a pull request (6.11), whose settings file is read from
    # its base revision (D35), not from `repo`.
    event = repo.parent / f"{repo.name}-event.json"
    event.write_text('{"ref": "refs/heads/main"}', encoding="utf-8")
    for name, value in {**GITHUB_RUN, "GITHUB_EVENT_PATH": str(event), **(env or {})}.items():
        monkeypatch.setenv(name, value)
    report = repo.parent / f"{repo.name}-report.json"
    code = main(["scan", str(repo), "--format", "json", "--output", str(report), *args])
    return code, report.read_bytes()


def test_a_scan_in_ci_pings_once(tmp_path, monkeypatch, make_repo, ping_requests):
    repo = make_repo(tmp_path / "repo", {"README.md": "nothing to scan\n"})
    code, _ = scan_in_ci(monkeypatch, repo)
    assert code == 0 and len(ping_requests) == 1
    assert json.loads(ping_requests[0].data)["org"] == "6ece64f2db0ecee34de1a73b2ad0effdf128e6b7a1a2babdb36203d72f61a785"


def test_a_scan_on_a_ci_without_ci_true_pings_as_other(tmp_path, monkeypatch, make_repo, ping_requests):
    from spellwarden_cli.main import main

    repo = make_repo(tmp_path / "repo", {"README.md": "nothing to scan\n"})
    monkeypatch.setenv("JENKINS_URL", "https://jenkins.acme.example/")
    assert main(["scan", str(repo), "--format", "json", "--output", str(tmp_path / "r.json")]) == 0
    assert [json.loads(request.data)["ci"] for request in ping_requests] == ["other"]


def test_a_local_scan_never_pings(tmp_path, make_repo, ping_requests):
    from spellwarden_cli.main import main

    repo = make_repo(tmp_path / "repo", {"README.md": "nothing to scan\n"})
    assert main(["scan", str(repo), "--format", "json", "--output", str(tmp_path / "r.json")]) == 0
    assert ping_requests == []


@pytest.mark.parametrize(("args", "env", "files"), [
    (("--no-telemetry",), {}, {}),
    ((), {"SPELLWARDEN_TELEMETRY": "off"}, {}),
    ((), {"SPELLWARDEN_TELEMETRY": "0"}, {}),
    ((), {"DO_NOT_TRACK": "1"}, {}),
    ((), {}, {".spellwarden/config.yml": "version: 1\ntelemetry: false\n"}),
], ids=["flag", "env off", "env 0", "DO_NOT_TRACK", "settings file"])
def test_each_opt_out_of_a_scan_sends_nothing(tmp_path, monkeypatch, make_repo, ping_requests, args, env, files):
    repo = make_repo(tmp_path / "repo", {"README.md": "nothing to scan\n", **files})
    code, _ = scan_in_ci(monkeypatch, repo, *args, env=env)
    assert code == 0 and ping_requests == []


def test_the_other_commands_never_ping(tmp_path, monkeypatch, make_repo, ping_requests):
    from spellwarden_cli.main import main

    repo = make_repo(tmp_path / "repo", {"README.md": "nothing to scan\n"})
    for name, value in GITHUB_RUN.items():
        monkeypatch.setenv(name, value)
    for argv in (["version"], ["rules"], ["lock", str(repo)], ["baseline", "list", str(repo)]):
        main(argv)
    assert ping_requests == []


def test_a_failing_ping_changes_neither_outputs_nor_exit_code(tmp_path, monkeypatch, make_repo, ping_requests):
    repo = make_repo(tmp_path / "repo", {".mcp.json": '{"mcpServers": {"plain": {"url": "http://mcp.example.com/mcp"}}}\n'})
    sent_code, sent_report = scan_in_ci(monkeypatch, repo)
    assert len(ping_requests) == 1

    def refuse(_request, timeout=None):  # noqa: ARG001 -- the shape of urlopen
        raise OSError("network unreachable")

    monkeypatch.setattr(ping, "_urlopen", refuse)
    failed_code, failed_report = scan_in_ci(monkeypatch, repo)
    assert (failed_code, failed_report) == (sent_code, sent_report) and sent_code == 1
