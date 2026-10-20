"""Spec 6.8 and claim C14, through the `run_probes` step of a scan: `--probe` off by default, off on a fork or
Dependabot pull request, private addresses only on a trusted run, the URL alone on the wire, probe findings
through the baseline. The fetcher's resolver and opener are replaced: no socket is opened."""
from __future__ import annotations

import json
from datetime import date

import pytest

from spellwarden_scan import RuleSet, parse_mcp_config
from spellwarden_cli import net, run
from spellwarden_cli.discover import Discovery
from spellwarden_cli.settings import Settings

RULES = RuleSet.baseline()
OPEN = {"server/discover": {"jsonrpc": "2.0", "id": 1, "result": {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}}},
        "tools/list": {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "query", "description": "Runs a query."}]}}}
PUSH_PROTECTED = {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_REF_PROTECTED": "true"}


class _Answer:
    def __init__(self, status: int, body: bytes) -> None:
        self.status, self._body = status, body

    def getheaders(self):
        return [("Content-Type", "application/json")]

    def read(self, amt=None):
        chunk, self._body = (self._body, b"") if amt is None else (self._body[:amt], self._body[amt:])
        return chunk

    read1 = read


class Wire:
    """Replaces the fetcher's default resolver and opener; every connection is recorded with its headers and body."""

    def __init__(self, monkeypatch, addresses: dict[str, str]) -> None:
        self.calls: list[dict] = []
        monkeypatch.setattr(net, "default_resolver", lambda host: [addresses.get(host, "8.8.8.8")])
        monkeypatch.setattr(net, "pinned_connection", self.open)

    def open(self, host, ip, port, timeout):  # noqa: ARG002 -- the opener's shape
        wire = self

        class Connection:
            def request(self, method, path, body=None, headers=None):
                wire.calls.append({"host": host, "ip": ip, "method": method, "path": path, "headers": dict(headers or {}),
                                   "body": body})
                rpc = json.loads(body)["method"] if body else ""
                self.answer = _Answer(200, json.dumps(OPEN[rpc]).encode()) if rpc in OPEN else _Answer(404, b"")

            def getresponse(self):
                return self.answer

            def close(self):
                pass

        return Connection()


def found_with(servers: dict) -> Discovery:
    document = parse_mcp_config(".mcp.json", json.dumps({"mcpServers": servers}, indent=2).encode("utf-8"))
    return Discovery(items=(), skills=(), documents=(document,), plugin_dirs=(), notices=(), errors=())


def probe(tmp_path, servers: dict, *, env: dict | None = None, **settings):
    options = run.ScanOptions(root=str(tmp_path), settings=Settings(**settings), as_of=date(2026, 12, 1), env=env or {})
    findings: list = []
    notices: list = []
    reports = run.run_probes(options, found_with(servers), RULES, findings, notices)
    return reports, findings, notices


def codes(notices) -> list[str]:
    return sorted(notice.code for notice in notices)


def test_nothing_is_probed_without_the_flag(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {})
    assert probe(tmp_path, {"remote": {"url": "https://mcp.example/mcp"}}) == ([], [], [])
    assert wire.calls == []


def test_a_probed_server_adds_its_findings(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {})
    reports, findings, _ = probe(tmp_path, {"remote": {"url": "https://mcp.example/mcp"}}, probe=True)
    assert [(r.item, r.status) for r in reports] == [(".mcp.json#remote", "probed")]
    assert findings and {f.item for f in findings} == {".mcp.json#remote"} and wire.calls


def test_only_the_url_reaches_the_wire(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {})
    probe(tmp_path, {"remote": {"url": "https://mcp.example/mcp", "headers": {"Authorization": "Bearer sekret-h"},
                                "env": {"TOKEN": "sekret-e"}}}, probe=True)
    assert wire.calls
    for call in wire.calls:  # the probe's own requests echo back nothing of the configuration
        assert "sekret" not in json.dumps(call["headers"]) and b"sekret" not in (call["body"] or b"")
        assert "authorization" not in {name.lower() for name in call["headers"]}


@pytest.mark.parametrize("env", [
    {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REPOSITORY": "acme/agents",
     "GITHUB_EVENT_PATH": "/nonexistent/event.json"},
    {"CI": "true", "GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "merge_request_event", "CI_PROJECT_ID": "42",
     "CI_MERGE_REQUEST_SOURCE_PROJECT_ID": "99"},
], ids=["github pull request with an unreadable event file", "gitlab merge request from a fork"])
def test_a_fork_turns_the_probe_off(tmp_path, monkeypatch, env):
    wire = Wire(monkeypatch, {})
    reports, findings, notices = probe(tmp_path, {"remote": {"url": "https://mcp.example/mcp"}}, env=env, probe=True)
    assert [(r.status, r.skip_reason) for r in reports] == [("skipped", "fork")] and findings == []
    assert codes(notices) == ["probe_fork_disabled"] and wire.calls == []


UNTRUSTED = {
    "same-repository pull request": {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
                                     "GITHUB_REF_PROTECTED": "true", "GITHUB_REPOSITORY": "acme/agents"},
    "unprotected push": {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_REF_PROTECTED": "false"},
    "gitlab unprotected push": {"CI": "true", "GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "push",
                                "CI_COMMIT_REF_PROTECTED": "false"},
    "other CI": {"CI": "true"},
    # Not on the allowlist of trusted events, though the ref is protected (spec 6.8).
    "github issue_comment on a protected ref": {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "issue_comment",
                                                "GITHUB_REF_PROTECTED": "true", "GITHUB_REPOSITORY": "acme/agents"},
    "gitlab api pipeline on a protected ref": {"CI": "true", "GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "api",
                                               "CI_COMMIT_REF_PROTECTED": "true"},
}


@pytest.mark.parametrize("env", UNTRUSTED.values(), ids=UNTRUSTED.keys())
def test_probe_private_is_ignored_on_an_untrusted_run(tmp_path, monkeypatch, env):
    wire = Wire(monkeypatch, {"intranet.example": "10.1.2.3"})
    event = tmp_path / "event.json"
    event.write_text('{"pull_request": {"number": 7, "head": {"repo": {"full_name": "acme/agents"}}}}', encoding="utf-8")
    reports, _, notices = probe(tmp_path, {"remote": {"url": "https://intranet.example/mcp"}},
                                env={**env, "GITHUB_EVENT_PATH": str(event)}, probe=True, probe_private=True)
    assert [(r.status, r.skip_reason) for r in reports] == [("skipped", "refused")]
    assert "probe_private_untrusted" in codes(notices) and wire.calls == []


@pytest.mark.parametrize("env", [PUSH_PROTECTED, {"CI": "true", "GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "push",
                                                  "CI_COMMIT_REF_PROTECTED": "true"}, {}],
                         ids=["github protected push", "gitlab protected push", "local run"])
def test_probe_private_is_honoured_on_a_trusted_run(tmp_path, monkeypatch, env):
    wire = Wire(monkeypatch, {"intranet.example": "10.1.2.3"})
    event = tmp_path / "event.json"
    event.write_text("{}", encoding="utf-8")  # a push event: readable, no pull request
    env = {**env, "GITHUB_EVENT_PATH": str(event)} if "GITHUB_ACTIONS" in env else env
    reports, _, notices = probe(tmp_path, {"remote": {"url": "https://intranet.example/mcp"}}, env=env,
                                probe=True, probe_private=True)
    assert [r.status for r in reports] == ["probed"] and "probe_private_untrusted" not in codes(notices)
    assert {call["ip"] for call in wire.calls} == {"10.1.2.3"}


def test_unresolved_and_plain_http_urls_are_not_probed(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {})
    reports, _, notices = probe(tmp_path, {"templated": {"url": "https://${HOST}/mcp"}, "plain": {"url": "http://mcp.example/mcp"}},
                                probe=True)
    assert [(r.item, r.skip_reason) for r in reports] == [(".mcp.json#templated", "unresolved")]
    assert codes(notices) == ["probe_skipped"] and wire.calls == []


def test_the_wrapper_flag_outranks_the_environment(tmp_path):
    """C14: with the wrapper input false (`--no-probe-private`) and `SPELLWARDEN_PROBE_PRIVATE=true`, the flag wins."""
    from spellwarden_cli.settings import Flags, load_settings

    env = {"SPELLWARDEN_PROBE_PRIVATE": "true"}
    assert load_settings(str(tmp_path), config=None, flags=Flags(probe_private=False), env=env).probe_private is False
    assert load_settings(str(tmp_path), config=None, flags=Flags(), env=env).probe_private is True


def test_a_settings_file_cannot_grant_private_probing(tmp_path, make_repo, run_cli):
    repo = make_repo(tmp_path / "repo", {".spellwarden/config.yml": "version: 1\nprobe: true\nprobe-private: true\n"})
    code, out, _err = run_cli(["scan", str(repo), "--no-telemetry"])
    assert code == 2 and "settings_invalid" in out and "probe-private" in out  # the error is in the report (stdout)
