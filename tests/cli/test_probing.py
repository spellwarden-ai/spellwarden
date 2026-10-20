"""Spec 6.8 and claim C14: the probe phase. Which servers are probed, the whole-phase budget (300 connections,
120 s), the server limit, refusals that keep no answer byte, bounded answers, nothing from the configuration on the
wire, and reports in item order whatever order the workers finish in. The real `Fetcher` runs over a scripted
opener and resolver: no socket is opened."""
from __future__ import annotations

import json
import random
import threading
import time

import pytest

from spellwarden_scan import Location, ProbeResult, RuleSet, ToolInfo, evaluate_probe, parse_mcp_config
from spellwarden_cli import probe as prober
from spellwarden_cli import probing
from spellwarden_cli.discover import Discovery
from spellwarden_cli.net import Fetcher
from spellwarden_cli.report import Notice

RULES = RuleSet.baseline()
NOW = "2026-12-01T00:00:00Z"
PUBLIC_IP = "8.8.8.8"
OPEN_SERVER = {  # answers discover and lists tools without authentication: SW-MCP-001 fires
    "server/discover": (200, {"Content-Type": "application/json"},
                        {"jsonrpc": "2.0", "id": 1, "result": {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}}}),
    "tools/list": (200, {"Content-Type": "application/json"},
                   {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "query", "description": "Runs a query."}]}}),
}


def discovery(servers: dict, path: str = ".mcp.json") -> Discovery:
    document = parse_mcp_config(path, json.dumps({"mcpServers": servers}, indent=2).encode("utf-8"))
    return Discovery(items=(), skills=(), documents=(document,), plugin_dirs=(), notices=(), errors=())


class _Answer:
    def __init__(self, status, headers, body):
        self.status, self._headers = status, headers
        self._body = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body

    def getheaders(self):
        return list(self._headers.items())

    def read(self, amt=None):
        chunk, self._body = (self._body, b"") if amt is None else (self._body[:amt], self._body[amt:])
        return chunk

    read1 = read


class _Connection:
    def __init__(self, server, host, ip):
        self.server, self.host, self.ip = server, host, ip
        self._answer = None

    def request(self, method, path, body=None, headers=None):
        server = self.server
        with server.lock:
            server.calls.append({"method": method, "host": self.host, "ip": self.ip, "path": path,
                                 "headers": dict(headers or {}), "body": body})
            if server.clock is not None:
                server.clock[0] += server.step
        if server.delay:
            time.sleep(server.rng.uniform(0, server.delay))
        rpc = json.loads(body)["method"] if method == "POST" and body else "GET"
        self._answer = _Answer(*server.answers.get(rpc, server.default))

    def getresponse(self):
        return self._answer

    def close(self):
        pass


class Server:
    """Scripted MCP servers behind the real fetcher: answers by JSON-RPC method (`GET` for every GET), records
    every connection. The default answers make a probe use seven connections: discover 404, initialize 404, the
    stream GET 404, tools/list 401 naming a resource metadata URL, then three metadata GETs, all 404."""

    def __init__(self, answers: dict | None = None, *, clock: list[float] | None = None, step: float = 0.0,
                 delay: float = 0.0, seed: int = 0):
        self.answers = answers if answers is not None else {
            "tools/list": (401, {"WWW-Authenticate": 'Bearer resource_metadata="https://meta.example/rm"'}, b"")}
        self.default = (404, {}, b"")
        self.calls: list[dict] = []
        self.lock = threading.Lock()
        self.clock, self.step, self.delay = clock, step, delay
        self.rng = random.Random(seed)

    def factory(self, **kwargs):
        return lambda: Fetcher(resolver=lambda _host: [PUBLIC_IP], opener=lambda host, ip, _port, _timeout: _Connection(self, host, ip),
                               **kwargs)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def targets_of(count: int) -> list[probing.ProbeTarget]:
    return [probing.ProbeTarget(f".mcp.json#s{index:02d}", ".mcp.json", index + 2, f"https://s{index:02d}.example/mcp")
            for index in range(count)]


def test_only_https_entries_are_targets_and_unresolved_urls_are_skipped():
    found = discovery({
        "remote": {"url": "https://mcp.example/mcp"},
        "plain": {"url": "http://mcp.example/mcp"},
        "templated": {"url": "https://${MCP_HOST}/mcp"},
        "sse": {"type": "sse", "url": "https://sse.example/events"},
        "local": {"command": "npx", "args": ["-y", "server@1.0.0"]},
    })
    targets, skipped = probing.probe_targets(found)
    assert [(t.item, t.url) for t in targets] == [(".mcp.json#remote", "https://mcp.example/mcp"),
                                                  (".mcp.json#sse", "https://sse.example/events")]
    assert [(r.item, r.status, r.skip_reason, r.result) for r in skipped] == [(".mcp.json#templated", "skipped", "unresolved", None)]
    assert targets[0].line == found.documents[0].servers[0].line


def test_a_probed_server_is_evaluated_and_its_findings_point_at_the_configuration_entry():
    server = Server(OPEN_SERVER)
    found = discovery({"remote": {"url": "https://mcp.example/mcp"}})
    targets, _ = probing.probe_targets(found)
    reports, findings = probing.run_phase(targets, RULES, fetcher_factory=server.factory(), now_iso=NOW)
    (report,) = reports
    assert (report.item, report.status, report.skip_reason) == (".mcp.json#remote", "probed", None)
    direct = evaluate_probe(prober.probe(server.factory()(), "https://mcp.example/mcp", release="r", now_iso=NOW), RULES)
    assert report.result == direct and direct.findings
    assert {f.finding.fingerprint for f in findings} == {f.fingerprint for f in direct.findings}  # the engine's fingerprint
    line = found.documents[0].servers[0].line
    assert {(f.item, f.finding.location) for f in findings} == {(".mcp.json#remote", Location(".mcp.json", line))}


def test_the_probe_sends_nothing_from_the_configuration():
    server = Server(OPEN_SERVER)
    found = discovery({"remote": {"url": "https://mcp.example/mcp", "headers": {"Authorization": "Bearer sekret-header",
                                                                               "X-Api-Key": "sekret-key"},
                                  "env": {"API_TOKEN": "sekret-env"}, "args": ["--token", "sekret-arg"]}})
    targets, _ = probing.probe_targets(found)
    probing.run_phase(targets, RULES, fetcher_factory=server.factory(), now_iso=NOW)
    assert server.calls
    for call in server.calls:
        assert "sekret" not in json.dumps(call["headers"]) and b"sekret" not in (call["body"] or b"")
        assert not {name.lower() for name in call["headers"]} & {"authorization", "cookie", "x-api-key"}


def test_the_request_budget_stops_new_connections_and_keeps_no_partial_result():
    server = Server()
    notices: list[Notice] = []
    reports, findings = probing.run_phase(targets_of(50), RULES, fetcher_factory=server.factory(), now_iso=NOW, notices=notices)
    assert len(server.calls) == probing.MAX_REQUESTS == 300  # 50 servers x 7 connections wanted, 300 allowed
    statuses = {report.status for report in reports}
    assert statuses <= {"probed", "skipped"} and len(reports) == 50
    budget = [report for report in reports if report.status == "skipped"]
    assert budget and all(r.skip_reason == "budget" and r.result is None for r in budget)
    assert sum(1 for r in reports if r.status == "probed") * 7 <= 300
    assert {n.path for n in notices if n.code == "probe_skipped"} == {r.item for r in budget}
    assert all(f.item not in {r.item for r in budget} for f in findings)


def test_the_wall_clock_budget_ends_the_phase_and_cancels_the_rest(monkeypatch):
    monkeypatch.setattr(probing, "MAX_WORKERS", 1)  # one at a time: the order of the refusals is deterministic
    clock = [0.0]
    server = Server(OPEN_SERVER, clock=clock, step=25.0)  # two connections per probe, 25 s each on the fake clock
    reports, _ = probing.run_phase(targets_of(5), RULES, fetcher_factory=server.factory(), clock=lambda: clock[0], now_iso=NOW)
    assert [(r.status, r.skip_reason) for r in reports] == [("probed", None), ("probed", None), ("skipped", "budget"),
                                                           ("skipped", "budget"), ("skipped", "budget")]
    assert len(server.calls) == 5 and clock[0] == 125.0  # the fifth started at 100 s; nothing started at or after 120 s
    assert all(r.result is None for r in reports[2:])


def test_at_most_fifty_servers_are_probed_and_the_rest_are_limit():
    server = Server(OPEN_SERVER)
    reports, _ = probing.run_phase(list(reversed(targets_of(52))), RULES, fetcher_factory=server.factory(), now_iso=NOW)
    assert [r.item for r in reports] == sorted(r.item for r in reports)
    assert [(r.item, r.skip_reason) for r in reports if r.status == "skipped"] == [(".mcp.json#s50", "limit"), (".mcp.json#s51", "limit")]
    assert len(server.calls) == 100


def test_a_refused_probe_records_its_code_and_no_answer_byte():
    server = Server({"server/discover": (200, {"Content-Type": "application/json"}, b'{"SECRET-ANSWER-BYTES": 1}')})
    target = [probing.ProbeTarget(".mcp.json#intranet", ".mcp.json", 3, "https://10.0.0.1/mcp")]
    notices: list[Notice] = []
    reports, findings = probing.run_phase(target, RULES, fetcher_factory=server.factory(), now_iso=NOW, notices=notices)
    assert [(r.status, r.skip_reason, r.result) for r in reports] == [("skipped", "refused", None)] and findings == []
    assert server.calls == []
    assert notices == [Notice("probe_skipped", ".mcp.json#intranet", "not probed (refused: private_address)")]
    allowed, _ = probing.run_phase(target, RULES, fetcher_factory=server.factory(private_origins={"https://10.0.0.1/mcp"}),
                                   now_iso=NOW)
    assert allowed[0].status == "probed" and server.calls[0]["ip"] == "10.0.0.1"


def test_a_configured_private_server_cannot_send_the_probe_to_another_private_address():
    """Spec 6.8: `--probe-private` exempts the configured server's origin only. The URLs its answers supply (a
    `resource_metadata` URL on the cloud metadata address, an authorization server on another private host) get
    the public-address rules: the probe never connects to them."""
    server = Server({
        "tools/list": (401, {"WWW-Authenticate": 'Bearer resource_metadata="https://169.254.169.254/latest/meta-data/"'}, b""),
        "GET": (200, {"Content-Type": "application/json"}, {"resource": "https://10.0.0.1/mcp",
                                                             "authorization_servers": ["https://10.0.0.2"]}),
    })
    target = [probing.ProbeTarget(".mcp.json#intranet", ".mcp.json", 3, "https://10.0.0.1/mcp")]
    reports, _ = probing.run_phase(target, RULES, fetcher_factory=server.factory(private_origins={"https://10.0.0.1/mcp"}),
                                   now_iso=NOW)
    assert reports[0].status == "probed"
    assert {call["ip"] for call in server.calls} == {"10.0.0.1"}
    assert [call["path"] for call in server.calls if call["method"] == "GET"][-1] == "/.well-known/oauth-protected-resource/mcp"


def test_answers_are_bounded_before_the_engine_sees_them():
    deep: dict = {}
    cursor = deep
    for _ in range(20):
        cursor["next"] = {}
        cursor = cursor["next"]
    huge = ProbeResult(endpoint="https://mcp.example/mcp", reachable=True,
                       discover={"serverInfo": {"name": "n" * 5000}, "deep": deep, "list": list(range(500)),
                                 **{f"k{index}": index for index in range(300)}},
                       www_authenticate="w" * 5000, negotiated_version="v" * 5000,
                       tools=tuple(ToolInfo(f"t{index}", "d" * 5000, {"a": "x" * 5000}) for index in range(250)))
    bounded = probing.bounded_result(huge)
    assert max(len(text) for text in _strings(bounded.to_dict())) <= probing.MAX_TEXT
    assert len(bounded.discover) <= probing.MAX_KEYS and len(bounded.discover["list"]) == probing.MAX_ITEMS
    assert len(bounded.tools) == probing.MAX_ITEMS and len(bounded.www_authenticate) == probing.MAX_TEXT
    depth, cursor = 0, bounded.discover["deep"]
    while cursor:
        cursor, depth = cursor["next"], depth + 1
    assert depth < probing.MAX_DEPTH


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_reports_are_in_item_order_whatever_order_the_workers_finish_in(seed):
    targets = targets_of(12)
    random.Random(seed).shuffle(targets)
    server = Server(OPEN_SERVER, delay=0.005, seed=seed)
    reports, findings = probing.run_phase(targets, RULES, fetcher_factory=server.factory(), now_iso=NOW)
    baseline, _ = probing.run_phase(targets_of(12), RULES, fetcher_factory=Server(OPEN_SERVER).factory(), now_iso=NOW)
    assert reports == baseline and [r.item for r in reports] == sorted(t.item for t in targets)
    assert [f.item for f in findings] == sorted(f.item for f in findings)


def test_verbose_events_are_one_escaped_line_each():
    lines: list[str] = []
    on_event = probing.event_logger(lines.append)
    on_event("net_request", {"host": "evil\x1b[2J.example", "method": "POST", "status": 200, "bytes": 3, "ms": 12})
    on_event("probe_failed", {"error_class": "RuntimeError"})
    assert lines == ["net: POST evil\\x1b[2J.example 200 (12 ms)", "probe: failed (RuntimeError)"]
