"""O4 spec 6.5 and claims N1 to N10, S4 (probe part), S5 (agents part), D1 (remote part): the remote agents and the key sets of the
probe phase, over the real fetcher on a scripted wire; one budget for MCP servers, agents and key sets; the remote findings that
do not fail a pull or merge request."""
from __future__ import annotations

import base64
import json
import threading
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from a2a_cards import card_bytes, clean_card
from a2a_wire import Wire

from spellwarden_scan import RuleSet

from spellwarden_cli import a2a_probe, net, probing, run
from spellwarden_cli.agents import KeyFetch, Trust
from spellwarden_cli.ci import LOCAL, CiContext
from spellwarden_cli.report import to_json_dict
from spellwarden_cli.settings import A2a, Settings

SIGNED = Path(__file__).resolve().parents[1] / "fixtures" / "a2a" / "signed"
RULES = RuleSet.baseline()
JSON = {"Content-Type": "application/json"}
SIGNATURE = "AQ" * 42 + "AQ"  # base64url of 64 bytes: the right length for ES256, never a valid signature
CARD = card_bytes(clean_card())
PUSH = CiContext(provider="github", event="push", is_request=False, request_number=None, fork=False, dependabot=False,
                 protected_ref=True, identity=None)
REQUEST = CiContext(provider="github", event="pull_request", is_request=True, request_number=7, fork=False, dependabot=False,
                    protected_ref=False, identity=None)
FORK = CiContext(provider="github", event="pull_request", is_request=True, request_number=7, fork=True, dependabot=False,
                 protected_ref=False, identity=None)


def signed(name: str) -> bytes:
    return (SIGNED / f"{name}.json").read_bytes()


def scan(tmp_path, *, agents=(), probe=True, context=PUSH, files: dict | None = None, **settings):
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    for path, content in (files or {}).items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(content if isinstance(content, bytes) else content.encode())
    a2a = settings.pop("a2a", A2a(agents=tuple(agents)))
    options = run.ScanOptions(root=str(root), settings=Settings(probe=probe, a2a=a2a, **settings), as_of=date(2026, 10, 26),
                              env={}, context=context)
    return run.scan(options)


def agent(report, item_fragment: str = ""):
    return next(entry for entry in report.agents if item_fragment in entry.item)


def codes(report) -> list[str]:
    return sorted(notice.code for notice in report.notices)


def card_routes(host: str = "agent.example.com", path: str = "/.well-known/agent-card.json", body: bytes = CARD) -> dict:
    return {f"https://{host}{path}": (200, JSON, body)}


# --- N1: without --probe nothing is fetched -------------------------------------------------------------------------------

def test_n1_without_probe_no_request_is_made_and_the_agents_are_skipped_with_one_notice(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, card_routes())
    report = scan(tmp_path, agents=["https://agent.example.com/", "https://other.example.com/card.json"], probe=False)
    assert wire.calls == []
    assert [(a.item, a.status, a.skip_reason, a.source) for a in report.agents] == [
        ("a2a-agent:https://agent.example.com/", "skipped", "probe_off", "remote"),
        ("a2a-agent:https://other.example.com/card.json", "skipped", "probe_off", "remote")]
    assert codes(report).count("a2a_agents_need_probe") == 1 and report.exit_code() == 0
    assert "no_agent_content" not in codes(report)


def test_n1_a_signed_repository_card_with_a_jku_is_not_fetched_either_without_probe(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {"https://agent.example.com/.well-known/jwks.json": (200, JSON, signed("jwks"))})
    report = scan(tmp_path, probe=False, files={".well-known/agent-card.json": signed("es256-jku")})
    assert wire.calls == [] and agent(report).result.signature_status == "unverified"
    assert "a2a_signature_unverified" in codes(report)


# --- N2: the shape of the requests ----------------------------------------------------------------------------------------

def test_n2_the_card_fetch_is_one_get_with_two_headers_and_nothing_from_the_repository(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, card_routes())
    report = scan(tmp_path, agents=["https://agent.example.com/"], files={"README.md": "secret-looking: sk-test"})
    [call] = wire.calls
    assert (call["method"], call["path"], call["body"], call["host"]) == ("GET", "/.well-known/agent-card.json", None, "agent.example.com")
    assert set(call["headers"]) == {"Accept", "User-Agent"} and call["headers"]["Accept"] == "application/json, application/a2a+json"
    assert call["headers"]["User-Agent"].startswith("Spellwarden/")
    assert agent(report).status == "checked" and agent(report).fetch == {
        "requested_url": "https://agent.example.com/.well-known/agent-card.json",
        "final_url": "https://agent.example.com/.well-known/agent-card.json", "http_status": 200}


def test_n2_the_key_set_fetch_is_one_get_with_the_same_two_headers(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {"https://agent.example.com/.well-known/jwks.json": (200, JSON, signed("jwks"))})
    scan(tmp_path, files={".well-known/agent-card.json": signed("es256-jku")})
    [call] = wire.calls
    assert (call["method"], call["path"], call["body"]) == ("GET", "/.well-known/jwks.json", None)
    assert set(call["headers"]) == {"Accept", "User-Agent"}


# --- N3 and N10: which URL is fetched -------------------------------------------------------------------------------------

def test_n3_a_base_url_that_404s_falls_back_once_to_the_old_path_and_a_direct_url_never_does(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {"https://old.example.com/.well-known/agent.json": (200, JSON, CARD)})
    report = scan(tmp_path, agents=["https://old.example.com/", "https://direct.example.com/card.json"])
    old = agent(report, "old.example.com")
    assert (old.status, old.path_form) == ("checked", "legacy_path")
    assert "SW-A2A-003" in {f.rule_id for f in old.result.findings}
    assert wire.urls.count("https://old.example.com/.well-known/agent-card.json") == 1
    assert wire.urls.count("https://old.example.com/.well-known/agent.json") == 1
    direct = agent(report, "direct.example.com")
    assert (direct.status, direct.fail_reason, direct.path_form, direct.fetch["http_status"]) == ("failed", "http_status", "direct", 404)
    assert [url for url in wire.urls if urlsplit(url).hostname == "direct.example.com"] == ["https://direct.example.com/card.json"]


def test_n10_a_trailing_slash_is_a_base_url_at_any_path_and_no_slash_is_the_cards_own_address(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {**card_routes(path="/agents/billing/.well-known/agent-card.json"),
                              "https://host.example.com/agents/billing": (200, JSON, CARD)})
    report = scan(tmp_path, agents=["https://agent.example.com/agents/billing/", "https://host.example.com/agents/billing"])
    assert sorted(wire.urls) == ["https://agent.example.com/agents/billing/.well-known/agent-card.json",
                                 "https://host.example.com/agents/billing"]
    assert [(a.path_form, a.status) for a in report.agents] == [("well_known", "checked"), ("direct", "checked")]
    assert a2a_probe.card_url("https://a.example.com")[0] == "https://a.example.com/.well-known/agent-card.json"
    assert a2a_probe.card_url("https://a.example.com/c.json?x=1")[:2] == ("https://a.example.com/c.json?x=1", None)


# --- N4: redirects and addresses ------------------------------------------------------------------------------------------

def test_n4_a_redirect_to_another_host_is_sw_a2a_016_and_to_a_private_address_is_refused(tmp_path, monkeypatch):
    routes = {"https://agent.example.com/.well-known/agent-card.json": (302, {"Location": "https://cdn.other.net/card.json"}, b""),
              "https://cdn.other.net/card.json": (200, JSON, CARD),
              "https://evil.example.com/.well-known/agent-card.json": (302, {"Location": "https://internal.target.net/c"}, b"")}
    wire = Wire(monkeypatch, routes, addresses={"internal.target.net": "10.0.0.7"})
    report = scan(tmp_path, agents=["https://agent.example.com/", "https://evil.example.com/"])
    moved = agent(report, "agent.example.com")
    assert moved.status == "checked" and "SW-A2A-016" in {f.rule_id for f in moved.result.findings}
    assert moved.fetch["final_url"] == "https://cdn.other.net/card.json"
    blocked = agent(report, "evil.example.com")
    assert (blocked.status, blocked.fail_reason) == ("failed", "private_address")
    assert not [call for call in wire.calls if call["host"] == "internal.target.net"]


def test_n4_a_redirect_that_stays_on_the_host_is_not_sw_a2a_016(tmp_path, monkeypatch):
    routes = {"https://agent.example.com/.well-known/agent-card.json": (301, {"Location": "/v2/card.json"}, b""),
              "https://agent.example.com/v2/card.json": (200, JSON, CARD)}
    Wire(monkeypatch, routes)
    result = agent(scan(tmp_path, agents=["https://agent.example.com/"])).result
    assert "SW-A2A-016" not in {f.rule_id for f in result.findings}


def test_n4_a_private_agent_is_fetched_only_on_a_trusted_run_with_probe_private_and_its_jku_only_on_its_own_origin(tmp_path, monkeypatch):
    jku_card = signed("es256-jku")
    routes = {"https://agent.internal.example/.well-known/agent-card.json": (200, JSON, jku_card),
              "https://agent.internal.example/.well-known/jwks.json": (200, JSON, signed("jwks"))}
    wire = Wire(monkeypatch, routes, addresses={"agent.internal.example": "10.0.0.5", "agent.example.com": "10.0.0.6"})
    refused = scan(tmp_path / "a", agents=["https://agent.internal.example/"])
    assert agent(refused).fail_reason == "private_address" and wire.calls == []
    allowed = scan(tmp_path / "b", agents=["https://agent.internal.example/"], probe_private=True)
    assert agent(allowed).status == "checked" and wire.urls == ["https://agent.internal.example/.well-known/agent-card.json"]
    # the card names a jku on agent.example.com, another origin that resolves to a private address: refused
    assert agent(allowed).result.signatures[0].detail == "network" and agent(allowed).result.signatures[0].outcome == "key_unavailable"
    untrusted = scan(tmp_path / "c", agents=["https://agent.internal.example/"], probe_private=True, context=REQUEST)
    assert agent(untrusted).fail_reason == "private_address" and "probe_private_untrusted" in codes(untrusted)


# --- N6 and failure reasons -----------------------------------------------------------------------------------------------

def test_n6_a_remote_agent_that_answers_500_does_not_change_the_exit_code(tmp_path, monkeypatch):
    Wire(monkeypatch, {"https://agent.example.com/.well-known/agent-card.json": (500, {}, b"")})
    report = scan(tmp_path, agents=["https://agent.example.com/"], files={"README.md": "x"})
    failed = agent(report)
    assert (failed.status, failed.fail_reason, failed.fetch["http_status"], failed.result) == ("failed", "http_status", 500, None)
    assert report.exit_code() == 0 and report.findings == () and report.errors == ()
    [note] = [n for n in report.notices if n.code == "a2a_fetch_failed"]
    assert "http_status 500" in note.message and "End the URL with /" in note.message and note.path == failed.item


@pytest.mark.parametrize(("answer", "reason"), [
    ((200, JSON, b"x" * (2**20 + 1)), "too_large"), ((200, JSON, b"\xff\xfe"), "not_utf8"), ((200, JSON, b"{nope"), "not_json"),
    ((200, JSON, b'\xef\xbb\xbf{"name": "x"}'), "not_json"), ((200, JSON, b'{"a": 1, "a": 2}'), "duplicate_key"),
    ((200, JSON, b"[1]"), "not_an_object"), ((200, JSON, b'{"a":' * 130 + b"1" + b"}" * 130), "too_deep"),
    ((403, {}, b""), "http_status"),
])
def test_a_card_that_cannot_be_read_is_a_failed_agent_with_the_closed_reason(tmp_path, monkeypatch, answer, reason):
    Wire(monkeypatch, {"https://agent.example.com/.well-known/agent-card.json": answer})
    failed = agent(scan(tmp_path, agents=["https://agent.example.com/"]))
    assert (failed.status, failed.fail_reason) == ("failed", reason)


def test_a_network_error_is_failed_network(tmp_path, monkeypatch):
    def refuse(host, ip, port, timeout):  # noqa: ARG001
        raise ConnectionRefusedError

    Wire(monkeypatch, card_routes())
    monkeypatch.setattr(net, "pinned_connection", refuse)
    assert agent(scan(tmp_path, agents=["https://agent.example.com/"])).fail_reason == "network"


# --- N8: remote findings on a pull or merge request -----------------------------------------------------------------------

def http_card() -> bytes:
    card = clean_card()
    card["supportedInterfaces"][0]["url"] = "http://agent.example.com/a2a"
    return card_bytes(card)


def test_n8_a_remote_card_with_a_high_finding_does_not_fail_a_request_but_fails_a_push(tmp_path, monkeypatch):
    Wire(monkeypatch, card_routes(body=http_card()))
    on_request = scan(tmp_path / "a", agents=["https://agent.example.com/"], context=REQUEST)
    assert agent(on_request).counts_toward_exit is False
    assert [(f.finding.rule_id, f.item) for f in on_request.findings if f.finding.rule_id == "SW-A2A-004"] == [
        ("SW-A2A-004", "a2a-agent:https://agent.example.com/")]
    assert on_request.exit_code() == 0
    assert to_json_dict(on_request)["agents"][0]["counts_toward_exit"] is False
    on_push = scan(tmp_path / "b", agents=["https://agent.example.com/"], context=PUSH)
    assert agent(on_push).counts_toward_exit is True and on_push.exit_code() == 1
    local = scan(tmp_path / "c", agents=["https://agent.example.com/"], context=LOCAL)
    assert local.exit_code() == 1


def test_n8_a_repository_card_finding_still_fails_a_request(tmp_path, monkeypatch):
    Wire(monkeypatch)
    report = scan(tmp_path, probe=False, context=REQUEST, files={".well-known/agent-card.json": http_card()})
    assert agent(report).counts_toward_exit is True and report.exit_code() == 1


def test_n8_findings_of_remote_agents_point_at_the_settings_file_with_no_line(tmp_path, monkeypatch):
    Wire(monkeypatch, card_routes(body=http_card()))
    report = scan(tmp_path, agents=["https://agent.example.com/"])
    finding = next(f.finding for f in report.findings if f.finding.rule_id == "SW-A2A-004")
    assert (finding.location.path, finding.location.line) == (".spellwarden/config.yml", None)


# --- N9: plain http agents ------------------------------------------------------------------------------------------------

def test_n9_http_agents_are_never_fetched_and_only_a_public_host_is_a_finding(tmp_path, monkeypatch):
    wire = Wire(monkeypatch)
    agents = ["http://10.0.0.5:8080/", "http://billing.internal/", "http://localhost:9000/", "http://agent.example.com/",
              "http://nodots/", "http://[::1]:9000/", "http://x.local/", "http://169.254.169.254/"]
    report = scan(tmp_path, agents=agents)
    assert wire.calls == [] and {(a.status, a.skip_reason) for a in report.agents} == {("skipped", "not_https")}
    flagged = [f.item for f in report.findings if f.finding.rule_id == "SW-A2A-004"]
    assert flagged == ["a2a-agent:http://agent.example.com/"]
    finding = next(f.finding for f in report.findings)
    assert (finding.severity, finding.location.path, finding.location.line) == ("high", ".spellwarden/config.yml", None)


def test_the_http_agent_finding_is_reported_without_probe_too(tmp_path, monkeypatch):
    Wire(monkeypatch)
    report = scan(tmp_path, agents=["http://agent.example.com/"], probe=False)
    assert agent(report).skip_reason == "not_https" and [f.finding.rule_id for f in report.findings] == ["SW-A2A-004"]


@pytest.mark.parametrize("probe", [True, False])
def test_r1_f3_an_http_agent_is_skipped_whatever_the_case_of_its_scheme(tmp_path, monkeypatch, probe):
    """(r1:F3) `HTTP://agent.example.com/` passes the settings check (the scheme is case-insensitive) and must be skipped
    `not_https` with SW-A2A-004 exactly like `http://`, never fetched."""
    wire = Wire(monkeypatch)
    report = scan(tmp_path, agents=["HTTP://agent.example.com/", "Http://10.0.0.5:8080/"], probe=probe)
    assert wire.calls == [] and {(a.status, a.skip_reason) for a in report.agents} == {("skipped", "not_https")}
    assert [f.item for f in report.findings if f.finding.rule_id == "SW-A2A-004"] == ["a2a-agent:http://agent.example.com/"]
    lower = scan(tmp_path / "lower", agents=["http://agent.example.com/"], probe=probe)
    assert [(a.status, a.skip_reason) for a in lower.agents] == [("skipped", "not_https")]


def test_r1_f3_a_card_jku_with_an_upper_case_https_scheme_is_fetched_like_the_lower_case_one(tmp_path, monkeypatch):
    routes = {**card_routes(body=signed("es256-jku")), "https://agent.example.com/.well-known/jwks.json": (200, JSON, signed("jwks"))}
    card = json.loads(signed("es256-jku"))
    sig = card["signatures"][0]
    header = json.loads(base64.urlsafe_b64decode(sig["protected"] + "=" * (-len(sig["protected"]) % 4)))
    assert header["jku"] == "https://agent.example.com/.well-known/jwks.json"
    header["jku"] = "HTTPS://agent.example.com/.well-known/jwks.json"
    sig["protected"] = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    wire = Wire(monkeypatch, {**routes, "https://agent.example.com/.well-known/agent-card.json": (200, JSON, json.dumps(card).encode())})
    scan(tmp_path, agents=["https://agent.example.com/"])
    assert "https://agent.example.com/.well-known/jwks.json" in wire.urls


@pytest.mark.parametrize("jku", ["http://[bad/keys.json", "https://[bad/keys.json", "https://keys.example.com:notaport/k.json"])
def test_r0_f1_a_remote_cards_jku_that_does_not_parse_is_key_unavailable_and_never_crashes_the_run(tmp_path, monkeypatch, jku):
    """(r0:F1, invariant 10) Any agent in a2a.agents can serve such a card: the `jku` is the reason `network`, nothing is
    requested for it, and the run is not an error."""
    card = json.loads(signed("es256-jku"))
    sig = card["signatures"][0]
    header = json.loads(base64.urlsafe_b64decode(sig["protected"] + "=" * (-len(sig["protected"]) % 4)))
    header["jku"] = jku
    sig["protected"] = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    wire = Wire(monkeypatch, {"https://agent.example.com/.well-known/agent-card.json": (200, JSON, json.dumps(card).encode())})
    report = scan(tmp_path, agents=["https://agent.example.com/"])
    assert not report.errors and wire.urls == ["https://agent.example.com/.well-known/agent-card.json"]
    [signature] = agent(report, "a2a-agent:").result.signatures
    assert (signature.outcome, signature.detail) == ("key_unavailable", "network")


# --- forks ---------------------------------------------------------------------------------------------------------------

def test_on_a_request_from_a_fork_no_agent_and_no_key_set_is_fetched(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {**card_routes(), "https://agent.example.com/.well-known/jwks.json": (200, JSON, signed("jwks"))})
    report = scan(tmp_path, agents=["https://agent.example.com/"], context=FORK,
                  files={".well-known/agent-card.json": signed("es256-jku")})
    assert wire.calls == []
    assert [(a.source, a.status, a.skip_reason) for a in report.agents if a.source == "remote"] == [("remote", "skipped", "fork")]
    assert [a.result.signature_status for a in report.agents if a.source == "repository"] == ["unverified"]


# --- the key sets ---------------------------------------------------------------------------------------------------------

def test_a_remote_card_with_a_jku_is_verified_by_the_key_set_it_names_and_says_so(tmp_path, monkeypatch):
    routes = {**card_routes(body=signed("es256-jku")), "https://agent.example.com/.well-known/jwks.json": (200, JSON, signed("jwks"))}
    wire = Wire(monkeypatch, routes)
    report = scan(tmp_path, agents=["https://agent.example.com/"])
    signature = agent(report).result.signatures[0]
    assert (signature.outcome, signature.key_source, signature.payload_form) == ("verified", "jku", "as_served")
    assert len(wire.calls) == 2 and agent(report).result.signature_status == "verified"
    assert not [f for f in report.findings if f.finding.rule_id in ("SW-A2A-010", "SW-A2A-013")]


def test_a_key_set_that_cannot_be_fetched_leaves_the_signature_unverified_with_a_notice(tmp_path, monkeypatch):
    routes = {**card_routes(body=signed("es256-jku")), "https://agent.example.com/.well-known/jwks.json": (404, {}, b"")}
    Wire(monkeypatch, routes)
    report = scan(tmp_path, agents=["https://agent.example.com/"])
    signature = agent(report).result.signatures[0]
    assert (signature.outcome, signature.detail) == ("key_unavailable", "http_status")
    assert [n.code for n in report.notices if n.code.startswith("a2a_keys")] == ["a2a_keys_unavailable"]


def test_with_a2a_keys_in_force_no_jku_is_requested_and_the_card_is_judged_by_the_keys_file(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {"https://agent.example.com/.well-known/jwks.json": (200, JSON, signed("jwks"))})
    a2a = A2a(keys=".well-known/jwks.json", keys_bytes=signed("jwks-stranger"))
    report = scan(tmp_path, a2a=a2a, files={".well-known/agent-card.json": signed("es256-jku")})
    assert wire.calls == []
    assert agent(report).result.signatures[0].outcome == "untrusted_key"
    assert report.exit_code() == 1


def test_a_card_with_three_jku_entries_fetches_two_and_the_third_is_limit(tmp_path, monkeypatch):
    card = json.loads(signed("es256-jku"))
    header = {"alg": "ES256", "kid": "es256"}
    def entry(url: str) -> dict:
        protected = base64.urlsafe_b64encode(json.dumps({**header, "jku": url}).encode()).rstrip(b"=").decode()
        return {"protected": protected, "signature": SIGNATURE}

    card["signatures"] = [entry(f"https://agent.example.com/k{n}.json") for n in range(3)]
    wire = Wire(monkeypatch, card_routes(body=json.dumps(card).encode()))
    report = scan(tmp_path, agents=["https://agent.example.com/"])
    details = sorted(s.detail for s in agent(report).result.signatures)
    assert details == ["http_status", "http_status", "limit"] and len(wire.calls) == 3  # the card and two key sets


def test_n7_25_distinct_jku_urls_across_repository_cards_make_at_most_20_requests(tmp_path, monkeypatch):
    base = json.loads(signed("es256"))

    def card_with(url: str) -> bytes:
        protected = base64.urlsafe_b64encode(json.dumps({"alg": "ES256", "kid": "es256", "jku": url}).encode()).rstrip(b"=").decode()
        return json.dumps({**base, "signatures": [{"protected": protected, "signature": SIGNATURE}]}).encode()

    files = {f"agents/a{n:02d}/.well-known/agent-card.json": card_with(f"https://keys{n:02d}.example.com/jwks.json") for n in range(25)}
    wire = Wire(monkeypatch)
    report = scan(tmp_path, files=files)
    assert len(wire.calls) == 20 and len(report.agents) == 25
    outcomes = [a.result.signatures[0] for a in report.agents]
    assert sorted(o.detail for o in outcomes).count("limit") == 5
    assert sorted(o.detail for o in outcomes).count("http_status") == 20
    assert codes(report).count("a2a_keys_unavailable") == 25


def test_a_key_set_named_by_several_cards_is_fetched_once(tmp_path, monkeypatch):
    wire = Wire(monkeypatch, {"https://agent.example.com/.well-known/jwks.json": (200, JSON, signed("jwks"))})
    scan(tmp_path, files={"a/.well-known/agent-card.json": signed("es256-jku"), "b/.well-known/agent-card.json": signed("es256-jku")})
    assert len(wire.calls) == 1


# --- N5: one budget -------------------------------------------------------------------------------------------------------

class _Task:
    """A task that takes `connections` from the phase's budget and records when it started."""

    kind = "agent"

    def __init__(self, item: str, connections: int, started: list[str], lock: threading.Lock) -> None:
        self.item, self.connections, self.started, self.lock = item, connections, started, lock

    def run(self, fetcher_factory, budget):  # noqa: ARG002 -- the task's shape
        if budget.spent:
            return self.skipped()
        with self.lock:
            self.started.append(self.item)
        for _ in range(self.connections):
            if not budget.take():
                return self.skipped()
        return ("ran", self.item)

    def skipped(self):
        return ("budget", self.item)


def test_n5_the_phase_is_shared_mcp_first_then_agents_then_key_sets_and_what_the_budget_cannot_cover_is_skipped(monkeypatch):
    started: list[str] = []
    lock = threading.Lock()
    monkeypatch.setattr(probing, "MAX_REQUESTS", 60)
    monkeypatch.setattr(probing, "MAX_WORKERS", 1)  # one worker: the order of submission is the order of starting
    targets = [probing.ProbeTarget(f".mcp.json#s{n:02d}", ".mcp.json", 1, f"https://s{n:02d}.example/mcp") for n in range(3)]
    Wire(monkeypatch)
    agents = [_Task(f"agent{n}", 10, started, lock) for n in range(25)]
    keysets = [_Task(f"keys{n}", 1, started, lock) for n in range(25)]
    result = probing.run_combined(targets, RULES, agent_tasks=agents, keyset_tasks=keysets, now_iso="2026-10-26T00:00:00Z",
                                  fetcher_factory=net.Fetcher)
    assert len(result.reports) == 3 and all(report.status in ("probed", "skipped") for report in result.reports)
    assert len(result.agents) == 25 and len(result.keysets) == 25
    ran = [item for kind, item in result.agents if kind == "ran"]
    assert started[:len(ran)] == ran and ran == [f"agent{n}" for n in range(len(ran))]  # agents start in order, after the servers
    assert all(kind == "budget" for kind, _ in result.keysets)  # the 60 connections went to the servers and the agents first
    assert any(kind == "budget" for kind, _ in result.agents)


def test_the_caps_per_kind_are_50_servers_20_agents_and_20_key_sets():
    assert (probing.MAX_SERVERS, probing.MAX_AGENTS, probing.MAX_CARD_KEYSETS) == (50, 20, 20)
    lock, started = threading.Lock(), []
    agents = [_Task(f"a{n:02d}", 0, started, lock) for n in range(23)]
    keysets = [_Task(f"k{n:02d}", 0, started, lock) for n in range(22)]
    result = probing.run_combined([], RULES, agent_tasks=agents, keyset_tasks=keysets, now_iso="2026-10-26T00:00:00Z",
                                  fetcher_factory=net.Fetcher)
    assert [kind for kind, _ in result.agents].count("ran") == 20 and [item for kind, item in result.agents if kind == "budget"] == [
        "a20", "a21", "a22"]
    assert [kind for kind, _ in result.keysets].count("ran") == 20 and len(result.keysets) == 22


def test_a_trust_and_a_key_fetch_are_plain_values():
    assert Trust().path is None and Trust().state == "none" and KeyFetch().keyset is None
    assert a2a_probe.MAX_AGENT_KEYSETS == 2 and a2a_probe.ACCEPT == "application/json, application/a2a+json"
