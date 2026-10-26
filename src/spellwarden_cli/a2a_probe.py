"""The A2A tasks of the probe phase (O4 spec 6.5 and 6.6): the fetch of a remote agent's card and of the key sets a card
names, over `net.Fetcher`, only under `--probe`. This module opens no connection itself (`tests/test_network_boundary.py`).

Each fetch is one `GET` with no body and exactly the headers `Accept` and `User-Agent`: no `Authorization`, no cookie, no
value from the repository other than the URL; it never sends a card, a key or a finding. The address rules, the redirect
rules and the deadlines are the fetcher's, and a request, a redirect or a `jku` cannot reach a private address that the
configured agent URLs do not name (`Fetcher(private_origins=...)`, and only on a trusted run).

An agent task makes at most four requests (the card, the old path, two key sets) plus redirects; a failure is the agent
report status `failed` and a notice, never an error, so a remote agent's outage cannot fail a repository's build."""
from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import urlsplit

from spellwarden_scan import CardOrigin, RuleSet, evaluate_agent_card, parse_agent_card, signature_inputs
from spellwarden_scan.rules.a2a import http_agent_finding

from spellwarden_cli import jws
from spellwarden_cli.agents import (KeyFetch, Trust, fetchable_https, key_notices, notice_keys, outcomes_of, reduced,
                                    truncation_notices)
from spellwarden_cli.net import FetchError, Fetcher
from spellwarden_cli.probing import _Budget, gated_fetcher
from spellwarden_cli.report import AgentReport, Notice, ReportFinding

ACCEPT = "application/json, application/a2a+json"
CARD_MAX_BYTES = 2**20
MAX_AGENT_KEYSETS = 2  # key sets one agent task may fetch, counted in its four requests
WELL_KNOWN = ".well-known/agent-card.json"
LEGACY = ".well-known/agent.json"
_DOCUMENT_FAILURES = {"too_large": "too_large", "not_utf8": "not_utf8", "not_json": "not_json", "bom": "not_json",
                      "duplicate_key": "duplicate_key", "too_deep": "too_deep", "not_an_object": "not_an_object"}
FETCH_HINT = "End the URL with / for discovery, or give the card's full URL."


def failure_reason(error: FetchError) -> str:
    """The closed reason of 6.5 step 4 for a fetch that raised: `private_address`, `not_https`, `too_large`, `timeout` (a
    deadline) or `network` (everything else)."""
    if error.code in ("private_address", "not_https", "too_large"):
        return error.code
    return "timeout" if error.code == "fetch_failed" and error.detail == "deadline" else "network"


def card_url(url: str) -> tuple[str, str | None, str]:
    """`(the URL to fetch, the base URL or None, path_form)` for a listed agent URL (6.5 step 1): one whose path is empty or
    ends in `/` is a base URL, and its card is at the URL followed by `.well-known/agent-card.json`; any other URL is the
    card's own address and is fetched as given."""
    parts = urlsplit(url)
    if parts.path in ("", "/") or url.split("?", 1)[0].endswith("/"):
        base = url.split("?", 1)[0].split("#", 1)[0]
        base = base if base.endswith("/") else base + "/"
        return base + WELL_KNOWN, base, "well_known"
    return url, None, "direct"


def internal_by_text(host: str) -> bool:
    """Whether a configured agent's host is, by its text alone (no lookup), one that listing exposes nothing about: an IP
    literal in a private, loopback or link-local range, `localhost`, a single-label name, or a name ending `.internal`,
    `.local` or `.localhost` (D30)."""
    host = host.lower().strip("[]")
    try:
        address = ipaddress.ip_address(host)
        return address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        pass
    return host == "localhost" or "." not in host or host.endswith((".internal", ".local", ".localhost"))


def fetch_keyset(fetcher: Fetcher, url: str, notices: list[Notice]) -> KeyFetch:
    """One `GET` of a `jku` URL (6.6 step 2): at most 64 KiB, a JWKS of at most 20 keys read with the strict reader. Anything
    else is the reason: `network`, `timeout`, `http_status`, `not_json`."""
    try:
        response = fetcher.get(url, max_bytes=jws.KEYS_MAX_BYTES, accept=ACCEPT)
    except FetchError as error:
        if error.code == "budget":
            raise
        reason = failure_reason(error)
        if reason == "too_large":
            reason = "not_json"
        elif reason in ("private_address", "not_https"):
            reason = "network"
        return KeyFetch(None, reason)
    if response.status != 200:
        return KeyFetch(None, "http_status")
    try:
        keyset = jws.load_jwks(response.body, max_keys=jws.KEYS_MAX)
    except jws.JwksError:
        return KeyFetch(None, "not_json")
    notice_keys(keyset, url, notices)
    return KeyFetch(keyset)


@dataclass(frozen=True)
class AgentOutcome:
    report: AgentReport
    findings: list[ReportFinding] = field(default_factory=list)
    notices: list[Notice] = field(default_factory=list)


@dataclass(frozen=True)
class KeysetOutcome:
    url: str
    fetch: KeyFetch
    notices: list[Notice] = field(default_factory=list)


@dataclass(frozen=True)
class KeysetTask:
    """The fetch of one key set that a repository card's `jku` names (shared by every card that names it)."""
    url: str
    kind: ClassVar[str] = "keyset"

    @property
    def item(self) -> str:
        return f"a2a-keys:{reduced(self.url)}"

    def run(self, fetcher_factory: Callable[[], Fetcher], budget: _Budget) -> KeysetOutcome:
        if budget.spent:
            return self.skipped()
        fetcher, refused = gated_fetcher(fetcher_factory, budget)
        notices: list[Notice] = []
        try:
            fetch = fetch_keyset(fetcher, self.url, notices)
        except FetchError:
            return self.skipped()
        return self.skipped() if refused.is_set() else KeysetOutcome(self.url, fetch, notices)

    def skipped(self) -> KeysetOutcome:
        return KeysetOutcome(self.url, KeyFetch(None, "budget"))


@dataclass(frozen=True)
class AgentTask:
    """The fetch and judgement of one remote agent listed in `a2a.agents`: `url` is the https URL as listed, `location_path` the
    settings file findings point at, `counts_toward_exit` false on a pull or merge request (P16)."""
    url: str
    rules: RuleSet
    trust: Trust
    location_path: str
    counts_toward_exit: bool = True
    kind: ClassVar[str] = "agent"

    @property
    def item(self) -> str:
        return f"a2a-agent:{reduced(self.url)}"

    def skipped(self) -> AgentOutcome:
        _, _, form = card_url(self.url)
        return AgentOutcome(AgentReport(self.item, "remote", form, "skipped", skip_reason="budget",
                                        counts_toward_exit=self.counts_toward_exit))

    def run(self, fetcher_factory: Callable[[], Fetcher], budget: _Budget) -> AgentOutcome:
        if budget.spent:
            return self.skipped()
        fetcher, refused = gated_fetcher(fetcher_factory, budget)
        try:
            outcome = self._fetch(fetcher)
        except FetchError:
            return self.skipped()
        return self.skipped() if refused.is_set() else outcome

    def _failed(self, form: str, reason: str, target: str, status: int | None = None, final: str | None = None) -> AgentOutcome:
        fetch = {"requested_url": reduced(target), "final_url": reduced(final), "http_status": status}
        report = AgentReport(self.item, "remote", form, "failed", fail_reason=reason, fetch=fetch,
                             counts_toward_exit=self.counts_toward_exit)
        note = Notice("a2a_fetch_failed", self.item, f"the agent's card could not be fetched ({reason}"
                      f"{f' {status}' if status is not None else ''}). {FETCH_HINT}")
        return AgentOutcome(report, [], [note])

    def _fetch(self, fetcher: Fetcher) -> AgentOutcome:
        target, base, form = card_url(self.url)
        try:
            response = fetcher.get(target, max_bytes=CARD_MAX_BYTES, accept=ACCEPT)
            if response.status in (404, 410) and base is not None:  # a base URL falls back once to the path before A2A 0.3
                target, form = base + LEGACY, "legacy_path"
                response = fetcher.get(target, max_bytes=CARD_MAX_BYTES, accept=ACCEPT)
        except FetchError as error:
            if error.code == "budget":
                raise
            return self._failed(form, failure_reason(error), target)
        if response.status != 200:
            return self._failed(form, "http_status", target, response.status, response.url)
        document = parse_agent_card(self.item, response.body)
        if document.error is not None:
            return self._failed(form, _DOCUMENT_FAILURES[document.error], target, 200, response.url)
        notices: list[Notice] = []
        fetched = self._key_sets(fetcher, document, notices)
        requested_host = (urlsplit(target).hostname or "").lower()
        cross = (urlsplit(response.url).hostname or "").lower() != requested_host
        origin = CardOrigin("remote", form, reduced(target), reduced(response.url), cross)
        outcomes = outcomes_of(document, self.trust, fetched)
        result = evaluate_agent_card(document, self.rules, origin=origin, signatures=outcomes, location_path=self.location_path)
        notices.extend(key_notices(self.item, outcomes))
        notices.extend(truncation_notices(self.item, result))
        fetch = {"requested_url": reduced(target), "final_url": reduced(response.url), "http_status": 200}
        report = AgentReport(self.item, "remote", form, "checked", fetch=fetch, result=result,
                             counts_toward_exit=self.counts_toward_exit)
        return AgentOutcome(report, [ReportFinding(finding, self.item) for finding in result.findings], notices)

    def _key_sets(self, fetcher: Fetcher, document, notices: list[Notice]) -> dict[str, KeyFetch]:
        """The key sets this card's `jku` entries name, fetched inside this task (at most two, 6.5 step 6) unless `a2a.keys` is
        in force (then no `jku` is fetched for any card)."""
        fetched: dict[str, KeyFetch] = {}
        if self.trust.path is not None:
            return fetched
        for si in signature_inputs(document):
            if si.error is not None or si.jku is None or si.jku in fetched or si.alg not in jws.VERIFIED_ALGS:
                continue
            if not fetchable_https(si.jku):  # not https (any case, r1:F3) or does not parse (r0:F1): never fetched
                fetched[si.jku] = KeyFetch(None, "network")
            elif len(fetched) >= MAX_AGENT_KEYSETS:
                fetched[si.jku] = KeyFetch(None, "limit")
            else:
                fetched[si.jku] = fetch_keyset(fetcher, si.jku, notices)
        return fetched


@dataclass
class RemotePlan:
    """What is decided before any connection: the reports of the agents that will not be fetched, the SW-A2A-004 findings of
    the plain `http://` ones on a public host, the notices, and the tasks for the agents that will."""
    reports: list[AgentReport] = field(default_factory=list)
    findings: list[ReportFinding] = field(default_factory=list)
    notices: list[Notice] = field(default_factory=list)
    tasks: list[AgentTask] = field(default_factory=list)


def plan_remote(agents: tuple[str, ...], location_path: str, *, probe: bool, fork: bool, request: bool, rules: RuleSet,
                trust: Trust) -> RemotePlan:
    """The plan for `a2a.agents` (6.5): an `http://` URL is never fetched (`skipped`, `not_https`; SW-A2A-004 when its host is
    public by its text, D30); without `--probe` every other agent is `skipped` (`probe_off`) and the run carries one notice;
    on a request from a fork they are `skipped` (`fork`); the rest become `AgentTask`s, in settings order."""
    plan = RemotePlan()
    off = 0
    for url in agents:
        item = f"a2a-agent:{reduced(url)}"
        _, _, form = card_url(url)
        counts = not request
        if urlsplit(url).scheme.lower() == "http":  # (r1:F3) `HTTP://` is the same scheme
            plan.reports.append(AgentReport(item, "remote", form, "skipped", skip_reason="not_https", counts_toward_exit=counts))
            if not internal_by_text(urlsplit(url).hostname or ""):
                plan.findings.append(ReportFinding(http_agent_finding(url, location_path), item))
        elif not probe:
            off += 1
            plan.reports.append(AgentReport(item, "remote", form, "skipped", skip_reason="probe_off", counts_toward_exit=counts))
        elif fork:
            plan.reports.append(AgentReport(item, "remote", form, "skipped", skip_reason="fork", counts_toward_exit=counts))
        else:
            plan.tasks.append(AgentTask(url, rules, trust, location_path, counts))
    if off:
        plan.notices.append(Notice("a2a_agents_need_probe", "", f"{off} remote agents named in a2a.agents were not fetched: they "
                                   "are fetched only with --probe"))
    return plan
