"""The probe phase of `spellwarden scan --probe` (spec 6.8; plan decision P8): which servers are probed, the
whole-phase budget, the workers, and the bounds on what an answer may put in a report.

- Probed: every `http` or `sse` server entry of a judged configuration document whose URL is `https://`. A URL holding
  `${` is not probed (`unresolved`); `http://` URLs are SW-CFG-001 findings and are never probed.
- Budget: four probes at a time; at most 50 servers (the rest `limit`); at most 300 connections and 120 s of wall
  clock for the whole phase. Once either is spent no new connection starts (the fetcher's gate), requests in
  flight end at their own 10 s deadline, and every server that was refused a connection or not started is `budget`
  with no partial result kept.
- A probe refused by the SSRF rules (`private_address`, `not_https`) records the refusal code only.
- Every string an answer puts in a result is cut to 1000 characters, every list to 200 items, every mapping to 200
  keys and 8 levels before the engine evaluates it; the output modules escape what they print (spec 6.13).

This module imports the fetcher and the prober; it opens no connection itself (`tests/test_network_boundary.py`)."""
from __future__ import annotations

import dataclasses
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlsplit

from spellwarden_scan import Location, OrgRuleBudget, ProbeResult, RuleSet, evaluate_probe
from spellwarden_scan.version import __version__

from spellwarden_cli import escape
from spellwarden_cli import probe as prober
from spellwarden_cli.discover import Discovery
from spellwarden_cli.net import FetchError, Fetcher
from spellwarden_cli.report import Notice, ProbeReport, ReportFinding

MAX_WORKERS = 4
MAX_SERVERS = 50
MAX_REQUESTS = 300
BUDGET_SECONDS = 120.0
REFUSALS = ("private_address", "not_https")
MAX_TEXT = prober.MAX_DESCRIPTION
MAX_ITEMS = prober.MAX_TOOLS
MAX_KEYS = 200
MAX_DEPTH = 8


@dataclass(frozen=True)
class ProbeTarget:
    item: str      # "<file>#<server name>", the mcp-server item
    path: str      # the configuration file
    line: int      # the server entry's line
    url: str


def probe_targets(found: Discovery) -> tuple[list[ProbeTarget], list[ProbeReport]]:
    """The servers to probe, sorted by item, and the `unresolved` skips."""
    targets: list[ProbeTarget] = []
    skipped: list[ProbeReport] = []
    for document in found.documents:
        if document.error not in (None, "truncated"):
            continue
        for server in document.servers:
            if server.transport not in ("http", "sse") or not server.url:
                continue
            item = f"{document.path}#{server.name}"
            if "${" in server.url:
                skipped.append(ProbeReport(item, "skipped", "unresolved", None))
                continue
            try:
                scheme = urlsplit(server.url).scheme.lower()
            except ValueError:
                continue
            if scheme == "https":
                targets.append(ProbeTarget(item, document.path, server.line, server.url))
    targets.sort(key=lambda target: target.item)
    skipped.sort(key=lambda report: report.item)
    return targets, skipped


class _Budget:
    """The whole phase's allowance: `take()` is True while connections and seconds are left; once it returns
    False it always does."""

    def __init__(self, clock: Callable[[], float], *, seconds: float, requests: int) -> None:
        self._clock = clock
        self._deadline = clock() + seconds
        self._left = requests
        self._lock = threading.Lock()
        self.spent = False

    def take(self) -> bool:
        with self._lock:
            if not self.spent and (self._left <= 0 or self._clock() >= self._deadline):
                self.spent = True
            if self.spent:
                return False
            self._left -= 1
            return True


def _text(value: object) -> object:
    return value[:MAX_TEXT] if isinstance(value, str) else value


def _bounded(value: object, depth: int = 0) -> object:
    if isinstance(value, str):
        return value[:MAX_TEXT]
    if isinstance(value, list):
        return [] if depth >= MAX_DEPTH else [_bounded(item, depth + 1) for item in value[:MAX_ITEMS]]
    if isinstance(value, dict):
        if depth >= MAX_DEPTH:
            return {}
        return {str(key)[:MAX_TEXT]: _bounded(item, depth + 1) for key, item in list(value.items())[:MAX_KEYS]}
    return value


def bounded_result(result: ProbeResult) -> ProbeResult:
    """`result` with every answer-supplied value cut to the caps of the module docstring."""
    metadata = result.auth_server_metadata
    if metadata is not None:
        metadata = dataclasses.replace(
            metadata, issuer=_text(metadata.issuer), registration_endpoint=_text(metadata.registration_endpoint),
            grant_types_supported=tuple(str(grant)[:MAX_TEXT] for grant in metadata.grant_types_supported[:MAX_ITEMS]))
    return dataclasses.replace(
        result, discover=_bounded(result.discover), initialize=_bounded(result.initialize),
        negotiated_version=_text(result.negotiated_version), www_authenticate=_text(result.www_authenticate),
        post_content_type=_text(result.post_content_type), get_content_type=_text(result.get_content_type),
        resource_metadata=_bounded(result.resource_metadata), auth_server_metadata=metadata,
        tools=tuple(dataclasses.replace(tool, name=tool.name[:MAX_TEXT], description=tool.description[:MAX_TEXT],
                                        annotations=_bounded(tool.annotations)) for tool in result.tools[:MAX_ITEMS]),
        list_result_meta=_bounded(result.list_result_meta), capabilities=_bounded(result.capabilities) or {})


def event_logger(log: Callable[[str], None]) -> Callable[[str, dict], None]:
    """`--verbose`: one line per connection (host, method, status, time) and per failed probe."""
    def on_event(name: str, fields: dict) -> None:
        if name == "net_request":
            log(escape.terminal(f"net: {fields.get('method')} {fields.get('host')} {fields.get('status')} "
                                f"({fields.get('ms')} ms)"))
        elif name == "probe_failed":
            log(escape.terminal(f"probe: failed ({fields.get('error_class')})"))
    return on_event


def _probe_one(target: ProbeTarget, rules: RuleSet, budget: _Budget, fetcher_factory: Callable[[], Fetcher],
               now_iso: str, org_budget: Callable[[], OrgRuleBudget] | None = None
               ) -> tuple[ProbeReport, list[ReportFinding], str | None]:
    if budget.spent:
        return ProbeReport(target.item, "skipped", "budget", None), [], None
    refused = threading.Event()

    def gate() -> None:
        if not budget.take():
            refused.set()
            raise FetchError("budget")

    fetcher = fetcher_factory()
    fetcher._gate = gate
    result = prober.probe(fetcher, target.url, release=__version__, now_iso=now_iso)
    if refused.is_set():  # the budget ran out during this probe: nothing of it is kept
        return ProbeReport(target.item, "skipped", "budget", None), [], None
    if result.error in REFUSALS and not result.reachable:
        return ProbeReport(target.item, "skipped", "refused", None), [], result.error
    evaluated = evaluate_probe(bounded_result(result), rules,
                               **({"org_rule_budget": org_budget()} if org_budget is not None else {}))
    findings = [ReportFinding(dataclasses.replace(finding, location=Location(target.path, target.line)), target.item)
                for finding in evaluated.findings]
    return ProbeReport(target.item, "probed", None, evaluated), findings, None


def run_phase(targets: Sequence[ProbeTarget], rules: RuleSet, *, fetcher_factory: Callable[[], Fetcher],
              clock: Callable[[], float] = time.monotonic, now_iso: str, notices: list[Notice] | None = None,
              org_budget: Callable[[], OrgRuleBudget] | None = None) -> tuple[list[ProbeReport], list[ReportFinding]]:
    """Probes `targets` under the budget. Reports are in item order, whatever order the workers finished in;
    every skip is also a `probe_skipped` notice in `notices` (a refusal names its code and nothing else). With
    `org_budget` (connected mode, O3 spec 6.5) each probed server's org rules run under a budget of their own; a rule
    that did not finish is named by `McpScanResult.org_rules_incomplete`."""
    ordered = sorted(targets, key=lambda target: target.item)
    chosen, over = ordered[:MAX_SERVERS], ordered[MAX_SERVERS:]
    budget = _Budget(clock, seconds=BUDGET_SECONDS, requests=MAX_REQUESTS)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="spellwarden-probe") as pool:
        outcomes = list(pool.map(lambda target: _probe_one(target, rules, budget, fetcher_factory, now_iso, org_budget), chosen))
    reports = [report for report, _, _ in outcomes] + [ProbeReport(t.item, "skipped", "limit", None) for t in over]
    findings = [finding for _, found, _ in outcomes for finding in found]
    if notices is not None:
        refusals = {report.item: code for report, _, code in outcomes if code is not None}
        for report in reports:
            if report.status == "skipped":
                reason = f"{report.skip_reason}: {refusals[report.item]}" if report.item in refusals else report.skip_reason
                notices.append(Notice("probe_skipped", report.item, f"not probed ({reason})"))
    reports.sort(key=lambda report: report.item)
    return reports, findings
