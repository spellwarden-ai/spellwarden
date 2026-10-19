"""Classification of a recorded probe and `evaluate_probe` (spec 5.7)."""
from __future__ import annotations

import dataclasses
import re
from datetime import date

from spellwarden_scan import checklist
from spellwarden_scan.model import McpScanResult, ProbeResult
from spellwarden_scan.rules import RuleSet
from spellwarden_scan.scan import run_rules
from spellwarden_scan.version import RULES_VERSION, __version__

SPEC_BASELINE = "2026-07-28"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TASKS_CAPABILITY = "io.modelcontextprotocol/tasks"
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_JSON_TYPES = ("application/json", "text/event-stream")
_DEPRECATED_ORDER = ("sse", "initialize_only", "sessions", "roots", "sampling", "logging", "dcr")
_LONG_RUNNING = re.compile(r"(may take (several |a few )?(minutes|hours)|long[- ]running)", re.IGNORECASE)


def is_date(text: object) -> bool:
    """A real calendar date written `YYYY-MM-DD`: `9999-99-99` has the shape and is not one."""
    if not isinstance(text, str) or _DATE.match(text) is None:
        return False
    try:
        date.fromisoformat(text)
    except ValueError:
        return False
    return True


def _media(value: str | None) -> str:
    return (value or "").split(";", 1)[0].strip().lower()


def transport_of(probe: ProbeResult) -> str:
    if probe.endpoint is None and probe.repository is not None:
        return "stdio"
    if probe.post_status == 200 and _media(probe.post_content_type) in _JSON_TYPES:
        return "streamable-http"
    if probe.post_status in (404, 405) and _media(probe.get_content_type) == "text/event-stream" and probe.sse_endpoint_event:
        return "sse"
    return "unknown"


def spec_version_of(probe: ProbeResult) -> str | None:
    if probe.discover is not None:
        versions = probe.discover.get("supportedVersions")
        if isinstance(versions, list):
            dates = sorted(v for v in versions if is_date(v))
            if dates:
                return dates[-1]
    if is_date(probe.negotiated_version):
        return probe.negotiated_version
    return None


def auth_mode_of(probe: ProbeResult) -> str:
    if probe.endpoint is None:
        return "unknown"
    status = probe.unauthenticated_status
    if status == 200:
        return "none"
    if status not in (401, 403):
        return "unknown"
    asm = probe.auth_server_metadata
    if asm is not None:
        if asm.client_id_metadata_document_supported:
            return "oauth-cimd"
        if JWT_BEARER in asm.grant_types_supported and not asm.registration_endpoint:
            return "xaa"
        if asm.registration_endpoint:
            return "oauth-dcr"
    if probe.resource_metadata is None:
        return "static-key"
    return "unknown"


def initialize_only(probe: ProbeResult) -> bool:
    return probe.discover is None and probe.initialize is not None


def deprecated_capabilities(probe: ProbeResult) -> list[str]:
    """`roots`, `sampling`, `logging` in the order of spec 5.7. `logging` is a server capability and
    is read from the server maps only (`probe.capabilities`, the result's `capabilities`); `roots`
    and `sampling` are read from the server maps and from the client-side maps too
    (`clientCapabilities`, `requiredClientCapabilities`), as SW-MCP-008 says."""
    found: set[str] = set()
    server_maps: list[dict] = [probe.capabilities]
    client_maps: list[dict] = []
    for result in (probe.discover, probe.initialize):
        if isinstance(result, dict):
            server_maps.append(result.get("capabilities") or {})
            for key in ("clientCapabilities", "requiredClientCapabilities"):
                client_maps.append(result.get(key) or {})
    for source in server_maps:
        if isinstance(source, dict):
            for name in ("roots", "sampling", "logging"):
                if name in source:
                    found.add(name)
    for source in client_maps:
        if isinstance(source, dict):
            for name in ("roots", "sampling"):
                if name in source:
                    found.add(name)
    return [name for name in ("roots", "sampling", "logging") if name in found]


def long_running_tools_of(probe: ProbeResult) -> tuple[str, ...]:
    """Tools whose `annotations.longRunning` is true or whose description says the call may take minutes."""
    return tuple(tool.name for tool in probe.tools
                 if tool.annotations.get("longRunning") is True or _LONG_RUNNING.search(tool.description or ""))


def list_meta_missing_of(probe: ProbeResult) -> bool:
    """A `tools/list` result was observed and lacks `ttlMs` or `cacheScope` (checklist item 10)."""
    meta = probe.list_result_meta
    return meta is not None and not ("ttlMs" in meta and "cacheScope" in meta)


def classify(probe: ProbeResult) -> tuple[str | None, str, str, tuple[str, ...]]:
    """`(spec_version, transport, auth_mode, deprecated_features)` of spec 5.7."""
    transport = transport_of(probe)
    spec_version = spec_version_of(probe)
    auth_mode = auth_mode_of(probe)
    present = set(deprecated_capabilities(probe))
    if transport == "sse":
        present.add("sse")
    if initialize_only(probe):
        present.add("initialize_only")
    if probe.session_id_seen:
        present.add("sessions")
    if auth_mode == "oauth-dcr":
        present.add("dcr")
    return spec_version, transport, auth_mode, tuple(name for name in _DEPRECATED_ORDER if name in present)


def migration_status_of(spec_version: str | None, auth_mode: str, deprecated_features: tuple[str, ...], transport: str) -> str:
    if transport == "stdio":
        return "not_probeable"
    current = spec_version is not None and spec_version >= SPEC_BASELINE
    if current and auth_mode in ("oauth-cimd", "xaa") and not deprecated_features:
        return "ready"
    return "to_migrate"


def evaluate_probe(probe: ProbeResult, rules: RuleSet, *, max_findings: int = 500, max_per_rule: int = 100) -> McpScanResult:
    spec_version, transport, auth_mode, deprecated = classify(probe)
    findings, truncated = run_rules(rules.ordered_for_scan("mcp"), probe, max_findings=max_findings, max_per_rule=max_per_rule)
    result = McpScanResult(
        findings=tuple(findings), truncated=truncated, spec_version=spec_version, transport=transport, auth_mode=auth_mode,
        deprecated_features=deprecated, migration_status=migration_status_of(spec_version, auth_mode, deprecated, transport),
        checklist=(), rules_version=RULES_VERSION, scanner_version=__version__,
        list_meta_missing=list_meta_missing_of(probe), long_running_tools=long_running_tools_of(probe),
        tasks_supported=TASKS_CAPABILITY in (probe.capabilities or {}),
        issuer_problem=any(f.rule_id == "SW-MCP-010" for f in findings),
    )
    return dataclasses.replace(result, checklist=checklist.migration_checklist(result))
