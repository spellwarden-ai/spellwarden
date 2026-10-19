"""The 11 MCP rules of spec 5.4. Each `detect(probe)` yields `Finding`s whose
location is the endpoint (or the repository), or `tool:<name>` for SW-MCP-011."""
from __future__ import annotations

import re
from collections.abc import Iterator

from spellwarden_scan.evidence import bounded_evidence, fingerprint, mask_credentials
from spellwarden_scan.model import Finding, Location, ProbeResult
from spellwarden_scan.probe import text_of
from spellwarden_scan.probe import auth_mode_of, classify, deprecated_capabilities, initialize_only, spec_version_of, transport_of
from spellwarden_scan.rules import Rule, make_rule
from spellwarden_scan.rules import patterns as P
from spellwarden_scan.rules.skill import visible

SPEC_BASELINE = "2026-07-28"
_TOOL_INJECTION = (
    re.compile(r"always (call|use|run) this tool", re.IGNORECASE),
    re.compile(r"before (any|every|all) other tools?", re.IGNORECASE),
    re.compile(r"(do not|don't|never) (mention|reveal|show|tell)", re.IGNORECASE),
    re.compile(r"<(system|instructions?|important)>", re.IGNORECASE),
    P.Then(r"IMPORTANT:", r"(ignore|override|must)"),  # linear: the regex `.*` form is quadratic on repeated `IMPORTANT:`
    re.compile(r"\bhidden\b", re.IGNORECASE),
    re.compile(r"secret instruction", re.IGNORECASE),
)


def _redacted(url: str) -> str:
    """`url` without userinfo, query or fragment: a finding's location and evidence never carry
    `https://user:pass@host/` or `?api_key=...` from a registered endpoint or repository URL."""
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    # An `@` ends the userinfo only when no `/`, `?` or `#` comes before it. Otherwise the `@` sits in the path or
    # query, or in a raw password that holds a delimiter: no reading is safe to show, so nothing is kept.
    if "@" in rest:
        userinfo, _, rest = rest.rpartition("@")
        if any(mark in userinfo for mark in "/?#"):
            return f"{scheme}://redacted"
    rest = rest.split("#", 1)[0].split("?", 1)[0]
    authority, separator, path = rest.partition("/")
    if not authority:
        return f"{scheme}://redacted"
    # A token carried in the path (`/api/mcp/s/<token>/mcp`) is masked like any evidence (spec 5.10), segment by segment
    # so the host and the other segments stay readable.
    path = "/".join(mask_credentials(segment) for segment in path.split("/"))
    return f"{scheme}://{authority}{separator}{path}"


def _where(probe: ProbeResult) -> str:
    return _redacted(probe.endpoint or probe.repository or "server")


def _finding(rule_id: str, severity: str, probe: ProbeResult, evidence: str, *, path: str | None = None) -> Finding:
    """The fingerprint is over the original text; the stored evidence is `bounded_evidence` of it."""
    location = path or _where(probe)
    return Finding(rule_id, severity, TITLES[rule_id], Location(location, None), bounded_evidence(evidence),
                   fingerprint(rule_id, location, evidence), False)


_DEFAULT_PORTS = {"https": "443", "http": "80"}


def _origin(url: str | None) -> str | None:
    """`scheme://host[:port]` of `url`, pure (no `urllib`): the scheme and host lower-cased, a default
    port dropped, the path, query and fragment removed. `None` when there is no scheme, no host,
    an unclosed IPv6 bracket, a port that is not a number, or userinfo in the authority (an
    `issuer` or `resource` with embedded credentials is never accepted as equal to anything)."""
    if not url or "://" not in url:
        return None
    scheme, rest = url.split("://", 1)
    scheme = scheme.lower()
    if not scheme.isalpha():
        return None
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if not authority or "@" in authority:
        return None
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return None
        host, port_part = authority[:end + 1].lower(), authority[end + 1:]
    else:
        host, separator, port = authority.partition(":")
        host = host.lower()
        port_part = separator + port
    if not host or host == "[]":
        return None
    if port_part:
        if not port_part.startswith(":") or not port_part[1:].isdigit():
            return None
        if port_part[1:] == _DEFAULT_PORTS.get(scheme):
            port_part = ""
    return f"{scheme}://{host}{port_part}"


def _canonical(url: str | None) -> str | None:
    """`_origin(url)` plus the path (query and fragment removed, trailing slash dropped): what an
    issuer and the metadata location are compared as (RFC 8414 allows an issuer with a path)."""
    origin = _origin(url)
    if origin is None or url is None:
        return None
    after_scheme = url.split("://", 1)[1]
    path = after_scheme[len(after_scheme.split("/", 1)[0]):] if "/" in after_scheme else ""
    path = path.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    return origin + path


def _probeable(probe: ProbeResult) -> bool:
    """Endpoint rules run only for an https endpoint (a `not_https` probe sees SW-MCP-009 alone)."""
    return probe.endpoint is not None and probe.error != "not_https"


def _mcp_001(probe: ProbeResult) -> Iterator[Finding]:
    if _probeable(probe) and auth_mode_of(probe) == "none":
        yield _finding("SW-MCP-001", "high", probe, f"tools/list answered 200 with {len(probe.tools)} tools")


def _mcp_002(probe: ProbeResult) -> Iterator[Finding]:
    if _probeable(probe) and auth_mode_of(probe) == "static-key":
        yield _finding("SW-MCP-002", "medium", probe, f"HTTP {probe.unauthenticated_status} without protected resource metadata")


def _mcp_003(probe: ProbeResult) -> Iterator[Finding]:
    if _probeable(probe) and auth_mode_of(probe) == "oauth-dcr":
        endpoint = probe.auth_server_metadata.registration_endpoint if probe.auth_server_metadata else ""
        yield _finding("SW-MCP-003", "medium", probe, f"registration_endpoint {endpoint}")


def _mcp_004(probe: ProbeResult) -> Iterator[Finding]:
    if _probeable(probe) and transport_of(probe) == "sse":
        yield _finding("SW-MCP-004", "medium", probe, f"POST {probe.post_status}, GET text/event-stream with an endpoint event")


def _mcp_005(probe: ProbeResult) -> Iterator[Finding]:
    if not _probeable(probe):
        return
    version = spec_version_of(probe)
    if version is not None and version < SPEC_BASELINE:
        yield _finding("SW-MCP-005", "low", probe, f"spec version {version}")
    elif version is None and initialize_only(probe):
        yield _finding("SW-MCP-005", "low", probe, "no protocol version negotiated")


def _mcp_006(probe: ProbeResult) -> Iterator[Finding]:
    if _probeable(probe) and probe.session_id_seen:
        yield _finding("SW-MCP-006", "medium", probe, "Mcp-Session-Id header seen")


def _mcp_007(probe: ProbeResult) -> Iterator[Finding]:
    if _probeable(probe) and initialize_only(probe):
        yield _finding("SW-MCP-007", "medium", probe, "initialize answered, server/discover did not")


def _mcp_008(probe: ProbeResult) -> Iterator[Finding]:
    if not _probeable(probe):
        return
    names = deprecated_capabilities(probe)
    if names:
        yield _finding("SW-MCP-008", "medium", probe, ", ".join(names))
        return
    for tool in probe.tools:
        if "sampling/createMessage" in text_of(tool.description):
            yield _finding("SW-MCP-008", "medium", probe, f"tool {tool.name} mentions sampling/createMessage")
            return


def _mcp_009(probe: ProbeResult) -> Iterator[Finding]:
    if probe.endpoint is None:
        return
    origin = _origin(probe.endpoint)
    if origin is None or not origin.startswith("https://"):
        yield _finding("SW-MCP-009", "high", probe, _redacted(probe.endpoint))


def _mcp_010(probe: ProbeResult) -> Iterator[Finding]:
    if not _probeable(probe) or auth_mode_of(probe) not in ("oauth-dcr", "oauth-cimd", "xaa"):
        return
    metadata = probe.resource_metadata
    if metadata is None:
        yield _finding("SW-MCP-010", "medium", probe, "no protected resource metadata")
        return
    if not metadata.get("authorization_servers"):
        yield _finding("SW-MCP-010", "medium", probe, "no authorization server listed")
        return
    asm = probe.auth_server_metadata
    if asm is not None and not text_of(asm.issuer).strip():
        # RFC 8414 makes `issuer` required: metadata without one cannot be validated, so it is never a pass.
        yield _finding("SW-MCP-010", "medium", probe, "authorization server metadata has no issuer")
        return
    if asm is not None and asm.metadata_url:
        # RFC 8414: the metadata of issuer `https://host/tenant` lives at
        # `https://host/.well-known/<suffix>/tenant`; the expected issuer is the origin plus that trailing path.
        before, _, after = asm.metadata_url.partition("/.well-known/")
        trailing = after.split("/", 1)[1] if "/" in after else ""
        expected = _canonical(before + ("/" + trailing if trailing else ""))
        if expected is None or _canonical(asm.issuer) != expected:
            yield _finding("SW-MCP-010", "medium", probe, f"issuer {asm.issuer} differs from {expected}")
            return
    resource = metadata.get("resource")
    if not isinstance(resource, str) or not _covers(resource, probe.endpoint):
        yield _finding("SW-MCP-010", "medium", probe, f"resource {resource} is not the endpoint")


def _covers(resource: str, endpoint: str | None) -> bool:
    """RFC 9728: the protected resource is the endpoint itself or a parent path of it on the same origin.
    Compared canonically (case, default port, trailing slash) and on a path-segment boundary, so neither
    `https://mcp.example` for `https://mcp.example.attacker.net/mcp` nor `/mc` for `/mcp` passes."""
    wanted, probed = _canonical(resource), _canonical(endpoint)
    if wanted is None or probed is None:
        return False
    return probed == wanted or probed.startswith(wanted + "/")


def _mcp_011(probe: ProbeResult) -> Iterator[Finding]:
    for tool in probe.tools:
        text = text_of(tool.description)
        seen = visible(text)  # invisible characters do not break a phrase up (`skill.visible`)
        if any(p.search(seen) for p in P.INJECTION) or any(p.search(seen) for p in _TOOL_INJECTION):
            yield _finding("SW-MCP-011", "high", probe, text, path=f"tool:{tool.name}")


TITLES = {
    "SW-MCP-001": "Server lists tools without authentication",
    "SW-MCP-002": "Static key authentication instead of OAuth",
    "SW-MCP-003": "OAuth dynamic client registration (deprecated; use Client ID Metadata Documents)",
    "SW-MCP-004": "HTTP+SSE transport (deprecated)",
    "SW-MCP-005": "Spec version older than 2026-07-28",
    "SW-MCP-006": "Protocol sessions (Mcp-Session-Id) in use",
    "SW-MCP-007": "Requires the initialize handshake; no server/discover",
    "SW-MCP-008": "Uses deprecated Roots, Sampling or Logging",
    "SW-MCP-009": "Endpoint not served over HTTPS",
    "SW-MCP-010": "No protected resource metadata, or issuer not validated",
    "SW-MCP-011": "Tool description contains instruction-like text",
}

RULES: tuple[Rule, ...] = (
    make_rule("SW-MCP-001", TITLES["SW-MCP-001"], "high", "mcp", owasp=("MCP01",), nist=("AC-3",), detect=_mcp_001, targets=("kong", "registry")),
    make_rule("SW-MCP-002", TITLES["SW-MCP-002"], "medium", "mcp", owasp=("MCP01",), nist=("IA-5",), detect=_mcp_002, targets=("registry",)),
    make_rule("SW-MCP-003", TITLES["SW-MCP-003"], "medium", "mcp", owasp=("MCP01",), nist=("IA-5",), detect=_mcp_003, targets=("registry",)),
    make_rule("SW-MCP-004", TITLES["SW-MCP-004"], "medium", "mcp", owasp=("ASI04",), nist=("SR-3",), detect=_mcp_004, targets=("registry",)),
    make_rule("SW-MCP-005", TITLES["SW-MCP-005"], "low", "mcp", owasp=("ASI04",), nist=("SR-3",), detect=_mcp_005, targets=("registry",)),
    make_rule("SW-MCP-006", TITLES["SW-MCP-006"], "medium", "mcp", owasp=("ASI04",), nist=("SR-3",), detect=_mcp_006),
    make_rule("SW-MCP-007", TITLES["SW-MCP-007"], "medium", "mcp", owasp=("ASI04",), nist=("SR-3",), detect=_mcp_007),
    make_rule("SW-MCP-008", TITLES["SW-MCP-008"], "medium", "mcp", owasp=("ASI04",), nist=("SR-3",), detect=_mcp_008),
    make_rule("SW-MCP-009", TITLES["SW-MCP-009"], "high", "mcp", owasp=("MCP01",), nist=("SC-7",), detect=_mcp_009, targets=("kong", "registry")),
    make_rule("SW-MCP-010", TITLES["SW-MCP-010"], "medium", "mcp", owasp=("MCP01",), nist=("IA-5",), detect=_mcp_010, targets=("registry",)),
    make_rule("SW-MCP-011", TITLES["SW-MCP-011"], "high", "mcp", owasp=("ASI01", "MCP10"), nist=("SI-10",), detect=_mcp_011, targets=("kong",)),
)

__all__ = ["RULES", "TITLES", "classify"]
