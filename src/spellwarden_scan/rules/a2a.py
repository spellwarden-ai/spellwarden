"""The nineteen A2A agent card rules (O4 spec 5.4; SW-A2A-019 since 1.4.0; 0.x snake_case members since 1.5.0). Each `detect(subject)` is a generator of
`Finding`s over a `CardSubject`: the parsed card, where it came from, what the command found out about its signatures and
the path findings point at. None is a malicious indicator and none has an export target. The engine never verifies a signature: SW-A2A-010,
011, 012, 013 and 017 read the `SignatureOutcome`s the command recorded, as `evaluate_probe` reads a recorded probe.

A finding's location is `location_path` with the line of the JSON value it is about for a repository card, and no line for
a remote card. Its fingerprint is `evidence.fingerprint(rule_id, location_path, matched)` where `matched` is the member's
stable identity (`a2a.owner_identity`), the member name and the reason, plus the requested URL for a remote card; never a
line number or an array index, so moving a member or inserting a skill keeps every fingerprint (claim R2). Evidence is the
RFC 6901 pointer, a colon and a short reason or the offending value, masked and at most 300 characters; URLs in it lose
userinfo, query and fragment.

Rules judge the card as a protobuf client reads it (`AgentCardDocument.view`): a member spelled with its proto field name
(`security_requirements`) is checked as the member it names, and pointers into it use the JSON names. Where that spelling
sits is SW-A2A-001 (`proto_field_name`) when it is the only one, SW-A2A-019 when the card spells the member both ways. A member
A2A 1.0 removed, spelled in snake_case, is read as `a2a-sdk` 0.3 reads it (1.5.0): SW-A2A-001 `legacy_field_name` alone,
SW-A2A-019 `name_kept` with its camelCase spelling.
SW-A2A-015 reads every value as served, so a credential under a spelling the reader drops is still found."""
from __future__ import annotations

import ipaddress
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from spellwarden_scan._json import Arr, Obj
from spellwarden_scan.a2a import (
    DEPRECATED_FLOWS, AgentCardDocument, capped, is_legacy_pointer, legacy_members, legacy_version_issues,
    owner_identity, pointer_of, read_as_client, signature_identity, skill_identity, validate_1_0,
)
from spellwarden_scan.a2a_proto import PROTO_NAMES
from spellwarden_scan.agentconfig import url_parts
from spellwarden_scan.evidence import EVIDENCE_MAX, bounded_evidence, code_point_names, fingerprint, mask_credentials
from spellwarden_scan.model import CardOrigin, Finding, Location, SignatureOutcome
from spellwarden_scan.rules import Rule, make_rule
from spellwarden_scan.rules import patterns as P
from spellwarden_scan.rules.mcp import TOOL_INJECTION_SECRET, TOOL_INJECTION_TAG
from spellwarden_scan.rules.mcp import _redacted as redacted_url
from spellwarden_scan.rules.skill import has_credential, hidden_characters, visible

TITLES = {
    "SW-A2A-001": "Agent card does not follow A2A 1.0",
    "SW-A2A-002": "Agent card uses a format older than A2A 1.0",
    "SW-A2A-003": "Agent card at the path used before A2A 0.3",
    "SW-A2A-004": "Agent endpoint or authentication URL not served over HTTPS",
    "SW-A2A-005": "OAuth implicit or password flow declared (deprecated in A2A 1.0)",
    "SW-A2A-006": "OAuth authorization code flow without PKCE required",
    "SW-A2A-007": "Agent declares no authentication",
    "SW-A2A-008": "API key sent in the URL query",
    "SW-A2A-009": "Skill inherits every scope of the agent",
    "SW-A2A-010": "Agent card signature does not verify",
    "SW-A2A-011": "Agent card signature is malformed or uses a refused algorithm",
    "SW-A2A-012": "Agent card is not signed",
    "SW-A2A-013": "Signing key not bound to the card's host",
    "SW-A2A-014": "Agent card text contains injected instructions or hidden characters",
    "SW-A2A-015": "Credential in the agent card",
    "SW-A2A-016": "Agent card fetched through a redirect to another host",
    "SW-A2A-017": "Agent card signed with a shared secret that only the agent can check",
    "SW-A2A-018": "Agent card cannot be read",
    "SW-A2A-019": "Agent card member spelled two ways",
}
SEVERITY = {"SW-A2A-001": "medium", "SW-A2A-002": "medium", "SW-A2A-003": "medium", "SW-A2A-004": "high",
            "SW-A2A-005": "high", "SW-A2A-006": "medium", "SW-A2A-007": "medium", "SW-A2A-008": "medium",
            "SW-A2A-009": "low", "SW-A2A-010": "high", "SW-A2A-011": "high", "SW-A2A-012": "low", "SW-A2A-013": "medium",
            "SW-A2A-014": "high", "SW-A2A-015": "critical", "SW-A2A-016": "medium", "SW-A2A-017": "medium",
            "SW-A2A-018": "high", "SW-A2A-019": "high"}
_KIND_OF_WRAPPER = {"apiKeySecurityScheme": "apiKey", "httpAuthSecurityScheme": "http", "oauth2SecurityScheme": "oauth2",
                    "openIdConnectSecurityScheme": "openIdConnect", "mtlsSecurityScheme": "mtls"}
_KIND_OF_TYPE = {"apiKey": "apiKey", "http": "http", "oauth2": "oauth2", "openIdConnect": "openIdConnect", "mutualTLS": "mtls"}
_AUTH_URLS = ("authorizationUrl", "tokenUrl", "refreshUrl", "deviceAuthorizationUrl")
_BOM_REASON = "a byte-order mark, which A2A clients reject"
# The member names of A2A 1.0 and of the older cards: a pointer segment from this list is shown as it is. Every other
# segment (a security scheme's name, a vendor member) is card text and goes through `mask_credentials`.
_PROTOCOL_NAMES = frozenset("""
    name description version supportedInterfaces provider iconUrl documentationUrl capabilities securitySchemes
    securityRequirements defaultInputModes defaultOutputModes skills signatures url protocolBinding protocolVersion tenant
    organization streaming pushNotifications extendedAgentCard extensions uri required params id tags examples inputModes
    outputModes protected signature header schemes list apiKeySecurityScheme httpAuthSecurityScheme oauth2SecurityScheme
    openIdConnectSecurityScheme mtlsSecurityScheme location scheme bearerFormat openIdConnectUrl oauth2MetadataUrl flows
    authorizationCode clientCredentials deviceCode implicit password authorizationUrl tokenUrl refreshUrl
    deviceAuthorizationUrl scopes pkceRequired preferredTransport additionalInterfaces supportsAuthenticatedExtendedCard
    supportsExtendedAgentCard security stateTransitionHistory transport type in
""".split()) | {alias for names in PROTO_NAMES.values() for alias in names}


@dataclass(frozen=True)
class CardSubject:
    """What a rule sees. `signatures` has one outcome per entry of the card's `signatures` (at most 5), in order; the
    command makes them (`spellwarden_cli.agents`), a test builds them by hand."""
    document: AgentCardDocument
    origin: CardOrigin
    signatures: tuple[SignatureOutcome, ...]
    location_path: str


def _root(subject: CardSubject) -> Obj | None:
    """The card as a protobuf client reads it when it parsed and has the card shape; every rule but 018 and the
    `not_a_card` half of 001 stops at a document that is not a card."""
    document = subject.document
    return read_as_client(document) if document.root is not None and document.card_shape else None


class _Ours(str):
    """Evidence detail the scanner writes from its own tables (member names, no card text): shown unmasked, since
    `mask_credentials` would take `oauth2SecurityScheme` for a token."""


def _at(pointer: str, detail: str) -> tuple[str, str]:
    """Evidence about the member at `pointer`: the pointer and a short reason or the offending value."""
    return pointer, detail


def _evidence(evidence: str | tuple[str, str]) -> str:
    """Evidence is masked and at most 300 characters (spec 5.10). A pointer is masked one segment at a time, and a segment
    that is a member name of the protocol or an index is not masked: `mask_credentials` takes a run of 20 or more path-like
    characters for a token and would hide `/skills/0/examples/0` and `.../oauth2SecurityScheme/...` whole. A member name
    chosen by the card (a scheme's name, a vendor member) is masked like the value."""
    if isinstance(evidence, str):
        return bounded_evidence(evidence)
    pointer, detail = evidence
    shown = "/".join(segment if segment in _PROTOCOL_NAMES or segment.isdigit() else mask_credentials(segment)
                     for segment in pointer.split("/"))
    said = ' '.join(str(detail).split())
    text = f"{' '.join(shown.split())}: {said if isinstance(detail, _Ours) else mask_credentials(said)}"
    return text if len(text) <= EVIDENCE_MAX else text[:EVIDENCE_MAX - 3] + "..."


def _finding(rule_id: str, subject: CardSubject, identity: str, member: str, reason: str,
             evidence: str | tuple[str, str], line: int | None) -> Finding:
    remote = subject.origin.source == "remote"
    matched = f"{identity}\x00{member}\x00{reason}" + (f"\x00{subject.origin.requested_url}" if remote else "")
    where = Location(subject.location_path, None if remote else line)
    return Finding(rule_id, SEVERITY[rule_id], TITLES[rule_id], where, _evidence(evidence),
                   fingerprint(rule_id, subject.location_path, matched), False)


def _line(node: object, key: object) -> int | None:
    if isinstance(node, Obj):
        return node.lines.get(key, node.line) if isinstance(key, str) else node.line
    if isinstance(node, Arr):
        return node.lines[key] if isinstance(key, int) and 0 <= key < len(node.lines) else node.line
    return None


def _scalar_leaves(node: object, pointer: str = "", member: str = "") -> Iterator[tuple[str, str, int | None, object]]:
    """`(pointer, member, line, value)` of every scalar under `node`; the member of an array item is its array's name."""
    if isinstance(node, Obj):
        for key, value in node.items():
            if isinstance(value, (Obj, Arr)):
                yield from _scalar_leaves(value, pointer + pointer_of(key), key)
            else:
                yield pointer + pointer_of(key), key, node.lines.get(key), value
    elif isinstance(node, Arr):
        for index, value in enumerate(node):
            if isinstance(value, (Obj, Arr)):
                yield from _scalar_leaves(value, pointer + pointer_of(index), member)
            else:
                yield pointer + pointer_of(index), member, _line(node, index), value


def _schemes(root: Obj) -> Iterator[tuple[str, str, Obj, str, int | None]]:
    """`(name, kind, body, body pointer, line)` of every security scheme: the 1.0 wrapper form and the 0.x `type` form,
    `kind` one of `apiKey`, `http`, `oauth2`, `openIdConnect`, `mtls`."""
    schemes = root.get("securitySchemes")
    if not isinstance(schemes, Obj):
        return
    for name in list(schemes)[:50]:
        scheme = schemes[name]
        if not isinstance(scheme, Obj):
            continue
        base = f"/securitySchemes/{pointer_of(name)[1:]}"
        wrapper = next((key for key in _KIND_OF_WRAPPER if isinstance(scheme.get(key), Obj)), None)
        if wrapper is not None:
            yield name, _KIND_OF_WRAPPER[wrapper], scheme[wrapper], f"{base}/{wrapper}", scheme.lines.get(wrapper)
        elif isinstance(scheme.get("type"), str) and scheme["type"] in _KIND_OF_TYPE:
            yield name, _KIND_OF_TYPE[scheme["type"]], scheme, base, _line(schemes, name)


def _flows(body: Obj, pointer: str) -> Iterator[tuple[str, Obj, str]]:
    flows = body.get("flows")
    if isinstance(flows, Obj):
        for flow, entry in flows.items():
            if isinstance(entry, Obj):
                yield flow, entry, f"{pointer}/flows/{flow}"


def _interface_urls(root: Obj, card_format: str) -> list[tuple[str, int | None, str]]:
    """`(pointer, line, url)` of every endpoint the card declares: `supportedInterfaces[].url` of a 1.0 card, the `url` and
    `additionalInterfaces[].url` of an older one."""
    found: list[tuple[str, int | None, str]] = []
    if card_format == "1.0":
        entries = [(f"/supportedInterfaces/{i}", item) for i, item in enumerate(capped(root.get("supportedInterfaces"), "interfaces"))]
    else:
        entries = [(f"/additionalInterfaces/{i}", item) for i, item in enumerate(capped(root.get("additionalInterfaces"), "interfaces"))]
        if isinstance(root.get("url"), str):
            found.append(("/url", root.lines.get("url"), root["url"]))
    for pointer, item in entries:
        if isinstance(item, Obj) and isinstance(item.get("url"), str):
            found.append((f"{pointer}/url", item.lines.get("url"), item["url"]))
    return found


def is_loopback_host(host: str) -> bool:
    """`localhost`, `127.0.0.0/8` and `::1` (the hosts a development card may use over plain HTTP)."""
    if host.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


# --- SW-A2A-018, 001, 002, 003 ---------------------------------------------------------------------------------------

def _a2a_018(subject: CardSubject) -> Iterator[Finding]:
    document, origin = subject.document, subject.origin
    if document.error is None or origin.source != "repository" or origin.path_form not in ("well_known", "listed"):
        return
    reason = _BOM_REASON if document.error == "bom" else document.error
    yield _finding("SW-A2A-018", subject, "card", "card", document.error, f"{document.error}: {reason}", None)


def _a2a_001(subject: CardSubject) -> Iterator[Finding]:
    document, origin = subject.document, subject.origin
    if document.root is None:
        return
    if not document.card_shape:
        if origin.source == "remote" or origin.path_form in ("well_known", "listed"):
            yield _finding("SW-A2A-001", subject, "card", "card", "not_a_card", _at("/", "not_a_card (no name, or neither supportedInterfaces nor url)"), document.root.line)
        return
    for issue in (*validate_1_0(document), *legacy_version_issues(document)):
        yield _finding("SW-A2A-001", subject, issue.identity, issue.member, issue.reason, _at(issue.pointer or "/", issue.reason),
                       issue.line)
    view = read_as_client(document)
    for alias in document.aliases:
        if alias.outcome == "alias_only" and alias.legacy:  # 1.5.0: a2a-sdk 0.3 reads it, a2a-sdk 1.x and the JS SDK do not
            yield _finding("SW-A2A-001", subject, owner_identity(view, alias.view_pointer), alias.alias, "legacy_field_name",
                           _at(alias.pointer, _Ours(f"the snake_case spelling of {alias.name}, which not every A2A client reads")),
                           alias.line)
        elif alias.outcome == "alias_only":
            yield _finding("SW-A2A-001", subject, owner_identity(view, alias.view_pointer), alias.alias, "proto_field_name",
                           _at(alias.pointer, _Ours(f"the proto field name of {alias.name}")), alias.line)


def _a2a_002(subject: CardSubject) -> Iterator[Finding]:
    root, document = _root(subject), subject.document
    if root is None:
        return
    if document.card_format in ("0.3", "0.2"):
        yield _finding("SW-A2A-002", subject, "card", "card", document.card_format,
                       _at("/", f"card format {document.card_format}"), root.line)
        return
    for pointer, member, line in legacy_members(document):
        yield _finding("SW-A2A-002", subject, owner_identity(root, pointer), member, "legacy_member",
                       _at(pointer, "removed or renamed in A2A 1.0"), line)


def _a2a_003(subject: CardSubject) -> Iterator[Finding]:
    root, origin = _root(subject), subject.origin
    if root is not None and origin.path_form == "legacy_path":
        yield _finding("SW-A2A-003", subject, "card", "card", "legacy_path", _at("/", "served at /.well-known/agent.json"), root.line)


_TWICE = {
    "alias_wins": "spelled twice; a protobuf reader keeps this later spelling, a reader of JSON names keeps {name}",
    "name_wins": "spelled twice; a protobuf reader keeps the later {name}",
    "refused": "spelled twice as {name}; a protobuf reader refuses the card",
    "name_kept": "spelled twice; a2a-sdk 0.3 keeps {name} whatever the order, other readers may keep this one",
}


def _a2a_019(subject: CardSubject) -> Iterator[Finding]:
    """Both spellings of one member: readers disagree on which one is the card. Reported at the proto field name, the
    identity and member those of the JSON name, the reason the `ProtoAlias` outcome."""
    root = _root(subject)
    if root is None:
        return
    for alias in subject.document.aliases:
        if alias.outcome in _TWICE:
            yield _finding("SW-A2A-019", subject, owner_identity(root, alias.view_pointer), alias.name, alias.outcome,
                           _at(alias.pointer, _Ours(_TWICE[alias.outcome].format(name=alias.name))), alias.line)


# --- SW-A2A-004 to 009 -----------------------------------------------------------------------------------------------

def _a2a_004(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is None:
        return
    interface_pointers = set()
    for pointer, line, url in _interface_urls(root, subject.document.card_format):
        interface_pointers.add(pointer)
        parts = url_parts(url)
        if parts is None:  # a GRPC `host:port` cannot be judged statically; the validator reports a malformed URL
            continue
        reason = ("http" if parts.scheme == "http" and not is_loopback_host(parts.host)
                  else "scheme" if parts.scheme not in ("http", "https", "grpcs") else None)
        if reason is not None:
            yield _finding("SW-A2A-004", subject, owner_identity(root, pointer), "url", reason,
                           _at(pointer, redacted_url(url)), line)
    for _name, kind, body, base, _where in _schemes(root):
        owner = owner_identity(root, base)
        urls = [(f"{base}/{key}", key, body.get(key), body.lines.get(key)) for key in ("oauth2MetadataUrl", "openIdConnectUrl")]
        if kind == "oauth2":
            for _flow, entry, flow_pointer in _flows(body, base):
                urls += [(f"{flow_pointer}/{key}", key, entry.get(key), entry.lines.get(key)) for key in _AUTH_URLS]
        for pointer, key, url, line in urls:
            parts = url_parts(url)
            if parts is not None and parts.scheme == "http" and not is_loopback_host(parts.host):
                yield _finding("SW-A2A-004", subject, owner, key, "http", _at(pointer, redacted_url(url)), line)
    for outcome in subject.signatures:
        parts = url_parts(outcome.jku)
        if parts is not None and parts.scheme == "http" and not is_loopback_host(parts.host):
            yield _finding("SW-A2A-004", subject, _signature_owner(root, outcome), "jku", "http",
                           _at(f"/signatures/{outcome.index}", f"jku {redacted_url(outcome.jku or '')}"), _signature_line(root, outcome))


def http_agent_finding(url: str, location_path: str) -> Finding:
    """SW-A2A-004 for an `a2a.agents` entry that is plain `http://` on a public host (6.2): at the settings file, no line,
    the identity `agent:<url>`. Made here so the rule's id, title and severity have one source."""
    subject = CardSubject(AgentCardDocument("", None, None, False, "unknown", (), ""), CardOrigin("remote", "direct", url),
                          (), location_path)
    return _finding("SW-A2A-004", subject, f"agent:{url}", "url", "http", _at("a2a.agents", redacted_url(url)), None)


def _signature_owner(root: Obj, outcome: SignatureOutcome) -> str:
    entries = root.get("signatures")
    index = outcome.index
    return signature_identity(entries[index], index) if isinstance(entries, list) and 0 <= index < len(entries) else f"signature:#{index}"


def _signature_line(root: Obj, outcome: SignatureOutcome) -> int | None:
    entries = root.get("signatures")
    return _line(entries, outcome.index) if isinstance(entries, Arr) else None


def _a2a_005(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is None:
        return
    for name, kind, body, base, _where in _schemes(root):
        if kind != "oauth2":
            continue
        for flow, _entry, pointer in _flows(body, base):
            if flow in DEPRECATED_FLOWS:
                yield _finding("SW-A2A-005", subject, f"scheme:{name}", flow, "deprecated_flow",
                               _at(pointer, "deprecated in A2A 1.0"), _line(body.get("flows"), flow))


def _a2a_006(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is None or subject.document.card_format != "1.0":
        return
    for name, kind, body, base, _where in _schemes(root):
        if kind != "oauth2":
            continue
        for flow, entry, pointer in _flows(body, base):
            if flow == "authorizationCode" and entry.get("pkceRequired") is not True:
                yield _finding("SW-A2A-006", subject, f"scheme:{name}", "pkceRequired", "not_required",
                               _at(pointer, "pkceRequired is not true"), _line(body.get("flows"), flow))


def _requirements(node: Obj, *, legacy: str = "security") -> list:
    """The requirements of a card or a skill: `securityRequirements`, or the 0.x `security` when that is absent."""
    value = node.get("securityRequirements") if "securityRequirements" in node else node.get(legacy)
    return [item for item in capped(value, "requirements") if isinstance(item, Obj)]


def _required_scopes(requirement: Obj) -> Iterator[tuple[str, object]]:
    """`(scheme name, scope list)` of one requirement in either shape: 1.0 `{"schemes": {"name": {"list": [...]}}}`, 0.x
    `{"name": [...]}`."""
    entries = requirement.get("schemes")
    if isinstance(entries, Obj):
        for name, entry in entries.items():
            yield name, entry.get("list") if isinstance(entry, Obj) else None
    else:
        yield from requirement.items()


def _a2a_007(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is None:
        return
    urls = [url_parts(url) for _pointer, _where, url in _interface_urls(root, subject.document.card_format)]
    if urls and all(parts is not None and is_loopback_host(parts.host) for parts in urls):
        return  # a local development card (P15)
    schemes = root.get("securitySchemes")
    skills = [skill for skill in capped(root.get("skills"), "skills") if isinstance(skill, Obj)]
    if not isinstance(schemes, Obj) or not schemes:
        reason = "no_scheme"
    elif not _requirements(root) and not any(_requirements(skill) for skill in skills):
        reason = "no_requirement"
    else:
        return
    yield _finding("SW-A2A-007", subject, "card", "securitySchemes", reason, _at("/", reason), root.line)


def _a2a_008(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is None:
        return
    for name, kind, body, base, line in _schemes(root):
        member = "location" if "location" in body else "in"
        if kind == "apiKey" and body.get(member) == "query":
            yield _finding("SW-A2A-008", subject, f"scheme:{name}", member, "query_key", _at(f"{base}/{member}", "query"),
                           body.lines.get(member, line))


def _a2a_009(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is None:
        return
    oauth = {name for name, kind, _body, _base, _where in _schemes(root) if kind in ("oauth2", "openIdConnect")}
    scopes: set[str] = set()
    for requirement in _requirements(root):
        for name, listed in _required_scopes(requirement):
            if name in oauth:
                scopes.update(item for item in capped(listed, "strings") if isinstance(item, str))
    if len(scopes) < 2:
        return
    skills = root.get("skills")
    for index, skill in enumerate(capped(skills, "skills")):
        if isinstance(skill, Obj) and not _requirements(skill):
            yield _finding("SW-A2A-009", subject, skill_identity(skills, index), "securityRequirements", "inherits_scopes",
                           _at(f"/skills/{index}", f"inherits {len(scopes)} scopes"), _line(skills, index))


# --- SW-A2A-010 to 013, 016, 017 -------------------------------------------------------------------------------------

def signature_status_of(outcomes: Sequence[SignatureOutcome], *, signed: bool) -> str:
    """The card's signature status (5.2): `unsigned` without signatures; `verified` when any outcome is; else `invalid` when
    any is `bad_signature`, `untrusted_key` or `unsigned_legacy`; else `refused` when any is `malformed` or `refused_alg`;
    else `unverified`."""
    if not signed:
        return "unsigned"
    kinds = {outcome.outcome for outcome in outcomes}
    if "verified" in kinds:
        return "verified"
    if kinds & {"bad_signature", "untrusted_key", "unsigned_legacy"}:
        return "invalid"
    if kinds & {"malformed", "refused_alg"}:
        return "refused"
    return "unverified"


def _signed(root: Obj) -> bool:
    return isinstance(root.get("signatures"), list) and bool(root["signatures"])


def _by_outcome(subject: CardSubject, rule_id: str, outcomes: tuple[str, ...], evidence) -> Iterator[Finding]:
    root = _root(subject)
    if root is None:
        return
    for outcome in subject.signatures:
        if outcome.outcome in outcomes:
            yield _finding(rule_id, subject, _signature_owner(root, outcome), "signature", outcome.outcome,
                           _at(f"/signatures/{outcome.index}", evidence(outcome)), _signature_line(root, outcome))


def _bad_evidence(outcome: SignatureOutcome) -> str:
    if outcome.outcome == "untrusted_key":
        return "the signing key is not in the trusted key file"
    if outcome.outcome == "unsigned_legacy":
        legacy = [pointer for pointer in outcome.unsigned_members if is_legacy_pointer(pointer)]
        return f"signed without members clients read: {', '.join(legacy)}"
    return "the signature does not verify over any payload form"


def _a2a_010(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is not None and signature_status_of(subject.signatures, signed=_signed(root)) == "invalid":
        yield from _by_outcome(subject, "SW-A2A-010", ("bad_signature", "untrusted_key", "unsigned_legacy"), _bad_evidence)


def _refused_evidence(outcome: SignatureOutcome) -> str:
    if outcome.detail:
        return outcome.detail
    return f"algorithm {outcome.alg} is refused" if outcome.outcome == "refused_alg" else "the signature is malformed"


def _a2a_011(subject: CardSubject) -> Iterator[Finding]:
    yield from _by_outcome(subject, "SW-A2A-011", ("malformed", "refused_alg"), _refused_evidence)


def _a2a_012(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is not None and not _signed(root):
        yield _finding("SW-A2A-012", subject, "card", "signatures", "unsigned", _at("/", "the card carries no signature"), root.line)


def _card_hosts(subject: CardSubject, root: Obj) -> list[str]:
    """The hosts a `jku` may sit on: the host the card was fetched from (remote), else the host of every interface URL."""
    if subject.origin.source == "remote":
        parts = url_parts(subject.origin.final_url or subject.origin.requested_url)
        return [parts.host] if parts is not None else []
    hosts = []
    for _pointer, _where, url in _interface_urls(root, subject.document.card_format):
        parts = url_parts(url)
        if parts is not None:
            hosts.append(parts.host)
    return hosts


def _a2a_013(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is None:
        return
    hosts = _card_hosts(subject, root)
    for outcome in subject.signatures:
        owner, line = _signature_owner(root, outcome), _signature_line(root, outcome)
        if outcome.outcome == "embedded_key_only":
            yield _finding("SW-A2A-013", subject, owner, "signature", "embedded_key",
                           _at(f"/signatures/{outcome.index}", "key carried in the signature header; self-asserted"), line)
        parts = url_parts(outcome.jku) if outcome.jku else None
        if parts is not None and not any(parts.host == host or parts.host.endswith("." + host) for host in hosts):
            yield _finding("SW-A2A-013", subject, owner, "jku", "off_host",
                           _at(f"/signatures/{outcome.index}", f"key set on another host: {parts.host}"), line)


def _a2a_016(subject: CardSubject) -> Iterator[Finding]:
    root, origin = _root(subject), subject.origin
    if root is not None and origin.cross_origin_redirect:
        requested, final = url_parts(origin.requested_url), url_parts(origin.final_url)
        shown = f"{requested.host if requested else '?'} to {final.host if final else '?'}"
        yield _finding("SW-A2A-016", subject, "card", "redirect", "cross_origin", _at("/", f"redirected {shown}"), root.line)


def _a2a_017(subject: CardSubject) -> Iterator[Finding]:
    yield from _by_outcome(subject, "SW-A2A-017", ("unverifiable_alg",),
                           lambda outcome: outcome.detail or f"algorithm {outcome.alg} needs a secret only the agent holds")


# --- SW-A2A-014 and 015 ----------------------------------------------------------------------------------------------

def _model_texts(root: Obj) -> Iterator[tuple[str, str, int | None, str]]:
    """`(pointer, member, line, text)` of the card's text a client's model reads to choose an agent and a skill."""
    for key in ("name", "description"):
        if isinstance(root.get(key), str):
            yield f"/{key}", key, root.lines.get(key), root[key]
    provider = root.get("provider")
    if isinstance(provider, Obj) and isinstance(provider.get("organization"), str):
        yield "/provider/organization", "organization", provider.lines.get("organization"), provider["organization"]
    for index, skill in enumerate(capped(root.get("skills"), "skills")):
        if not isinstance(skill, Obj):
            continue
        for key in ("name", "description"):
            if isinstance(skill.get(key), str):
                yield f"/skills/{index}/{key}", key, skill.lines.get(key), skill[key]
        for key in ("tags", "examples"):
            for item_index, item in enumerate(capped(skill.get(key), "strings")):
                if isinstance(item, str):
                    yield f"/skills/{index}/{key}/{item_index}", key, _line(skill.get(key), item_index), item
    capabilities = root.get("capabilities")
    for index, extension in enumerate(capped(capabilities.get("extensions") if isinstance(capabilities, Obj) else None, "extensions")):
        if isinstance(extension, Obj) and isinstance(extension.get("description"), str):
            yield f"/capabilities/extensions/{index}/description", "description", extension.lines.get("description"), extension["description"]
    for _name, _kind, body, base, _where in _schemes(root):
        if isinstance(body.get("description"), str):
            yield f"{base}/description", "description", body.lines.get("description"), body["description"]


def _a2a_014(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is None:
        return
    for pointer, member, line, text in _model_texts(root):
        seen = visible(text)  # invisible characters do not break a phrase up
        if (any(pattern.search(seen) for pattern in P.INJECTION) or TOOL_INJECTION_TAG.search(seen)
                or TOOL_INJECTION_SECRET.search(seen)):
            yield _finding("SW-A2A-014", subject, owner_identity(root, pointer), member, "injection", _at(pointer, text), line)
        hidden = hidden_characters(text)
        if hidden:
            names = code_point_names("".join(hidden))
            yield _finding("SW-A2A-014", subject, owner_identity(root, pointer), member, "hidden", _at(pointer, names), line)


def _a2a_015(subject: CardSubject) -> Iterator[Finding]:
    root = _root(subject)
    if root is None:
        return
    for pointer, member, line, value in _scalar_leaves(subject.document.root):
        if not isinstance(value, str):
            continue
        parts = url_parts(value)
        password = parts is not None and parts.userinfo is not None and ":" in parts.userinfo
        if password or any(has_credential(text) for text in value.splitlines() or [value]):
            yield _finding("SW-A2A-015", subject, owner_identity(root, pointer), member, "credential", _at(pointer, value), line)


RULES: tuple[Rule, ...] = (
    make_rule("SW-A2A-001", TITLES["SW-A2A-001"], "medium", "a2a", owasp=("ASI07",), nist=("SI-10",), detect=_a2a_001),
    make_rule("SW-A2A-002", TITLES["SW-A2A-002"], "medium", "a2a", owasp=("ASI07",), nist=("SI-10",), detect=_a2a_002),
    make_rule("SW-A2A-003", TITLES["SW-A2A-003"], "medium", "a2a", owasp=("ASI07",), nist=("SI-10",), detect=_a2a_003),
    make_rule("SW-A2A-004", TITLES["SW-A2A-004"], "high", "a2a", owasp=("ASI07",), nist=("SC-8",), detect=_a2a_004),
    make_rule("SW-A2A-005", TITLES["SW-A2A-005"], "high", "a2a", owasp=("ASI03",), nist=("IA-5",), detect=_a2a_005),
    make_rule("SW-A2A-006", TITLES["SW-A2A-006"], "medium", "a2a", owasp=("ASI03",), nist=("IA-5",), detect=_a2a_006),
    make_rule("SW-A2A-007", TITLES["SW-A2A-007"], "medium", "a2a", owasp=("ASI03",), nist=("AC-3",), detect=_a2a_007),
    make_rule("SW-A2A-008", TITLES["SW-A2A-008"], "medium", "a2a", owasp=("ASI03",), nist=("IA-5",), detect=_a2a_008),
    make_rule("SW-A2A-009", TITLES["SW-A2A-009"], "low", "a2a", owasp=("ASI03",), nist=("AC-6",), detect=_a2a_009),
    make_rule("SW-A2A-010", TITLES["SW-A2A-010"], "high", "a2a", owasp=("ASI07",), nist=("SI-7",), detect=_a2a_010),
    make_rule("SW-A2A-011", TITLES["SW-A2A-011"], "high", "a2a", owasp=("ASI07",), nist=("SI-7",), detect=_a2a_011),
    make_rule("SW-A2A-012", TITLES["SW-A2A-012"], "low", "a2a", owasp=("ASI07",), nist=("SI-7",), detect=_a2a_012),
    make_rule("SW-A2A-013", TITLES["SW-A2A-013"], "medium", "a2a", owasp=("ASI07",), nist=("SI-7",), detect=_a2a_013),
    make_rule("SW-A2A-014", TITLES["SW-A2A-014"], "high", "a2a", owasp=("ASI01",), nist=("SI-10",), detect=_a2a_014),
    make_rule("SW-A2A-015", TITLES["SW-A2A-015"], "critical", "a2a", owasp=("ASI03",), nist=("IA-5",), detect=_a2a_015),
    make_rule("SW-A2A-016", TITLES["SW-A2A-016"], "medium", "a2a", owasp=("ASI07",), nist=("SC-8",), detect=_a2a_016),
    make_rule("SW-A2A-017", TITLES["SW-A2A-017"], "medium", "a2a", owasp=("ASI07",), nist=("SI-7",), detect=_a2a_017),
    make_rule("SW-A2A-018", TITLES["SW-A2A-018"], "high", "a2a", owasp=("ASI07",), nist=("SI-10",), detect=_a2a_018),
    make_rule("SW-A2A-019", TITLES["SW-A2A-019"], "high", "a2a", owasp=("ASI07",), nist=("SI-10",), detect=_a2a_019),
)
assert all(SEVERITY[rule.id] == rule.severity_default for rule in RULES)  # one table of severities, checked at import
