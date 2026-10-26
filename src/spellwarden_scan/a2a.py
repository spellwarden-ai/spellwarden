"""A2A agent cards (O4 spec 5.1 and 5.3): the strict read of a card, its shape, format and protocol versions, and the
validator of the A2A 1.0 field rules. Pure and total: a card it cannot read becomes an `AgentCardDocument` with `error`
set and no root, never an exception. Everything in a card is hostile text; nothing here executes or follows it.

The validator is written by hand from the normative proto at `v1.0.1` (`specification/a2a.proto`), not from the published
JSON Schema (non-normative, no `required` lists, `additionalProperties: false` against specification 5.7) or from the
SDK's protobuf types. Unknown fields are ignored. It runs on cards of format `1.0` only; an older card is reported by
SW-A2A-002 and the migration checklist, not validated against the 0.3 or 0.2 schemas."""
from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass

from spellwarden_scan._json import MAX_DOCUMENT_BYTES, Arr, Obj, Refused, load_json
from spellwarden_scan.agentconfig import url_parts
from spellwarden_scan.jcs import JcsError, jcs_canonicalize

CARD_DEPTH = 128  # the SDK's own bound (`_jcs.py`, `MAX_DEPTH`), reached through the free-form `AgentExtension.params`
CARD_ERRORS = ("too_large", "bom", "not_utf8", "not_json", "duplicate_key", "too_deep", "not_an_object")
CARD_FORMATS = ("1.0", "0.3", "0.2", "unknown")
MIGRATION_STATUSES = ("ready", "to_migrate", "invalid")
SIGNATURE_STATUSES = ("unsigned", "verified", "invalid", "refused", "unverified")
EVIDENCE_STRING_MAX = 1000  # a string longer than 10,000 characters is kept whole for the canonical form, cut for evidence
# Collection caps (5.1): what lies beyond is not judged and the document is marked truncated. The canonical form is
# always computed from the whole card, so a cap never changes what a signature covers.
CAPS = {"interfaces": 50, "skills": 500, "schemes": 50, "requirements": 50, "extensions": 50, "signatures": 5, "strings": 200}
SCHEME_KEYS = ("apiKeySecurityScheme", "httpAuthSecurityScheme", "oauth2SecurityScheme", "openIdConnectSecurityScheme",
               "mtlsSecurityScheme")
FLOW_KEYS = ("authorizationCode", "clientCredentials", "deviceCode", "implicit", "password")
DEPRECATED_FLOWS = ("implicit", "password")
REQUIRED_FLOW_MEMBERS = {"authorizationCode": ("authorizationUrl", "tokenUrl"), "clientCredentials": ("tokenUrl",),
                         "deviceCode": ("deviceAuthorizationUrl", "tokenUrl"), "implicit": (), "password": ()}
BINDINGS = ("JSONRPC", "GRPC", "HTTP+JSON")
# What 1.0 removed or renamed (the proto's removals and `a2a-python` `card_resolver.py` at `e12d494`). One list for SW-A2A-002
# and for the signature rule of 5.6: a legacy member that stays unsigned changes what a client does.
LEGACY_TOP_LEVEL = ("url", "preferredTransport", "additionalInterfaces", "protocolVersion", "supportsAuthenticatedExtendedCard",
                    "supportsExtendedAgentCard", "security")
_LEGACY_POINTER = re.compile(
    r"^/(?:" + "|".join(LEGACY_TOP_LEVEL) + r")(?:/.*)?$"
    r"|^/capabilities/stateTransitionHistory(?:/.*)?$"
    r"|^/skills/[0-9]+/security(?:/.*)?$"
    r"|^/supportedInterfaces/[0-9]+/transport(?:/.*)?$"
    r"|^/securitySchemes/[^/]+/(?:type|in)(?:/.*)?$"
    r"|^/securitySchemes/[^/]+/apiKeySecurityScheme/in(?:/.*)?$")
# At most nine digits a number: `int()` raises past 4300 digits, and a version that long is a `version_format` issue (r1:F1).
_VERSION = re.compile(r"^([0-9]{1,9})\.([0-9]{1,9})(?:\.([0-9]{1,9}))?$")
_SCHEME_PREFIX = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:)?//")


def _small_int(text: str) -> int | None:
    """`text` as an int only when it is one to nine ASCII digits, else None. `str.isdigit` accepts `'²'` and `int` raises on a
    5000-digit string, so no conversion in this module sees a card's text without this (O4 spec invariant 10, r1:F1)."""
    return int(text) if text.isascii() and text.isdigit() and len(text) <= 9 else None
_ABSOLUTE_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")
_GRPC_ADDRESS = re.compile(r"^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):[0-9]{1,5}$")


@dataclass(frozen=True)
class AgentCardDocument:
    """One parsed agent card. `root` is the whole parsed object (`_json.Obj`, private to the engine: callers use the other
    fields), None when `error` is set. `card_format` is one of `CARD_FORMATS`; `protocol_versions` the sorted `Major.Minor`
    versions the card declares; `raw_sha256` the SHA-256 of the bytes; `truncated` that a cap of `CAPS` applied."""
    path: str
    error: str | None
    root: Obj | None
    card_shape: bool
    card_format: str
    protocol_versions: tuple[str, ...]
    raw_sha256: str
    truncated: bool = False


@dataclass(frozen=True)
class Issue:
    """One thing the validator found. `pointer` is the RFC 6901 pointer of the member, `identity` the stable identity of the
    object it sits in (`card`, `skill:<id>`, `interface:<url>`, `scheme:<name>`, `requirement:<sha>`, `extension:<uri>`,
    `signature:<kid>`), `member` the member name, `reason` one of `missing`, `wrong_type`, `empty`, `version_format`,
    `binding_unknown`, `not_absolute_uri`, `duplicate_skill_id`, `scheme_type`, `flow_count`, `undefined_scheme`,
    `not_a_card`; `line` the line of the member (of its object when it is missing)."""
    pointer: str
    identity: str
    member: str
    reason: str
    line: int | None


def pointer_of(*parts: object) -> str:
    """The RFC 6901 pointer of `parts`: `~` is `~0` and `/` is `~1`."""
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def is_legacy_pointer(pointer: str) -> bool:
    """Whether `pointer` names a member that A2A 1.0 removed or renamed (the list of 5.4 SW-A2A-002 and 5.6)."""
    return _LEGACY_POINTER.match(pointer) is not None


def skill_identity(skills: list, index: int) -> str:
    """`skill:<id>`, or `skill-at:<index>` when the id is missing, not a string or an earlier skill's (SW-A2A-001 reports it)."""
    skill = skills[index] if 0 <= index < len(skills) else None
    skill_id = skill.get("id") if isinstance(skill, dict) else None
    if not isinstance(skill_id, str) or any(isinstance(other, dict) and other.get("id") == skill_id for other in skills[:index]):
        return f"skill-at:{index}"
    return f"skill:{skill_id}"


def interface_identity(interface: object, index: int) -> str:
    url = interface.get("url") if isinstance(interface, dict) else None
    return f"interface:{_reduced_url(url) if isinstance(url, str) else f'#{index}'}"


def extension_identity(extension: object, index: int) -> str:
    uri = extension.get("uri") if isinstance(extension, dict) else None
    return f"extension:{uri if isinstance(uri, str) else f'#{index}'}"


def signature_identity(signature: object, index: int) -> str:
    kid = _kid_of(signature) if isinstance(signature, dict) else None
    return f"signature:{kid or f'#{index}'}"


def requirement_identity(parent: str, requirement: object, index: int) -> str:
    """`<parent>/requirement:<sha256 of the requirement's canonical JSON>`, by index when it cannot be canonicalised."""
    try:
        return f"{parent}/requirement:{hashlib.sha256(jcs_canonicalize(requirement)).hexdigest()}"
    except JcsError:
        return f"{parent}/requirement-at:{index}"


def owner_identity(root: Obj, pointer: str) -> str:
    """The stable identity (5.4) of the object a member sits in, from its RFC 6901 pointer: `card` for a top-level member,
    else the skill, interface, scheme, extension, signature or requirement the pointer enters."""
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]
    if len(parts) < 2:
        return "card"
    head, key = parts[0], parts[1]
    index = _small_int(key)
    index = -1 if index is None else index
    if head == "skills" and isinstance(root.get("skills"), list) and 0 <= index < len(root["skills"]):
        ident = skill_identity(root["skills"], index)
        skill = root["skills"][index]
        if len(parts) > 3 and parts[2] in ("securityRequirements", "security") and isinstance(skill, dict):
            items = skill.get(parts[2])
            at = _small_int(parts[3])
            if isinstance(items, list) and at is not None and at < len(items):
                return requirement_identity(ident, items[at], at)
        return ident
    interfaces = root.get("supportedInterfaces")
    if head == "supportedInterfaces" and isinstance(interfaces, list) and 0 <= index < len(interfaces):
        return interface_identity(interfaces[index], index)
    if head == "securitySchemes":
        return f"scheme:{key}"
    if head == "signatures" and isinstance(root.get("signatures"), list) and 0 <= index < len(root["signatures"]):
        return signature_identity(root["signatures"][index], index)
    at = _small_int(parts[2]) if head == "capabilities" and key == "extensions" and len(parts) > 2 else None
    if at is not None:
        extensions = root["capabilities"].get("extensions") if isinstance(root.get("capabilities"), dict) else None
        if isinstance(extensions, list) and at < len(extensions):
            return extension_identity(extensions[at], at)
    if head in ("securityRequirements", "security") and isinstance(root.get(head), list) and 0 <= index < len(root[head]):
        return requirement_identity("card", root[head][index], index)
    return "card"


def capped(value: object, name: str) -> list:
    """The first `CAPS[name]` entries of a list (an empty list for anything else)."""
    return list(value[:CAPS[name]]) if isinstance(value, list) else []


def parse_agent_card(path: str, content: bytes) -> AgentCardDocument:
    """Reads `content` in strict mode (no comments, no trailing commas, no byte-order mark) at depth 128 and at most
    1 MiB. A failure is a document with `error` one of `CARD_ERRORS` and no root."""
    digest = hashlib.sha256(content).hexdigest()
    try:
        root = load_json(content, strict=True, max_depth=CARD_DEPTH, max_bytes=MAX_DOCUMENT_BYTES)
    except Refused as refused:
        return AgentCardDocument(path, refused.code, None, False, "unknown", (), digest)
    if not isinstance(root, Obj):
        return AgentCardDocument(path, "not_an_object", None, False, "unknown", (), digest)
    shape = isinstance(root.get("name"), str) and (isinstance(root.get("supportedInterfaces"), list)
                                                   or isinstance(root.get("url"), str))
    card_format = _format_of(root, shape)
    return AgentCardDocument(path, None, root, shape, card_format, _versions_of(root, card_format), digest,
                             _over_caps(root))


def _format_of(root: Obj, shape: bool) -> str:
    if not shape:
        return "unknown"
    if "supportedInterfaces" in root:
        return "1.0"
    version = root.get("protocolVersion")
    if "url" in root and ("signatures" in root or (isinstance(version, str) and version.startswith("0.3"))):
        return "0.3"
    return "0.2"


def _reduced(version: object) -> tuple[int, int] | None:
    match = _VERSION.match(version) if isinstance(version, str) else None
    return (int(match.group(1)), int(match.group(2))) if match else None  # `_VERSION` holds at most nine ASCII digits a number


def _versions_of(root: Obj, card_format: str) -> tuple[str, ...]:
    if card_format == "unknown":
        return ()
    if card_format == "1.0":
        declared = [interface.get("protocolVersion") for interface in capped(root.get("supportedInterfaces"), "interfaces")
                    if isinstance(interface, dict)]
    else:
        declared = [root.get("protocolVersion")]
    found = {reduced for reduced in map(_reduced, declared) if reduced is not None}
    return tuple(f"{major}.{minor}" for major, minor in sorted(found))


def _over_caps(root: Obj) -> bool:
    """Whether any collection of the card holds more than its cap of 5.1."""
    def over(value: object, name: str) -> bool:
        return isinstance(value, list) and len(value) > CAPS[name]

    def over_strings(value: object) -> bool:
        return isinstance(value, list) and len(value) > CAPS["strings"]

    capabilities = root.get("capabilities")
    schemes = root.get("securitySchemes")
    if over(root.get("supportedInterfaces"), "interfaces") or over(root.get("skills"), "skills"):
        return True
    if over(root.get("signatures"), "signatures") or over(root.get("securityRequirements"), "requirements"):
        return True
    if over(root.get("security"), "requirements"):
        return True
    if isinstance(schemes, dict) and len(schemes) > CAPS["schemes"]:
        return True
    if isinstance(capabilities, dict) and over(capabilities.get("extensions"), "extensions"):
        return True
    if any(over_strings(root.get(name)) for name in ("defaultInputModes", "defaultOutputModes")):
        return True
    for skill in capped(root.get("skills"), "skills"):
        if not isinstance(skill, dict):
            continue
        if over(skill.get("securityRequirements"), "requirements"):
            return True
        if any(over_strings(skill.get(name)) for name in ("tags", "examples", "inputModes", "outputModes")):
            return True
    return False


# --- the 1.0 validator ----------------------------------------------------------------------------------------------

def _line(node: object, key: object) -> int | None:
    """The line of `key` (a member name or an index) in a parsed object or array, else of the container itself."""
    if isinstance(node, Obj):
        return node.lines.get(key, node.line) if isinstance(key, str) else node.line
    if isinstance(node, Arr):
        return node.lines[key] if isinstance(key, int) and 0 <= key < len(node.lines) else node.line
    return None


class _Checker:
    def __init__(self) -> None:
        self.issues: list[Issue] = []

    def add(self, node: object, ptr: str, ident: str, member: str, reason: str) -> None:
        """An issue with the member `member` of the object `node` that sits at `ptr`."""
        self.issues.append(Issue(ptr + pointer_of(member), ident, member, reason, _line(node, member)))

    def add_item(self, array: object, ptr: str, ident: str, member: str, reason: str, index: int) -> None:
        """An issue with element `index` of the array `array` that sits at `ptr`."""
        self.issues.append(Issue(ptr + pointer_of(index), ident, member, reason, _line(array, index)))

    def string(self, node: Obj, key: str, ptr: str, ident: str, *, required: bool) -> bool:
        if key not in node:
            if required:
                self.add(node, ptr, ident, key, "missing")
            return False
        if not isinstance(node[key], str):
            self.add(node, ptr, ident, key, "wrong_type")
            return False
        return True

    def boolean(self, node: Obj, key: str, ptr: str, ident: str) -> None:
        if key in node and not isinstance(node[key], bool):
            self.add(node, ptr, ident, key, "wrong_type")

    def array(self, node: Obj, key: str, ptr: str, ident: str, *, required: bool = False, non_empty: bool = False) -> list | None:
        if key not in node:
            if required:
                self.add(node, ptr, ident, key, "missing")
            return None
        value = node[key]
        if not isinstance(value, list):
            self.add(node, ptr, ident, key, "wrong_type")
            return None
        if non_empty and not value:
            self.add(node, ptr, ident, key, "empty")
        return value

    def strings(self, node: Obj, key: str, ptr: str, ident: str, *, required: bool = False, non_empty: bool = False) -> None:
        value = self.array(node, key, ptr, ident, required=required, non_empty=non_empty)
        if value is not None and not all(isinstance(item, str) for item in capped(value, "strings")):
            self.add(node, ptr, ident, key, "wrong_type")

    def object(self, node: Obj, key: str, ptr: str, ident: str, *, required: bool = False) -> Obj | None:
        if key not in node:
            if required:
                self.add(node, ptr, ident, key, "missing")
            return None
        if not isinstance(node[key], Obj):
            self.add(node, ptr, ident, key, "wrong_type")
            return None
        return node[key]


def validate_1_0(document: AgentCardDocument) -> tuple[Issue, ...]:
    """The issues of a card of format `1.0` (5.3); none for any other card. `AgentCard.signatures[]` are checked for their
    own fields only; what a signature proves is the command's business (6.6)."""
    if document.root is None or document.card_format != "1.0":
        return ()
    root, check = document.root, _Checker()
    for key in ("name", "description", "version"):
        check.string(root, key, "", "card", required=True)
    for key in ("documentationUrl", "iconUrl"):
        check.string(root, key, "", "card", required=False)
    for key in ("defaultInputModes", "defaultOutputModes"):
        check.strings(root, key, "", "card", required=True, non_empty=True)
    capabilities = check.object(root, "capabilities", "", "card", required=True)
    if capabilities is not None:
        _capabilities(check, capabilities)
    provider = check.object(root, "provider", "", "card")
    if provider is not None:
        for key in ("url", "organization"):
            check.string(provider, key, "/provider", "card", required=True)
    _interfaces(check, root)
    names = _schemes(check, root)
    _skills(check, root, names)
    _requirements(check, root, "", "card", names)
    _signatures(check, root)
    return tuple(check.issues)


def _capabilities(check: _Checker, capabilities: Obj) -> None:
    for key in ("streaming", "pushNotifications", "extendedAgentCard"):
        check.boolean(capabilities, key, "/capabilities", "card")
    extensions = check.array(capabilities, "extensions", "/capabilities", "card")
    for index, extension in enumerate(capped(extensions, "extensions")):
        ptr = f"/capabilities/extensions/{index}"
        if not isinstance(extension, Obj):
            check.add_item(extensions, "/capabilities/extensions", "card", "extensions", "wrong_type", index)
            continue
        ident = extension_identity(extension, index)
        for key in ("uri", "description"):
            check.string(extension, key, ptr, ident, required=False)
        check.boolean(extension, "required", ptr, ident)


def _interfaces(check: _Checker, root: Obj) -> None:
    interfaces = check.array(root, "supportedInterfaces", "", "card", required=True, non_empty=True)
    for index, interface in enumerate(capped(interfaces, "interfaces")):
        ptr = f"/supportedInterfaces/{index}"
        if not isinstance(interface, Obj):
            check.add_item(interfaces, "/supportedInterfaces", "card", "supportedInterfaces", "wrong_type", index)
            continue
        url = interface.get("url")
        ident = interface_identity(interface, index)
        has_url = check.string(interface, "url", ptr, ident, required=True)
        has_binding = check.string(interface, "protocolBinding", ptr, ident, required=True)
        has_version = check.string(interface, "protocolVersion", ptr, ident, required=True)
        check.string(interface, "tenant", ptr, ident, required=False)
        binding = interface.get("protocolBinding")
        if has_binding and binding not in BINDINGS and _ABSOLUTE_URI.match(binding) is None:
            check.add(interface, ptr, ident, "protocolBinding", "binding_unknown")
        if has_version and _VERSION.match(interface["protocolVersion"]) is None:
            check.add(interface, ptr, ident, "protocolVersion", "version_format")
        if has_url and url_parts(url) is None and not (binding == "GRPC" and _GRPC_ADDRESS.match(url)):
            check.add(interface, ptr, ident, "url", "not_absolute_uri")


def _reduced_url(url: str) -> str:
    """The URL without userinfo, query and fragment, as findings and fingerprints name an interface."""
    parts = url_parts(url)
    if parts is None:
        # The fallback strips userinfo first, from the authority (up to the first `/`) to its last `@`, and only then the
        # query and fragment: a `?` or `#` inside the password must not cut the text before the `@` is found (r0:F2).
        prefix = _SCHEME_PREFIX.match(url)
        head = prefix.group(0) if prefix else ""
        authority, slash, path = url[len(head):].partition("/")
        text = head + authority.rpartition("@")[2] + slash + path
        return text.split("?", 1)[0].split("#", 1)[0]
    host = f"[{parts.host}]" if ":" in parts.host else parts.host
    return f"{parts.scheme}://{host}{':' + parts.port if parts.port else ''}{parts.path}"


def _skills(check: _Checker, root: Obj, names: set[str]) -> None:
    skills = check.array(root, "skills", "", "card", required=True, non_empty=True)
    seen: dict[str, int] = {}
    for index, skill in enumerate(capped(skills, "skills")):
        ptr = f"/skills/{index}"
        if not isinstance(skill, Obj):
            check.add_item(skills, "/skills", "card", "skills", "wrong_type", index)
            continue
        skill_id = skill.get("id")
        duplicate = isinstance(skill_id, str) and skill_id in seen
        ident = skill_identity(skills, index)
        for key in ("id", "name", "description"):
            check.string(skill, key, ptr, ident, required=True)
        check.strings(skill, "tags", ptr, ident, required=True, non_empty=True)
        for key in ("examples", "inputModes", "outputModes"):
            check.strings(skill, key, ptr, ident)
        _requirements(check, skill, ptr, ident, names)
        if isinstance(skill_id, str):
            if duplicate:
                check.add(skill, ptr, ident, "id", "duplicate_skill_id")
            seen.setdefault(skill_id, index)


def _schemes(check: _Checker, root: Obj) -> set[str]:
    schemes = check.object(root, "securitySchemes", "", "card")
    names: set[str] = set()
    if schemes is None:
        return names
    for name in list(schemes)[:CAPS["schemes"]]:
        names.add(name)
        scheme, ptr, ident = schemes[name], f"/securitySchemes/{pointer_of(name)[1:]}", f"scheme:{name}"
        if not isinstance(scheme, Obj):
            check.add(schemes, "/securitySchemes", ident, name, "wrong_type")
            continue
        kinds = [key for key in SCHEME_KEYS if key in scheme]
        if len(kinds) != 1:
            check.issues.append(Issue(ptr, ident, "scheme", "scheme_type", _line(schemes, name)))
            continue
        body = scheme[kinds[0]]
        if not isinstance(body, Obj):
            check.add(scheme, ptr, ident, kinds[0], "wrong_type")
            continue
        _scheme(check, kinds[0], body, f"{ptr}/{kinds[0]}", ident)
    return names


def _scheme(check: _Checker, kind: str, body: Obj, ptr: str, ident: str) -> None:
    check.string(body, "description", ptr, ident, required=False)
    if kind == "apiKeySecurityScheme":
        check.string(body, "name", ptr, ident, required=True)
        if check.string(body, "location", ptr, ident, required=True) and body["location"] not in ("query", "header", "cookie"):
            check.add(body, ptr, ident, "location", "wrong_type")
    elif kind == "httpAuthSecurityScheme":
        check.string(body, "scheme", ptr, ident, required=True)
        check.string(body, "bearerFormat", ptr, ident, required=False)
    elif kind == "openIdConnectSecurityScheme":
        check.string(body, "openIdConnectUrl", ptr, ident, required=True)
    elif kind == "oauth2SecurityScheme":
        check.string(body, "oauth2MetadataUrl", ptr, ident, required=False)
        flows = check.object(body, "flows", ptr, ident, required=True)
        if flows is None:
            return
        chosen = [key for key in FLOW_KEYS if key in flows]
        if len(chosen) != 1:
            check.add(body, ptr, ident, "flows", "flow_count")
            return
        flow = flows[chosen[0]]
        if not isinstance(flow, Obj):
            check.add(flows, f"{ptr}/flows", ident, chosen[0], "wrong_type")
            return
        _flow(check, chosen[0], flow, f"{ptr}/flows/{chosen[0]}", ident)


def _flow(check: _Checker, kind: str, flow: Obj, ptr: str, ident: str) -> None:
    for key in REQUIRED_FLOW_MEMBERS[kind]:
        check.string(flow, key, ptr, ident, required=True)
    for key in ("authorizationUrl", "tokenUrl", "refreshUrl", "deviceAuthorizationUrl"):
        if key not in REQUIRED_FLOW_MEMBERS[kind]:
            check.string(flow, key, ptr, ident, required=False)
    scopes = check.object(flow, "scopes", ptr, ident, required=kind not in DEPRECATED_FLOWS)
    if scopes is not None and not all(isinstance(value, str) for value in scopes.values()):
        check.add(flow, ptr, ident, "scopes", "wrong_type")  # scopes MAY be empty: `empty` never applies here
    if kind == "authorizationCode":
        check.boolean(flow, "pkceRequired", ptr, ident)


def _requirements(check: _Checker, node: Obj, ptr: str, ident: str, names: set[str]) -> None:
    requirements = check.array(node, "securityRequirements", ptr, ident)
    for index, requirement in enumerate(capped(requirements, "requirements")):
        at = f"{ptr}/securityRequirements/{index}"
        if not isinstance(requirement, Obj):
            check.add_item(requirements, f"{ptr}/securityRequirements", ident, "securityRequirements", "wrong_type", index)
            continue
        inner = requirement_identity(ident, requirement, index)
        schemes = check.object(requirement, "schemes", at, inner, required=True)
        if schemes is None:
            continue
        for name, entry in schemes.items():
            if not isinstance(entry, Obj):
                check.add(schemes, f"{at}/schemes", inner, name, "wrong_type")
                continue
            if "list" in entry:
                values = entry["list"]
                if not isinstance(values, list) or not all(isinstance(item, str) for item in capped(values, "strings")):
                    check.add(entry, f"{at}/schemes/{pointer_of(name)[1:]}", inner, "list", "wrong_type")
            if name not in names:
                check.add(schemes, f"{at}/schemes", inner, name, "undefined_scheme")


def _signatures(check: _Checker, root: Obj) -> None:
    signatures = check.array(root, "signatures", "", "card")
    for index, signature in enumerate(capped(signatures, "signatures")):
        ptr = f"/signatures/{index}"
        if not isinstance(signature, Obj):
            check.add_item(signatures, "/signatures", "card", "signatures", "wrong_type", index)
            continue
        ident = signature_identity(signature, index)
        for key in ("protected", "signature"):
            check.string(signature, key, ptr, ident, required=True)
        check.object(signature, "header", ptr, ident)


def _kid_of(signature: Obj) -> str | None:
    """The `kid` of a signature entry's protected header, for identities; None when it cannot be read here."""
    protected = signature.get("protected")
    if not isinstance(protected, str) or len(protected) > 8192:
        return None
    try:
        decoded = base64.urlsafe_b64decode(protected + "=" * (-len(protected) % 4))
        header = load_json(decoded, strict=True, max_depth=8, max_bytes=4096)
    except (ValueError, Refused):
        return None
    kid = header.get("kid") if isinstance(header, Obj) else None
    return kid if isinstance(kid, str) and kid else None


def legacy_members(document: AgentCardDocument) -> Iterator[tuple[str, str, int | None]]:
    """`(pointer, member name, line)` of every member A2A 1.0 removed or renamed that the card carries (SW-A2A-002):
    the legacy top-level keys, `capabilities.stateTransitionHistory`, a skill's `security`, an interface's `transport`, a
    scheme's `type` and an API key scheme's `in`. A card of format `0.3` or `0.2` is reported once as a whole instead."""
    root = document.root
    if root is None:
        return
    for key in LEGACY_TOP_LEVEL:
        if key in root:
            yield pointer_of(key), key, root.lines.get(key)
    capabilities = root.get("capabilities")
    if isinstance(capabilities, Obj) and "stateTransitionHistory" in capabilities:
        yield (pointer_of("capabilities", "stateTransitionHistory"), "stateTransitionHistory",
               capabilities.lines.get("stateTransitionHistory"))
    for index, skill in enumerate(capped(root.get("skills"), "skills")):
        if isinstance(skill, Obj) and "security" in skill:
            yield pointer_of("skills", index, "security"), "security", skill.lines.get("security")
    for index, interface in enumerate(capped(root.get("supportedInterfaces"), "interfaces")):
        if isinstance(interface, Obj) and "transport" in interface:
            yield pointer_of("supportedInterfaces", index, "transport"), "transport", interface.lines.get("transport")
    schemes = root.get("securitySchemes")
    for name in list(schemes)[:CAPS["schemes"]] if isinstance(schemes, Obj) else ():
        scheme = schemes[name]
        if not isinstance(scheme, Obj):
            continue
        for key in ("type", "in"):
            if key in scheme:
                yield pointer_of("securitySchemes", name, key), key, scheme.lines.get(key)
        body = scheme.get("apiKeySecurityScheme")
        if isinstance(body, Obj) and "in" in body:
            yield pointer_of("securitySchemes", name, "apiKeySecurityScheme", "in"), "in", body.lines.get("in")


def legacy_version_issues(document: AgentCardDocument) -> tuple[Issue, ...]:
    """SW-A2A-001 (`version_format`) for the top-level `protocolVersion` of a 0.x card that matches neither
    `Major.Minor` nor `Major.Minor.Patch`; a 0.x card is not validated further."""
    root = document.root
    if root is None or document.card_format not in ("0.3", "0.2") or "protocolVersion" not in root:
        return ()
    value = root["protocolVersion"]
    if isinstance(value, str) and _VERSION.match(value):
        return ()
    return (Issue("/protocolVersion", "card", "protocolVersion", "version_format", root.lines.get("protocolVersion")),)
