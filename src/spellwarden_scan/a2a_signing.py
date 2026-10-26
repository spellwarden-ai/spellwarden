"""Signature inputs of an A2A agent card (O4 spec 5.6). Pure: it takes the parsed card and returns, for each entry of
`signatures`, the decoded protected header and the byte strings a verifier must check the signature over. The engine
never verifies: `spellwarden_cli.jws` does, with `cryptography`, over these inputs.

A signature covers `ASCII(protected) || "." || BASE64URL(payload)` (specification 8.4.2); the payload is not carried in the
card, so the verifier rebuilds it: the card without `signatures`, canonicalised with RFC 8785 (`jcs`), in up to three forms
that differ only in which members they keep, deduplicated in this order:

- `as_served`: the card as read.
- `spec`: what a signer that follows specification 8.4.1 over the proto signs. Only the members the proto defines are kept;
  a member that is neither REQUIRED nor `optional` nor a `oneof` member is dropped when it holds its default (`false`, `0`,
  `""`, an empty array, an empty object); REQUIRED, `optional` and `oneof` members and free-form structs are kept as served.
- `sdk`: what `a2a-sdk` 1.2.3 signs: the `spec` form, then every empty string, array and object removed recursively, REQUIRED
  ones included, and a container emptied by that removal removed in turn (`signing.py::_clean_empty`).

Each form only removes members, so a card verifies over a form only when the signer signed exactly the members that remain;
what a form removed is either a default the protocol treats as absent or listed in `unsigned_members`."""
from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from spellwarden_scan._json import Obj, Refused, load_json
from spellwarden_scan.a2a import AgentCardDocument, capped, pointer_of
from spellwarden_scan.jcs import JcsError, jcs_canonicalize

HEADER_MAX_BYTES = 4096
NUMBER_DETAIL = "number outside the range the scanner canonicalises"
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]*$")

# Every field of the messages an agent card is made of at `v1.0.1`: `message -> JSON name -> (rule, kind)`. `rule` is
# `required` (REQUIRED), `optional` (the `optional` keyword), `oneof` (a member of a `oneof`, which tracks presence) or
# `plain`. `kind` is `scalar`, `struct`, `message:<M>`, `repeated:string`, `repeated:message:<M>`, `map:string` or
# `map:message:<M>`. Generated from `tests/fixtures/a2a/proto/a2a-v1.0.1-card.proto` and compared with it by
# `tests/test_a2a_signing.py` (claim S8).
_PRESENCE: dict[str, dict[str, tuple[str, str]]] = {
    "AgentInterface": {
        "url": ("required", "scalar"),
        "protocolBinding": ("required", "scalar"),
        "tenant": ("plain", "scalar"),
        "protocolVersion": ("required", "scalar"),
    },
    "AgentCard": {
        "name": ("required", "scalar"),
        "description": ("required", "scalar"),
        "supportedInterfaces": ("required", "repeated:message:AgentInterface"),
        "provider": ("plain", "message:AgentProvider"),
        "version": ("required", "scalar"),
        "documentationUrl": ("optional", "scalar"),
        "capabilities": ("required", "message:AgentCapabilities"),
        "securitySchemes": ("plain", "map:message:SecurityScheme"),
        "securityRequirements": ("plain", "repeated:message:SecurityRequirement"),
        "defaultInputModes": ("required", "repeated:string"),
        "defaultOutputModes": ("required", "repeated:string"),
        "skills": ("required", "repeated:message:AgentSkill"),
        "signatures": ("plain", "repeated:message:AgentCardSignature"),
        "iconUrl": ("optional", "scalar"),
    },
    "AgentProvider": {
        "url": ("required", "scalar"),
        "organization": ("required", "scalar"),
    },
    "AgentCapabilities": {
        "streaming": ("optional", "scalar"),
        "pushNotifications": ("optional", "scalar"),
        "extensions": ("plain", "repeated:message:AgentExtension"),
        "extendedAgentCard": ("optional", "scalar"),
    },
    "AgentExtension": {
        "uri": ("plain", "scalar"),
        "description": ("plain", "scalar"),
        "required": ("plain", "scalar"),
        "params": ("plain", "struct"),
    },
    "AgentSkill": {
        "id": ("required", "scalar"),
        "name": ("required", "scalar"),
        "description": ("required", "scalar"),
        "tags": ("required", "repeated:string"),
        "examples": ("plain", "repeated:string"),
        "inputModes": ("plain", "repeated:string"),
        "outputModes": ("plain", "repeated:string"),
        "securityRequirements": ("plain", "repeated:message:SecurityRequirement"),
    },
    "AgentCardSignature": {
        "protected": ("required", "scalar"),
        "signature": ("required", "scalar"),
        "header": ("plain", "struct"),
    },
    "StringList": {
        "list": ("plain", "repeated:string"),
    },
    "SecurityRequirement": {
        "schemes": ("plain", "map:message:StringList"),
    },
    "SecurityScheme": {
        "apiKeySecurityScheme": ("oneof", "message:APIKeySecurityScheme"),
        "httpAuthSecurityScheme": ("oneof", "message:HTTPAuthSecurityScheme"),
        "oauth2SecurityScheme": ("oneof", "message:OAuth2SecurityScheme"),
        "openIdConnectSecurityScheme": ("oneof", "message:OpenIdConnectSecurityScheme"),
        "mtlsSecurityScheme": ("oneof", "message:MutualTlsSecurityScheme"),
    },
    "APIKeySecurityScheme": {
        "description": ("plain", "scalar"),
        "location": ("required", "scalar"),
        "name": ("required", "scalar"),
    },
    "HTTPAuthSecurityScheme": {
        "description": ("plain", "scalar"),
        "scheme": ("required", "scalar"),
        "bearerFormat": ("plain", "scalar"),
    },
    "OAuth2SecurityScheme": {
        "description": ("plain", "scalar"),
        "flows": ("required", "message:OAuthFlows"),
        "oauth2MetadataUrl": ("plain", "scalar"),
    },
    "OpenIdConnectSecurityScheme": {
        "description": ("plain", "scalar"),
        "openIdConnectUrl": ("required", "scalar"),
    },
    "MutualTlsSecurityScheme": {
        "description": ("plain", "scalar"),
    },
    "OAuthFlows": {
        "authorizationCode": ("oneof", "message:AuthorizationCodeOAuthFlow"),
        "clientCredentials": ("oneof", "message:ClientCredentialsOAuthFlow"),
        "implicit": ("oneof", "message:ImplicitOAuthFlow"),
        "password": ("oneof", "message:PasswordOAuthFlow"),
        "deviceCode": ("oneof", "message:DeviceCodeOAuthFlow"),
    },
    "AuthorizationCodeOAuthFlow": {
        "authorizationUrl": ("required", "scalar"),
        "tokenUrl": ("required", "scalar"),
        "refreshUrl": ("plain", "scalar"),
        "scopes": ("required", "map:string"),
        "pkceRequired": ("plain", "scalar"),
    },
    "ClientCredentialsOAuthFlow": {
        "tokenUrl": ("required", "scalar"),
        "refreshUrl": ("plain", "scalar"),
        "scopes": ("required", "map:string"),
    },
    "ImplicitOAuthFlow": {
        "authorizationUrl": ("plain", "scalar"),
        "refreshUrl": ("plain", "scalar"),
        "scopes": ("plain", "map:string"),
    },
    "PasswordOAuthFlow": {
        "tokenUrl": ("plain", "scalar"),
        "refreshUrl": ("plain", "scalar"),
        "scopes": ("plain", "map:string"),
    },
    "DeviceCodeOAuthFlow": {
        "deviceAuthorizationUrl": ("required", "scalar"),
        "tokenUrl": ("required", "scalar"),
        "refreshUrl": ("plain", "scalar"),
        "scopes": ("required", "map:string"),
    },
}


@dataclass(frozen=True)
class SignatureInput:
    """One entry of `signatures`. `alg`, `kid`, `typ` and `jku` are the protected header's string members (None when absent
    or not a string); `has_jwk`, `has_x5c`, `has_x5u` say the header carries a key itself or points to a certificate, and
    `has_crit` that it names critical extensions. `signature` is the decoded signature. `error` is None or the detail of why
    the entry is malformed (no `inputs` then): a header that is not base64url without padding, over 4 KiB or not a JSON
    object; no `alg` or `kid`; `crit`; `b64` false; a signature that is not base64url without padding; a number the
    canonicalisation refuses. `inputs` are `(form, signing input, unsigned members)` in the order of the module docstring."""
    index: int
    protected: str | None
    alg: str | None
    kid: str | None
    typ: str | None
    jku: str | None
    has_jwk: bool
    has_x5c: bool
    has_x5u: bool
    has_crit: bool
    signature: bytes | None
    error: str | None
    inputs: tuple[tuple[str, bytes, tuple[str, ...]], ...]


def b64url_decode(text: str) -> bytes | None:
    """`text` as base64url without padding (RFC 7515 2), None when it is anything else; the empty string is empty bytes (the
    signature of `alg` `none`)."""
    if _BASE64URL.match(text) is None or len(text) % 4 == 1:
        return None
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _is_default(value: object) -> bool:
    return value is False or value == 0 or value in ("", [], {}) or value is None


def _project(value: Any, kind: str, pointer: str, dropped: list[str]) -> Any:
    """`value` as a proto-based signer would have written it, following `kind` (see `_PRESENCE`)."""
    if kind.startswith("message:"):
        return _message(value, kind.split(":", 1)[1], pointer, dropped) if isinstance(value, dict) else value
    if kind.startswith("repeated:message:"):
        name = kind.split(":", 2)[2]
        return ([_message(item, name, pointer + pointer_of(index), dropped) if isinstance(item, dict) else item
                 for index, item in enumerate(value)] if isinstance(value, list) else value)
    if kind.startswith("map:message:"):
        name = kind.split(":", 2)[2]
        return ({key: _message(item, name, pointer + pointer_of(key), dropped) if isinstance(item, dict) else item
                 for key, item in value.items()} if isinstance(value, dict) else value)
    return value  # scalars, free-form structs, repeated strings and maps of strings are kept as served


def _message(value: Mapping, name: str, pointer: str, dropped: list[str]) -> dict:
    table = _PRESENCE[name]
    projected: dict = {}
    for key, member in value.items():
        if key not in table:
            if not _is_default(member):  # a member the proto never saw, with a value: a signer cannot have signed it
                dropped.append(pointer + pointer_of(key))
            continue
        rule, kind = table[key]
        if rule == "plain" and _is_default(member):
            continue
        projected[key] = _project(member, kind, pointer + pointer_of(key), dropped)
    return projected


def _clean_empty(value: Any) -> Any:
    """`a2a-sdk`'s `_clean_empty`: empty strings, arrays and objects removed recursively, `None` for what is left empty."""
    if isinstance(value, dict):
        cleaned = {key: item for key, member in value.items() if (item := _clean_empty(member)) is not None}
        return cleaned or None
    if isinstance(value, list):
        kept = [item for member in value if (item := _clean_empty(member)) is not None]
        return kept or None
    if isinstance(value, str) and not value:
        return None
    return value


def _forms(root: Obj) -> tuple[tuple[str, bytes, tuple[str, ...]], ...]:
    """`(form, canonical payload, unsigned members)` for the card without `signatures`; raises `JcsError` for a number the
    canonicalisation refuses."""
    served = {key: value for key, value in root.items() if key != "signatures"}
    dropped: list[str] = []
    spec = _message(served, "AgentCard", "", dropped)
    sdk = _clean_empty(spec) or {}
    forms: list[tuple[str, bytes, tuple[str, ...]]] = []
    seen: set[bytes] = set()
    for name, payload, unsigned in (("as_served", served, ()), ("spec", spec, tuple(dropped)), ("sdk", sdk, tuple(dropped))):
        canonical = jcs_canonicalize(payload)
        if canonical not in seen:
            seen.add(canonical)
            forms.append((name, canonical, unsigned))
    return tuple(forms)


def _malformed(index: int, detail: str, **fields: Any) -> SignatureInput:
    base: dict[str, Any] = {"protected": None, "alg": None, "kid": None, "typ": None, "jku": None, "has_jwk": False,
                            "has_x5c": False, "has_x5u": False, "has_crit": False, "signature": None}
    base.update(fields)
    return SignatureInput(index=index, error=detail, inputs=(), **base)


def signature_inputs(document: AgentCardDocument) -> tuple[SignatureInput, ...]:
    """One `SignatureInput` per entry of `signatures` (at most 5), in order; nothing for an unreadable or unsigned card."""
    root = document.root
    if root is None:
        return ()
    entries = capped(root.get("signatures"), "signatures")
    try:
        forms: tuple[tuple[str, bytes, tuple[str, ...]], ...] | None = _forms(root) if entries else ()
        payload_error = None
    except JcsError:
        forms, payload_error = None, NUMBER_DETAIL
    return tuple(_one(index, entry, forms, payload_error) for index, entry in enumerate(entries))


def _one(index: int, entry: object, forms, payload_error: str | None) -> SignatureInput:
    if not isinstance(entry, Obj):
        return _malformed(index, "the entry is not an object")
    protected, signature = entry.get("protected"), entry.get("signature")
    if not isinstance(protected, str) or not isinstance(signature, str):
        return _malformed(index, "protected and signature must be strings")
    decoded = b64url_decode(protected)
    if decoded is None:
        return _malformed(index, "the protected header is not base64url without padding", protected=protected)
    if len(decoded) > HEADER_MAX_BYTES:
        return _malformed(index, "the protected header is over 4 KiB", protected=protected)
    try:
        header = load_json(decoded, strict=True, max_depth=8, max_bytes=HEADER_MAX_BYTES)
    except Refused:
        return _malformed(index, "the protected header is not a JSON object", protected=protected)
    if not isinstance(header, Obj):
        return _malformed(index, "the protected header is not a JSON object", protected=protected)

    def text(name: str) -> str | None:
        return header[name] if isinstance(header.get(name), str) else None

    fields = {"protected": protected, "alg": text("alg"), "kid": text("kid"), "typ": text("typ"), "jku": text("jku"),
              "has_jwk": "jwk" in header, "has_x5c": "x5c" in header, "has_x5u": "x5u" in header, "has_crit": "crit" in header}
    if fields["alg"] is None:
        return _malformed(index, "the protected header has no alg", **fields)
    if fields["kid"] is None:
        return _malformed(index, "the protected header has no kid", **fields)
    if fields["has_crit"]:
        return _malformed(index, "the protected header has crit and the scanner understands no extension", **fields)
    if header.get("b64") is False:
        return _malformed(index, "the protected header has b64 false", **fields)
    raw = b64url_decode(signature)
    if raw is None:
        return _malformed(index, "the signature is not base64url without padding", **fields)
    if payload_error is not None:
        return _malformed(index, payload_error, **fields, signature=raw)
    inputs = tuple((form, protected.encode("ascii") + b"." + b64url_encode(payload).encode("ascii"), unsigned)
                   for form, payload, unsigned in forms)
    return SignatureInput(index=index, error=None, inputs=inputs, signature=raw, **fields)
