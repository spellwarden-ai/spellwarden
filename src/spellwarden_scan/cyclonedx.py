"""CycloneDX 1.7 documents (phase 3 batch 2a spec 7.2, 7.3): the one mapping of Spellwarden's objects to an AI bill of
materials, shared by the command's `--format cyclonedx` and the hosted export. Pure functions over plain dicts and strings:
no I/O, no clock, no randomness. Every function returns its object with a fixed key order and leaves out a key whose value
is absent or empty, so the same input gives the same bytes.

The serial number is reproducible (spec D17): a UUID version 5 in the URL namespace whose name is the SHA-256 of the
canonical JSON of the document without `serialNumber` and `metadata.timestamp`. Property names start with
`PROPERTY_PREFIX`; property values are strings, as the schema requires (`true` and `false` for a boolean)."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from collections.abc import Iterable, Sequence

from spellwarden_scan.agentconfig import url_parts
from spellwarden_scan.evidence import mask_credentials
from spellwarden_scan.text import utf8

SPEC_VERSION = "1.7"
SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.7.schema.json"
PROPERTY_PREFIX = "spellwarden:"
SOURCE_NAME = "Spellwarden"
SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
# A finding's status to the CycloneDX analysis state and responses (spec D14): an open finding is being triaged, an accepted
# one is a known risk that will not be fixed.
ANALYSIS = {"open": ("in_triage", ()), "accepted": ("exploitable", ("will_not_fix",))}


def _drop_empty(entries: Iterable[tuple[str, object]]) -> dict:
    return {key: value for key, value in entries if value is not None and value != [] and value != {}}


def prop(name: str, value: object) -> dict:
    """One property: `name` gains `PROPERTY_PREFIX` unless it has it; a boolean is `true` or `false`, anything else `str()`."""
    full = name if name.startswith(PROPERTY_PREFIX) else PROPERTY_PREFIX + name
    text = ("true" if value else "false") if isinstance(value, bool) else str(value)
    return {"name": full, "value": text}


# A credential carried in a path segment as `name=value` whose name's last word (split on `_` or `-`) is one of these
# (`/key=<secret>/`, `/sig=<signature>/`, `/x-api-key=...`): the value becomes `***`. The same expression as the hosted
# backend's `util.mask_path_credentials`, so the two never disagree; `monkey=1`, `design=x` and `keys=1` are not names of it.
_PATH_CREDENTIAL = re.compile(r"^((?:[A-Za-z0-9]+[_-])*(?:key|apikey|token|secret|password|passwd|sig|signature))=.+$",
                              re.IGNORECASE)
# The ASCII characters an IRI reference allows in a host (`ireg-name`: unreserved and sub-delims) and, with `:`, `@` and `/`,
# in a path (RFC 3987 `ipath-abempty`); `%` only as the start of an escape `%XX`. Every other ASCII character (`<`, `>`, `"`,
# `{`, `}`, `|`, `\`, `^`, a backtick, `[`, `]`, a stray `%`) is percent-encoded.
_HOST_ASCII = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=")
_PATH_ASCII = _HOST_ASCII | frozenset(":@/")
_HEX = frozenset("0123456789abcdefABCDEF")
_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")


def _ucschar(code: int) -> bool:
    """RFC 3987 `ucschar`: the characters above ASCII an IRI holds as they are outside its query. C1 controls, surrogates,
    noncharacters and the private use areas are not among them."""
    if 0xA0 <= code <= 0xD7FF or 0xF900 <= code <= 0xFDCF or 0xFDF0 <= code <= 0xFFEF:
        return True
    plane, low = code >> 16, code & 0xFFFF
    if 1 <= plane <= 0xD:
        return low <= 0xFFFD
    return plane == 0xE and 0x1000 <= low <= 0xFFFD


def _iri_escaped(text: str, allowed: frozenset[str]) -> str:
    """`text` with every character an IRI reference does not allow there percent-encoded as its UTF-8 bytes (a lone surrogate
    as the bytes `surrogatepass` gives, so nothing raises). A valid escape `%XX` and an allowed character stay as they are,
    so escaping twice gives the same text."""
    out: list[str] = []
    for index, char in enumerate(text):
        if char == "%" and text[index + 1:index + 2] in _HEX and text[index + 2:index + 3] in _HEX:
            out.append(char)
        elif char in allowed or (ord(char) > 0x7F and _ucschar(ord(char))):
            out.append(char)
        else:
            out.append("".join(f"%{byte:02X}" for byte in char.encode("utf-8", "surrogatepass")))
    return "".join(out)


def _decoded_for_names(segment: str) -> str:
    """The text a path segment's credential name is judged on (1.16.2): every `%` followed by two hex digits, either case,
    becomes that byte and every other character its UTF-8 bytes (a lone surrogate as `surrogatepass` gives them); the bytes are
    decoded as UTF-8 with an invalid sequence read as U+FFFD. One pass: `%2565` reads as `%65`, not `e`. So `k%65y=secret`,
    `%6Bey=secret` and `x-key%3Dsecret` read as `key=secret` and `x-key=secret`."""
    raw = bytearray()
    index = 0
    while index < len(segment):
        if segment[index] == "%" and segment[index + 1:index + 2] in _HEX and segment[index + 2:index + 3] in _HEX:
            raw.append(int(segment[index + 1:index + 3], 16))
            index += 3
        else:
            raw += segment[index].encode("utf-8", "surrogatepass")
            index += 1
    return raw.decode("utf-8", "replace")


def _mask_names(segment: str) -> str:
    """`_PATH_CREDENTIAL` on the decoded segment (`_decoded_for_names`): when it matches, the segment becomes the decoded name
    (group 1) and `=***`; otherwise the segment is left as it is, escapes included. On a segment without an escape this is the
    backend's `_PATH_CREDENTIAL.sub(r"\1=***", segment)`."""
    match = _PATH_CREDENTIAL.match(_decoded_for_names(segment))
    return f"{match.group(1)}=***" if match else segment


_MASKINGS = ("full", "evidence", "none")


def _reduced_segment(segment: str, masking: str) -> str:
    """A raw path segment masked, then escaped for an IRI, in rounds until a round changes nothing. The first round masks the
    segment as it was written, so escaping never hides a credential from the masking (`{"token":"x"}` is masked before `"` is
    `%22`); the result is valid in an IRI and a fixed point of the round, so `reduce_url` is idempotent. `mask_credentials`
    alone is not always its own fixed point (`ghp_<36>-user:pw@x` becomes `ghp_***-user:pw@x`, which a second pass masks to
    `ghp_***-user:***`). It settles in two or three rounds; the bound only backs that up."""
    for _ in range(8):
        masked = segment
        if masking != "none":
            masked = mask_credentials(masked)
        if masking == "full":
            masked = _mask_names(masked)
        masked = _iri_escaped(masked, _PATH_ASCII)
        if masked == segment:
            break
        segment = masked
    return segment


def reduce_url(text: object, *, masking: str = "full") -> str | None:
    """`scheme://host[:port]/path` of an absolute URL: user name and password, query and fragment removed, scheme and host
    lower-cased (the rule of `identity._reduce_source`), a credential in a path segment masked, and (1.16.2) every character an
    IRI reference does not allow in the host or the path percent-encoded, so the result is a valid `iri-reference` (CycloneDX
    `externalReferences[].url`, `services[].endpoints[]`). None for anything that is not an absolute URL, that holds an ASCII
    control character or whitespace, or whose bracketed host is no IPv6 address. Idempotent. Used for every
    endpoint and every source URL an export writes. Never raises for any `text`.

    `masking` (1.16.2): `full`, the default, masks each path segment as evidence is masked (`mask_credentials`) and a
    `name=value` segment named like a credential (`_PATH_CREDENTIAL`, as the hosted backend does); `evidence` only the first,
    as 1.16.1 did; `none` masks nothing, for a canonical repository URL (no user name, no query) whose readable path is the
    point of the link."""
    if masking not in _MASKINGS:
        raise ValueError(f"masking is one of {', '.join(_MASKINGS)}")
    if not isinstance(text, str) or any(ord(char) < 0x21 or ord(char) == 0x7F for char in text):
        return None
    parts = url_parts(text)
    if parts is None:
        return None
    if ":" in parts.host:  # it came bracketed: an IPv6 address needs no escape; anything else (a zone, IPvFuture) is no host
        try:
            ipaddress.IPv6Address(parts.host)
        except ValueError:
            return None
        if "%" in parts.host:
            return None
        host = f"[{parts.host}]"
    else:  # the host came lower-cased, its escapes too: their hex digits are written in upper case, as they are made
        host = _ESCAPE.sub(lambda match: match.group(0).upper(), _iri_escaped(parts.host, _HOST_ASCII))
    # A token carried in the path (`/api/mcp/s/<token>/mcp`, a webhook's secret segment) is masked like any evidence, segment
    # by segment, as `evidence.redacted_url` does, so the host and the other segments stay readable, and a `name=value`
    # segment named like a credential is masked whole (1.16.2, `_mask_names`). Each segment is masked as written, then escaped.
    path = "/".join(_reduced_segment(segment, masking) for segment in parts.path.split("/"))
    return f"{parts.scheme}://{host}{':' + parts.port if parts.port else ''}{path}"


def component(*, ref: str | None, type: str, name: str, version: str | None = None, hashes: Sequence[str] = (),
              external: Sequence[tuple[str, str]] = (), properties: Sequence[dict] = (),
              components: Sequence[dict] = ()) -> dict:
    """A component. `hashes` are SHA-256 hex digests; `external` is `(type, url)` pairs (`vcs`, `distribution`, `website`)."""
    return _drop_empty((
        ("bom-ref", ref), ("type", type), ("name", name), ("version", version),
        ("hashes", [{"alg": "SHA-256", "content": digest} for digest in hashes]),
        ("externalReferences", [{"type": kind, "url": url} for kind, url in external]),
        ("properties", list(properties)), ("components", list(components)),
    ))


def service(*, ref: str, name: str, version: str | None = None, endpoints: Sequence[str] = (),
            authenticated: bool | None = None, properties: Sequence[dict] = ()) -> dict:
    """A service: an MCP server or an A2A agent. `authenticated` is left out when unknown."""
    return _drop_empty((
        ("bom-ref", ref), ("name", name), ("version", version), ("endpoints", list(endpoints)),
        ("authenticated", authenticated), ("properties", list(properties)),
    ))


def vulnerability(*, ref: str, title: str, severity: str, affects: Sequence[str], state: str, rule_id: str | None = None,
                  url: str | None = None, response: Sequence[str] = (), detail: str | None = None,
                  created: str | None = None, properties: Sequence[dict] = (), recommendation: str | None = None) -> dict:
    """A finding. `state` and `response` are CycloneDX analysis values (`ANALYSIS` maps a status to them). `rule_id=None`
    writes no `id` (a manual finding); `url=None` writes the source with its name alone (a manual finding and an
    organisation rule's finding have no public rule page, spec D42). `recommendation` (1.21.0, P6-15 spec 6.9) is the rule's
    fix sentence, written after `description`; None writes none."""
    source = _drop_empty((("name", SOURCE_NAME), ("url", url)))
    analysis = _drop_empty((("state", state), ("response", list(response)), ("detail", detail)))
    return _drop_empty((
        ("bom-ref", ref), ("id", rule_id), ("source", source),
        ("ratings", [{"source": source, "severity": SEVERITY[severity], "method": "other"}]),
        ("description", title), ("recommendation", recommendation), ("created", created), ("analysis", analysis),
        ("affects", [{"ref": target} for target in affects]), ("properties", list(properties)),
    ))


def dependency(ref: str, depends_on: Sequence[str]) -> dict:
    """`ref` depends on each of `depends_on` (a marketplace on its plugins, a plugin on its skills, a document on its servers)."""
    return {"ref": ref, "dependsOn": list(depends_on)}


def _canonical(value: object) -> bytes:
    # 1.18.0: a lone surrogate as U+FFFD (text.utf8); any other value gives the bytes it always gave
    return utf8(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def document(*, subject: dict, tool_version: str, tool_url: str, timestamp: str, components: Sequence[dict],
             services: Sequence[dict], vulnerabilities: Sequence[dict], dependencies: Sequence[dict],
             properties: Sequence[dict], tool_properties: Sequence[dict] = ()) -> dict:
    """The whole document in a fixed key order. `subject` is `metadata.component` (the organisation, the scan root or the
    workstation); `tool_url` is the tagged home page of Spellwarden (spec 4.6); `tool_properties` are the properties of the
    tool component (the hosted export names its service there, spec 7.3). Empty lists are left out."""
    tool = component(ref=None, type="application", name=SOURCE_NAME, version=tool_version, external=[("website", tool_url)],
                     properties=tool_properties)
    metadata = _drop_empty((("timestamp", timestamp), ("tools", {"components": [tool]}), ("component", subject),
                            ("properties", list(properties))))
    body = _drop_empty((
        ("$schema", SCHEMA_URL), ("bomFormat", "CycloneDX"), ("specVersion", SPEC_VERSION), ("version", 1),
        ("metadata", metadata), ("components", list(components)), ("services", list(services)),
        ("dependencies", list(dependencies)), ("vulnerabilities", list(vulnerabilities)),
    ))
    unstamped = {**body, "metadata": {key: value for key, value in metadata.items() if key != "timestamp"}}
    serial = uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(_canonical(unstamped)).hexdigest())
    return {key: body[key] for key in ("$schema", "bomFormat", "specVersion")} | {"serialNumber": f"urn:uuid:{serial}"} | {
        key: value for key, value in body.items() if key not in ("$schema", "bomFormat", "specVersion")}


__all__ = ["ANALYSIS", "PROPERTY_PREFIX", "SCHEMA_URL", "SEVERITY", "SOURCE_NAME", "SPEC_VERSION", "component", "dependency",
           "document", "prop", "reduce_url", "service", "vulnerability"]
