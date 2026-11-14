"""CycloneDX 1.7 documents (phase 3 batch 2a spec 7.2, 7.3): the one mapping of Spellwarden's objects to an AI bill of
materials, shared by the command's `--format cyclonedx` and the hosted export. Pure functions over plain dicts and strings:
no I/O, no clock, no randomness. Every function returns its object with a fixed key order and leaves out a key whose value
is absent or empty, so the same input gives the same bytes.

The serial number is reproducible (spec D17): a UUID version 5 in the URL namespace whose name is the SHA-256 of the
canonical JSON of the document without `serialNumber` and `metadata.timestamp`. Property names start with
`PROPERTY_PREFIX`; property values are strings, as the schema requires (`true` and `false` for a boolean)."""
from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Sequence

from spellwarden_scan.agentconfig import url_parts

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


def reduce_url(text: object) -> str | None:
    """`scheme://host[:port]/path` of an absolute URL: user name and password, query and fragment removed, scheme and host
    lower-cased (the rule of `identity._reduce_source`). None for anything that is not an absolute URL, or that holds a
    control character or whitespace. Used for every endpoint and every source URL an export writes."""
    if not isinstance(text, str) or any(ord(char) < 0x21 or ord(char) == 0x7F for char in text):
        return None
    parts = url_parts(text)
    if parts is None:
        return None
    host = f"[{parts.host}]" if ":" in parts.host else parts.host
    return f"{parts.scheme}://{host}{':' + parts.port if parts.port else ''}{parts.path}"


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
                  created: str | None = None, properties: Sequence[dict] = ()) -> dict:
    """A finding. `state` and `response` are CycloneDX analysis values (`ANALYSIS` maps a status to them). `rule_id=None`
    writes no `id` (a manual finding); `url=None` writes the source with its name alone (a manual finding and an
    organisation rule's finding have no public rule page, spec D42)."""
    source = _drop_empty((("name", SOURCE_NAME), ("url", url)))
    analysis = _drop_empty((("state", state), ("response", list(response)), ("detail", detail)))
    return _drop_empty((
        ("bom-ref", ref), ("id", rule_id), ("source", source),
        ("ratings", [{"source": source, "severity": SEVERITY[severity], "method": "other"}]),
        ("description", title), ("created", created), ("analysis", analysis),
        ("affects", [{"ref": target} for target in affects]), ("properties", list(properties)),
    ))


def dependency(ref: str, depends_on: Sequence[str]) -> dict:
    """`ref` depends on each of `depends_on` (a marketplace on its plugins, a plugin on its skills, a document on its servers)."""
    return {"ref": ref, "dependsOn": list(depends_on)}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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
