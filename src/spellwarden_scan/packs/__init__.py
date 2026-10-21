"""Policy packs (Phase C spec 5.3, 5.4): the enforcement rules, the
Spellwarden baseline pack, and the schema-1 pack document with its validator
and canonical form. Pure: the baseline is parsed from the string constant
`BASELINE_JSON`, which a test keeps byte-equal to `packs/baseline.json` (the
copy for readers), because the engine opens no file."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache

from spellwarden_scan.orgrules import OrgRuleError, validate_org_rule
from spellwarden_scan.packs.enforcement import ENFORCEMENT_IDS, ENFORCEMENT_RULES, TARGET_IDS, EnforcementRule
from spellwarden_scan.text import valid_block, valid_line
from spellwarden_scan.version import RULES_VERSION, __version__

PACK_ERROR_CODES = ("bad_schema", "bad_pack", "bad_rules", "bad_org_rule", "too_many_org_rules")
MAX_ORG_RULES = 200
MAX_NAME = 80
MAX_DESCRIPTION = 500
# The canonical document is stored as one DynamoDB attribute by the hosted product (spec 6.2); 200 org rules at their
# largest ASCII sizes stay well below it (claim E6), and a pack whose text makes it larger is refused.
MAX_DOCUMENT_BYTES = 300_000
_DOCUMENT_KEYS = frozenset({"schema", "pack", "engine", "rules", "org_rules"})
_PACK_KEYS = frozenset({"id", "name", "version", "description"})
_ENGINE_KEYS = frozenset({"version", "rules_version"})
_RULE_KEYS = frozenset({"id", "enabled"})
_PACK_ID = re.compile(r"baseline|[0-9a-f]{32}")
_VERSION = re.compile(r"[0-9]{1,3}\.[0-9]{1,4}")

BASELINE_JSON = """{
  "schema": 1,
  "pack": {
    "id": "baseline",
    "name": "Spellwarden Baseline for Agents",
    "version": "1.0",
    "description": "The eight Spellwarden baseline enforcement rules, mapped to OWASP and NIST."
  },
  "engine": {
    "version": "1.1.0",
    "rules_version": "2026.10.2"
  },
  "rules": [
    {
      "id": "SW-HK-001",
      "enabled": true
    },
    {
      "id": "SW-HK-002",
      "enabled": true
    },
    {
      "id": "SW-GW-003",
      "enabled": true
    },
    {
      "id": "SW-GW-004",
      "enabled": true
    },
    {
      "id": "SW-EG-005",
      "enabled": true
    },
    {
      "id": "SW-GW-006",
      "enabled": true
    },
    {
      "id": "SW-RG-007",
      "enabled": true
    },
    {
      "id": "SW-OB-008",
      "enabled": true
    }
  ],
  "org_rules": []
}
"""


class PackError(ValueError):
    """A pack document this engine refuses; `code` is one of PACK_ERROR_CODES. For `bad_org_rule`, `rule_id` names
    the org rule (or its position) and `rule_error` is its OrgRuleError code when there is one."""

    def __init__(self, code: str, message: str, *, rule_id: str | None = None, rule_error: str | None = None) -> None:
        if code not in PACK_ERROR_CODES:
            raise ValueError(f"unknown pack error code {code!r}")
        super().__init__(message)
        self.code = code
        self.message = message
        self.rule_id = rule_id
        self.rule_error = rule_error


@dataclass(frozen=True, slots=True)
class PackDocument:
    pack_id: str
    name: str
    version: str
    description: str
    engine_version: str
    rules_version: str
    rules: tuple[tuple[str, bool], ...]
    org_rules: tuple[dict, ...]

    def enabled(self) -> tuple[str, ...]:
        """The enabled enforcement rule ids, in id order."""
        return tuple(rule_id for rule_id, on in self.rules if on)

    def to_dict(self) -> dict:
        """The schema-1 JSON object of spec 5.4 (a fresh copy every call)."""
        return {
            "schema": 1,
            "pack": {"id": self.pack_id, "name": self.name, "version": self.version, "description": self.description},
            "engine": {"version": self.engine_version, "rules_version": self.rules_version},
            "rules": [{"id": rule_id, "enabled": on} for rule_id, on in self.rules],
            "org_rules": [_copy(spec) for spec in self.org_rules],
        }


def _copy(value: object):
    """A deep copy that is plain JSON (dicts, lists, strings, numbers, booleans, null)."""
    return json.loads(json.dumps(value, ensure_ascii=False))


def _pack_block(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != _PACK_KEYS:
        raise PackError("bad_pack", "The pack block is an object with exactly the keys id, name, version and description.")
    if not isinstance(value["id"], str) or _PACK_ID.fullmatch(value["id"]) is None:
        raise PackError("bad_pack", "The pack id is baseline or 32 lowercase hexadecimal characters.")
    if not valid_line(value["name"], MAX_NAME):
        raise PackError("bad_pack", "The pack name is 1 to 80 characters on one line, without control or format characters.")
    if not isinstance(value["version"], str) or _VERSION.fullmatch(value["version"]) is None:
        raise PackError("bad_pack", "The pack version is two numbers joined by a dot, such as 1.0.")
    description = value["description"]
    if not isinstance(description, str) or (description != "" and not valid_block(description, MAX_DESCRIPTION)):
        raise PackError("bad_pack", "The pack description is empty or at most 500 characters, without control or format "
                                    "characters other than line breaks.")
    return value


def _rules(value: object) -> tuple[tuple[str, bool], ...]:
    message = "The rules list holds each of the eight enforcement rules once, in id order, with a true or false enabled value."
    if not isinstance(value, list) or len(value) != len(ENFORCEMENT_IDS):
        raise PackError("bad_rules", message)
    rules = []
    for expected, item in zip(ENFORCEMENT_IDS, value, strict=True):
        if not isinstance(item, dict) or set(item) != _RULE_KEYS or item["id"] != expected or type(item["enabled"]) is not bool:
            raise PackError("bad_rules", message)
        rules.append((expected, item["enabled"]))
    return tuple(rules)


def _org_rules(value: object) -> tuple[dict, ...]:
    if not isinstance(value, list):
        raise PackError("bad_schema", "The org_rules value is a list of org rule specs.")
    if len(value) > MAX_ORG_RULES:
        raise PackError("too_many_org_rules", "A pack holds at most 200 org rules.")
    previous = ""
    for position, spec in enumerate(value, start=1):
        label = spec["id"] if isinstance(spec, dict) and isinstance(spec.get("id"), str) else f"number {position}"
        try:
            validate_org_rule(spec)
        except OrgRuleError as exc:
            raise PackError("bad_org_rule", f"Org rule {label}: {exc.message}", rule_id=label, rule_error=exc.code) from None
        if spec["id"] <= previous:
            raise PackError("bad_org_rule", f"Org rule {label}: org rules have distinct ids, in id order.", rule_id=label)
        previous = spec["id"]
    return tuple(_copy(spec) for spec in value)


def validate_pack(doc: object) -> PackDocument:
    """Spec 5.4: the checks of `schemas/pack.schema.json` and the ones a schema cannot state (the text rules, the org
    rule specs through `validate_org_rule`, id order, the size bound). Raises PackError."""
    if not isinstance(doc, dict) or set(doc) != _DOCUMENT_KEYS:
        raise PackError("bad_schema", "A pack document is an object with exactly the keys schema, pack, engine, rules and "
                                      "org_rules.")
    if type(doc["schema"]) is not int or doc["schema"] != 1:
        raise PackError("bad_schema", "This engine reads pack documents of schema 1.")
    engine = doc["engine"]
    if not isinstance(engine, dict) or set(engine) != _ENGINE_KEYS or not all(isinstance(engine[k], str) for k in _ENGINE_KEYS):
        raise PackError("bad_schema", "The engine block is an object with the strings version and rules_version.")
    pack = _pack_block(doc["pack"])
    document = PackDocument(
        pack_id=pack["id"], name=pack["name"], version=pack["version"], description=pack["description"],
        engine_version=engine["version"], rules_version=engine["rules_version"], rules=_rules(doc["rules"]),
        org_rules=_org_rules(doc["org_rules"]),
    )
    try:
        size = len(canonical_json(document))
    except UnicodeEncodeError:
        raise PackError("bad_schema", "The pack holds text that is not valid Unicode.") from None
    if size > MAX_DOCUMENT_BYTES:
        raise PackError("too_many_org_rules", "The pack is larger than 300 000 bytes. Include fewer org rules.")
    return document


def make_pack_document(*, pack_id: str, name: str, version: str, description: str, rules: Mapping[str, bool],
                       org_rules: Sequence[dict]) -> dict:
    """The schema-1 dict for a pack the caller assembled (the hosted product's publish, spec 6.4.1): the engine block
    names this engine, `rules` follows id order, `org_rules` is sorted by id and copied. It does not validate: pass
    the result to `validate_pack`."""
    unknown = set(rules) - set(ENFORCEMENT_IDS)
    if unknown:
        raise ValueError(f"unknown enforcement rule ids {sorted(unknown)}")
    return {
        "schema": 1,
        "pack": {"id": pack_id, "name": name, "version": version, "description": description},
        "engine": {"version": __version__, "rules_version": RULES_VERSION},
        "rules": [{"id": rule_id, "enabled": rules[rule_id]} for rule_id in ENFORCEMENT_IDS],
        "org_rules": sorted((_copy(spec) for spec in org_rules), key=lambda spec: spec["id"]),
    }


def canonical_json(doc: PackDocument | dict) -> bytes:
    """Sorted keys, no whitespace, UTF-8 (spec 5.4): two documents with the same canonical JSON are one pack version."""
    value = doc.to_dict() if isinstance(doc, PackDocument) else doc
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def pack_sha256(doc: PackDocument | dict) -> str:
    return hashlib.sha256(canonical_json(doc)).hexdigest()


@lru_cache(maxsize=1)
def baseline_pack() -> PackDocument:
    """The Spellwarden baseline pack: id `baseline`, version 1.0, every enforcement rule on, no org rules (spec 5.3)."""
    return validate_pack(json.loads(BASELINE_JSON))


__all__ = [
    "BASELINE_JSON", "ENFORCEMENT_IDS", "ENFORCEMENT_RULES", "MAX_DOCUMENT_BYTES", "MAX_ORG_RULES", "PACK_ERROR_CODES",
    "TARGET_IDS", "EnforcementRule", "PackDocument", "PackError", "baseline_pack", "canonical_json",
    "make_pack_document", "pack_sha256", "validate_pack",
]
