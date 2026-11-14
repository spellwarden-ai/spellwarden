"""The frameworks the rules are tagged with (Phase 3 batch 1 spec 9.1, 11.3): their names, versions and items, the ids of the
pinned MITRE ATLAS release and the rules that have no ATLAS technique. Pure data; the engine reads no files, so the JSON files of
this directory reach the module as the string constants of `_data.py` (generated, kept equal to the files by a test)."""
from __future__ import annotations

import json
from dataclasses import dataclass

from spellwarden_scan.frameworks import _data


@dataclass(frozen=True)
class FrameworkItem:
    id: str
    name: str


@dataclass(frozen=True)
class Framework:
    """`status` is a label printed beside the version wherever the framework's version is shown (None for a stable one)."""
    id: str
    name: str
    version: str
    url: str
    items: tuple[FrameworkItem, ...]
    status: str | None = None


_TECHNIQUES = json.loads(_data.ATLAS_TECHNIQUES_JSON)
_SCOPE = json.loads(_data.ATLAS_SCOPE_JSON)
_DOCUMENT = json.loads(_data.FRAMEWORKS_JSON)

ATLAS_VERSION: str = _TECHNIQUES["release"]
ATLAS_FORMAT_VERSION: str = _TECHNIQUES["format_version"]
ATLAS_MODIFIED: str = _TECHNIQUES["modified"]


def _atlas_name(identifier: str) -> str:
    entry = _TECHNIQUES["techniques"][identifier]
    parent = entry.get("parent")
    return f"{_TECHNIQUES['techniques'][parent]['name']}: {entry['name']}" if parent else entry["name"]


# Every technique and sub-technique of the pinned release, `AML.T0051.001` -> "LLM Prompt Injection: Indirect". The release file
# has no deprecation marker, so a rule's id is valid when it is a key here.
ATLAS_TECHNIQUES: dict[str, str] = {identifier: _atlas_name(identifier) for identifier in _TECHNIQUES["techniques"]}
# The rules with no ATLAS technique, each with the reason (a rule has `atlas` ids or an entry here, never both, never neither).
NO_ATLAS: dict[str, str] = dict(_DOCUMENT["no_atlas"])


def _framework(key: str, items: tuple[FrameworkItem, ...]) -> Framework:
    entry = _DOCUMENT["frameworks"][key]
    return Framework(id=key, name=entry["name"], version=entry["version"], url=entry["url"], items=items,
                     status=entry.get("status"))


def _listed(key: str) -> tuple[FrameworkItem, ...]:
    return tuple(FrameworkItem(item["id"], item["name"]) for item in _DOCUMENT["frameworks"][key]["items"])


FRAMEWORKS: dict[str, Framework] = {
    "owasp_agentic": _framework("owasp_agentic", _listed("owasp_agentic")),
    "owasp_mcp": _framework("owasp_mcp", _listed("owasp_mcp")),
    "nist": _framework("nist", _listed("nist")),
    # the ATLAS "scope" of the crosswalk page (spec 9.2), not all 221 ids
    "atlas": _framework("atlas", tuple(FrameworkItem(identifier, ATLAS_TECHNIQUES[identifier]) for identifier in _SCOPE["ids"])),
    "owasp_ast": _framework("owasp_ast", _listed("owasp_ast")),
}
AST_VERSION: str = FRAMEWORKS["owasp_ast"].version
AST_STATUS: str | None = FRAMEWORKS["owasp_ast"].status
AST_IDS = frozenset(item.id for item in FRAMEWORKS["owasp_ast"].items)

__all__ = ["AST_IDS", "AST_STATUS", "AST_VERSION", "ATLAS_FORMAT_VERSION", "ATLAS_MODIFIED", "ATLAS_TECHNIQUES", "ATLAS_VERSION",
           "FRAMEWORKS", "NO_ATLAS", "Framework", "FrameworkItem"]
