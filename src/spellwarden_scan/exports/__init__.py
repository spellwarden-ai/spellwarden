"""Exports (Phase C spec 5.5): a pack document compiled to the files of an
enforcement target, as `{path: bytes}` relative to the archive root. Pure:
the caller zips and stores them. Every export holds `SPELLWARDEN-README.md`
(`readme_text`), which lists what the target enforces, what it cannot
enforce and why, and what the pack leaves out. User-controlled text (a pack
name, a rule title, the build time) reaches a generated file only through a
serialiser or `text.comment_safe`, so it can never start a line or a key."""
from __future__ import annotations

import re
from collections.abc import Sequence

from spellwarden_scan.packs import ENFORCEMENT_RULES, PackDocument
from spellwarden_scan.text import comment_safe

EXPORT_TARGETS = ("claude-code-hooks", "kong", "zuplo")
PLANNED_TARGETS = ("agentcore-policy", "cloudflare-egress")
EXPORT_MODES = ("project", "managed")
README_NAME = "SPELLWARDEN-README.md"
VENDOR_LINE = "Validate field names against the vendor's current documentation before use."
TARGET_NAMES = {"claude-code-hooks": "Claude Code hooks", "kong": "Kong", "zuplo": "Zuplo",
                "agentcore-policy": "AWS AgentCore Policy", "cloudflare-egress": "Cloudflare sandbox egress",
                "registry": "Private registry"}
# Escaped text may be longer than what it escapes (`é` for one letter): user text in generated files is cut
# well above the longest valid value, never in the middle of a name the text rules accepted.
TEXT_MAX = 1200
_HOOKS_EXPORT = "enforced by the Claude Code hooks export"
_REGISTRY = "enforced by the private registry, not by an export"
_EGRESS = "a sandbox egress proxy is not in this version"
_MCP_PLUGINS = "needs Kong's MCP plugins"
_ZUPLO_SCRIPT = ("checked at deploy by the included script when your pipeline runs it; the gateway does not refuse "
                 "the route")
# (enforcement rule id, export target) -> why an enabled rule is not enforced there (spec 5.5). Exactly the pairs
# whose target is not in the rule's `enforced_by` (a test keeps it so).
CANNOT_ENFORCE: dict[tuple[str, str], str] = {
    ("SW-HK-001", "kong"): _HOOKS_EXPORT,
    ("SW-HK-002", "kong"): _HOOKS_EXPORT,
    ("SW-GW-003", "kong"): _MCP_PLUGINS,
    ("SW-GW-003", "claude-code-hooks"): _MCP_PLUGINS,
    ("SW-GW-004", "claude-code-hooks"): "enforced by the Kong export, for prompts",
    ("SW-EG-005", "kong"): _EGRESS,
    ("SW-EG-005", "claude-code-hooks"): _EGRESS,
    ("SW-GW-006", "kong"): _HOOKS_EXPORT,
    ("SW-RG-007", "kong"): _REGISTRY,
    ("SW-RG-007", "claude-code-hooks"): _REGISTRY,
    ("SW-OB-008", "kong"): "a protected audit trail of tool calls is not in this version",
    ("SW-OB-008", "claude-code-hooks"): "a local activity log is not an audit trail",
    ("SW-HK-001", "zuplo"): _HOOKS_EXPORT,
    ("SW-HK-002", "zuplo"): _HOOKS_EXPORT,
    ("SW-GW-003", "zuplo"): _ZUPLO_SCRIPT,
    ("SW-EG-005", "zuplo"): _EGRESS,
    ("SW-GW-006", "zuplo"): _HOOKS_EXPORT,
    ("SW-RG-007", "zuplo"): _REGISTRY,
    ("SW-OB-008", "zuplo"): "Zuplo's audit logs are an Enterprise add-on set up in the Zuplo portal, not by this export",
}
# (rule id, target) -> the qualifier shown after the id of an enforced rule.
ENFORCED_NOTES: dict[tuple[str, str], str] = {("SW-GW-004", "kong"): "prompts only",
                                              ("SW-GW-004", "zuplo"): "MCP server responses"}
_PACK_ID = re.compile(r"baseline|[0-9a-f]{32}")
_VERSION = re.compile(r"[0-9]{1,3}\.[0-9]{1,4}")


def coverage(doc: PackDocument, target: str) -> tuple[list[str], list[tuple[str, str]], list[str]]:
    """What `target` does with each rule of the pack: the enforced rules (labels: the id, then the note of
    ENFORCED_NOTES in parentheses), the enabled rules it cannot enforce with the reason, and the rules not included
    (disabled enforcement rules, org rules without this target). Enforcement rules first in id order, then org
    rules in id order."""
    enforced: list[str] = []
    cannot: list[tuple[str, str]] = []
    not_included: list[str] = []
    on = set(doc.enabled())
    for rule in ENFORCEMENT_RULES:
        if rule.id not in on:
            not_included.append(rule.id)
        elif target in rule.enforced_by:
            note = ENFORCED_NOTES.get((rule.id, target))
            enforced.append(f"{rule.id} ({note})" if note else rule.id)
        else:
            cannot.append((rule.id, CANNOT_ENFORCE[(rule.id, target)]))
    for spec in doc.org_rules:
        (enforced if target in spec.get("targets", ()) else not_included).append(spec["id"])
    return enforced, cannot, not_included


def _titles(doc: PackDocument) -> dict[str, str]:
    titles = {rule.id: rule.title for rule in ENFORCEMENT_RULES}
    titles.update({spec["id"]: spec["title"] for spec in doc.org_rules})
    return titles


def _safe(text: object) -> str:
    return comment_safe(str(text), TEXT_MAX)


def readme_text(doc: PackDocument, *, target: str, mode: str | None, built_at: str, enforced: Sequence[str],
                cannot_enforce: Sequence[tuple[str, str]], not_included: Sequence[str], install: Sequence[str],
                limits: Sequence[str]) -> bytes:
    """`SPELLWARDEN-README.md` of an export (spec 5.5). Each entry of `enforced` starts with a rule id (a label of
    `coverage`); `install` and `limits` are the target's own sentences. ASCII only: every value from the pack goes
    through `comment_safe`."""
    titles = _titles(doc)

    def entry(label: str) -> str:
        rule_id = label.split(" ", 1)[0]
        return f"- {_safe(label)}: {_safe(titles.get(rule_id, ''))}"

    lines = [
        "# Spellwarden policy export",
        "",
        f"- Pack: {_safe(doc.name)} {_safe(doc.version)} (id {_safe(doc.pack_id)})",
        f"- Built: {_safe(built_at)}",
        f"- Target: {TARGET_NAMES[target]}",
    ]
    if mode is not None:
        lines.append(f"- Mode: {_safe(mode)}")
    lines += ["", "## Enforced by this export", ""]
    lines += [entry(label) for label in enforced] or ["Nothing in this pack is enforced by this target."]
    lines += ["", "## Enabled but not enforced by this target", ""]
    lines += [f"{entry(rule_id)}. Not enforced here: {_safe(reason)}." for rule_id, reason in cannot_enforce] or ["None."]
    lines += ["", "## Not included", "", "Rules turned off in this pack, and org rules without this target:", ""]
    lines += [entry(rule_id) for rule_id in not_included] or ["None."]
    lines += ["", "## Install", ""]
    lines += [f"{number}. {step}" for number, step in enumerate(install, start=1)]
    lines += ["", "## Limits", ""]
    lines += [f"- {limit}" for limit in limits]
    lines += ["", VENDOR_LINE, ""]
    return "\n".join(lines).encode("ascii")


def build(doc: PackDocument, target: str, *, built_at: str, mode: str = "project") -> dict[str, bytes]:
    """The files of the export of `doc` to `target` (spec 5.5), README included. `mode` matters only for
    `claude-code-hooks` (`kong` and `zuplo` ignore it). Raises ValueError for a target outside EXPORT_TARGETS, a mode
    outside EXPORT_MODES, or a document whose id or version could not have passed `validate_pack` (they name files)."""
    if target not in EXPORT_TARGETS:
        raise ValueError(f"unknown export target {target!r}")
    if mode not in EXPORT_MODES:
        raise ValueError(f"unknown export mode {mode!r}")
    if _PACK_ID.fullmatch(doc.pack_id) is None or _VERSION.fullmatch(doc.version) is None:
        raise ValueError("the pack id or version is not one validate_pack accepts")
    if target == "kong":
        from spellwarden_scan.exports.kong import kong_files

        return kong_files(doc, built_at=built_at)
    if target == "zuplo":
        from spellwarden_scan.exports.zuplo import zuplo_files

        return zuplo_files(doc, built_at=built_at)
    from spellwarden_scan.exports.hooks import hooks_files  # Task 6 (spec 5.5.1)

    return hooks_files(doc, built_at=built_at, mode=mode)


__all__ = [
    "CANNOT_ENFORCE", "ENFORCED_NOTES", "EXPORT_MODES", "EXPORT_TARGETS", "PLANNED_TARGETS", "README_NAME",
    "TARGET_NAMES", "TEXT_MAX", "VENDOR_LINE", "build", "coverage", "readme_text",
]
