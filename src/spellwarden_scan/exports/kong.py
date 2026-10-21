"""The Kong export (Phase C spec 5.5.2): a decK file with one global
`ai-prompt-guard` plugin whose `deny_patterns` hold the engine's injection
patterns (SW-GW-004) and the PCRE form of every org pattern rule with the
`kong` target. The plugin takes at most 10 patterns of at most 500
characters (Kong's plugin reference, checked on 2026-10-21), so every
pattern is wrapped in a scoped group (`(?i:...)` or `(?:...)`) and the
groups are joined with `|` into as few entries as fit, first fit in rule
order; an org rule that fits nowhere is listed as not enforced."""
from __future__ import annotations

import re
from collections.abc import Iterator

import yaml

from spellwarden_scan.exports import README_NAME, TEXT_MAX, VENDOR_LINE, coverage, readme_text
from spellwarden_scan.orgrules import CompiledPattern, compile_pattern
from spellwarden_scan.packs import PackDocument
from spellwarden_scan.rules.patterns import INJECTION
from spellwarden_scan.text import comment_safe

MAX_PATTERNS = 10
MAX_PATTERN_CHARS = 500
FORBIDDEN = ("(?P", "(?#", "(?<", "\\A", "\\Z")
OVERFLOW_REASON = "the ai-prompt-guard plugin holds at most 10 patterns of 500 characters, and this one did not fit"


def yaml_path(doc: PackDocument) -> str:
    return f"kong/spellwarden-{doc.pack_id}-{doc.version}.yaml"


def scoped(pcre: str) -> str:
    """A pattern as one group that keeps its own case flag inside an alternation (PCRE and Python alike)."""
    if pcre.startswith("(?i)"):
        return "(?i:" + pcre[len("(?i)"):] + ")"
    return "(?:" + pcre + ")"


def kong_pattern(compiled: CompiledPattern) -> str:
    """One deny pattern. A single part is a scoped group (`scoped`). Several parts are a line-anchored chain of atomic
    groups, `(?im:^(?>.*?A)(?>.*?B))`, which takes the first A on a line and then the first B after it, as the
    engine's `pattern_search` does, and never backtracks across parts: `A.*B.*C` backtracks with the cube of the
    prompt's length, so a prompt could hold the gateway (owner decision of 2026-10-21, after the security review)."""
    if len(compiled.parts) == 1:
        return scoped(compiled.pcre)
    texts = [part.pattern for part in compiled.parts]
    groups = ["(?>" + texts[0][1:] + ")" if texts[0].startswith("^") else "(?>.*?" + texts[0] + ")"]
    groups += ["(?>.*?" + text + ")" for text in texts[1:]]
    return ("(?m:" if compiled.case_sensitive else "(?im:") + "^" + "".join(groups) + ")"


def _alternatives(doc: PackDocument) -> list[tuple[str | None, str]]:
    """(the org rule id, or None for SW-GW-004's patterns; the scoped pattern), in rule order."""
    items: list[tuple[str | None, str]] = []
    if "SW-GW-004" in doc.enabled():
        items += [(None, "(?i:" + pattern.pattern + ")") for pattern in INJECTION]
    for spec in doc.org_rules:
        if "kong" in spec.get("targets", ()):
            detection = spec["detection"]
            compiled = compile_pattern(detection["pattern"], case_sensitive=detection.get("case_sensitive", False))
            items.append((spec["id"], kong_pattern(compiled)))
    return items


def deny_patterns(doc: PackDocument) -> tuple[list[str], list[str]]:
    """The plugin's entries and the org rule ids that did not fit (first fit, in rule order)."""
    entries: list[str] = []
    overflow: list[str] = []
    for owner, alternative in _alternatives(doc):
        for index, entry in enumerate(entries):
            if len(entry) + 1 + len(alternative) <= MAX_PATTERN_CHARS:
                entries[index] = entry + "|" + alternative
                break
        else:
            if len(entries) < MAX_PATTERNS and len(alternative) <= MAX_PATTERN_CHARS:
                entries.append(alternative)
            elif owner is not None:
                overflow.append(owner)
            else:  # the nine injection patterns fit in one entry; a change that breaks this is a bug
                raise RuntimeError("the injection patterns do not fit the plugin")
    for entry in entries:
        _check(entry)
    return entries, overflow


def _tokens(entry: str) -> Iterator[str]:
    """The regex tokens of `entry` that `FORBIDDEN` names, read as a regex reads them: an escaped character is one
    token (`\\\\A` is a backslash and A, not `\\A`), and `(` opens a group only outside a bracket class."""
    index, in_class = 0, False
    while index < len(entry):
        char = entry[index]
        if char == "\\":
            yield entry[index:index + 2]
            index += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            yield entry[index:index + 3]
        index += 1


def _check(entry: str) -> None:
    """Spec 5.5.2: every emitted pattern compiles with Python `re` and uses nothing PCRE reads differently. A
    failure is a bug in the engine, never a user error, so it raises instead of being reported."""
    if len(entry) > MAX_PATTERN_CHARS or any(token in FORBIDDEN for token in _tokens(entry)):
        raise RuntimeError(f"export pattern outside the shared subset: {entry[:80]!r}")
    re.compile(entry)


def kong_files(doc: PackDocument, *, built_at: str) -> dict[str, bytes]:
    enforced, cannot, not_included = coverage(doc, "kong")
    entries, overflow = deny_patterns(doc)
    enforced = [label for label in enforced if label.split(" ", 1)[0] not in overflow]
    cannot = cannot + [(rule_id, OVERFLOW_REASON) for rule_id in overflow]
    plugins = [{"name": "ai-prompt-guard", "config": {"deny_patterns": entries}}] if entries else []
    header = [
        f'# Spellwarden policy export: pack "{comment_safe(doc.name, TEXT_MAX)}" {comment_safe(doc.version)}, '
        f"built {comment_safe(built_at)}.",
        "# Enforced here: " + (", ".join(enforced) if enforced else "nothing") + ".",
        "# Not enforced by this target: "
        + (", ".join(f"{rule_id} ({reason})" for rule_id, reason in cannot) if cannot else "none") + ".",
        "# " + VENDOR_LINE,
    ]
    body = yaml.safe_dump({"_format_version": "3.0", "plugins": plugins}, sort_keys=False, width=4096)
    path = yaml_path(doc)
    if plugins:
        install = [
            f"Add the plugin entry of {path} to your decK state, for example with deck file merge. Do not sync this "
            "file alone: deck gateway sync removes every entity that is not in the files it is given.",
            "Scope the plugin to your AI routes or services by adding a route: or service: key to the plugin entry.",
            "Run deck gateway diff, check the changes, then run deck gateway sync.",
        ]
        limits = [
            "The ai-prompt-guard plugin checks the prompts sent through Kong. It does not check tool results, so "
            "SW-GW-004 is enforced for prompts only.",
            "Org rules are matched against the prompt text. Their file patterns and the choice between lines and "
            "shell commands do not apply in Kong.",
            "The plugin is global in this file until you scope it to routes or services.",
            "The plugin holds at most 10 patterns of 500 characters. Spellwarden joins the patterns into as few "
            "entries as fit; org rules that do not fit are listed above as not enforced.",
        ]
    else:
        install = ["This export holds no plugin, so there is nothing to install."]
        limits = ["This pack enforces nothing in Kong: the plugins list is empty."]
    readme = readme_text(doc, target="kong", mode=None, built_at=built_at, enforced=enforced, cannot_enforce=cannot,
                         not_included=not_included, install=install, limits=limits)
    return {path: ("\n".join(header) + "\n" + body).encode("utf-8"), README_NAME: readme}


__all__ = ["FORBIDDEN", "MAX_PATTERNS", "MAX_PATTERN_CHARS", "OVERFLOW_REASON", "deny_patterns", "kong_files",
           "kong_pattern", "scoped", "yaml_path"]
