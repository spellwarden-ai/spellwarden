"""The Zuplo export (Zuplo export spec 4.3): a TypeScript outbound policy for Zuplo's MCP Gateway (`zuplo_guard.GUARD_TS`,
the same bytes for every pack), a `policies.json` fragment that declares it with the pack's patterns in its options, a
dependency-free Node script that checks a Zuplo project is wired as the export requires, a README and `SHA256SUMS`.
SW-GW-004's nine injection patterns and the JavaScript form of every org pattern rule with the `zuplo` target are the
guard's `checks`. Pure: the files are returned as `{path: bytes}`. Nothing user-controlled reaches the TypeScript or
JavaScript files; a pack name, a rule title or a version reaches the JSON only as a string value and the README only
through `text.comment_safe`."""
from __future__ import annotations

import hashlib
import json
import re

from spellwarden_scan.exports import README_NAME, coverage, readme_text
from spellwarden_scan.exports.zuplo_guard import CHECK_MJS, GUARD_TS
from spellwarden_scan.orgrules import compile_pattern
from spellwarden_scan.packs import ENFORCEMENT_RULES, PackDocument
from spellwarden_scan.rules.patterns import INJECTION
from spellwarden_scan.version import RULES_VERSION, __version__

TARGET = "zuplo"
POLICY_NAME = "spellwarden-mcp-guard"
GUARD_PATH = "zuplo/modules/spellwarden-mcp-guard.ts"
POLICIES_PATH = "zuplo/config/spellwarden-policies.json"
CHECK_PATH = "zuplo/spellwarden-zuplo-check.mjs"
JS_REASON = "its pattern cannot be written for JavaScript"
SUMS_NAME = "SHA256SUMS"
MAX_BODY_BYTES = 1_048_576
_PUNCTUATION = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ")
_CLASS_ESCAPES = frozenset("sSdDwW")
_ESCAPES = _CLASS_ESCAPES | {"b"}
_QUANTIFIER = re.compile(r"\{[0-9]{1,3}(?:,[0-9]{1,3})?\}")


def _js_char(char: str, *, in_class: bool) -> str | None:
    """One literal character as JavaScript source without the `u` flag: ASCII as it is, any other character of the BMP
    as `\\uXXXX`, an astral character as its surrogate pair (never inside a class, where a pair would be two members)."""
    code = ord(char)
    if code < 0x80:
        return char
    if code <= 0xFFFF:
        return f"\\u{code:04X}"
    if in_class:
        return None
    code -= 0x10000
    return f"\\u{0xD800 + (code >> 10):04X}\\u{0xDC00 + (code & 0x3FF):04X}"


def _class(text: str, at: int) -> tuple[str, int] | None:
    """A bracket class starting at `text[at]`: its JavaScript source and the index after it."""
    out = ["["]
    index = at + 1
    if text[index:index + 1] == "^":
        out.append("^")
        index += 1
    members = 0
    while index < len(text):
        char = text[index]
        if char == "]":
            return ("".join(out) + "]", index + 1) if members else None
        if char == "[":
            return None
        if char == "\\":
            escaped = text[index + 1:index + 2]
            if escaped in _CLASS_ESCAPES or (escaped and escaped in _PUNCTUATION):
                out.append("\\" + escaped)
                index += 2
                members += 1
                continue
            return None
        if char == "-":
            out.append("-")
            index += 1
            members += 1
            continue
        piece = _js_char(char, in_class=True)
        if piece is None:
            return None
        out.append(piece)
        index += 1
        members += 1
    return None


def zuplo_part(source: str) -> str | None:
    """The JavaScript form of one emitted part of a pattern (`part.pattern`), or None when the part holds anything the
    token grammar of the spec does not name. Tokens: an escape (`\\` and ASCII punctuation or a space, or one of
    `\\s \\S \\d \\D \\w \\W \\b`), `.`, `^` first, `$` last, a bracket class, a quantifier (`*`, `+`, `?`, `{m}`,
    `{m,n}`; never two in a row), a group `(` or `(?:` with alternatives separated by `|`, and any other single
    character as a literal. A non-ASCII character is written as `\\uXXXX`; an astral character outside a class as its
    surrogate pair, inside a group of its own when a quantifier follows it, so that the quantifier repeats the character
    and not its second half."""
    out: list[str] = []
    depth = 0
    after_atom = False
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char == "\\":
            escaped = source[index + 1:index + 2]
            if escaped in _ESCAPES or (escaped and escaped in _PUNCTUATION):
                out.append("\\" + escaped)
                after_atom = escaped != "b"
                index += 2
                continue
            return None
        if char == "^":
            if index != 0:
                return None
            out.append("^")
            index += 1
            continue
        if char == "$":
            if index != length - 1:
                return None
            out.append("$")
            index += 1
            continue
        if char == "[":
            parsed = _class(source, index)
            if parsed is None:
                return None
            out.append(parsed[0])
            index = parsed[1]
            after_atom = True
            continue
        if char == "(":
            if source.startswith("(?", index):
                if not source.startswith("(?:", index):
                    return None
                out.append("(?:")
                index += 3
            else:
                out.append("(")
                index += 1
            depth += 1
            after_atom = False
            continue
        if char == ")":
            if depth == 0:
                return None
            depth -= 1
            out.append(")")
            index += 1
            after_atom = True
            continue
        if char == "|":
            if depth == 0:
                return None
            out.append("|")
            index += 1
            after_atom = False
            continue
        if char in "*+?":
            if not after_atom:
                return None
            out.append(char)
            index += 1
            after_atom = False
            continue
        if char == "{":
            match = _QUANTIFIER.match(source, index)
            if match is None or not after_atom:
                return None
            out.append(match.group(0))
            index = match.end()
            after_atom = False
            continue
        if char in "}]":
            return None
        piece = _js_char(char, in_class=False)
        if piece is None:
            return None
        if ord(char) > 0xFFFF:
            following = source[index + 1:index + 2]
            if following and (following in "*+?" or following == "{"):
                piece = "(?:" + piece + ")"
        out.append(piece)
        after_atom = True
        index += 1
    return "".join(out) if depth == 0 else None


def options_sha256(options: dict) -> str:
    """The SHA-256 of the canonical options, with `spellwarden.options_sha256` left out: `json.dumps(..., sort_keys=True,
    separators=(",", ":"), ensure_ascii=True)`. The check script computes the same text in JavaScript."""
    body = {**options, "spellwarden": {key: value for key, value in options["spellwarden"].items() if key != "options_sha256"}}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def _titles() -> dict[str, str]:
    return {rule.id: rule.title for rule in ENFORCEMENT_RULES}


def _org_checks(doc: PackDocument) -> tuple[list[dict], list[str]]:
    """`(checks, ids)` of the org rules with the `zuplo` target whose parts can be written for JavaScript, in pack order;
    `ids` are the rules that cannot."""
    checks: list[dict] = []
    refused: list[str] = []
    for spec in doc.org_rules:
        if TARGET not in spec.get("targets", ()):
            continue
        detection = spec["detection"]
        compiled = compile_pattern(detection["pattern"], case_sensitive=bool(detection.get("case_sensitive", False)))
        parts = [zuplo_part(part.pattern) for part in compiled.parts]
        if any(part is None for part in parts):
            refused.append(spec["id"])
            continue
        checks.append({"rule_id": spec["id"], "title": spec["title"], "parts": parts,
                       "flags": "" if compiled.case_sensitive else "i", "anchored_end": compiled.anchored_end})
    return checks, refused


def build_options(doc: PackDocument, *, built_at: str, checks: list[dict]) -> dict:
    """The `options` of the policy entry (spec 4.3), `options_sha256` set last."""
    options = {
        "spellwarden": {
            "format": 1, "pack_id": doc.pack_id, "pack": doc.name, "version": doc.version, "built_at": built_at,
            "engine": __version__, "rules_version": RULES_VERSION,
            "guard_sha256": hashlib.sha256(GUARD_TS.encode("ascii")).hexdigest(), "options_sha256": "",
        },
        "maxBodyBytes": MAX_BODY_BYTES,
        "onTooLarge": "block",
        "checks": checks,
        "deployChecks": {"SW-GW-003": True} if "SW-GW-003" in doc.enabled() else {},
    }
    options["spellwarden"]["options_sha256"] = options_sha256(options)
    return options


def policies_json(options: dict) -> bytes:
    entry = {
        "name": POLICY_NAME,
        "policyType": "custom-code-outbound",
        "handler": {"export": "default", "module": "$import(./modules/spellwarden-mcp-guard)", "options": options},
    }
    return (json.dumps({"policies": [entry]}, indent=2, ensure_ascii=True) + "\n").encode("ascii")


INSTALL = [
    "Copy `zuplo/modules/spellwarden-mcp-guard.ts` to the `modules/` folder of your Zuplo project.",
    "Add the entry of `zuplo/config/spellwarden-policies.json` to the `policies` array of `config/policies.json`, replacing "
    "an older entry named `spellwarden-mcp-guard`.",
    "Add `\"spellwarden-mcp-guard\"` as the last entry of `policies.outbound` of every MCP Gateway route (a route whose "
    "handler is `McpProxyHandler`), as in this route (the other keys are yours):\n\n"
    "       \"x-zuplo-route\": {\n"
    "         \"handler\": {\"export\": \"McpProxyHandler\", \"module\": \"$import(@zuplo/runtime/mcp-gateway)\", ...},\n"
    "         \"policies\": {\"inbound\": [...], \"outbound\": [\"spellwarden-mcp-guard\"]}\n"
    "       }\n\n"
    "   Add it to the routes with `mcpServerHandler` too when your API returns content that other people write.",
    "Copy `zuplo/spellwarden-zuplo-check.mjs` to the root of the project and run `node spellwarden-zuplo-check.mjs` in the "
    "pipeline before `zuplo deploy`, or as a required status check on the production branch. It needs Node 20 or later and "
    "prints one line for each route that is not wired as this export requires.",
    "Run `zuplo lint`, try the project with `zuplo dev`, then deploy.",
    "Requirements: Zuplo's MCP Gateway and `compatibilityDate` 2026-03-01 or later in `zuplo.jsonc` (a later date that Zuplo "
    "defines is fine). Zuplo's plans and limits are on https://zuplo.com/pricing and https://zuplo.com/docs/articles/limits.",
]
LIMITS = [
    "Only what MCP servers send is checked, not what the agent sends. JSON strings are checked as JSON decodes them, once: "
    "text that is itself JSON-encoded inside a string is not decoded again. Image and audio data and binary blobs are "
    "skipped only where MCP puts content (the content of a tool result or of a prompt message, the contents of a resource, "
    "an embedded resource); everywhere else every string is checked.",
    "Text is normalised before matching: invisible characters are removed and the text is NFKC-normalised. An org rule "
    "written to find invisible or compatibility characters never matches here.",
    "The patterns are the engine's, run as JavaScript regular expressions without the `u` flag. `.` and `{m,n}` count UTF-16 "
    "code units and `.` does not match U+2028 or U+2029; `\\s` does not match U+001C to U+001F or U+0085; `\\d`, `\\w` "
    "and `\\b` are ASCII; case folding is JavaScript's; windows count UTF-16 code units; and the guard and the scanner read "
    "their own Unicode tables. "
    "An org rule can miss a match longer than 512 characters that crosses a 4096-character window boundary, as in the hooks "
    "export.",
    "A response over `maxBodyBytes` (1 MiB; at most 16 MiB) is blocked unless `onTooLarge` is `allow`. A response that cannot "
    "be read as JSON or as an event stream, or that has an unsupported content encoding, is blocked. An error answer (a "
    "status that is not 2xx) whose body is not JSON is checked as one text, because MCP clients show that body to the "
    "agent; one that is not UTF-8 is blocked.",
    "Event streams are read until the response to the request, so progress notifications of a long tool call arrive with its "
    "result and notifications after it are dropped. A request that the server sends mid-call (sampling, elicitation) is "
    "refused with `server_request`.",
    "A blocked `initialize` answer makes that server unusable until the pack or the server changes. Text blobs must be "
    "standard base64.",
    "SW-GW-004 carries the scanner's nine injection patterns, not the tool-specific patterns of SW-MCP-011, so a tool "
    "description that the scanner flags only by those is not blocked here.",
    "The guard protects only the routes it is wired to, which the check script verifies. The check proves wiring, not that the "
    "files are the published pack's: compare `SHA256SUMS` with the files committed for the project.",
    "SW-GW-003 is enforced only as far as your pipeline runs the check script, and the check proves that the gateway is "
    "configured to use OAuth towards the upstream, not that the upstream requires it.",
    "There is no audit trail of tool calls (SW-OB-008).",
]


def _sums(files: dict[str, bytes]) -> bytes:
    return "".join(f"{hashlib.sha256(files[path]).hexdigest()}  {path}\n" for path in sorted(files)).encode("ascii")


def zuplo_files(doc: PackDocument, *, built_at: str) -> dict[str, bytes]:
    """The five files of the export of `doc` to Zuplo (spec 4.3), by archive path."""
    enforced, cannot, not_included = coverage(doc, TARGET)
    org_checks, refused = _org_checks(doc)
    enforced = [label for label in enforced if label.split(" ", 1)[0] not in refused]
    cannot = cannot + [(rule_id, JS_REASON) for rule_id in refused]
    checks: list[dict] = []
    if "SW-GW-004" in doc.enabled():
        title = _titles()["SW-GW-004"]
        checks += [{"rule_id": "SW-GW-004", "title": title, "parts": [zuplo_part(pattern.pattern)], "flags": "i",
                    "anchored_end": False} for pattern in INJECTION]
    checks += org_checks
    options = build_options(doc, built_at=built_at, checks=checks)
    readme = readme_text(doc, target=TARGET, mode=None, built_at=built_at, enforced=enforced, cannot_enforce=cannot,
                         not_included=not_included, install=INSTALL, limits=LIMITS)
    files = {
        GUARD_PATH: GUARD_TS.encode("ascii"),
        POLICIES_PATH: policies_json(options),
        CHECK_PATH: CHECK_MJS.encode("ascii"),
        README_NAME: readme,
    }
    files[SUMS_NAME] = _sums(files)
    return files


__all__ = ["CHECK_PATH", "GUARD_PATH", "JS_REASON", "POLICIES_PATH", "POLICY_NAME", "build_options", "options_sha256",
           "policies_json", "zuplo_files", "zuplo_part"]
