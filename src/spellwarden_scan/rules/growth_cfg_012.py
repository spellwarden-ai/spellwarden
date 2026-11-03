"""SW-CFG-012: MCP server configured to approve every tool call automatically.

Read over the servers of MCP client configurations (`.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, at any
depth; no other document kind) from `McpServerEntry.options`. A server fires, once per key and at the key's line,
when

* `default_tools_approval_mode` is `approve` (any case),
* a `tools` entry has `approval_mode` `approve` (any case),
* `autoApprove` or `alwaysAllow` is a non-empty array, or
* `trust` is `true`.

An empty array, a `prompt` value, a string where an array is expected and a key outside a server object are quiet. A
per-tool `approve`, and an `autoApprove`/`alwaysAllow` list, are quiet when every tool they name is read-only by its
name: a read verb (`get`, `list`, `read`, `search`, `view`, `resize`, ...) and no verb that writes, runs or sends. A
wildcard and every server-wide setting fire as they are (gate 9.2: automatic approval of a viewport resize or a
documentation search is not the class).
Each server yields at most `_PER_SERVER` findings. The module is registered by the rule set, not here."""
from __future__ import annotations

import re
from collections.abc import Iterator

from spellwarden_scan.evidence import bounded_evidence, fingerprint
from spellwarden_scan.model import Finding, Location

RULE_ID = "SW-CFG-012"
TITLE = "MCP server configured to approve every tool call automatically"
SEVERITY = "high"
OWASP = ("ASI02",)
NIST = ("AC-6", "CM-7")
MALICIOUS = False

_PER_SERVER = 20
_ARRAY_KEYS = ("autoApprove", "alwaysAllow")
_READ_VERBS = frozenset({"get", "list", "read", "search", "find", "view", "show", "describe", "lookup", "status", "info",
                         "inspect", "resize", "screenshot", "count", "ping", "version", "help"})
_ACTING = frozenset({
    "write", "create", "update", "delete", "remove", "rm", "exec", "execute", "run", "send", "post", "put", "set", "install",
    "kill", "deploy", "push", "commit", "move", "mv", "rename", "drop", "insert", "upload", "shell", "eval", "edit", "patch",
    "apply", "merge", "click", "type", "navigate", "submit", "pay", "transfer", "sign", "approve", "fetch", "browse",
    "open", "call", "invoke", "start", "stop", "wipe", "erase", "destroy", "purge", "reset", "terminate", "grant",
    "revoke", "modify", "change", "replace", "save", "store", "add", "append", "attach", "assign", "enable", "disable",
    "publish", "schedule", "trigger", "launch", "spawn", "restart", "reboot", "shutdown", "format", "truncate", "clear",
    "cancel", "close", "accept", "reject", "login", "logout", "auth", "token", "key", "secret", "password", "credential",
    "email", "mail", "message", "tweet", "order", "buy", "sell", "trade", "swap", "withdraw", "deposit", "mint", "burn",
    "command", "cmd", "script", "terminal", "sql", "query", "mutate", "mutation", "sync", "import", "export", "download",
})
_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")


def _read_only(tool: object) -> bool:
    """A tool whose name has a read verb and no verb that writes, runs, sends or fetches (`search_docs`, `getStatus`,
    `browser_resize`); a wildcard, a non-string and anything else may act."""
    if not isinstance(tool, str) or "*" in tool or not tool.isascii() or len(tool) >= 200:
        return False  # fail closed: a wildcard, an over-long or non-ASCII name may act
    words = [word.lower() for word in _WORDS.findall(tool)]
    # The name must start with a read verb (`get_status`, `browser_resize` names its object first: one leading noun is
    # allowed) and hold no word that writes, runs, sends, fetches or touches secrets.
    return bool(words) and (words[0] in _READ_VERBS or (len(words) > 1 and words[1] in _READ_VERBS)) and not set(words) & _ACTING


def _approves(value: object) -> bool:
    return isinstance(value, str) and value.lower() == "approve"


def _triggers(options: dict) -> Iterator[tuple[str, str, int]]:
    """`(field, shown value, line)` for each option that approves calls without asking."""
    for key in _ARRAY_KEYS:
        option = options.get(key)
        if option and isinstance(option["value"], list) and option["value"]:
            if not option.get("cut") and all(_read_only(tool) for tool in option["value"]):
                continue
            yield key, f"{len(option['value'])} tool(s) listed", option["line"]
    option = options.get("trust")
    if option and option["value"] is True:
        yield "trust", "true", option["line"]
    option = options.get("default_tools_approval_mode")
    if option and _approves(option["value"]):
        yield "default_tools_approval_mode", "approve", option["line"]
    for key, option in options.items():
        if key.startswith("tools.") and key.endswith(".approval_mode") and _approves(option["value"]):
            if not option.get("dropped") and _read_only(key[len("tools."):-len(".approval_mode")]):
                continue
            yield key, "approve", option["line"]


def detect(config) -> Iterator[Finding]:
    # Imported here, not at the top: rules/config.py will import this module to register it (import cycle).
    from spellwarden_scan.rules.config import config_matched

    for doc, entry in config.servers():
        if doc.kind != "mcp":
            continue
        for index, (field, shown, line) in enumerate(_triggers(entry.options)):
            if index >= _PER_SERVER:
                break
            matched = config_matched("server", entry.name, field, shown)
            yield Finding(RULE_ID, SEVERITY, TITLE, Location(doc.path, line),
                          bounded_evidence(f"{entry.name}: {field} = {shown}"), fingerprint(RULE_ID, doc.path, matched),
                          MALICIOUS)
