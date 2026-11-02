"""SW-CFG-012: MCP server configured to approve every tool call automatically.

Read over the servers of MCP client configurations (`.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, at any
depth; no other document kind) from `McpServerEntry.options`. A server fires, once per key and at the key's line,
when

* `default_tools_approval_mode` is `approve` (any case),
* a `tools` entry has `approval_mode` `approve` (any case),
* `autoApprove` or `alwaysAllow` is a non-empty array, or
* `trust` is `true`.

An empty array, a `prompt` value, a string where an array is expected and a key outside a server object are quiet.
Each server yields at most `_PER_SERVER` findings. The module is registered by the rule set, not here."""
from __future__ import annotations

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


def _approves(value: object) -> bool:
    return isinstance(value, str) and value.lower() == "approve"


def _triggers(options: dict) -> Iterator[tuple[str, str, int]]:
    """`(field, shown value, line)` for each option that approves calls without asking."""
    for key in _ARRAY_KEYS:
        option = options.get(key)
        if option and isinstance(option["value"], list) and option["value"]:
            yield key, f"{len(option['value'])} tool(s) listed", option["line"]
    option = options.get("trust")
    if option and option["value"] is True:
        yield "trust", "true", option["line"]
    option = options.get("default_tools_approval_mode")
    if option and _approves(option["value"]):
        yield "default_tools_approval_mode", "approve", option["line"]
    for key, option in options.items():
        if key.startswith("tools.") and key.endswith(".approval_mode") and _approves(option["value"]):
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
