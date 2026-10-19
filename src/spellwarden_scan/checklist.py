"""The migration checklist (spec 5.8): twelve items in a fixed order, each
present when its condition holds, the last one always. Empty for stdio."""
from __future__ import annotations

from spellwarden_scan.model import ChecklistItem, McpScanResult

SPEC_BASELINE = "2026-07-28"

ITEMS: tuple[tuple[str, str], ...] = (
    ("streamable_http", "Move to streamable HTTP"),
    ("server_discover", "Add `server/discover`"),
    ("remove_sessions", "Remove sessions"),
    ("meta_version", "Carry the protocol version and capabilities in `_meta` on each request"),
    ("sampling_to_mrtr", "Replace `sampling/createMessage` with an `input_required` result"),
    ("logging_to_meta", "Replace Logging with a per-request `_meta` log level"),
    ("tasks_extension", "Move long jobs to the Tasks extension"),
    ("oauth_cimd", "Register a Client ID Metadata Document and enable OAuth with RFC 9728 Protected Resource Metadata "
                   "and RFC 8707 resource indicators"),
    ("validate_iss", "Validate `iss`"),
    ("list_ttl", "Set `ttlMs` and `cacheScope` on list results"),
    ("traceparent", "Propagate `traceparent` in `_meta`"),
    ("rescan", "Re-run the Spellwarden scan"),
)


def migration_checklist(result: McpScanResult) -> tuple[ChecklistItem, ...]:
    """The public one-argument generator (spec 5.2): everything it needs is on the result
    (`evaluate_probe` fills `list_meta_missing`, `long_running_tools`, `tasks_supported`,
    `issuer_problem`), so a stored result reproduces its checklist without the probe."""
    if result.transport == "stdio":
        return ()
    deprecated = set(result.deprecated_features)
    version = result.spec_version
    below = version is not None and version < SPEC_BASELINE
    unknown = version is None
    needs_oauth = result.auth_mode in ("none", "static-key", "oauth-dcr", "unknown")
    conditions = {
        "streamable_http": "sse" in deprecated,
        "server_discover": "initialize_only" in deprecated or below,
        "remove_sessions": "sessions" in deprecated,
        "meta_version": below or unknown,
        "sampling_to_mrtr": "sampling" in deprecated,
        "logging_to_meta": "logging" in deprecated,
        "tasks_extension": bool(result.long_running_tools) and not result.tasks_supported,
        "oauth_cimd": needs_oauth,
        "validate_iss": needs_oauth or result.issuer_problem,
        "list_ttl": below or result.list_meta_missing,
        "traceparent": below,
        "rescan": True,
    }
    return tuple(ChecklistItem(order, key, text) for order, (key, text) in enumerate(ITEMS, start=1) if conditions[key])
