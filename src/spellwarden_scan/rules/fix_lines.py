"""1.21.0 (P6-15 spec 4.4): the setting lines a finding shows where its fix is a setting the engine can state exactly for every
finding of its row. Text to copy, never applied (O-6): fixed engine strings, never the scanned content, within the bounds of
spec 4.7 (`where` at most 80 characters, `text` at most 200 characters and 3 lines), checked at import.

Each row is a switch its server's own documentation names, read on the date beside it (`SOURCES`). A row the documentation
did not confirm on the day of the build writes no lines, and the rule's fix sentence alone serves it. On 2026-11-23 two rows of
spec 4.4 were not confirmed, so SW-CFG-013 writes no lines for them:

- the `@supabase/mcp-server-supabase` package and `"--read-only"`: neither the package's README
  (https://github.com/supabase-community/supabase-mcp) nor Supabase's MCP guide
  (https://supabase.com/docs/guides/getting-started/mcp) names the argument; the guide names only the hosted `read_only=true`;
- `kubernetes-mcp-server` and `"--read-only"`: its configuration changes page
  (https://github.com/containers/kubernetes-mcp-server/blob/main/docs/configuration-changes.md) lists `--read-only` among the
  dropped command-line flags (the TOML key `read_only` replaces it, v0.1.3).

A line follows the syntax of the document its finding is in (the owner's answer to plan Q2 of 1.21.0, 2026-11-23). The switch
of `mcp-server-kubernetes` therefore has two forms. `KUBERNETES_ENV` is a JSON member, as the server's README shows it, for a
server of a JSON document. `KUBERNETES_ENV_TOML` is a TOML key for a server of Codex's `config.toml`, the one TOML file the
scanner reads servers from: the same variable, in the form Codex's documentation gives for a server's environment variables (a
`[mcp_servers.<id>.env]` table of `KEY = "value"` lines; the row's `syntax` page). The value is the string `"true"`, since
Codex reads the table as a map of strings. `growth_cfg_013` picks the form by the document's path."""
from __future__ import annotations

from typing import NamedTuple

from spellwarden_scan.model import FixLines

CHECKED = "2026-11-23"
WHERE_MAX = 80
TEXT_MAX = 200
TEXT_LINES_MAX = 3

SUPABASE_HOSTED = FixLines("the query of the mcp.supabase.com address", "read_only=true")
KUBERNETES_ENV = FixLines("the server's env", '"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS": "true"')
KUBERNETES_ENV_TOML = FixLines("the server's env table", 'ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS = "true"')
A2A_PKCE = FixLines("the authorizationCode flow of the card's OAuth scheme", '"pkceRequired": true')
MCP_CIMD = FixLines("the authorization server's metadata", '"client_id_metadata_document_supported": true')


class Source(NamedTuple):
    rule_id: str
    lines: FixLines
    source: str   # the server's or the protocol's own documentation that names the switch
    checked: str  # the date it was read, YYYY-MM-DD
    syntax: str = ""  # where `source` shows the switch in another syntax: the page that gives this form, read the same day


SOURCES = (
    Source("SW-CFG-013", SUPABASE_HOSTED, "https://supabase.com/docs/guides/getting-started/mcp", CHECKED),
    Source("SW-CFG-013", KUBERNETES_ENV, "https://github.com/Flux159/mcp-server-kubernetes/blob/main/README.md", CHECKED),
    Source("SW-CFG-013", KUBERNETES_ENV_TOML, "https://github.com/Flux159/mcp-server-kubernetes/blob/main/README.md", CHECKED,
           syntax="https://learn.chatgpt.com/docs/extend/mcp"),
    Source("SW-A2A-006", A2A_PKCE, "https://github.com/a2aproject/A2A/blob/main/specification/a2a.proto", CHECKED),
    Source("SW-MCP-003", MCP_CIMD,
           "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration", CHECKED),
)

for _row in SOURCES:  # the bounds of spec 4.7, checked once at import
    if len(_row.lines.where) > WHERE_MAX or len(_row.lines.text) > TEXT_MAX or _row.lines.text.count("\n") >= TEXT_LINES_MAX:
        raise ValueError(f"{_row.rule_id}: setting lines over the bounds of P6-15 spec 4.7")

__all__ = ["A2A_PKCE", "KUBERNETES_ENV", "KUBERNETES_ENV_TOML", "MCP_CIMD", "SOURCES", "SUPABASE_HOSTED", "Source"]
