<!-- spellwarden-scan -->
**Spellwarden scan failed at high.** 4 findings (0 critical, 3 high, 1 medium, 0 low), 0 accepted.

| Severity | Rule | Location | Title |
|---|---|---|---|
| high | SW-CFG-013 | `.mcp.json:3` | Database or cluster MCP server with write access although a read-only mode exists |
| high | SW-CFG-013 | `.mcp.json:4` | Database or cluster MCP server with write access although a read-only mode exists |
| high | SW-CFG-013 | `.mcp.json:5` | Database or cluster MCP server with write access although a read-only mode exists |
| medium | SW-SKL-009 | `skills/report/SKILL.md:13` | Unpinned dependency install |

**How to fix**

- **SW-CFG-013** Add the server's read-only switch, and give write access to a separate entry that stays disabled until the work needs it. [Rule page](https://spellwarden.ai/docs/rules/sw-cfg-013?utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix)
  - In the query of the mcp.supabase.com address, write: `read_only=true`
  - In the server's env, write: `"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS": "true"`
- **SW-SKL-009** Pin each install to an exact version, for example package==1.4.2 for pip, and add a lock file or hashes where the tool supports them. [Rule page](https://spellwarden.ai/docs/rules/sw-skl-009?utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix)

Spellwarden 1.21.0, rules 2026.11.8. [What each rule checks](https://github.com/spellwarden-ai/spellwarden#the-rules)
