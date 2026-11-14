<!-- spellwarden-scan -->
**Spellwarden scan failed at high.** 5 findings (0 critical, 2 high, 2 medium, 1 low), 1 accepted.

| Severity | Rule | Location | Title |
|---|---|---|---|
| high | SW-CFG-005 | `.claude/settings.json:4` | Hook pipes remote content to a shell |
| high | SW-SKL-007 | `.claude/skills/deploy/scripts/setup.sh:2` | Remote script piped to a shell |
| medium | SW-A2A-002 | `.well-known/agent-card.json:1` | Agent card uses a format older than A2A 1.0 |
| medium | SW-CFG-003 | `.mcp.json:3` | MCP server launched from an unpinned package |
| low | SW-A2A-012 | `.well-known/agent-card.json:1` | Agent card is not signed |

**Instruction files:** 1 file scanned.

**A2A agent cards:**

| Agent | Origin | Card | Signature |
|---|---|---|---|
| `a2a-card:.well-known/agent-card.json` | repository, well\_known | format 0.3, protocol 0.3, migration to\_migrate | not signed |

`a2a-card:.well-known/agent-card.json`:
- 2. Move url, preferredTransport and additionalInterfaces into supportedInterfaces, each with url, protocolBinding and protocolVersion
- 3. Declare protocolVersion "1.0" on each interface, without a patch number
- 6. Rename security to securityRequirements, in the form {"schemes": {"name": {"list": \[scopes\]}}}, on the card and on each skill
- 7. Write each security scheme under its type key (apiKeySecurityScheme, httpAuthSecurityScheme, oauth2SecurityScheme, openIdConnectSecurityScheme, mtlsSecurityScheme) and rename in to location
- 11. Update the agent and its clients for the 1.0 protocol: PascalCase method names, SCREAMING\_SNAKE\_CASE enum values, the A2A-Version header, REST paths without /v1

1 accepted finding with its reasons is listed in the baseline file.

Spellwarden 1.13.0, rules 2026.11.6. [What each rule checks](https://github.com/spellwarden-ai/spellwarden#the-rules)
