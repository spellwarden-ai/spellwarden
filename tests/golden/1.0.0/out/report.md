<!-- spellwarden-scan -->
**Spellwarden scan failed at high.** 2 findings (0 critical, 2 high, 0 medium, 0 low), 1 accepted.

| Severity | Rule | Location | Title |
|---|---|---|---|
| high | SW-CFG-008 | `.claude/settings.json:2` | Settings switch off approval prompts |
| high | SW-SKL-007 | `.claude/skills/deploy/SKILL.md:13` | Remote script piped to a shell |

1 accepted finding with its reasons is listed in the baseline file.

Spellwarden 1.0.0, rules 2026.10.2. [What each rule checks](https://github.com/spellwarden-ai/spellwarden#the-rules)
