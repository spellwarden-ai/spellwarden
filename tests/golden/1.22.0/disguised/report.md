<!-- spellwarden-scan -->
**Spellwarden scan failed at high.** 6 findings (5 critical, 1 high, 0 medium, 0 low), 0 accepted.

| Severity | Rule | Location | Title |
|---|---|---|---|
| critical | SW-SKL-004 | `SKILL.md:26` | Encoded payload decoded and executed |
| critical | SW-SKL-032 | `SKILL.md:16` | Instructions lure the user into running a password-protected download or a pasted script |
| critical | SW-SKL-032 | `SKILL.md:17` | Instructions lure the user into running a password-protected download or a pasted script |
| critical | SW-SKL-032 | `SKILL.md:21` | Instructions lure the user into running a password-protected download or a pasted script |
| critical | SW-SKL-032 | `SKILL.md:26` | Instructions lure the user into running a password-protected download or a pasted script |
| high | SW-SKL-007 | `SKILL.md:26` | Remote script piped to a shell |

**How to fix**

- **SW-SKL-004** Write the command out in plain text where a reviewer can read it, and remove the step that decodes and runs it. [Rule page](https://spellwarden.ai/docs/rules/sw-skl-004?utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix)
- **SW-SKL-007** Download the script to a file and check it against a published checksum before you run it, or install the tool from a package manager at a pinned version. [Rule page](https://spellwarden.ai/docs/rules/sw-skl-007?utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix)
- **SW-SKL-032** Remove the download and the pasted script, and name the tool by its package so the user installs it from a package manager or the vendor's site. [Rule page](https://spellwarden.ai/docs/rules/sw-skl-032?utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix)

**Description lint (informational, never changes the exit code):** 2 notes. [What each check means](https://spellwarden.ai/docs/activation-checks?utm_source=scanner&utm_medium=cli&utm_campaign=description-lint)

| Skill | Check | Note |
|---|---|---|
| `.` | SW-LINT-002 | The description has no use-when clause ("use when", "use this when", "when the user" or "triggers on"), so an agent has to guess when the skill applies. |
| `.` | SW-LINT-003 | The description names no trigger phrase: no quoted phrase and no list of requests, so an agent has few words to match a request against. |

Spellwarden 1.22.0, rules 2026.11.9. [What each rule checks](https://github.com/spellwarden-ai/spellwarden#the-rules)
