# Changelog

## 1.3.0 (RELEASE_DATE)

A2A agent cards: the scanner reads the agent cards of a repository and, with `--probe`, the cards of remote agents, and
checks them against A2A 1.0. A repository with no file named like a card and no `a2a` setting is scanned as 1.2.1 scanned
it: every output is equal apart from the two version strings (the rules version is `2026.10.4`), the eighteen new rules in
the SARIF rule table and in `spellwarden rules`, and the index each SARIF result takes into that table. A look-alike file
(`.well-known/agent.json` or another file named `agent-card.json` that is not a card) adds the notice `a2a_not_card` and
nothing else.

- Eighteen rules, `SW-A2A-001` to `SW-A2A-018` (README, "Checking A2A agent cards"). These can fail a build at the default
  `--fail-on high`: `SW-A2A-004` (an endpoint or authentication URL over plain HTTP), `SW-A2A-005` (an OAuth implicit or
  password flow), `SW-A2A-010` (a signature that does not verify), `SW-A2A-011` (a malformed signature or a refused
  algorithm), `SW-A2A-014` (injected instructions or hidden characters in the card's text), `SW-A2A-018` (a card at a
  `.well-known/agent-card.json` path or in `a2a.cards` that cannot be read, including a symbolic link that leaves the scan
  root or points at nothing, reported as `unsafe_path`, and a file the system refuses to read, `unreadable`) and, at critical, `SW-A2A-015` (a credential in
  the card). A baseline accepts any of them, `exclude` leaves a tree of broken sample cards out, and none of them can make
  a run exit 2.
- Findings on a remote agent's card are reported and uploaded but do not count toward the exit code of a pull or merge
  request; on every other run they count.
- The settings file gains `a2a: {cards, keys, agents}`. On a pull or merge request `a2a.keys`, the keys file and
  `a2a.agents` are read from the base revision, even under `--config`. A key file that is present and is not a key set is
  `settings_invalid` (exit 2).
- Signatures are verified with the `cryptography` package, the scanner's first compiled dependency (imported by one module,
  `spellwarden_cli/jws.py`): ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, Ed25519 and EdDSA with an
  Ed25519 key. The report says which key verified a signature, the trusted key file or the key set the card names, and
  which members the matching form does not cover (`unsigned_members`). A legacy 0.x member, or a member spelled with its
  proto field name (`security_requirements`, which protobuf readers also accept), that the signature does not cover makes
  it invalid (`SW-A2A-010`). Install
  needs a `cryptography` wheel: Linux (glibc and musl, x86_64 and aarch64), macOS and Windows. The Action runs on the Python
  3.11 to 3.14 its pinned `cffi` has wheels for.
- The report gains an optional `agents` list (written only when a card was read or fetched), nine notice codes
  (`a2a_not_card`, `a2a_cards_limit`, `a2a_agents_need_probe`, `a2a_fetch_failed`, `a2a_signature_unverified`,
  `a2a_keys_unavailable`, `a2a_keys_missing`, `a2a_key_without_kid`, `a2a_private_key_in_jwks`) and the rule-id pattern
  `^SW-(SKL|MCP|CFG|REG|A2A|ORG)-[0-9]{3}$`. Connected mode uploads the A2A findings and the agents reduced to nine fields.
- `--probe` also fetches the key sets that signed repository cards name and the cards of the agents `a2a.agents` lists,
  under the one budget of the probe phase (300 requests and 120 seconds, MCP servers first). The probe phase is now a list
  of typed tasks; the MCP probe is unchanged.
- The usage ping carries a sixth field, `a2a`: true when the run checked at least one agent card. No card, URL or count is
  sent; the privacy policy names it.
- `spellwarden_scan` gains `parse_agent_card`, `evaluate_agent_card`, `signature_inputs`, `a2a_checklist`,
  `jcs_canonicalize` (RFC 8785; `canonical_json` and `canonical_sha256` are not) and the data classes they use. The strict
  JSON reader of the configuration files is shared (`spellwarden_scan._json`) and behaves as before for them.
- Compatibility: a 1.2.x scanner refuses a settings file with an `a2a` mapping (`settings_invalid`, unknown key) and a
  baseline file with an `SW-A2A` entry, as it would any later key or rule; a team that runs two scanner versions against one
  repository must upgrade both. Organisation rules cannot map to the new OWASP and NIST tags (`ASI03`, `ASI07`, `SC-8`,
  `SI-7`) or target the `a2a` area in this release.

## 1.2.1 (2026-10-23)

- Connected mode on a runner without an IPv6 route: the resolver now lists the IPv4 addresses of a host before
  the IPv6 ones. The connection is pinned to the first resolved address and never falls back to another, and a plain
  string sort could put a `2600:` address ahead of a `3.` one, so the exchange with dash.spellwarden.ai failed with
  `connected_unavailable` on GitHub-hosted runners whenever the CDN's rotation returned such a set. Free mode is
  unchanged; no output changes.

## 1.2.0 (2026-10-23)

Connected mode: the `spellwarden` command can link a scan to a Spellwarden organisation. Without a credential, without
`SPELLWARDEN_ORG` and without `connected.required`, nothing connected happens and every output is what 1.1.1 wrote, apart
from the rules version, the three gate rules in the SARIF rule table and in `spellwarden rules`, and the index each SARIF
result takes into that table. The rules version is `2026.10.3`; the 1.0.0 golden files are unchanged.

- Connected mode (README, "Connected mode"). `SPELLWARDEN_ORG` with the OIDC token of GitHub Actions (or
  `SPELLWARDEN_ID_TOKEN`, for GitLab's `id_tokens`), or a CI key in `SPELLWARDEN_API_KEY`. The organisation's CI policy
  decides the rules or the policy pack the run applies, the registry gate checks the run against the private registry,
  and the results are uploaded in CI. The settings file gains `connected: {pack, upload, required}`; `--upload` and
  `--no-upload`, `SPELLWARDEN_UPLOAD`, `SPELLWARDEN_DEFAULT_BRANCH`, `SPELLWARDEN_RUN_ID` and the test hook
  `SPELLWARDEN_API_URL` are new. A credential is never a flag or a setting, is read once, printed as `***`, removed from the
  environment and never written to an output, a notice or an upload body.
- The registry gate: three rules, `SW-REG-001` (a skill package, plugin or marketplace the registry does not admit),
  `SW-REG-002` (an MCP server it does not admit) and `SW-REG-003` (content it cannot judge: `unhashable`, `unresolved`,
  `insecure`, `unpinned`, `unknown_launcher`, `launch_override`, `resolver_override`), severity high. A request is judged on
  what it adds or changes; the default-branch run judges everything. A finding may be accepted in the baseline for at most
  90 days, and on a request only by the base revision's baseline.
  An option the scanner does not know before the package makes the launch `unresolved`, the names of an entry's `env` keys
  (never their values) enter its identity, and `--userconfig` and its relatives (`uvx --config-file`, `pipx run --pip-args` among them) are launch overrides. The README lists, per launcher, every option accepted before the package or image, and every environment
  variable name that is a launch override; a test keeps those lists equal to the scanner's.
- The engine: `spellwarden_scan.identity` (package hashes, normalised server addresses, pinned command identities,
  plugin and marketplace identities, resolver files), `spellwarden_scan.gate`, `SkillScanResult.package_sha256`,
  `org_rule_min_version` and `PREDICATE_SINCE`. Claude Code settings are parsed for `extraKnownMarketplaces` and
  `enabledPlugins` as inventory, and the rule-id grammar is `SW-(SKL|MCP|CFG|REG|ORG)-NNN`. The archive reader ignores
  `__MACOSX/` entries and `.DS_Store` files before it looks for a common top directory.
  A package hash leaves out `.git/`, `__MACOSX/`, any `.DS_Store` and, at the top of the package, `.spellwarden/lock.json`,
  `.spellwarden/config.yml` and `.spellwarden/baseline.yml`; every other path under `.spellwarden/` is hashed.
- The report gains an optional `connected` block, `upload_truncated` and `upload_truncated_fields`; the notice codes
  `connected`, `connected_fallback`, `dependabot_free_mode`, `fork_free_mode`, `api_url_override`, `reg_baseline_from_base`,
  `gate_scope_all`, `org_rules_skipped`, `plugin_marketplace_unknown`, `uploaded`, `upload_failed`, `upload_skipped`,
  `upload_ci_only`, `upload_disabled`, `registry_gate_off`, `mcp_rules_need_probe` and `policy_newer_than_scanner`; and
  the error codes `connected_config`, `connected_key_invalid`, `connected_no_credential`, `connected_auth`,
  `connected_subscription`, `connected_ci_key_required`, `connected_forbidden`, `connected_rate_limited`,
  `connected_unavailable`, `connected_required`, `policy_not_found`, `policy_invalid`, `org_rules_incomplete`,
  `registry_check_failed` and `registry_check_too_large`. Exit codes do not change.
- `spellwarden baseline`: `add` takes `--rule SW-REG-NNN|SW-ORG-NNN` and `--finding-path PATH` with a fingerprint from a
  connected report; `list` shows such an entry as `connected` (a fifth state next to active, expired, invalid and
  unmatched); `prune` keeps it until it has expired and 30 more days, since these commands scan without a connection.
- The command: `api.py` is the fourth module that reaches the network (the Spellwarden API, the code host's token
  endpoint, a proxy from `HTTPS_PROXY`); `net.Fetcher.get` takes `redirects=`. The CI context gains the repository, commit,
  branch, run link and default branch, and `ci-run gitlab` maps `SW_ORG` and `SW_UPLOAD`.
- Releases: `release.yml` runs the built wheel against a loopback fake of the service (`fixtures/ci/fake_api.py`) with a CI
  connection and with a CI key before it publishes.
- The README: "Connected mode", the rules table's three new rows, and the Action and the component releasing at the
  engine's version again.

## 1.1.1 (2026-10-22)

A fix release of the MCP prober: no rule, fingerprint, report or command changes. The rules version stays `2026.10.2`.
The baseline pack document names this engine version, so its SHA-256 changes; its eight rules do not.

- The prober sends the protocol version the server negotiated in `initialize` on every later request
  (`MCP-Protocol-Version`, MCP 2025-06-18). It sent its own version, `2025-11-25`, and a server that negotiated an
  older one refused `tools/list` with `400 Unsupported protocol version` (seen with the AWS MCP server on
  2026-10-22), so no tool list was recorded for such servers. `server/discover` keeps `2026-07-28`.

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
