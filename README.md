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

Ids 016 to 018 and 020 to 030 are reserved. `RuleSet.baseline()` returns these rules; `ruleset.with_rules(extra)` adds your own `Rule` objects built with `spellwarden_scan.rules.make_rule`.

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

`PATH` (default `.`) is the scan root. Inside a git work tree the file set is what git tracks plus untracked files that are not ignored, under the scan root only (submodules are not entered); elsewhere it is a walk that skips `.git`, `node_modules`, `.venv`, `venv` and `__pycache__`. Symbolic links are never followed and files over 10 MiB are skipped, each with a notice. `include` and `exclude` in the settings narrow the set further.

In that set the scanner finds:

| Item | Where | Judged by |
|---|---|---|
| Skill | every directory holding a `SKILL.md`, with every file below it (a nested `SKILL.md` starts its own skill) | the `SW-SKL` rules |
| MCP client configuration | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`; each server in it is an item of its own | `SW-CFG-001` to `004`, `010`; `SW-MCP` rules under `--probe` |
| Claude Code settings | `.claude/settings.json`, `.claude/settings.local.json` (with their hooks) | `SW-CFG-005` to `008` |
| Plugin marketplace | `.claude-plugin/marketplace.json` and every plugin it lists | `SW-CFG-009`; a local plugin's skills, `.mcp.json`, `hooks/hooks.json` and `.claude-plugin/plugin.json` are scanned like the files above |

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

An entry accepts one finding, by fingerprint, from `added` to `expires`. It needs a reason, may last at most 365 days, and at most 30 days for a malicious-indicator rule (SW-SKL-004, SW-SKL-008, SW-CFG-006, SW-CFG-007). An invalid entry accepts nothing and fails the scan (exit 2); an expired one stops accepting, and the report says which entry expired on which date. Accepted findings stay in every report, marked as accepted with their reason. `spellwarden baseline add --all --reason "..."` accepts every current finding (90 days by default), `prune` removes entries that no longer match anything, `list` shows each entry's state.

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

`--probe-private` (or `SPELLWARDEN_PROBE_PRIVATE=true`) also allows private addresses, but only on a local run or on a CI run of a protected branch or tag that is not a pull or merge request; anywhere else it is ignored with the notice `probe_private_untrusted`, because whoever can push a revision controls the endpoints it names. It cannot be set in `.spellwarden/config.yml`.

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

The server keeps one row per hashed identity and ISO week: the number of runs, the first and last time seen, the last scanner and rules versions and the CI kind. It stores no IP address and no user agent; the rate limiter keeps the address for one hour. Rows are deleted after 400 days. No repository content is ever sent, and nothing is sent from a local run or by `lock`, `baseline`, `rules` or `version`.

Switch it off with any of: `--no-telemetry`, `SPELLWARDEN_TELEMETRY=off` (or `0`, `false`, `no`), `DO_NOT_TRACK=1`, `telemetry: false` in `.spellwarden/config.yml`, or the `telemetry: false` input of the Action or the GitLab component. A failed or slow ping never changes a report or an exit code.

### Schemas and compatibility

`schemas/` holds JSON Schemas (draft 2020-12) for the settings, the baseline, the lock file and the JSON report, including every closed list of values. Readers of the report must ignore fields they do not know; the settings and the baseline refuse them. From 1.0.0, removing or renaming a field or a value, or changing an exit code, is a major version; adding an optional field, a notice code or a rule is a minor one.

### Verifying a release

Every file on PyPI carries a PEP 740 attestation from trusted publishing, which names this repository and the release workflow:

```
pip download --no-deps spellwarden==0.3.0 -d dist/
pipx run pypi-attestations verify pypi --repository https://github.com/spellwarden-ai/spellwarden pypi:spellwarden-0.3.0-py3-none-any.whl
```

## Versions

`spellwarden_scan.__version__` is the package version and `spellwarden_scan.RULES_VERSION` (`YYYY.MM.N`) the rule set's. A change to what any rule detects bumps both the rules version and the package minor version; a fix anywhere else bumps the patch. Every scan result carries both, so a stored finding always says which rules produced it.

## Releases

Releases are built and published by GitHub Actions through PyPI trusted publishing (OpenID Connect): a push of a tag `vX.Y.Z` whose version equals the one in `pyproject.toml` builds the sdist and the wheel and publishes them from the `pypi` environment. No API token exists anywhere. The sources are checked on Python 3.11, 3.12 and 3.13 on Linux, and on Python 3.13 on macOS and Windows, on every push; every workflow is checked with `actionlint`.

## Development

```
make check     # ruff, pytest, uv build
```

`tests/test_pure.py` fails the build if any module of `spellwarden_scan` reaches for the network, the file system or the environment; `tests/test_network_boundary.py` fails it if any module of `spellwarden_cli` other than the prober's fetcher (`net.py`), the usage ping (`ping.py`) and the comment poster (`forge.py`) can reach the network; `tests/test_fixture_coverage.py` fails it if a rule lacks a positive or a negative fixture. Every test runs offline: HTTP exchanges are recorded under `tests/recorded/` and git repositories are made by the tests.

## License

Apache-2.0. See `LICENSE`.
