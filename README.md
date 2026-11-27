# spellwarden

The Spellwarden scan engine: the baseline rules for agent skills, MCP servers and A2A agent cards, the probe classification against the 2026-07-28 MCP specification, the migration checklist and the curation score. It is the engine of the hosted product at [spellwarden.ai](https://spellwarden.ai) and is published so that the same rules run in your own tooling.

## What it checks and what it does not

It checks agent content before that content is installed, merged or served:

- skills (`SKILL.md` packages), Claude Code plugin marketplaces, settings and hooks, MCP client configurations, instruction files such as `AGENTS.md` and `CLAUDE.md`, and A2A agent cards, with [the rules](#the-rules) in the table below, each mapped to the OWASP lists for agents and MCP, NIST SP 800-53 and MITRE ATLAS;
- remote MCP servers against the 2026-07-28 specification, when you ask for it with [`--probe`](#probing---probe);
- the agent configuration of a workstation, with [`scan --user`](#scanning-a-workstation): Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex and Gemini CLI;
- each skill with a model you choose, when you ask for it with [`--analyze`](#model-assisted-analyzer---analyze): your own endpoint and key, or a local server. Its verdicts are advisory and never change the exit code.

It does not:

- sit in the path while an agent runs. It reads no tool call and no tool result. A policy pack [exports](#exports) to Claude Code hooks, Kong, Zuplo, ToolHive and Docker MCP Gateway, and each export lists what that target enforces;
- look for MCP servers declared in program code, or look up known vulnerabilities of dependencies. It flags installs without a pinned version;
- make a passed scan a promise of safety. A passed scan means that no rule found a problem. Content the scanner leaves unread ends the scan as incomplete, never as a pass ([Limits](#limits)).
- understand what text means. Rules match patterns; text written another way can pass them. See [Disguised content](#disguised-content).

The scanner, its rules, the GitHub Action and the GitLab CI component ([Use it in CI](#use-it-in-ci)) and the [pre-commit hook](#pre-commit-hook) are free under Apache-2.0 and run on your machine or runner. The hosted product at spellwarden.ai is a paid subscription with a 14-day trial; it runs the same engine.

More: [what Spellwarden checks and what it does not](https://spellwarden.ai/docs/scope?utm_source=github&utm_medium=readme&utm_campaign=scope) and [questions and answers](https://spellwarden.ai/docs/faq?utm_source=github&utm_medium=readme&utm_campaign=faq).

One distribution holds two import packages. `spellwarden_scan` is the engine and is pure code: it never opens a connection, reads a file or an environment variable; you hand it the bytes of a package, a configuration file or the recorded result of a probe, and it hands back findings. `spellwarden_cli` is the `spellwarden` command: it finds the agent content in a repository, runs the engine on it on your machine or CI runner, and writes the reports. The GitHub Action and the GitLab CI component that run the command in pipelines arrive with 1.0.0.

```
pipx run spellwarden scan .          # or: pip install spellwarden, then spellwarden scan .
```

Python 3.11 or newer. The runtime dependencies are PyYAML and `cryptography`, which verifies the signatures on A2A agent cards.

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
- `unpack_zip(data, limits=ArchiveLimits(), with_modes=False, root="")` reads a zip held in memory and refuses unsafe archives with an `ArchiveError` whose `code` is one of `too_large`, `too_many_files`, `unsafe_path`, `symlink`, `bad_zip`, `empty`; since 1.23.0 its `why` names the case where a code has several, and is `""` otherwise. The default limits are 20 MiB compressed, 50 MiB uncompressed, 2000 files, 10 MiB per file, 255 characters a path and, since 1.23.0, 100,000 entries in the whole archive (`max_entries`), counted as the central directory headers the archive's bytes hold before any is parsed: over it is `too_many_files` with `why` `archive_entries`. Since 1.23.0 the path bound is measured on the path inside the archive's top directory, the path in the repository; before, a forge's top directory of 54 characters counted too. `REPOSITORY_LIMITS` (since 1.23.0) holds the same limits with 50 MiB compressed, for a repository's archive read under a named `root`. With a non-empty `root` (the skill's directory inside a larger repository archive) the file-count, size, link and unsafe-name rules apply only to the entries under `root`; every other entry is skipped unread and is not returned, and an archive with no file under `root` is `empty`. The limits on the compressed size and on the entries of the whole archive always apply, and so does the rule that no entry's path passes through a link. `root=""` and `root=None` check the whole archive. Since 1.23.0 a symbolic link under `root` is read when its target, judged from its text alone, is a regular file inside the tree (the directory `root` names; the whole archive for `""` and `None`): the link's path holds the target's bytes, executable when the target is, and the target's size counts again toward the 50 MiB uncompressed. Every other link is `symlink`, and its `why` says why: `outside` (the target leaves the tree, even when a later segment comes back in), `dangling` (no entry of that exact name, or a text that walks through a file or a name the archive does not hold, such as `missing/../x.md`), `chain` (a link to a link, a loop among them), `directory`, `through_link`, or `unsafe_target` (absolute, a drive, a backslash, a NUL, an empty segment or one of only dots and spaces, not UTF-8, empty or over 4,096 bytes); a device, FIFO or socket is `symlink` with `why` `special`. Up to 1.22.0 every link under `root` was `symlink`. `list_zip(data, limits=REPOSITORY_LIMITS)` (since 1.23.0) returns the names of every file and link of an archive from its central directory alone, opening no entry, with only the checks of the whole archive: the compressed size, the entries, `bad_zip`, an unsafe raw name and a path through a link.
- `scan_skill_package(..., kind="skill")` runs every rule. `kind="instructions"` scans instruction files that have no `SKILL.md` (`AGENTS.md`, agent prompts, agent memory) with every rule except the two `SKILL.md` structure rules, SW-SKL-015 and SW-SKL-031. Any other `kind` raises `ValueError`.
- `result.sha256` is the canonical hash of the package: SHA-256 over `path NUL content NUL` for every path in sorted order, stable across archive layout.
- `result.metadata` holds `name`, `description`, `version`, `license`, `publisher` from the frontmatter (nested `metadata:` keys and `author` are read too), which of them are present, and the problems that rule SW-SKL-015 reports.
- `max_findings` (500) and `max_per_rule` (100) bound what the scan keeps; rules run worst severity first and `result.truncated` counts the matches that were not kept.
- `deadline` (since 1.24.0; keyword-only, default `None`) is a `Deadline`, made with `Deadline.after(seconds)` and shared by every package of a scan. When its clock reaches it the call raises `TimeLimit`, which names the file being read (`path`, or `None`) and the stage (`stage`: `before`, `reading`, `normalising` or `judging`), and returns nothing for that package: the findings found so far are dropped with it, so a package that was not read whole never looks like a pass. The clock is read before each file, each view and each rule and once for every 64 KiB of line text; the default clock is `time.monotonic`, and `Deadline(at, clock)` takes your own. Without `deadline` nothing changes. The other entry points take none, because what they read is bounded already: `scan_agent_config` (documents of at most 1 MiB), `evaluate_agent_card`, `evaluate_probe` (the probe's own budget), `unpack_zip` and `list_zip` (`ArchiveLimits`). An entry point that reads content of unbounded size takes a deadline.
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

`ProbeResult` is the record of an unauthenticated probe: the `server/discover` or `initialize` result, the status and content type of the POST and GET, whether a session header was seen, the `tools/list` answer, the RFC 9728 protected resource metadata and the authorization server metadata. Since 1.13.0 it also records, for a server that declares the capability, the server's prompts, resources and resource templates (names, titles, descriptions, prompt argument names and descriptions and resource addresses, never their contents) and the server's own `instructions` (at most 16,000 characters). Each list holds at most 200 entries, read over its pages since 1.16.1 (the probe follows `nextCursor`, at most 10 pages of one list), with a completeness flag (`prompts_complete`, `resources_complete`, `resource_templates_complete`), and `lists_read` names the lists the server answered; a field that holds its default is left out of `to_dict`, so a server that declares neither capability and sends no instructions serialises as before. SW-MCP-011 and the organisation-rule check `tool_description_matches` read these texts as well, and a finding names its place in `location.path`: `prompt:<name>`, `resource:<uri>`, `resource_template:<uriTemplate>` or `server_instructions`. The classification follows one rule set:

- transport: `streamable-http`, `sse`, `stdio` (a repository without an endpoint) or `unknown`;
- authentication: `none`, `static-key`, `oauth-dcr`, `oauth-cimd`, `xaa` or `unknown`;
- spec version: the highest `supportedVersions` date of `server/discover`, else the negotiated `initialize` version;
- deprecated features, in a fixed order: `sse`, `initialize_only`, `sessions`, `roots`, `sampling`, `logging`, `dcr`;
- `migration_status`: `ready` when the spec version is 2026-07-28 or later, authentication is CIMD or XAA and nothing deprecated is in use; `to_migrate` otherwise; `not_probeable` for stdio servers.

The checklist has twelve items in a fixed order, each present only when it applies (move to streamable HTTP; add `server/discover`; remove sessions; carry the protocol version and capabilities in `_meta`; replace `sampling/createMessage` with an `input_required` result; replace Logging with a per-request `_meta` log level; move long jobs to the Tasks extension; register a Client ID Metadata Document and enable OAuth with RFC 9728 and RFC 8707; validate `iss`; set `ttlMs` and `cacheScope` on list results; propagate `traceparent`; re-run the scan, which is always last).

### Tool lists and SW-MCP-012

Since 1.15.0 `spellwarden_scan.toolhash` computes one canonical listing of what a probe read. `listing_of(probe)` returns a `ToolListing`, or None when the probe read nothing, with one hash per item (a tool's name, description and input schema; a prompt's name, title, description and arguments; a resource's or resource template's address, name, title and description; the server's instructions), one hash per kind (`tools`, `prompts`, `resources`, `resource_templates`, `instructions`) and a `digest` for the whole. The order the server sent does not matter: an item hash is the SHA-256 of `spellwarden-tool-item-v1`, a NUL byte and the RFC 8785 JSON of the item's fields; a kind hash is the SHA-256 of the RFC 8785 JSON of the sorted list of item keys and item hashes; the digest is the SHA-256 of the RFC 8785 JSON of `{"format": 1, "kinds": {kind: kind hash}}`. Tool annotations are not hashed.

The only whitespace the hash ignores is in descriptions, titles and the instructions: line endings (`\r\n` and `\r` read as `\n`), spaces and tabs at the end of a line, the leading and trailing whitespace of the whole text and the Unicode NFC form. These differ between server frameworks, operating systems and serialisers without any change of meaning, and a hash that saw them would raise findings nobody could act on. Spaces inside a line, blank lines inside a text, letter case and every other character count, because an instruction can hide in them. Names, addresses and address templates are compared exactly, and input schemas as RFC 8785 JSON, so key order and the spelling of a number do not matter. A schema RFC 8785 refuses, such as one with `"maximum": 9223372036854775807`, and a schema nested deeper than 128 levels of objects and arrays are hashed as their sorted-key JSON text, where `1.0` and `1` differ, and a lone surrogate in any text is read as U+FFFD: no server can make the hash fail. The hash covers each text as the probe kept it, so a change past one of the probe's cuts is not seen.

`to_json()` and `ToolListing.from_json(data)` store and read a listing; `diff(baseline, listing)`, `change_details`, `adopt` and `carry` compare, show and merge two of them. `evaluate_probe(probe, rules, baseline=Baseline(kinds, listing, approved_at), listing=None, pinned=False)` compares the probe's listing, or the `listing` given, with an approved one and raises SW-MCP-012 once per item: added (medium), removed (low) or changed (high when `pinned` says the server is one the organisation relies on, medium otherwise). The evidence shows the old and the new text from just before their first difference, at most 120 characters a side; the fingerprint is over the old and new item hashes, so the same change keeps its fingerprint and a new change gets a new one. In a list the server sent only in part, or in which the probe cut a text at its cap, an item present on both sides is compared, an item present now is an addition only when the approved list held every entry, and an item missing now is a removal only when the current list holds every entry (a list missing entries proves that an item exists, never that it is gone; a cut text does not make an entry missing); a list the baseline has and the probe did not read is not compared, and an approved list whose stored copy is gone gives one finding at `server_tools`. Without `baseline` nothing changes: the result is the one 1.14.0 gave. The hosted product keeps each server's approved list and passes it in. The scanner never raises SW-MCP-012, since a remote server must not be able to fail a build: it pins the kind hashes in the lock file instead (see "The lock file"). To resolve a finding, review the changes, then approve the new list or remove the server from your agents.

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

Ids are `SW-SKL-NNN` (skill packages), `SW-MCP-NNN` (probed MCP servers), `SW-CFG-NNN` (agent configuration files: MCP client configurations, Claude Code settings and hooks, plugin marketplaces), `SW-REG-NNN` (the registry gate of connected mode) and `SW-A2A-NNN` (A2A agent cards). Mappings use the OWASP Agentic Top 10 (ASI) and OWASP MCP Top 10 (MCP) identifiers, NIST SP 800-53 base controls (labelled as a provisional mapping to SP 800-53 base controls), MITRE ATLAS technique ids (the ATLAS column; release 2026.10, data format 6.1.0; an empty cell means no technique fits the rule) and OWASP Agentic Skills Top 10 ids (the AST column; version 1.0, 2026 edition, an OWASP incubator project under public review). The mapping, with its sources and the reason for every empty ATLAS cell, is in [docs/frameworks.md](docs/frameworks.md); the JSON report carries each finding's tags and `spellwarden rules --format json` each rule's. Five rules are malicious indicators: an open finding from one of them quarantines the package.

<!-- rules:start -->
| Id | Title | Severity | OWASP | NIST | ATLAS | AST |
|---|---|---|---|---|---|---|
| SW-SKL-001 | Prompt-injection phrases in skill instructions | high | ASI01 | SI-10 | AML.T0051.001, AML.T0110.000 | AST05 |
| SW-SKL-002 | Hidden text: zero-width or bidirectional control characters | high | ASI01 | SI-10 | AML.T0068, AML.T0110.000 | AST05 |
| SW-SKL-003 | Instructions to skip approvals or disable hooks | high | ASI10 | AC-6 | AML.T0081 | AST03 |
| SW-SKL-004 | Encoded payload decoded and executed (malicious indicator) | critical | ASI04 | SR-3 | AML.T0011.002 | AST01 |
| SW-SKL-005 | Writes to agent configuration | high | ASI10 | AC-6 | AML.T0081 | AST03 |
| SW-SKL-006 | Destructive command without a confirmation step | medium | ASI10 | AC-6 | AML.T0101 |  |
| SW-SKL-007 | Remote script piped to a shell | high | ASI04, MCP04 | SR-3 | AML.T0010.005 | AST02 |
| SW-SKL-008 | Sends local file contents to an external host (malicious indicator) | critical | ASI10 | SC-7 | AML.T0086, AML.T0037 | AST01 |
| SW-SKL-009 | Unpinned dependency install | medium | ASI04, MCP04 | SR-3 | AML.T0010.005 | AST02, AST07 |
| SW-SKL-010 | Bundled binary or executable file | medium | ASI04 | SR-3 | AML.T0011.001 | AST02 |
| SW-SKL-011 | Hard-coded credential in the package | critical | MCP01 | IA-5 | AML.T0055 |  |
| SW-SKL-012 | Reads a credential file path without stating purpose | medium | ASI04 | IA-5 | AML.T0098 |  |
| SW-SKL-013 | Network calls to raw IP addresses or URL shorteners | medium | ASI10 | SC-7 | AML.T0025 |  |
| SW-SKL-014 | Obfuscated script code | medium | ASI04 | SR-3 | AML.T0011.001 |  |
| SW-SKL-015 | Frontmatter missing or invalid (name, description) | low | ASI04 | SR-3 |  | AST04 |
| SW-SKL-019 | Fetches external URL content into context without an allowlist | medium | ASI01, MCP06 | SI-10 | AML.T0051.001 | AST05 |
| SW-SKL-031 | Missing license and version metadata | low | ASI04 | SR-3 |  | AST04 |
| SW-SKL-032 | Instructions lure the user into running a password-protected download or a pasted script (malicious indicator) | critical | ASI04, ASI09 | SR-3, SI-3 | AML.T0011 | AST01 |
| SW-SKL-036 | Frontmatter pre-approves an unscoped shell or interpreter | medium | ASI02, ASI03 | AC-6, CM-7 | AML.T0053 | AST03 |
| SW-SKL-037 | Executable downloaded from a moving reference and run without an integrity check | medium | ASI04, ASI05, MCP04 | SR-3, SI-7 | AML.T0010.005, AML.T0109 | AST02, AST07 |
| SW-MCP-001 | Server lists tools without authentication | high | MCP07 | AC-3 | AML.T0084.001, AML.T0132 |  |
| SW-MCP-002 | Static key authentication instead of OAuth | medium | MCP01, MCP07 | IA-5 |  |  |
| SW-MCP-003 | OAuth dynamic client registration (deprecated; use Client ID Metadata Documents) | medium | MCP07 | IA-5 |  |  |
| SW-MCP-004 | HTTP+SSE transport (deprecated) | medium | ASI04 | SR-3 |  |  |
| SW-MCP-005 | Spec version older than 2026-07-28 | low | ASI04 | SR-3 |  |  |
| SW-MCP-006 | Protocol sessions (Mcp-Session-Id) in use | medium | ASI04 | SR-3 |  |  |
| SW-MCP-007 | Requires the initialize handshake; no server/discover | medium | ASI04 | SR-3 |  |  |
| SW-MCP-008 | Uses deprecated Roots, Sampling or Logging | medium | ASI04 | SR-3 |  |  |
| SW-MCP-009 | Endpoint not served over HTTPS | high |  | SC-7 |  |  |
| SW-MCP-010 | No protected resource metadata, or issuer not validated | medium | MCP07 | IA-5 |  |  |
| SW-MCP-011 | MCP server text contains instruction-like text | high | ASI01, MCP03 | SI-10 | AML.T0110.000, AML.T0051.001 |  |
| SW-MCP-012 | MCP server's tools changed since they were approved | high | ASI04, MCP03 | SI-7 | AML.T0109, AML.T0110.000 |  |
| SW-MCP-013 | Tool takes a command line to run as an argument | medium | ASI05, MCP05 | SI-10 | AML.T0053 |  |
| SW-CFG-001 | Remote MCP server over plain HTTP | high |  | SC-7 |  |  |
| SW-CFG-002 | Credential written into an MCP server configuration | critical | MCP01, MCP07 | IA-5 | AML.T0055, AML.T0083 |  |
| SW-CFG-003 | MCP server launched from an unpinned package | medium | ASI04, MCP04 | SR-3 | AML.T0010.005 | AST02, AST07 |
| SW-CFG-004 | MCP server at a raw IP address or behind a URL shortener | medium | ASI10 | SC-7 | AML.T0010.005 |  |
| SW-CFG-005 | Hook pipes remote content to a shell | high | ASI04 | SR-3 | AML.T0142 |  |
| SW-CFG-006 | Hook sends local file contents to an external host (malicious indicator) | critical | ASI10 | SC-7 | AML.T0142, AML.T0086 |  |
| SW-CFG-007 | Hook decodes and runs an encoded payload (malicious indicator) | critical | ASI04 | SR-3 | AML.T0142, AML.T0011.001 |  |
| SW-CFG-008 | Settings switch off approval prompts | high | ASI10 | AC-6 | AML.T0081 |  |
| SW-CFG-009 | Marketplace plugin source not pinned to a commit | medium | ASI04, MCP04 | SR-3 | AML.T0010.005, AML.T0109 | AST02, AST07 |
| SW-CFG-010 | Literal value under a secret name in an MCP server configuration | high | MCP01, MCP07 | IA-5 | AML.T0083 |  |
| SW-CFG-012 | MCP server configured to approve every tool call automatically | high | ASI02 | AC-6, CM-7 | AML.T0053 |  |
| SW-CFG-013 | Database or cluster MCP server with write access although a read-only mode exists | high | ASI03, MCP02 | AC-3, AC-6 | AML.T0053 |  |
| SW-CFG-015 | MCP server given the whole home directory or the filesystem root | high | ASI03, MCP02 | AC-6 | AML.T0053 |  |
| SW-REG-001 | Skill package not admitted in the organisation's private registry | high | ASI04 | SR-3 | AML.T0010.005 | AST09 |
| SW-REG-002 | MCP server not admitted in the organisation's private registry | high | MCP09 | SR-3 | AML.T0010.005 | AST09 |
| SW-REG-003 | Agent content the private registry cannot judge | high | ASI04 | SR-3 | AML.T0010.005 | AST09 |
| SW-A2A-001 | Agent card does not follow A2A 1.0 | medium | ASI07 | SI-10 |  |  |
| SW-A2A-002 | Agent card uses a format older than A2A 1.0 | medium | ASI07 | SI-10 |  |  |
| SW-A2A-003 | Agent card at the path used before A2A 0.3 | medium | ASI07 | SI-10 |  |  |
| SW-A2A-004 | Agent endpoint or authentication URL not served over HTTPS | high | ASI07 | SC-8 |  |  |
| SW-A2A-005 | OAuth implicit or password flow declared (deprecated in A2A 1.0) | high | ASI03 | IA-5 |  |  |
| SW-A2A-006 | OAuth authorization code flow without PKCE required | medium | ASI03 | IA-5 |  |  |
| SW-A2A-007 | Agent declares no authentication | medium | ASI03 | AC-3 | AML.T0132 |  |
| SW-A2A-008 | API key sent in the URL query | medium | ASI03 | IA-5 | AML.T0055 |  |
| SW-A2A-009 | Skill inherits every scope of the agent | low | ASI03 | AC-6 |  |  |
| SW-A2A-010 | Agent card signature does not verify | high | ASI07 | SI-7 | AML.T0074 |  |
| SW-A2A-011 | Agent card signature is malformed or uses a refused algorithm | high | ASI07 | SI-7 | AML.T0074 |  |
| SW-A2A-012 | Agent card is not signed | low | ASI07 | SI-7 | AML.T0074 |  |
| SW-A2A-013 | Signing key not bound to the card's host | medium | ASI07 | SI-7 | AML.T0074 |  |
| SW-A2A-014 | Agent card text contains injected instructions or hidden characters | high | ASI01 | SI-10 | AML.T0051.001, AML.T0110.000 |  |
| SW-A2A-015 | Credential in the agent card | critical | ASI03 | IA-5 | AML.T0055 |  |
| SW-A2A-016 | Agent card fetched through a redirect to another host | medium | ASI07 | SC-8 | AML.T0074 |  |
| SW-A2A-017 | Agent card signed with a shared secret that only the agent can check | medium | ASI07 | SI-7 | AML.T0074 |  |
| SW-A2A-018 | Agent card cannot be read | high | ASI07 | SI-10 |  |  |
| SW-A2A-019 | Agent card member spelled two ways | high | ASI07 | SI-10 |  |  |
<!-- rules:end -->

SW-REG-001 to SW-REG-003 are the registry gate of connected mode (Enterprise). They fire only in a connected run.

The severity in the table is each rule's worst case. Since 1.9.0 two MCP rules grade a finding by what the probe saw. SW-MCP-001 is low when the server answered `tools/list` without authentication with no tool, medium when every listed tool declares itself read-only (`readOnlyHint` true and `destructiveHint` not true; a hint the server writes, so never lower than medium), and high otherwise; only a list the probe read whole is graded, so an unreadable answer, a page the probe did not read (since 1.16.1 it follows `nextCursor` up to 10 pages), more than 200 tools or a pasted list stays high. SW-MCP-011 is medium when a tool description only steers the model towards the tool (such as an order to put it before any other tool, or "IMPORTANT: ... you must") and high for concealment, override or injected instructions, or when the steering text also names conversation, prompt or credential material. Since 1.11.0 SW-MCP-011 reads descriptions with their whitespace collapsed, and the patterns 1.11.0 narrowed, unchanged since, need the words that make them an instruction: "hidden" only as hidden instructions, prompts, commands or directives, "keep this hidden" or hidden from the person using it; the negations (do not, don't, never) with "mention, reveal, show, tell or disclose" only as whole words aimed at the user, the tool itself or the instructions, or "mention" and "reveal" followed by "the", "this", "that", "it", "them", "any", "your" or "these"; "IMPORTANT:" with ignore, override or disregard (high) or with a "must" aimed at the model or a tool in the same sentence (medium, high with conversation or credential words or a secret file path such as `id_rsa` or `mcp.json`). Descriptions such as "includes hidden files", "the key is never shown again" and "IMPORTANT: the date must be ISO 8601" do not match. Since 1.12.0 the rule also reads other wordings beside those patterns. As steering (medium): the tool first in every session, conversation or task or before anything else, or a "START HERE" banner in capitals; a required check before a whole class of actions or before answering ("before sending any payment, call this tool"), also after "IMPORTANT:"; broad triggers ("use this tool proactively", "call this whenever possible"); claims that the model's own knowledge is outdated or must not be used; a ban on working something out by hand; the tool ranked above web search, built-in tools or rivals; paid offers slipped into the answer. As concealment (high): a negated "mention", "reveal", "disclose", "divulge" or "acknowledge", or "tell" or "show" with the user as the object, about the tool's own calls, steps, checks, instructions, partners or sources ("never reveal which partner supplied the item"); keeping the tool's internals out of what the user sees; acting without telling the user. A finding that only these steering forms make is high when the description asks for conversation, prompt or credential material outside the words the form matched. No description is graded lower than in 1.11.1, and an ordinary line added before or after a description never lowers its finding, except when it is glued on with no character between, or only an invisible one, so that two words merge. The evidence text, and so the fingerprint, is unchanged, so baselines and accepted findings carry over. In SARIF a result's `level` is its own severity; the rule's `security-severity`, which code scanning on the forge shows, stays that of the worst case. Since 1.13.0 the rule is titled "MCP server text contains instruction-like text" and also reads the prompts, resources, resource templates and instructions a probed server advertises; in those four places only the injection and concealment forms apply, never the steering forms (a prompt or the server's instructions exist to steer a model), and the rule's precision there has not been measured: the figures in the changelog are for tool descriptions.

Since 1.22.0 the skill rules SW-SKL-001, SW-SKL-003, SW-SKL-004, SW-SKL-005, SW-SKL-006, SW-SKL-007, SW-SKL-008, SW-SKL-009, SW-SKL-012, SW-SKL-013, SW-SKL-014, SW-SKL-019, SW-SKL-032 and SW-SKL-037 also read a normalised copy of the text, so that the same content written another way is still found. The steps, in this order: HTML character references such as `&#110;` are read as their character, a reference to a line break left as written; zero-width and other format characters are removed; compatibility forms such as full-width letters, ligatures and compatibility spaces are folded with Unicode NFKC; look-alike letters of the Cyrillic, Greek, Armenian and Latin extended blocks are folded to the ASCII letter they look like, in words that hold an ASCII letter or only such letters; each run of spaces and tabs inside a line, and each tab, becomes one space; base64 text of 16 characters or more is decoded, up to three layers, and the decoded text is read as part of the line it came from. The text as written is still matched first, exactly as 1.21.0 matched it, and a normalised reading only adds findings: a finding is added only at a line where the same rule found nothing in the text as written. The evidence of an added finding starts with "Matched after normalising:" and quotes the line as written, and its fingerprint is computed from the line as written, so a baseline written before keeps working and shows an added finding as new. Every other skill rule (SW-SKL-002, SW-SKL-010, SW-SKL-011, SW-SKL-015, SW-SKL-031 and SW-SKL-036) reads the text as written only. Normalisation follows the Unicode version of the Python that runs the scanner. A library caller passes `normalise=False` to `scan_skill_package` for the reading of 1.21.0. [Disguised content](#disguised-content) says what is measured and what stays out of reach.

The numbers SW-SKL-016 to 018, SW-SKL-020 to 030, SW-SKL-033 to 035, SW-CFG-011 and SW-CFG-014 are reserved and unused, and so is SW-SKL-038: its rule was built and withdrawn by the count gate (2 flagged of 18,789 files, from 2 components) before it was released (see [Rules measured on a set of their own](#rules-measured-on-a-set-of-their-own)). A rule id is never reused or renamed, and the id of a retired rule stays reserved as well (see [Schemas and compatibility](#schemas-and-compatibility)). Retired rules: none. `RuleSet.baseline()` returns these rules; `ruleset.with_rules(extra)` adds your own `Rule` objects built with `spellwarden_scan.rules.make_rule`.

### Rules measured on a set of their own

A rule that is not a skill rule, or whose question the labels "malicious" and "benign skill" do not answer, is measured on a set of its own before it is released, by the method in [benchmarks/README.md](benchmarks/README.md#rules-measured-on-a-set-of-their-own). The set is never published, because it holds third-party text; this table is the record of what it gave: the size of the set, the units the frozen rule flagged that were scored (the half kept back for scoring, or the whole frame when too few units were flagged to split it), its precision with the 95% Wilson interval, its recall with its interval, the severity the precision gives and what the rule does not see. A rule whose precision does not reach the medium bar is not released.

<!-- measured-sets:start -->
| Rule | Set | Flagged units scored | Precision | Recall | Severity | Measured | What it does not see |
|---|---|---|---|---|---|---|---|
| SW-CFG-015 | 9,859 units of public MCP client configuration files | 22 (whole frame) | 100.0% (85.1% to 100.0%) | 66.1% (47.0% to 84.8%) | high | 2026-11-26 | It does not see what a server does with the folder it is given, a grant made outside the arguments a client file holds, or every environment variable. The set was scored whole: no part of it was held out, and the rule was not tuned on it. The two labellers' agreement was reported and not used as a gate at stage 1, because fewer than 30 units carried both labellers' labels there. The set is a random sample of the public files that GitHub code search lists under these file names. |
| SW-MCP-013 | 210,994 units of public tool lists of remote MCP servers | 54 (whole frame) | 66.7% (53.4% to 77.8%) | 13.1% (7.2% to 20.8%) | medium | 2026-11-26 | It does not see injection through an argument of a tool that runs a fixed program, whether a server filters the command, servers that run as local processes, or code interpreters whose parameter is code. The set was scored whole: no part of it was held out, and the rule was not tuned on it. |

SW-SKL-038 was withdrawn by the count gate before release: 2 flagged units from 2 components, where 60 and 20 were needed; its id stays reserved.

SW-CFG-015 was first measured on a split design and withdrawn by the count gate: 22 flagged units from 16 components, where 60 and 20 were needed.

SW-MCP-013 was first measured on a split design and withdrawn by the count gate: 54 flagged units from 47 components, where 60 and 20 were needed.
<!-- measured-sets:end -->

## Measured rates

What the rules find on fixed public sets of malicious and harmless skills, measured again for every release by the release workflow. Rules only: no model is called. A skill is found when the rules report at least one finding at or above the line (medium or above, or high or above, the lines `--fail-on` and the presets use), at each rule's own severity (no preset). A rate counts skills, with its 95% Wilson interval. Skills the scanner could not read whole are counted apart, never as found and never as clean. A set of four skills is too small for a rate: each of its skills is shown as found or not found. Only the 20 skill rules can be measured on skills; the MCP, configuration, registry and A2A rules are not measured here, and a rule that is not measured on skills is measured on [a set of its own](#rules-measured-on-a-set-of-their-own) before it is released. Each release also measures disguised versions of the malicious skills (look-alike letters, hidden characters, encoding, joined strings, padding, markup and a word-list translation), with the rules on the text as written and after normalisation; see [Disguised content](#disguised-content). The full table per rule and per stratum, every release so far and the ids of the malicious skills the rules missed are in [benchmarks/RESULTS.md](benchmarks/RESULTS.md); how to run it yourself, the sources and their licences are in [benchmarks/README.md](benchmarks/README.md). The same table, release by release, is at
[spellwarden.ai/research/rule-benchmark](https://spellwarden.ai/research/rule-benchmark?utm_source=github&utm_medium=readme&utm_campaign=rule-benchmark).

<!-- benchmark:start -->
| Set | Skills | Line | Detection | False positives | Not read whole |
|---|---|---|---|---|---|
| Held-out half of Spellwarden's labelled set | 163 | medium or above | 54.7% (29 of 53; 41.5% to 67.3%) | 29.1% (32 of 110; 21.4% to 38.2%) | 0 |
|  |  | high or above | 37.7% (20 of 53; 25.9% to 51.2%) | 6.4% (7 of 110; 3.1% to 12.6%) | 0 |
| MaliciousSkillBench test split (source-disjoint) | 1384 | medium or above | 36.1% (303 of 839; 32.9% to 39.4%) | 26.6% (145 of 545; 23.1% to 30.5%) | 0 |
|  |  | high or above | 3.8% (32 of 839; 2.7% to 5.3%) | 9.7% (53 of 545; 7.5% to 12.5%) | 0 |
| Tuning half of Spellwarden's labelled set (tuning) | 170 | medium or above | 47.5% (29 of 61; 35.5% to 59.8%) | 34.9% (38 of 109; 26.6% to 44.2%) | 0 |
|  |  | high or above | 23.0% (14 of 61; 14.2% to 34.9%) | 6.4% (7 of 109; 3.1% to 12.7%) | 0 |

Trail of Bits scanner-bypass skills, medium or above: found `m-tob-csv-summarizer`, `m-tob-dev-env-setup`, `m-tob-simple-formatter`; not found `m-tob-context-loader`.
Trail of Bits scanner-bypass skills, high or above: not found `m-tob-context-loader`, `m-tob-csv-summarizer`, `m-tob-dev-env-setup`, `m-tob-simple-formatter`.

Disguised samples, medium or above, rules on the text as written and after normalisation:

| Samples | Held-out half of Spellwarden's labelled set | MaliciousSkillBench test split (source-disjoint) | Tuning half of Spellwarden's labelled set (tuning) |
|---|---|---|---|
| plain samples | as written 54.7% (29 of 53), normalised 54.7% (29 of 53) | as written 36.0% (302 of 839), normalised 36.1% (303 of 839) | as written 47.5% (29 of 61), normalised 47.5% (29 of 61) |
| look-alike letters | as written 52.8% (28 of 53), normalised 52.8% (28 of 53) | as written 35.3% (296 of 839), normalised 36.1% (303 of 839) | as written 44.3% (27 of 61), normalised 45.9% (28 of 61) |
| zero-width characters inside words | as written 100.0% (53 of 53), normalised 100.0% (53 of 53) | as written 100.0% (839 of 839), normalised 100.0% (839 of 839) | as written 100.0% (61 of 61), normalised 100.0% (61 of 61) |
| one encoding layer | as written 83.0% (44 of 53), normalised 83.0% (44 of 53) | as written 88.2% (740 of 839), normalised 89.2% (748 of 839) | as written 82.0% (50 of 61), normalised 82.0% (50 of 61) |
| two encoding layers | as written 83.0% (44 of 53), normalised 83.0% (44 of 53) | as written 88.2% (740 of 839), normalised 89.2% (748 of 839) | as written 82.0% (50 of 61), normalised 82.0% (50 of 61) |
| strings joined at run time | as written 45.5% (20 of 44), normalised 45.5% (20 of 44) | as written 30.0% (218 of 727), normalised 30.0% (218 of 727) | as written 50.0% (24 of 48), normalised 50.0% (24 of 48) |
| padding | as written 52.8% (28 of 53), normalised 54.7% (29 of 53) | as written 12.2% (102 of 839), normalised 36.1% (303 of 839) | as written 41.0% (25 of 61), normalised 47.5% (29 of 61) |
| markup tricks | as written 54.7% (29 of 53), normalised 54.7% (29 of 53) | as written 35.6% (299 of 839), normalised 36.0% (302 of 839) | as written 45.9% (28 of 61), normalised 45.9% (28 of 61) |
| word-list translation | as written 54.7% (29 of 53), normalised 54.7% (29 of 53) | as written 35.6% (299 of 839), normalised 35.8% (300 of 839) | as written 47.5% (29 of 61), normalised 47.5% (29 of 61) |

SW-SKL-002, SW-SKL-004 and SW-SKL-014 report the disguise itself (a hidden character, a decode-and-run line), so a row can be high as written while the other rules no longer see the content: [benchmarks/RESULTS.md](benchmarks/RESULTS.md) shows every row without those three rules, as written and normalised.

Trail of Bits scanner-bypass skills, disguised, medium or above: one encoding layer found 3 of 4 as written, 3 of 4 normalised; two encoding layers found 3 of 4 as written, 3 of 4 normalised; strings joined at run time found 3 of 3 as written, 3 of 3 normalised; look-alike letters found 3 of 4 as written, 3 of 4 normalised; markup tricks found 3 of 4 as written, 3 of 4 normalised; padding found 3 of 4 as written, 3 of 4 normalised; word-list translation found 3 of 4 as written, 3 of 4 normalised; zero-width characters inside words found 4 of 4 as written, 4 of 4 normalised.

Held-out half of Spellwarden's labelled set: Normalisation adds no finding on harmless skills.

MaliciousSkillBench test split (source-disjoint): Normalisation adds no finding on harmless skills.

Tuning half of Spellwarden's labelled set: Normalisation adds no finding on harmless skills.

Scanner 1.25.0, rules version 2026.11.10, released 2026-11-27.
<!-- benchmark:end -->

### Disguised content

A rule that reads text as written can be avoided by writing the text another way. Since 1.22.0 the rule benchmark measures that: a generator turns each malicious skill of its sets into disguised versions, one per technique (look-alike letters, zero-width characters inside words, one and two layers of base64 encoding, strings joined at run time, padding, markup tricks and a word-list translation into Spanish), and the skill rules scan each version with the text as written and after normalisation. The versions exist only in memory and are never written, printed or run; the generator is seeded, so every run builds the same bytes. The table above shows the detection per technique at medium or above; [benchmarks/RESULTS.md](benchmarks/RESULTS.md) shows both lines, the counts and every row without SW-SKL-002, SW-SKL-004 and SW-SKL-014, and [benchmarks/README.md](benchmarks/README.md#disguised-samples) says how each technique works and what its numbers do and do not show.

SW-SKL-002, SW-SKL-004 and SW-SKL-014 report a disguise itself: a hidden character, a decode-and-run line, obfuscated script code. So the rows for zero-width characters and for encoding are high as written for that reason, whatever the content, and the columns without those three rules show whether the other rules still see the content.

What stays out of reach of the rules, as written or normalised: strings joined at run time, markup tricks that are not character references (comments and emphasis inside words), other languages, base64 wrapped over several lines, more than three encoding layers, other encodings (hex, gzip, rot13 and so on), look-alike letters outside the table, and meaning that no pattern names. Normalisation only takes steps that cannot hide content, so it never removes markup or joins strings. Look-alike letters are folded with a table written for the common Cyrillic, Greek, Armenian and Latin letters; it covers every letter the generator uses, so the look-alike row shows that the folding works on that set, not that every look-alike is caught. Meaning is the job of the model-assisted analyzer ([`--analyze`](#model-assisted-analyzer---analyze)), whose rates are not published yet: its verdicts say "Unmeasured model".

## Org rules, packs and exports

Since 1.1.0 the engine also holds what the hosted product calls Ward: rules an organisation writes as data (org rules), policy packs, and the exports that turn a pack into enforcement for Claude Code hooks, Kong and Zuplo. All of it is pure, like the rest of the engine. In connected mode the command applies the organisation's CI policy (see Connected mode).

### Org rules

An org rule is a JSON object that `validate_org_rule(spec)` checks and `compile_org_rule(spec)` turns into a `Rule` that `RuleSet.with_rules` accepts. A refused spec raises `OrgRuleError` with a `code` (`bad_id`, `bad_title`, `bad_severity`, `bad_area`, `bad_mapping`, `bad_target`, `bad_detection`, `bad_glob`, `pattern_too_long`, `pattern_syntax`, `pattern_too_complex`, `bad_predicate`, `bad_values`, `unknown_key`) and a one-sentence `message` that names the position of a pattern error.

- `id` is `SW-ORG-001` to `SW-ORG-999`; `title` 1 to 120 characters on one line; `severity` `critical`, `high`, `medium` or `low`; `owasp` and `nist` at most five identifiers each from the lists the baseline rules use; `malicious` (only with `critical`) makes a finding quarantine the package, as the baseline's malicious indicators do; unknown keys are refused.
- `area` `skill` takes a pattern detection: `{"kind": "pattern", "files": "**/*.sh", "in": "commands", "pattern": "...", "case_sensitive": false}`. `files` is a path glob inside the skill (`*`, `?` and `[...]` within one folder, `**` for any number of folders; default `**`). `in` is `lines` (every line of every selected text file, the default) or `commands` (every shell command of the selected scripts and of the fenced code blocks of the selected Markdown files, with `\`, `|`, `&&` and `||` continuations joined, which is what a Claude Code hook sees as a Bash command). One finding per matching line or command.
- `area` `mcp` takes one of eight server checks: `{"kind": "probe", "predicate": "auth_mode_in", "values": ["none", "static-key"]}`. The predicates are `auth_mode_in`, `transport_in`, `deprecated_feature_any`, `spec_version_below` (also true when the version is unknown), `endpoint_host_in` and `endpoint_host_not_in` (lower-case host names, or `*.example.com` for every subdomain, which does not match `example.com` itself), and `tool_name_matches` and `tool_description_matches`, which take a `pattern` and give one finding per tool at `tool:<name>`. A stdio server has no endpoint and is judged by `transport_in` and the two tool checks only.
- `targets` names the exports that enforce the rule: `claude-code-hooks` (a pattern rule with `"in": "commands"`), `kong` and `zuplo` (any pattern rule; a pattern the Zuplo guard cannot write for JavaScript is listed as not enforced there). A server check has no target. The target `zuplo` is read by engines from 1.6.0; the hosted product leaves it out of the policy it serves to an older scanner.

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

| Id | Rule | Enforced by (1.15.0) |
|---|---|---|
| `SW-HK-001` | Block remote scripts piped to a shell in agent shell tools | Claude Code hooks |
| `SW-HK-002` | Block reads of credential files (`~/.aws`, `~/.ssh`, `.env`) | Claude Code hooks |
| `SW-GW-003` | Deny MCP upstreams without OAuth | Not enforced by an export in this version (needs Kong's MCP plugins); the Zuplo export includes a script that checks it at deploy when your pipeline runs it |
| `SW-GW-004` | Prompt-injection deny patterns on prompts and tool results | Kong, prompts only; Zuplo, MCP server responses; Docker MCP Gateway, tool results |
| `SW-EG-005` | Sandbox egress only to registry-admitted hosts | Not enforced by an export in this version |
| `SW-GW-006` | Destructive tool verbs require human approval | Claude Code hooks (asks for approval); ToolHive and Docker MCP Gateway (deny: the gateway cannot ask a person) |
| `SW-RG-007` | Registry admits only curated, auth-enabled entries on spec 2026-07-28 with no open critical or high finding | The hosted private registry's admission policy, not an export |
| `SW-OB-008` | Emit an audit record for every tool call | Not enforced: the Claude Code export writes a local activity log, which is not an audit trail |

"Enforced" means enforced where the export is deployed in a way the developer cannot change: for Claude Code that is the managed mode below.

### Exports

`build_export(pack, target, built_at=..., mode=...)` returns the files of an export as `{path: bytes}`; `target` is one of `EXPORT_TARGETS` (`claude-code-hooks`, `kong`, `zuplo`, `toolhive`, `docker-mcp-gateway`), and `PLANNED_TARGETS` (`agentcore-policy`, `cloudflare-egress`) are not available yet. Every export holds `SPELLWARDEN-README.md`, which lists what the target enforces, what it cannot enforce and why, how to install it and the limits of its mode, and the line: Validate field names against the vendor's current documentation before use. The ToolHive and Docker MCP Gateway READMEs end with a link to the target's guide after that line.

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

**Zuplo.** Five files: `zuplo/modules/spellwarden-mcp-guard.ts`, `zuplo/config/spellwarden-policies.json`, `zuplo/spellwarden-zuplo-check.mjs`, `SPELLWARDEN-README.md` and `SHA256SUMS` (it lists the four other files). The paths mirror a Zuplo project, so `modules/` and `config/` land where the README of the export says. `spellwarden-mcp-guard.ts` is an outbound policy for Zuplo's MCP Gateway, the same file for every pack of a release, written against Web standard APIs with a type-only import of Zuplo's types. It checks what MCP servers send through the gateway (results, errors, and the requests and notifications a server sends on the stream) against SW-GW-004's nine injection patterns and the org rules with the `zuplo` target, after removing invisible characters and normalising to NFKC, and answers a JSON-RPC error (code -32001, HTTP 200, the request's id) in place of a response that matches or that cannot be checked: a body over `maxBodyBytes` (1 MiB by default), an unsupported content encoding, a 2xx body that is neither JSON nor an event stream, nesting deeper than 64, a request that the server sends before its response. An error answer whose body is not JSON is checked as one text, since MCP clients show it to the agent; image and audio data and binary blobs are skipped only where MCP puts content. It checks again, in a response-sending hook, any response that a later policy replaced. `zuplo/config/spellwarden-policies.json` holds the policy entry to merge into `config/policies.json`: the pack's patterns are in its `options`, with `guard_sha256` and `options_sha256`. `spellwarden-zuplo-check.mjs` (Node 20 or later, no dependencies) checks that a project is wired as the export requires: the entry, the guard file and the options are the ones the export wrote, `compatibilityDate` is 2026-03-01 or later, every `McpProxyHandler` route lists the guard last among its outbound policies and, when SW-GW-003 is on in the pack, uses a `mcp-token-exchange-inbound` policy with an OAuth `authMode`. SW-GW-003 is therefore enforced only as far as your pipeline runs the script, and the export lists it as not enforced. A pattern that cannot be written as a JavaScript regular expression without the `u` flag is listed as not enforced; the differences from the engine's matching (UTF-16 windows, ASCII `\d \w \b`, JavaScript's case folding) are in the README of the export. The baseline pack's policies file begins:

<!-- zuplo-example:start -->
```json
{
  "policies": [
    {
      "name": "spellwarden-mcp-guard",
      "policyType": "custom-code-outbound",
      "handler": {
        "export": "default",
        "module": "$import(./modules/spellwarden-mcp-guard)",
        "options": {
          "spellwarden": {
            "format": 1,
            "pack_id": "baseline",
            "pack": "Spellwarden Baseline for Agents",
            "version": "1.0",
            "built_at": "2026-12-01T00:00:00Z",
            "engine": "<engine version>",
            "rules_version": "2026.11.10",
            "guard_sha256": "<sha256 of the guard file>",
            "options_sha256": "<sha256 of the canonical options>"
          },
          "maxBodyBytes": 1048576,
          "onTooLarge": "block",
          "checks": [
            {
              "rule_id": "SW-GW-004",
              "title": "Prompt-injection deny patterns on prompts and tool results",
              "parts": [
                "ignore (all |any |the |your )?(previous|prior|above|earlier) (instructions|prompts|rules)"
              ],
              "flags": "i",
              "anchored_end": false
```
<!-- zuplo-example:end -->

The three values in angle brackets are the engine version and the two SHA-256 digests; the rest is what the baseline pack exports.

**ToolHive.** Three files: `toolhive/spellwarden-authz.json`, `SPELLWARDEN-README.md` and `SHA256SUMS` (it lists the other two). `spellwarden-authz.json` is an authorization file for Stacklok ToolHive's `thv run --authz-config`, in the format ToolHive v0.65.0 documents (`"version": "1.0"`, `"type": "cedarv1"`, Cedar policies): it permits every request, then, while SW-GW-006 is on, forbids every `call_tool` request for a tool whose name starts with one of the verbs of the Claude Code hooks export (`delete`, `drop`, `destroy`, `remove`, `purge`, `truncate`, `terminate`, `wipe`, `reset`, `force`) or holds one as a `_`- or `-`-separated word. A `forbid` wins over every `permit`, so a server that already has an authorization file takes only the `forbid` policies into it; ToolHive hides the denied tools from `tools/list` and answers a call to one with HTTP 403. The gateway cannot ask a person, so SW-GW-006 is a deny here. Cedar's `like` is case-sensitive: the lower case, Capitalised and UPPER spellings of each verb are matched, a mixed-case spelling such as `dElete_row` is not. Only `tools/call` is restricted. The release workflow runs ToolHive v0.65.0 on the baseline pack's export at every engine release.

**Docker MCP Gateway.** Six files: `docker-mcp-gateway/spellwarden_gateway_guard.py`, `docker-mcp-gateway/Dockerfile`, `docker-mcp-gateway/compose.yaml`, `docker-mcp-gateway/gateway-flags.txt`, `SPELLWARDEN-README.md` and `SHA256SUMS` (it lists the other five). Docker MCP Gateway documents a list of tools to enable and on/off switches, but no rule that denies a tool by name; it denies only through `--interceptor` scripts, whose input Docker describes in an examples README, not in its documentation. The export is therefore pinned to Docker MCP Gateway v0.44.3, and the release workflow runs that gateway with the guard at every engine release. The guard (Python 3.8 or newer, standard library only, run as `python3 -I`) denies the destructive tool verbs of SW-GW-006 when a tool is called, matched in any case, and replaces a tool result whose text or structured content holds one of SW-GW-004's nine injection patterns after invisible characters are removed and the text is normalised to NFKC. The gateway image needs Python 3: the Dockerfile adds it to the pinned `docker/mcp-gateway` image and copies the guard read-only, `compose.yaml` shows a whole service and `gateway-flags.txt` holds the two flags for `docker mcp gateway run` on a host with Python. The guard fails closed: a request or a result over 1 MiB, one that is not JSON, or a request without a tool name is answered with an error result. Run the gateway with `--transport=sse` or over stdio: with `--transport=streaming`, v0.44.3 cannot hand a tool call to a `before` interceptor and fails every call, so nothing passes. A later gateway release may change the interceptor input; an export is checked against it only by a later engine release.

Obot is not an export target: it creates its access policies, tool selections and filters in its admin UI, and has no documented configuration file an export could write (checked at Obot v0.28.1).

## The `spellwarden` command

```
spellwarden scan [PATH] [--format FMT [--output FILE]]... [--fail-on LEVEL] [--locked] [--probe | --no-probe]
                 [--probe-private | --no-probe-private] [--baseline FILE] [--config FILE] [--as-of YYYY-MM-DD]
                 [--staged] [--follow-links] [--time-limit SECONDS] [--no-telemetry] [--no-invite] [--upload | --no-upload]
                 [--preset strict|balanced|low-noise] [--quiet] [--verbose]
spellwarden lock [PATH] [--check | --probe] [--follow-links]
spellwarden baseline add [PATH] (--fingerprint FP... | --all) --reason TEXT [--expires YYYY-MM-DD | --days N] [--follow-links]
spellwarden baseline add [PATH] --fingerprint FP --rule SW-REG-NNN|SW-ORG-NNN [--finding-path PATH] --reason TEXT [--expires YYYY-MM-DD | --days N] [--follow-links]
spellwarden baseline prune [PATH] [--follow-links]
spellwarden baseline list [PATH] [--follow-links]
spellwarden rules [--format text|json|markdown] [--preset strict|balanced|low-noise]
spellwarden ci comment --provider github|gitlab --body FILE
spellwarden ci-run gitlab
spellwarden otel normalise PATH --signal traces|logs [--encoding auto|protobuf|json] [--content] [--max-records N] [--max-bytes N]
spellwarden version
```

`python -m spellwarden_cli` is the same command; the CI wrappers use that form.

### What a scan reads

`PATH` (default `.`) is the scan root. Inside a git work tree the file set is what git tracks plus untracked files that are not ignored, under the scan root only (submodules are not entered); elsewhere it is a walk that skips `.git`, `node_modules`, `.venv`, `venv` and `__pycache__`. A symbolic link is never read as a file: one at an agent-content path (a configuration file, `SKILL.md`, a plugin manifest or hooks file, a manifest reference) is followed when its target is a regular file of the file set inside the scan root, and named by the link in every output. The target is judged from its text alone, never by asking the file system where it leads: an absolute target (`/x`, `C:\x`, `\\host\share\x`) is the error `unsafe_path` (use a relative link or a real file), and a relative one is resolved against the scan root as written. One that leaves the scan root, passes through a linked directory or points at another link is the error `unsafe_path`; a link inside a skill or a local plugin directory is followed by the same rules, and since 1.23.0 one whose relative target leaves the scan root is the error `unsafe_path` as well, an incomplete scan (exit 2): replace the link with the file it names, or leave it out with `exclude` (up to 1.22.0 it was skipped with a notice and its target text was locked); any other link is skipped with a notice. For these links, at a configuration path and inside a skill or a local plugin directory, the command follows the link rule of the archive reader and the hosted scan, with the scan root as its tree. Its tree differs from the hosted scan's on purpose: the command reads a skill in place in its repository, where a link to a file elsewhere in the repository resolves, so `spellwarden scan .` reads such a link at its target; the hosted scan judges a copy of the skill's folder alone, where that link names nothing, so there the same skill ends incomplete. `spellwarden scan path/to/skill` makes the skill's folder the scan root and reads what the hosted scan reads. Two exceptions to the link rule are kept: an instruction file that is itself a link the scan cannot follow, wherever it points, out of the scan root included, and a file named like an agent card that is no listed or `.well-known` card, are the notice `symlink_skipped`, and the scan can pass with them unread. A link to a directory is never read as a folder of the file set, with one exception: since 1.20.0, `--follow-links` follows a linked directory in an instruction folder (see "Instruction files"). A file over 10 MiB is not read. Since 1.16.1 one that is agent content (a configuration file, `SKILL.md` or any file of a skill, any file of a local plugin directory, an instruction file while they are on, a file named like an agent card or listed in `a2a.cards`, or the target of a link at such a path) is the error `unreadable` and an incomplete scan (exit 2): make it smaller, or leave it out with `exclude` (in connected mode a skill with an excluded file has no identity for the registry check, as for any file `exclude` leaves out of a skill). Any other file over 10 MiB is the notice `file_too_large`. Configuration and marketplace file names match whatever their case (`.MCP.json`), as macOS and Windows open them. A link target, a manifest reference and a plugin's own `.mcp.json`, `hooks/hooks.json` and `.claude-plugin/plugin.json` must name a file exactly as the file set holds it: one that matches a file or directory only in another case or Unicode form is `unsafe_path`, because on Linux the other spelling is another file. A skill is a directory holding exactly `SKILL.md`; another spelling (`skill.md`) gets the notice `skill_name_case`, and is judged as the skill's `SKILL.md` only under a `skills/` directory, where agents on macOS and Windows load it. `include` and `exclude` in the settings narrow the set further.

`--staged` (since 1.19.0; the pre-commit hook runs it) reads the git index instead: the paths git has staged under the scan root (`git ls-files -s -z`), their content as staged (`git cat-file --batch`, the bytes as stored, so the same on every system) and their executable mode from the index; never an untracked file or a change that is not staged, and a path removed from the index is not scanned. `.spellwarden/config.yml`, the baseline and, under `--locked`, the lock file are read from the index too, and one the index does not hold is absent; a `--config` or `--baseline` file named on the command line is read as given. This holds on a pull or merge request in CI too: there a scan with `--staged` reads the settings file, the baseline and the `a2a.keys` file from the index, which is the request's own commit, never from the base revision (see "Settings"), so a request can change what such a scan judges; keep a scan without `--staged` (the Action, the GitLab component) as the check that decides a merge. The file limits of a working-tree scan apply, and a path the index holds only as an unresolved merge conflict is the error `unreadable`. `--staged` sends nothing to Spellwarden: no connected mode, no upload and no usage ping; `SPELLWARDEN_ORG` and `SPELLWARDEN_API_KEY` are ignored, with the notice `staged_credentials_ignored`, and `--upload` and `--user` cannot be used with it. In CI, where settings that say `connected.required: true` make a scan without `--staged` connect, a staged scan gives the notice `staged_connected_required`: connected mode was not evaluated, so the organisation's rules and the registry gate were not applied. It is a notice, so the exit code does not change. `--probe` and `--analyze` still reach the servers and the model endpoint you name, as in any scan. Outside a git repository, or when git cannot read the index, the scan stops with the error `staged_unavailable` (exit 2).

The reading of skills and instruction files can be bounded in time: `--time-limit SECONDS` (since 1.24.0, see [Limits](#limits)).

In that set the scanner finds:

| Item | Where | Judged by |
|---|---|---|
| Skill | every directory holding a `SKILL.md`, with every file below it (a nested `SKILL.md` starts its own skill) | the `SW-SKL` rules |
| MCP client configuration | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, and since 1.20.0 `.devin/mcp_config.json`, `.devin/mcp_config.local.json` and `.github/mcp.json` (which may also be a bare map of servers); each server in it is an item of its own | `SW-CFG-001` to `004`, `010`, `012`, `013`; `SW-MCP` rules under `--probe` |
| Claude Code settings | `.claude/settings.json`, `.claude/settings.local.json` (with their hooks) | `SW-CFG-005` to `008` |
| Codex and Gemini CLI configuration | since 1.20.0, `.codex/config.toml` (TOML: `[mcp_servers.<id>]` and `[hooks]`; its `[plugins]` and `[marketplaces]` entries are listed) and `.gemini/settings.json` (`mcpServers`, `hooks`); each server in it is an item of its own | servers: `SW-CFG-001` to `004`, `010`, `012`, `013`; hooks: `SW-CFG-005` to `007`; `SW-MCP` rules under `--probe` |
| Hooks file | since 1.20.0, `.codex/hooks.json`, `.cursor/hooks.json`, `.windsurf/hooks.json`, `.devin/hooks.v1.json` and every `.json` file directly in `.github/hooks/` | `SW-CFG-005` to `007` on each command; in Copilot's files on each of `bash`, `powershell` and `command` |
| Copilot and Devin settings | since 1.20.0, `.github/copilot/settings.json` and `.github/copilot/settings.local.json` (hooks, `enabledPlugins`, `extraKnownMarketplaces`), `.devin/config.json` and `.devin/config.local.json` (hooks) | `SW-CFG-005` to `007` on the hooks; the plugins and marketplaces as Claude Code's |
| Plugin marketplace | `.claude-plugin/marketplace.json` and every plugin it lists (a local source `./` is the marketplace's own directory) | `SW-CFG-009`; a local plugin's skills, `.mcp.json`, `hooks/hooks.json` and `.claude-plugin/plugin.json` are scanned like the files above |
| Instruction file | `AGENTS.md`, `CLAUDE.md` and `GEMINI.md` at any depth, and since 1.20.0 `AGENTS.override.md`, `AGENTS.local.md`, `AGENT.md` and `CLAUDE.local.md`; `.github/copilot-instructions.md`, `.cursorrules` and `.windsurfrules` at the scan root; `.mdc` files under `.cursor/rules/`; `.md` files under `.windsurf/rules/` or `.devin/rules/` (every depth since 1.20.0), and `.windsurf/global_rules.md` and `.devin/global_rules.md`; since 1.20.0 also `.md` files under `.claude/rules/`, `.claude/commands/`, `.claude/agents/` and `.github/agents/` at every depth, `.instructions.md` files under `.github/instructions/`, `.md` files directly in `.claude/output-styles/`, `.cursor/agents/`, `.codex/agents/`, `.gemini/agents/`, `.devin/agents/` and `.agents/agents/` (and `<name>/AGENT.md` in the last two), and the Markdown under `commands/` and `agents/` of a local plugin directory; every folder at any depth | the `SW-SKL` rules except `SW-SKL-015` and `SW-SKL-031`, which judge `SKILL.md` metadata; see "Instruction files" |
| A2A agent card | `.well-known/agent-card.json` at any depth, `.well-known/agent.json` and any other file named `agent-card.json` (when it is a card), and the files `a2a.cards` lists; remote agents under `--probe` | the `SW-A2A` rules; see "Checking A2A agent cards" |

A plugin hosted elsewhere (a GitHub repository or a URL) is listed and locked by its declared source, never fetched. Configuration files are read as JSON with comments and trailing commas (VS Code's `mcp.json` dialect). A file with a key repeated in one object is refused (`duplicate_key`): agents disagree on which copy wins, so the scanner will not guess. Everything read from the repository is treated as hostile: sizes and nesting are bounded, paths are confined to the scan root, and every string is escaped for the place it is printed.

Read but not judged. Since 1.20.0 a scan reads more files than its rules judge in full, and says so here rather than with a notice, since nothing is left unread. In a hooks file, an entry without a command is not judged: `type` `prompt` (Cursor, Devin, Copilot), `http` (Copilot), `agent` and `mcp_tool` (Codex); it is part of the document's hash, so the lock sees a change to it. In `.codex/config.toml` only the servers and hooks are judged: the `[plugins]` and `[marketplaces]` entries are listed, not judged and not gated, and `developer_instructions`, `model_instructions_file`, the approval and sandbox keys, `[agents]` and profiles are not read; `notify` is not a hook in a project file, since Codex ignores it there. In `.gemini/settings.json`, `tools.discoveryCommand`, `tools.callCommand`, `mcp.serverCommand`, `tools.allowed` and `context.fileName` are not judged. In `.github/copilot/settings*.json` only the hooks, `enabledPlugins` and `extraKnownMarketplaces` are read: every other key is one Copilot ignores, and `permissions` is not judged. In `.devin/config*.json` only the hooks are read; the permissions are not judged. Commands, subagents, output styles and Copilot instruction files are judged by every skill rule except `SW-SKL-015` and `SW-SKL-031` over their text, and by `SW-SKL-036` over `allowed-tools` in the front matter of a file under a `commands` or `agents` folder. The other front matter keys are not judged for what they configure: inline `hooks` and `mcpServers` (a subagent's inline server is not a server item and is not gated), `permissionMode`, `tools`, `disallowedTools`, `model` and `skills`; a Copilot custom agent's `mcp-servers`, `hooks` and `handoffs`; a Gemini CLI agent file's `auth` values, which can run a command.

### Instruction files

Since 1.13.0 the scanner also finds the files that give instructions to a coding agent (the table above) and scans each one as an instruction file: every skill rule except the two about `SKILL.md` metadata, with Markdown rules reading a `.mdc`, `.cursorrules` or `.windsurfrules` file as Markdown. Paths match whatever their case (`claude.md`, `.Cursor/Rules/x.MDC`), as macOS and Windows open them and as configuration file names match, after `include`, `exclude` and the walk rules. A file inside a skill directory belongs to that skill and is scanned there, once, with a `.mdc`, `.cursorrules` or `.windsurfrules` file still read as Markdown; at most 300 instruction files are read per scan root, those an agent reads at the root of the repository first (root `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` and their variants, the Copilot file, the root Cursor and Windsurf rules and, since 1.20.0, the files of the agent folders at the root: `.claude/`, `.cursor/agents/`, `.codex/agents/`, `.gemini/agents/`, `.devin/`, `.agents/agents/`, `.github/instructions/` and `.github/agents/`), then the rest shallowest first; more is the error `instructions_limit` and an incomplete scan (exit 2; see [Limits](#limits)). A symbolic link at one of these names is followed like one at a configuration file's name; one that cannot be followed is the notice `symlink_skipped`, wherever it points, even out of the scan root: an exception to the link rule of "What a scan reads", kept in 1.23.0.

Each file is an item of kind `instructions` with a `format` (`agents-md`, `claude-md`, `gemini-md`, `copilot-instructions`, `cursor-mdc`, `cursorrules`, `windsurf-rules`, and since 1.20.0 `claude-rule`, `claude-command`, `claude-agent`, `claude-output-style`, `cursor-agent`, `codex-agent`, `gemini-agent`, `devin-agent`, `github-instructions` and `github-agent`; a `spellwarden scan --user` run also writes `codex-agents-md`, `devin-rules`, `codex-prompt` and `cursor-command`, see "Scanning a workstation") and a `front_matter`. The front matter of a Cursor rule (`description`, `globs`, `alwaysApply`), of a Windsurf or Devin rule (`trigger`, `globs`, `description`), of a Claude Code rule (`paths`, shown as `globs`), of a GitHub instruction file (`applyTo`, one string of comma-separated globs shown as `globs`, and `description`) and of a command, subagent or output style (`description`; one written as a YAML block, `|` or `>`, is not read and stays null) is read by a line parser, not YAML, because Cursor writes values YAML refuses (`globs: *.ts`); a block that cannot be read leaves `front_matter` null, still scans the file and gives the notice `instructions_front_matter`. The text and Markdown reports say when the agent applies a file next to its findings (`Applied: always`, `Applied to files matching: ...`, `Applied when the agent judges it relevant: ...` or `Applied when asked for`; since 1.20.0 a `global_rules.md` directly in a `.windsurf` or `.devin` folder is always applied, an output style when asked for, and a command, subagent or GitHub instruction file as its `globs` or `description` says), and SARIF results of an instruction file carry `properties.instructions` with the format and that scope. Each file is pinned in the lock file (`kind` `instructions`, with its `format` and the hash of its name and bytes) and uploaded in connected mode; the registry gate does not consider instruction files.

Since 1.20.0 commands, subagents and output styles are instruction files too: Markdown an agent takes as instructions. Each is an item of kind `instructions` with its format, counts toward the 300, is pinned in the lock file, uploaded in connected mode and left out with `instructions: false`. The commands and agents of a local plugin directory carry the plugin's name, and are never read before the root places; a command or agent file inside a skill directory belongs to that skill. Precision of the skill rules on command and subagent text has not been measured.

A linked directory in an instruction folder (`.claude/rules/shared -> ../../shared-rules`, as Claude Code documents for sharing rules) is not followed by default: it is the notice `symlink_skipped`, the rule files reached only through it are not judged, and the scan can pass with them unread. Since 1.20.0 `--follow-links` follows it. A link counts when a directory at its place could hold an instruction file by a folder rule (below `.claude/rules/`, `.cursor/rules/`, `.windsurf/rules/`, `.devin/rules/`, `.claude/commands/`, `.claude/agents/`, `.github/instructions/` or `.github/agents/`, a `<name>` folder in `.devin/agents/` or `.agents/agents/`, or the folder itself). When its target is a directory of the file set inside the scan root, each file below the target is offered under the link's path (`.claude/rules/shared/a.md`), the folder's own rule decides whether it is an instruction file there, and every output, the lock and the upload name it by that path. A link is followed one level: a link below the target is the error `unsafe_path` where its path would be an instruction file. A target that cannot be followed (absolute, through or to another link, missing, ignored by git, left out by `exclude`, written in another case, the scan root, or a directory that holds the link) is the error `unsafe_path` and an incomplete scan (exit 2): replace the link with the files it should hold, or leave it out with `exclude`. Never followed, with or without the argument: a link whose target is outside the scan root (without the argument the notice `symlink_skipped`; with it, since 1.23.0, the error `unsafe_path` and an incomplete scan, exit 2, with the same way out, where up to 1.22.0 it was a notice and what it leads to was not judged), a linked folder above an instruction folder (`.claude`, `.github`, `.cursor` itself) and a linked directory anywhere else, such as one that holds an `AGENTS.md` (the notice `symlink_skipped`; the files in them are judged where they really are), a link to a directory inside a skill or a local plugin directory (the error `unsafe_path`), and a configuration document, skill, plugin or agent card below a followed directory. Give `spellwarden lock`, `lock --check`, `scan --locked` and the `baseline` commands the same `--follow-links` as `scan`: the lock does not record it, so a lock written with it is stale without it, and the other way round. `--staged --follow-links` reads the links and their targets as the index holds them. `scan --user` follows a link to a directory inside the home already and refuses `--follow-links`.

Instruction files are on by default. Set `instructions: false` in `.spellwarden/config.yml` to leave them out: they are then not found, locked, scanned or reported, and the report is the one 1.12.0 wrote, apart from the `tags` each finding carries since 1.13.0. Upgrading can change a result: a repository that holds instruction files can gain findings, so a gate that passed can fail, and a repository with a lock file sees its instruction files as `added` (lock `stale`, exit 3) until `spellwarden lock` is run once. A lock file that holds them is unreadable to 1.12.0 and older (`lock_unreadable`), and an older scanner refuses a config with the `instructions` key, so a team that runs two scanner versions against one repository must upgrade both or set `instructions: false`. Not read: `.github/prompts/*.prompt.md` (prompt files of VS Code's Local harness, which VS Code removes in February 2027); `.md` files in `.cursor/rules/` (Cursor ignores them); `.cursor/commands/` (no documented format); Windsurf and Devin workflows (`.windsurf/workflows/`, `.devin/workflows/`: they run only when the user asks, and the current agent does not support them); `.codex/agents/*.toml`; Gemini CLI's `.gemini/commands/**/*.toml`; and the files that need a parser or a rule the scanner does not have: `.cursor/permissions.json`, `.cursor/sandbox.json`, `.cursor/cli.json`, `.cursor/worktrees.json`, `.cursor/environment.json`, `.codex/rules/*.rules`, `.agents/plugins/marketplace.json`, Gemini CLI's policy files, `.claude/workflows/*.js`, a plugin's `.lsp.json` and `monitors/monitors.json`, the permissions of `.devin/config.json`, the approval keys of `.vscode/settings.json` and `copilot-setup-steps.yml`. The global rule files in a user's home directory are not part of a repository scan: `spellwarden scan --user` reads them (see "Scanning a workstation").

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Passed: no unsuppressed finding at or above `--fail-on` (default `high`; `never` always passes on findings). |
| 1 | Failed on findings. |
| 2 | Incomplete or invalid (for `scan`, and since 1.16.2 for `lock` and `lock --check`, which then write and confirm no lock): a usage or settings error, an unreadable file (a file of agent content over 10 MiB among them), a configuration document or agent card the scanner refused or cut short (over 200 servers, 500 hooks or 200 plugins), a skill over 2000 files or 50 MiB, a symbolic link inside a skill or a local plugin directory whose target leaves the scan root (since 1.23.0), a front matter past its limits (since 1.19.0), a package the scan did not finish because `--time-limit` was reached (since 1.24.0), over 300 instruction files or 300 agent cards, or with `--follow-links` over 50 linked directories in instruction folders or a linked instruction folder whose target leaves the scan root (since 1.23.0), an invalid baseline entry, or a scanner crash; under `--user`, over 300 instruction files of one client or 1,000 skills in one skills directory, a link out of the home directory to files the scan reads, or to a directory inside a skill, a missing workstation credential or label, or a workstation upload that failed or was too large. |
| 3 | `--locked` (or `lock --check`) and the lock file is absent or out of date, everything having been read. |

When several apply, 2 wins over 1, and 1 over 3: an incomplete scan never looks like a pass. Every requested report is written before the exit.

The notes of the description lint and the verdicts of the model-assisted analyzer (`--analyze`) never change the exit code: both are informational (see "Description lint" and "Model-assisted analyzer"). What a skill the analyzer could not read does to the exit code is in [Limits](#limits).

### Limits

The scanner has limits so that a run ends in bounded time and memory. One rule decides what happens when a limit is reached, and every limit follows it: **content the scanner leaves unread never looks like a pass.**

- **What the repository holds** (files, configuration documents, skills, instruction files, agent cards): the repository decides its size, so a limit reached is an error and the scan is incomplete (exit 2). The way out is a narrower scan with `exclude` in `.spellwarden/config.yml`, a change reviewers see in the diff, never a skip the scanner makes on its own. Where the scanner must choose what to read first, it reads what an agent loads first (for instruction files, the places at the repository root). Since 1.20.0 `--follow-links` follows at most 50 linked directories in instruction folders per scan root, those in the agent folders at the root first; more is the error `instructions_limit` (exit 2), and every file read through a link counts toward the 300 instruction files. A file over 10 MiB that is agent content is the error `unreadable` (since 1.16.1; it was a notice), and `exclude` is the way out (in connected mode a skill with an excluded file has no identity for the registry check, as for any file `exclude` leaves out of a skill); a file over 10 MiB that is no agent content is not read and is the notice `file_too_large`, since nothing an agent loads is left unjudged. Since 1.16.2 the same errors stop `spellwarden lock`, which writes no lock file (one already there is left as it was), and `lock --check`, which confirms nothing, both with exit 2 and each error printed with its way out: a lock written without the item would pass `--locked` while the item changed unseen (see [the lock file](#the-lock-file-spellwardenlockjson)). Since 1.22.0 the rules read a text file of a skill, and an instruction file, up to 10 MiB, the size up to which the command reads files; before, a text file over 1 MiB was read by no text rule, so the scan could pass. A library caller that hands the engine a larger text file gets the error `TextLimit`, never a result. A symbolic link inside a skill or a local plugin directory, or at a configuration path, that the scan does not follow is an error and the scan is incomplete, since 1.23.0 one whose target leaves the scan root too; an instruction file that is a link the scan cannot follow is the exception, a notice (see "What a scan reads"). The library's archive reader, which the hosted scan uses, bounds what it reads under a named directory at 2,000 files, 50 MiB unpacked and 10 MiB a file, and a whole archive at 100,000 entries and 50 MiB zipped for a repository read under a named directory (`REPOSITORY_LIMITS`, since 1.23.0), 20 MiB zipped otherwise; each bound reached is an error, never a pass.
- **What a remote server sends to the probe** (tool, prompt and resource lists, a remote agent card): the server decides its size, and a limit reached there cannot fail your build, or any server could. It is shown in every report (`probe_list_incomplete`, the card's notice), and it never lowers a judgement: a tool list not read whole keeps SW-MCP-001 high. Since 1.16.1 the probe follows `nextCursor` as clients do, so a list split over pages is read whole: at most 10 pages of one list, 12 later-page requests per server on top of its first nine requests, and 200 entries per list, under the run's budget. A later page starts only while the probe's time so far, plus 10 seconds for that page and 10 for each first-page request it may still send, stays within 90 seconds, the longest a 1.16.0 probe could take (nine requests of at most 10 seconds), so a slow server cannot hold the run longer than before. A later page the run's budget refuses ends that list and never discards the probe or its findings. An entry identical to one already read in the list is read once, so a server that ignores the cursor and repeats a page gives each tool once; two different entries with the same name are both kept. A list is whole only when its last page named no further page; a repeated cursor or page, a cursor that is not a string, a page that cannot be read and any limit reached leave it read in part.
- **How long the scan reads** (the time limit, since 1.24.0): `--time-limit SECONDS` (default: no limit; there is no environment variable and no settings key, so a file in the repository cannot raise or remove it) limits the engine's reading of skills and instruction files, the one step whose time the repository decides, to SECONDS counted from the start of the scan, listing files and discovering items included; the configuration documents, the remote probes and agent-card fetches, the model-assisted analyzer, the baseline, the lock and the output have their own bounds, are not limited by it and still run. A skill or instruction file that the engine had not finished is the error `time_limit` and is not judged: a package is judged whole or not at all, and one that was not judged has no finding in the report. Every skill and instruction file after it is named by an error of its own, so nothing unread goes unnamed. The packages judged before the limit keep their findings, and the scan is incomplete (exit 2), so no gate passes on it. The way out is to split the content, leave a file out with `exclude` in `.spellwarden/config.yml`, or raise the limit. The limit is read at every file, every view and every rule and once for every 64 KiB of line text, so the scan stops within about the time one rule needs for one line of 10 MiB after it: at most 1.79 s past the limit on the machine of the 1.24.0 release run; the hosted step measured about twice this machine's time on a 50 MiB skill (257 s against 126.82 s), so a limit there leaves about twice that room. `scan --user` takes no limit.
- **What the scanner writes** (the findings kept per package, the evidence of a finding): these cut output, not reading. Everything was judged, and the count of what was left out is shown (`findings_truncated`).

Since 1.19.0 the YAML front matter of a `SKILL.md`, and of a Markdown file in a skill's `commands/` or `agents/` directory, follows the rule for repository content (**SKILL.md front matter**): it is read only up to 64 KiB of text, 2,000 YAML nodes, a nesting depth of 32 and 50 aliases. A front matter past one of them is not read: the file is the error `unreadable`, naming the limit, the skill is not judged and the scan is incomplete (exit 2); it is never reported as a finding. The way out is to make the front matter smaller, or to leave the file out with `exclude` in `.spellwarden/config.yml`; `scan --user` reads no settings file, so there it is to make the front matter smaller or to remove a skill that is not used. Each limit is at least ten times the largest front matter among the repository's own fixtures (57 files measured for 1.19.0: at most 198 bytes, 11 nodes, a depth of 2 and no alias).

The probed tool hashes of 1.15.0 follow the rule for remote content. `lock --probe` does not pin a list with entries missing (more than 200 entries, a page not read, an entry without a name or address) and keeps the stored pin of a server it cannot read, with a warning; `scan --probe --locked` gives the notice `tools_not_compared` for a pinned server, or a list, it could not read or read with entries missing, and never makes the lock stale for it. The hashes cover each text as the probe keeps it (a description 1,000 characters, a title 256, a name 128, an address 2,048, 20 prompt arguments of 500 characters, the instructions 16,000 and a schema 16 KiB, above which a tool has no schema). A change past a cut is not seen. Since 1.16.1 a list whose entries were all read is pinned and compared even when the probe cut a text or dropped a schema in it, as the hosted product compares (1.15.0 and 1.16.0 left such a list out, so padding one description past 1,000 characters took a list out of the comparison): the hash over the texts as the probe keeps them changes when anything before a cut changes, `lock --probe` warns that the list is pinned as the probe keeps it, and `scan --probe --locked` gives the notice `probe_list_incomplete` naming it. Pins written by 1.15.0 and 1.16.0 compare as before. The probe result names such lists in `lists_cut`; the server's instructions cut at 16,000 characters count the same way. A schema nested deeper than 128 levels of objects and arrays is hashed as its JSON text, not as RFC 8785 JSON, so a change in it is still seen. The evidence of SW-MCP-012 shows at most 120 characters of each side. In the exports, the Docker MCP Gateway guard reads at most 1 MiB of a tool call or result and answers anything larger with an error result, and the ToolHive export matches the lower case, Capitalised and UPPER spellings of each verb only.

`spellwarden scan --user` (see "Scanning a workstation") follows the same rule. What a home directory holds is the user's own content, so each of these limits reached is an error and an incomplete scan (exit 2), and the way out is to remove what is not used, or to scan without `--user`:

- at most 300 instruction files per client (`user_instructions_limit`), read in the order of the client table;
- at most 1,000 skills per skills directory (`user_skills_limit`);
- at most 200 plugins and 200 marketplaces per state file (`installed_plugins.json`, `known_marketplaces.json`, Codex's `config.toml`) and 200 Gemini CLI extensions (`truncated`), and since 1.20.0 200 plugin directories each of Codex (`$CODEX_HOME/plugins/cache/`), Copilot (`$COPILOT_HOME/installed-plugins/`) and Cursor (`~/.cursor/plugins/local/`) (`truncated`); each configuration document keeps the limits of a repository scan (1 MiB, 200 servers, 500 hooks, 200 plugins);
- files over 10 MiB (`unreadable`); Claude Code's `~/.claude.json`, which holds the client's own state, is read up to 10 MiB;
- a symbolic link to a place outside the home directory that leads to files the scan reads, and a link to a directory inside a skill (`unreadable`, one error per link, since 1.16.1; they were the notice `symlink_skipped`): they are not followed (spec decision D39), so what they lead to is not judged. Dotfile managers such as Nix home-manager make every client file such a link: those files are then not scanned, and the scan says so instead of reading as complete. A link out of the home is that error only when what the scan looks for below it exists below its target, checked without reading or listing anything there: for a link on a table path, the rest of that path (where the path has a `*`, the directory it would be matched in); for an entry of a skills directory, a `SKILL.md` in it; for an entry of Gemini CLI's extensions directory, a `gemini-extension.json` in it; inside a skill, the target itself. The way out: remove the link, or replace it with a copy of what it leads to; for a link on the base directory of a client (`~/.config`, `~/.claude`, `~/.codex`), the error also names the variable that moves that base (`XDG_CONFIG_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`, `APPDATA`) when every row that reached the link starts there, since a base outside the home that such a variable names is read as it is: set it to the real path. A link out of the home that leads to nothing the scan reads, and a link whose target is missing or a loop, stay the notice `symlink_skipped`;
- the workstation upload: 1 MiB, 2,000 items and 1,000 findings, never cut (`workstation_upload_too_large`, nothing is sent). Its body lists at most 50 errors and 50 notices and carries their totals, and at most 8 roots per client with the client's number of roots in `roots_total` (since 1.16.2): output caps, since the report on the workstation lists them all, and each shows the count left out.

The description lint (since 1.17.0) lists at most 20 notes per skill in each report, an output cap: every description was checked, and the count left out is shown (`left_out` in the JSON report, "more notes were not kept" in the text report and "more notes are in the JSON report" in the Markdown report). Only overlap notes are ever left out; the three single-skill notes always fit.

A preset (since 1.18.0, see "Presets") is an output cap in this sense: a finding it turns off was judged and is counted in every report (the notice `preset`, the JSON report's `preset.off`), never silently dropped. It adds no limit, never leaves content unread and never hides an error.

The HTML report (since 1.18.0) has no size cap of its own: it holds every finding, notice and error of the JSON report, under the caps above (the findings kept per package, the evidence of a finding).

The model-assisted analyzer (`--analyze`, since 1.17.0) follows the same rule:

- what one skill sends is at most 120,000 bytes of masked UTF-8 text, SKILL.md and scripts together, all or nothing. A skill past it, or one whose SKILL.md or a script is not UTF-8 text, is not analysed: its `analysis` entry is `incomplete` with the `limit` (`too_large` with the bytes and the bound, or `not_text` with the file), the notice `analysis_incomplete` names the skill, and it is never shown as analysed or clean. The way out is to split the skill, or to raise the bound with `--analyze-max-bytes` (at most 10,000,000); for a file that is not text, make the file UTF-8 text, or move it out of the script selection (out of `scripts/`, without an executable mode and without a script extension). A skill with a SKILL.md or script the scan itself did not read (a file over 10 MiB, the error `unreadable`, or a member link that was not followed) is `incomplete` with `too_large` as well (its bytes are 10,485,760, the file limit, and since 1.19.0 its `limit` names that file in `path`), nothing is sent for it and nothing is cached; the way out is the file's own: make it smaller, leave it out of the skill, or replace the link with the file. Since 1.19.0 a SKILL.md or script the scan did not read for another reason (a path the git index holds only as an unresolved merge conflict under `--staged`, a file that cannot be read) is `incomplete` with `too_large` too, with that file in `path` and no `bytes`, since its size is not known, and the notice says that the file was not read; the way out is what the scan's error `unreadable` for that file says. Since 1.19.0 a skill with a front matter past a limit (see above), in its SKILL.md or in a Markdown file of its `commands/` or `agents/` directory, is the same: no rule judged the skill, so it is `incomplete` with `too_large`, that file in `path` and its real size in `bytes` (it was read, but not judged), nothing is sent for it, and a notice names the front matter; the description lint leaves such a skill out too. The analyzer is an extra you asked for, not the judgement of the rules, so only the analysis is incomplete: the scan's errors and its exit code stay as the rules left them;
- the model's answer is content a remote party controls: one over 1 MiB, off the schema or quoting a span that is not in the source is `not_analyzed` or `no_verdict` with its reason, and it never lowers a judgement; run the scan again;
- each request asks for an answer of at most a `max_tokens` of 4,096 tokens: the model's answer is content a remote party controls, and an answer cut there is not one whole JSON object, so it is `no_verdict` (`not_json`), never clean; the way out is to analyse again, or analyse a smaller skill, whose answer needs fewer tokens;
- each category keeps at most 5 spans, a summary of 300 characters and spans of 200: output caps, with the count of spans left out (`spans_left_out`); every span was checked before the cap.

### Settings: `.spellwarden/config.yml`

```yaml
version: 1
include: []                 # globs; empty means every file of the file set
exclude: ["tests/fixtures/**"]
fail-on: high
probe: false
telemetry: true
instructions: true           # instruction files; see "Instruction files"
preset: balanced             # strict, balanced or low-noise; see "Presets"
a2a:                          # agent cards; see "Checking A2A agent cards"
  cards: [deploy/agent/card.json]
  keys: .well-known/jwks.json
  agents: [https://agent.example.com/]
```

The file is optional. An unknown key or a `version` other than 1 is an error (exit 2), so a typo never silently weakens a gate. A flag wins over the environment (`SPELLWARDEN_FAIL_ON`, `SPELLWARDEN_PROBE`, `SPELLWARDEN_TELEMETRY`, `SPELLWARDEN_PRESET`), which wins over the file. Private probing is deliberately not a setting (see "Probing"). The `preset` key (since 1.18.0: `strict`, `balanced` or `low-noise`) is described under "Presets"; on a pull or merge request it is read from the base revision with the rest of the file, so a request cannot lower its own checks. The `instructions` key (a boolean, default true) leaves the instruction files out when false; it has no flag and no environment variable, and on a pull or merge request it is read from the base revision with the rest of the file, so a request cannot switch off its own scanning. The `connected` mapping (`pack`, `upload`, `required`) is described under "Connected mode", the `a2a` mapping (`cards`, `keys`, `agents`) under "Checking A2A agent cards". On a pull or merge request `a2a.keys` and `a2a.agents` are read from the base revision even under `--config`, like `connected.pack` and `connected.required`: a request cannot choose the keys its cards are verified with or the agents that are fetched.

**On a pull or merge request, this file and the baseline are read from the base revision**, the commit the request targets, never from the request itself. Otherwise a request could add a malicious `.mcp.json` together with `exclude: [".mcp.json"]`, or accept its own finding in the baseline, and pass its own check. A request that changes either file therefore sees the change apply only once it is merged, and the report says so with the notice `settings_from_base`. The lock file is still read from the request: a request that changes agent content must update it, and reviewers see that change. Under `--locked` the lock is computed with the base's `include` and `exclude`, so a request that changes those patterns and the lock together is reported stale until the settings change is merged first. Local runs, pushes, schedules and manual runs read the working tree as before. A `--config` or `--baseline` file named on the command line is read as given: whoever runs the scanner chose it. A scan with `--staged` (since 1.19.0; the pre-commit hook runs it) is the exception: it reads this file, the baseline and the `a2a.keys` file from the git index on a request too (see "What a scan reads"), so it is not the check to rely on for a merge.

The scanner reads the base revision with git. A shallow clone that lacks it is fetched once from `origin` (that one commit, depth 1, no tags, hooks off). When the base still cannot be read (the event names no base commit, git is missing, or the fetch failed) the scan uses the default settings and no baseline, and the notice `base_unavailable` says why. On GitHub, check out with `actions/checkout` `fetch-depth: 0`, or keep its default `persist-credentials: true` so the fetch can authenticate. On GitLab, set `GIT_DEPTH: 0` (or a depth that reaches the merge base) in the job, because the scanner image cannot write to a clone it does not own.

### The lock file: `.spellwarden/lock.json`

`spellwarden lock` records every discovered configuration file, MCP server, plugin source, local plugin directory, skill and instruction file with a hash. `spellwarden scan --locked` (and `spellwarden lock --check`) exits 3 when anything was added, removed or changed since, and names each item, so a change to agent content is a visible, reviewed change. Since 1.16.2 a lock is written and checked only over content that was read in full: when discovery reports an error (an agent content file over 10 MiB such as an 11 MB `AGENTS.md`, a configuration document refused or cut short, over 300 instruction files, a link that cannot be followed; the errors that make `scan` exit 2), `spellwarden lock` writes no lock file and leaves one already there as it was, and `lock --check` confirms nothing; both print each error and exit 2. The way out is the one of [Limits](#limits): fix the content, or leave it out with `exclude` in `.spellwarden/config.yml`. `scan --locked` already exits 2 for such a repository. A symbolic link inside a skill or a local plugin directory to `.spellwarden/lock.json` before that file exists, whose target passes through real directories only (never through another link, and `.spellwarden` no link either) with nothing at the lock's path on disk, is a member of its package, left out of the package's lock hash as the lock is once it exists (notice `symlink_skipped`), so the first `spellwarden lock` already holds the package and `lock --check` passes at once; any other link to the lock file is the error `unsafe_path`, and `lock` exits 2. 1.16.1 and older wrote or confirmed a lock without the unread item, with a warning and exit 0. The lock holds no scanner version: upgrading the scanner never makes it stale. A skill's hash is computed over paths relative to the skill's directory, so moving a skill changes only its path. Since 1.20.0 a lock written with `--follow-links` holds the instruction files read through a linked directory under the link's path; the lock does not record the argument, so give `lock`, `lock --check` and `scan --locked` the same `--follow-links`, or those files show as `removed` or `added` (exit 3).

Since 1.15.0 `spellwarden lock --probe` also probes the configured remote servers (public `https` addresses only, with the rules of `--probe`) and pins, for each server whose tools it read, the `toolhash` kind hashes of the lists it read in full (every entry read; since 1.16.1 also when the probe cut a text in one, see [Limits](#limits)), as an item of kind `mcp-tools`: `{"kind": "mcp-tools", "path": ".mcp.json#jira", "format": 1, "kinds": {"tools": "<sha256>", ...}}`, never the endpoint, a header, an environment value or a credential. A list the server sent only in part is not pinned, and a server it cannot read (unreachable, refused for want of a credential, a private address, an `http://` URL) keeps the pin the lock already holds; each is a warning on standard error, and the exit code stays 0: a remote server is never an error of `lock --probe`. `spellwarden scan --probe --locked` compares every pinned list it read in full again: another hash makes the lock stale (`changed mcp-tools .mcp.json#jira`, exit 3), the same tools in another order do not, and a pinned server or list it could not read in full is the notice `tools_not_compared`, never a stale lock. `spellwarden scan --probe` without `--locked` reports a differing pin as the notice `tools_changed` and keeps its exit code. Every comparison without `--probe`, `lock --check` included, leaves the pins out, and `spellwarden lock` without `--probe` keeps the pin of every server it locks again. A lock without pins is a 1.14.0 lock and works as before; a lock with pins is refused by 1.14.0 and older (an item of an unknown kind, exit 2), so upgrade every scanner that reads it.

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

An entry accepts one finding, by fingerprint, from `added` to `expires`. It needs a reason, may last at most 365 days, and at most 30 days for a malicious-indicator rule (SW-SKL-004, SW-SKL-008, SW-SKL-032, SW-CFG-006, SW-CFG-007). An invalid entry accepts nothing and fails the scan (exit 2); an expired one stops accepting, and the report says which entry expired on which date. Accepted findings stay in every report, marked as accepted with their reason. `spellwarden baseline add --all --reason "..."` accepts every current finding (90 days by default), `prune` removes entries that no longer match anything, `list` shows each entry's state. These three commands work on the files in your working tree. With `--follow-links` they read a linked directory in an instruction folder as `scan --follow-links` does: give them the argument whenever your scan has it, or `prune` removes the entries of findings on linked files. They scan without a connection, so they cannot see an `SW-REG` or `SW-ORG` finding: `prune` keeps an entry that names such a rule until it has expired (and 30 more days), `list` shows it as `connected` instead of `unmatched`, and to accept one you give its fingerprint from a connected report with `--rule` (and `--finding-path`): `spellwarden baseline add --fingerprint FP --rule SW-REG-001 --finding-path skills/setup --reason "..."`, at most 90 days for `SW-REG` and 365 for `SW-ORG`.

On a pull or merge request the scan reads the baseline from the base revision, like the settings file (see "Settings"): a request cannot accept its own finding. To accept a finding that a request introduces, merge the baseline entry first, in a request of its own; an entry that matches nothing yet is valid.

### Reports

`--format` may be given several times, each followed by its own `--output` (stdout when omitted, one format at most). Every report is byte-identical for the same files, settings and `--as-of` date and, for the Markdown report, the same CI service and run kind, which its links and lines depend on (see "Links in the Markdown report"), holds no timestamp (a CycloneDX document's `metadata.timestamp` is the `--as-of` date at midnight UTC) and no absolute path, and is sorted.

| Format | For |
|---|---|
| `text` (default) | a terminal |
| `json` | tools; the shape is `schemas/report.schema.json` |
| `sarif` | GitHub code scanning (SARIF 2.1.0, one fingerprint per result under `partialFingerprints["spellwarden/v1"]`, accepted findings as `suppressions`) |
| `markdown` | the job summary and the pull or merge request comment (starts with `<!-- spellwarden-scan -->`, at most 60,000 characters); links to each rule's page and, in free mode, a line about the dashboard; see "Links in the Markdown report" |
| `gitlab-codequality` | the GitLab Code Quality report (critical, high, medium and low become critical, major, minor and info) |
| `cyclonedx` | an AI bill of materials, CycloneDX 1.7 JSON (since 1.14.0): skills, plugins, marketplaces, instruction files and configuration documents as components, MCP servers and A2A agent cards as services, findings as vulnerabilities naming their component or service (open ones `in_triage`, accepted ones `exploitable` with `will_not_fix` and the baseline's reason), the rest as `spellwarden:` properties; the serial number is derived from the content, so the same scan gives the same file |
| `html` | a person, in a browser (since 1.18.0): one self-contained file, every string from the repository escaped, no script and no network request when opened; see "HTML report" |

Paths are relative to the scan root, except in SARIF and Code Quality, where they are relative to the repository root, because that is where GitHub and GitLab resolve them.

### HTML report

`--format html` (since 1.18.0; `spellwarden scan --format html --output report.html`) writes one self-contained HTML file to open in a browser or attach to a ticket: the scanner and rules versions and the date, the preset when one other than `balanced` applied, the outcome and exit code, the counts by severity, the notices and errors, then every finding grouped by item (rule id, title, severity, location, evidence, fingerprint, the baseline's reason for an accepted finding, and a link to the rule's page), the items scanned, the probed servers and agent cards, the lock changes and the description lint. Under `--analyze` it also holds the analysis. It does not hold everything the JSON report holds: the connected-mode details (the credential, the organisation, the run, the policy applied, the registry gate and the upload outcome) and the instruction-file scopes (when the agent applies each instruction file) are not in the HTML report. They are in the JSON report (its `connected` block, and each instruction file's `format` and `front_matter`), and the text and Markdown reports show them. The notices of a connected run, the upload's among them, are in the HTML report with every other notice. The report is byte-identical for the same files, settings and `--as-of` date.

The file is built for content you do not trust. Every string from the scanned repository or a probed server is escaped (`&`, `<`, `>`, `"` and `'` as character references, hidden characters and lone surrogates as `\u{NNNN}`, control characters as `\xNN`), so a skill whose text holds `<script>` shows it as text. There is no script element, no event attribute, no form, no frame, no image, no font and no stylesheet but one inline style without `url(`, and a Content-Security-Policy (`default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`) forbids every fetch: opening the file makes no network request. The only links are the rule pages on spellwarden.ai, plain links a person may click. The report has no size cap of its own (see [Limits](#limits)).

### How to fix

Since 1.21.0 every finding of a baseline rule says how to fix it: its rule's fix sentence (`Rule.fix`, one sentence, the same in every report) and the address of the rule's page, `https://spellwarden.ai/docs/rules/<id in lower case>` (`Rule.page`), where the full steps are. Each report shows them its own way:

| Report | What it shows |
|---|---|
| `json` | each finding's `fix` and `rule_url` (the page with `utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix`), and `fix_lines` where the finding has setting lines |
| `text` | a "How to fix" section after the findings, with each rule that has an open finding, its sentence and its page, and a `write in` line under a finding that has setting lines |
| `markdown` | a "How to fix" section under the findings table for the rules of the rows the table shows, with the setting lines under their rule; the pull request comment and the merge request note are this report; its links carry `utm_medium` of the CI service (`cli` for a local run) |
| `html` | the sentence and the setting lines in each finding, above its link to the rule page |
| `sarif` | each baseline rule's `help` (text and Markdown) and its page as its `helpUri`, which a code scanning alert shows; a result's setting lines as `properties.fix_lines` |
| `cyclonedx` | each vulnerability's `recommendation`, the sentence |
| `gitlab-codequality` | nothing new: GitLab shows only the description, and the merge request note carries the fix |

The text report's section, for a scan with findings of two rules:

```
How to fix
  SW-CFG-013 Add the server's read-only switch, and give write access to a separate entry that stays disabled until the work needs it.
    https://spellwarden.ai/docs/rules/sw-cfg-013?utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix
  SW-SKL-009 Pin each install to an exact version, for example package==1.4.2 for pip, and add a lock file or hashes where the tool supports them.
    https://spellwarden.ai/docs/rules/sw-skl-009?utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix
```

Setting lines are text to copy, never applied: no report changes your files, and the SARIF file holds no `fixes` object. They are fixed words of the scanner, never text from your files, and only three rules write them, each where the lines are exact for every finding of the row:

| The finding is about | Rule | Where to write | Lines |
|---|---|---|---|
| the hosted Supabase endpoint without `read_only=true` | SW-CFG-013 | the query of the mcp.supabase.com address | `read_only=true` |
| `mcp-server-kubernetes` with no restricting switch, in a JSON configuration | SW-CFG-013 | the server's env | `"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS": "true"` |
| `mcp-server-kubernetes` with no restricting switch, in Codex's `config.toml` | SW-CFG-013 | the server's env table | `ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS = "true"` |
| an authorization code flow without PKCE required | SW-A2A-006 | the authorizationCode flow of the card's OAuth scheme | `"pkceRequired": true` |
| dynamic client registration | SW-MCP-003 | the authorization server's metadata | `"client_id_metadata_document_supported": true` |

Each row is a switch its server's or protocol's own documentation names; `src/spellwarden_scan/rules/fix_lines.py` names the page and the date it was read. A line follows the syntax of the file its finding is in: the `mcp-server-kubernetes` line is a JSON member in a JSON configuration and a TOML key in Codex's `config.toml`, in the form Codex's documentation gives for a server's environment variables. Every other server SW-CFG-013 finds, the `@supabase/mcp-server-supabase` package and `kubernetes-mcp-server` among them, gets the sentence alone.

An organisation rule has no fix sentence and no page, because its policy pack holds no fix text: its findings have `fix` and `rule_url` null, and the text and Markdown sections end with one line that says to ask the people who manage the pack. The upload of connected mode leaves out `fix`, `rule_url` and `fix_lines`, as it leaves out `tags`.

### Links in the Markdown report

Since 1.26.0 the Markdown report, which is the job summary and the pull or merge request comment, links back to Spellwarden. Every link it writes to spellwarden.ai or to the dashboard carries `utm_source=scanner`, a `utm_medium` that names the CI service the scan detected, and a `utm_campaign` that names the link:

| The scan ran on | `utm_medium` |
|---|---|
| GitHub Actions | `github-action` |
| GitLab CI/CD | `gitlab-component` |
| another CI service | `ci` |
| no CI service (a local run) | `cli` |

The medium names the CI service, not the wrapper: a workflow that runs `pipx run spellwarden` on GitHub Actions counts as `github-action`. The campaigns are `rule-docs` for each rule id in the findings table and for the last line, `rule-fix` for the "How to fix" links, `description-lint`, `analyzer` and `presets` for the guides of those sections, `dashboard` for the dashboard line and `badge` for the badge guide. The JSON, SARIF, text, CycloneDX and HTML reports keep their own links and tags in every environment (see "How to fix").

Two runs over the same files, settings and `--as-of` date write the same Markdown report when they agree on the CI service (GitHub Actions, GitLab CI/CD, another CI service, or none for a local run), on the kind of run (a pull or merge request, the default branch, another branch) and, on GitHub, on whether the repository is public or private, which the badge offer reads. No other format depends on any of these.

The findings table links each baseline rule id to its page; an organisation rule's id stays plain text. The last line names the scanner and rules versions and links to `https://spellwarden.ai/docs/rules` and to the source code on GitHub.

**The dashboard line.** In free mode (no connected mode, no "Connected mode unavailable" line and no connected-mode error) the report has one line above its last line. On GitHub Actions and GitLab CI/CD it reads:

```text
**Spellwarden dashboard:** see the findings of all your repositories in one place and turn on a live status badge for each one. [Create an account](https://dash.spellwarden.ai/signup?utm_source=scanner&utm_medium=github-action&utm_campaign=dashboard). To leave this line out, set the input `invite` to `false`, or add `--no-invite` if you run the scanner yourself.
```

The address carries the medium of the run. On another CI service and in a local run the line ends "To leave this line out, add `--no-invite`." instead. It names no price.

**The badge offer.** The job summary of a run that meets four conditions ends with a folded block that offers a "Scanned by Spellwarden" badge to copy into your README: the report is in free mode, the run is on GitHub Actions, it is a `push` or `workflow_dispatch` run of the default branch, never a pull request, and the repository is public. A scheduled run gets no block: its event does not say whether the repository is public, so the scanner treats it as private. The badge is a static image on spellwarden.ai: it shows that this repository runs the Spellwarden scan, not that the scan passed, so the block is there whatever the verdict. The block starts with the line `<!-- spellwarden-summary-only -->` and is the very end of the file. It lives only in the job summary: `spellwarden ci comment` and `spellwarden ci-run gitlab` post the report without it. They remove it only as the exact end of the file; that text anywhere else in a report cuts nothing. A report cut at 60,000 characters, or one that the block would take over that cap, has no block. A repository connected to the dashboard gets no block either: its `Results:` link leads to the repository page where its live status badge is turned on.

**Leaving them out.** `--no-invite` (since 1.26.0) leaves out the dashboard line and the badge offer; the rule links stay. The GitHub Action and the GitLab component take an input `invite`, `true` by default, and `false` passes `--no-invite`; `spellwarden ci-run gitlab` reads it as the variable `SW_INVITE`. `spellwarden scan` itself reads no settings key and no environment variable for it, so a scanned settings file cannot change it.

**Nothing is sent.** The scanner sends nothing for any of this: a link is a plain link, and the badge image is a static file on spellwarden.ai that a README viewer or GitHub's image proxy fetches like any image.

### Presets

`--preset strict|balanced|low-noise` (since 1.18.0), the setting `preset` in `.spellwarden/config.yml` and the variable `SPELLWARDEN_PRESET` change the severity of named rules, or leave a rule's findings out of the reports, from the table below. As for every setting, the flag wins over the environment, which wins over the file; without any of them there is no preset.

- **`balanced`** is each rule's own severity: the scanner's behaviour without a preset. With `balanced`, or no preset, nothing changes at all: every report and exit code is the one a scan without presets writes, with no notice and no added field.
- **`strict`** raises the medium rules that describe a direct risk (credentials, code execution, exfiltration paths, authentication) to high, so they fail at the default `--fail-on high`, and the low metadata rules to medium. It turns nothing off.
- **`low-noise`** turns off the rules about metadata, format or protocol age that fire on most benign content, and lowers to low the medium rules whose pattern is common in benign skills and configurations.

What a preset never does, whatever its table says:

- it never lowers or turns off a critical or high finding or a malicious indicator: `low-noise` changes medium and low findings only;
- it never changes an organisation rule (`SW-ORG-`) or a finding of the registry gate (`SW-REG-`): it changes the scanner's own rules (`SW-SKL-`, `SW-MCP-`, `SW-CFG-`, `SW-A2A-`) only;
- it never changes what the baseline accepts: the baseline is applied first and matches by fingerprint, which a preset does not change, and `spellwarden baseline` and `spellwarden lock` ignore presets;
- it never hides an error: an incomplete scan stays exit 2;
- in connected mode it never changes what your organisation sees: the upload carries every finding at the rule's own severity and the exit code they give, while the reports written and the process exit code are the preset's;
- on a pull or merge request the settings file is read from the base revision (see "Settings"), so a request cannot choose its own preset through the file. A `--config` file and the flag are the choice of whoever runs the scanner.

Every report says when a preset other than `balanced` applied: the notice `preset` in the text, JSON and HTML reports, a line under the verdict of the Markdown report, the first entry of a GitLab Code Quality file (or an informational entry of its own when no finding is left), the JSON report's `preset` block (`name`, `source` (`flag`, `environment` or `file`), `changed` and `off`), SARIF's `runs[0].properties.preset` and CycloneDX's `spellwarden:preset` properties. A finding whose severity a preset changed carries `preset_from`, its severity without the preset, and the reports say "raised from medium by the strict preset" or "lowered from medium by the low-noise preset". A finding a preset turns off is counted (`off`), never silently dropped. `spellwarden rules --preset NAME` prints each rule with its severity under that preset, or `off`. `--preset` cannot be used with `--user`. In the GitLab component the input `preset` reaches `spellwarden ci-run gitlab` as `SW_PRESET` and becomes `--preset` when it is not empty; the GitHub Action takes the same input from its 1.18.0 release.

A rule a later release adds is `balanced` in every preset until a release gives it a row.

<!-- presets:start -->
| Rule | Title | Default | strict | low-noise | Why |
|---|---|---|---|---|---|
| `SW-A2A-001` | Agent card does not follow A2A 1.0 | medium | medium | low | format conformance, no attack path |
| `SW-A2A-002` | Agent card uses a format older than A2A 1.0 | medium | medium | off | protocol age only |
| `SW-A2A-003` | Agent card at the path used before A2A 0.3 | medium | medium | off | protocol age only |
| `SW-A2A-004` | Agent endpoint or authentication URL not served over HTTPS | high | high | high | high: never lowered |
| `SW-A2A-005` | OAuth implicit or password flow declared (deprecated in A2A 1.0) | high | high | high | high: never lowered |
| `SW-A2A-006` | OAuth authorization code flow without PKCE required | medium | high | medium | authentication weakness: strict raises; low-noise keeps a real risk at medium |
| `SW-A2A-007` | Agent declares no authentication | medium | high | medium | authentication: as above |
| `SW-A2A-008` | API key sent in the URL query | medium | high | medium | credential exposure: as above |
| `SW-A2A-009` | Skill inherits every scope of the agent | low | medium | off | least-privilege hygiene, low |
| `SW-A2A-010` | Agent card signature does not verify | high | high | high | high: never lowered |
| `SW-A2A-011` | Agent card signature is malformed or uses a refused algorithm | high | high | high | high: never lowered |
| `SW-A2A-012` | Agent card is not signed | low | medium | off | most cards are unsigned; hygiene |
| `SW-A2A-013` | Signing key not bound to the card's host | medium | high | medium | trust of the signature: strict raises |
| `SW-A2A-014` | Agent card text contains injected instructions or hidden characters | high | high | high | high: never lowered |
| `SW-A2A-015` | Credential in the agent card | critical | critical | critical | critical: never lowered |
| `SW-A2A-016` | Agent card fetched through a redirect to another host | medium | high | medium | possible card substitution: strict raises |
| `SW-A2A-017` | Agent card signed with a shared secret that only the agent can check | medium | high | medium | unverifiable signature: strict raises |
| `SW-A2A-018` | Agent card cannot be read | high | high | high | high: never lowered |
| `SW-A2A-019` | Agent card member spelled two ways | high | high | high | high: never lowered |
| `SW-CFG-001` | Remote MCP server over plain HTTP | high | high | high | high: never lowered |
| `SW-CFG-002` | Credential written into an MCP server configuration | critical | critical | critical | critical |
| `SW-CFG-003` | MCP server launched from an unpinned package | medium | high | low | `npx -y package` style launches are the common way configurations are written; strict treats an unpinned launch as supply-chain risk |
| `SW-CFG-004` | MCP server at a raw IP address or behind a URL shortener | medium | high | medium | a hidden destination: strict raises; not common in benign configurations |
| `SW-CFG-005` | Hook pipes remote content to a shell | high | high | high | high |
| `SW-CFG-006` | Hook sends local file contents to an external host | critical | critical | critical | malicious indicator |
| `SW-CFG-007` | Hook decodes and runs an encoded payload | critical | critical | critical | malicious indicator |
| `SW-CFG-008` | Settings switch off approval prompts | high | high | high | high |
| `SW-CFG-009` | Marketplace plugin source not pinned to a commit | medium | high | medium | supply chain: strict raises |
| `SW-CFG-010` | Literal value under a secret name in an MCP server configuration | high | high | high | high |
| `SW-CFG-012` | MCP server configured to approve every tool call automatically | high | high | high | high |
| `SW-CFG-013` | Database or cluster MCP server with write access although a read-only mode exists | high | high | high | high |
| `SW-CFG-015` | MCP server given the whole home directory or the filesystem root | high | high | high | high |
| `SW-MCP-001` | Server lists tools without authentication | high | high | high | high: never lowered, although it fires on 16,546 census hosts, most of them public read-only servers by design; the largest remaining source of MCP noise |
| `SW-MCP-002` | Static key authentication instead of OAuth | medium | high | medium | authentication: strict raises |
| `SW-MCP-003` | OAuth dynamic client registration (deprecated; use Client ID Metadata Documents) | medium | medium | low | protocol migration; 5,366 census hosts (63% of OAuth servers) |
| `SW-MCP-004` | HTTP+SSE transport (deprecated) | medium | medium | low | protocol migration |
| `SW-MCP-005` | Spec version older than 2026-07-28 | low | low | off | protocol age; 13,897 census hosts |
| `SW-MCP-006` | Protocol sessions (Mcp-Session-Id) in use | medium | medium | off | protocol migration; 1,708 hosts |
| `SW-MCP-007` | Requires the initialize handshake; no server/discover | medium | medium | off | protocol migration; 13,852 hosts |
| `SW-MCP-008` | Uses deprecated Roots, Sampling or Logging | medium | medium | off | protocol migration; 715 hosts |
| `SW-MCP-009` | Endpoint not served over HTTPS | high | high | high | high |
| `SW-MCP-010` | No protected resource metadata, or issuer not validated | medium | high | medium | token audience and issuer checks: strict raises |
| `SW-MCP-011` | MCP server text contains instruction-like text | high | high | high | precision tuned on its own record (87 holdout false alarms in 1.12.0); a preset does not override it |
| `SW-MCP-012` | MCP server's tools changed since they were approved | high | high | high | high |
| `SW-MCP-013` | Tool takes a command line to run as an argument | medium | high | medium | a command primitive the user may intend (a shell server): strict raises |
| `SW-REG-001` | Skill package not admitted in the organisation's private registry | high | high | high | the organisation's policy: no preset touches it |
| `SW-REG-002` | MCP server not admitted in the organisation's private registry | high | high | high | as above |
| `SW-REG-003` | Agent content the private registry cannot judge | high | high | high | as above |
| `SW-SKL-001` | Prompt-injection phrases in skill instructions | high | high | high | high |
| `SW-SKL-002` | Hidden text: zero-width or bidirectional control characters | high | high | high | high |
| `SW-SKL-003` | Instructions to skip approvals or disable hooks | high | high | high | high |
| `SW-SKL-004` | Encoded payload decoded and executed | critical | critical | critical | malicious indicator |
| `SW-SKL-005` | Writes to agent configuration | high | high | high | high |
| `SW-SKL-006` | Destructive command without a confirmation step | medium | high | low | common in benign operations skills (`rm -rf build/`); strict treats it as a direct risk |
| `SW-SKL-007` | Remote script piped to a shell | high | high | high | high |
| `SW-SKL-008` | Sends local file contents to an external host | critical | critical | critical | malicious indicator |
| `SW-SKL-009` | Unpinned dependency install | medium | high | low | unpinned installs are the analyzer's most common benign category; strict treats them as supply-chain risk |
| `SW-SKL-010` | Bundled binary or executable file | medium | high | medium | an unreadable file: strict raises; kept at medium because a binary cannot be judged |
| `SW-SKL-011` | Hard-coded credential in the package | critical | critical | critical | critical |
| `SW-SKL-012` | Reads a credential file path without stating purpose | medium | high | low | many benign cloud skills name `~/.aws/credentials` to explain setup; strict treats it as an exfiltration path |
| `SW-SKL-013` | Network calls to raw IP addresses or URL shorteners | medium | high | medium | a hidden destination: strict raises |
| `SW-SKL-014` | Obfuscated script code | medium | high | medium | obfuscation: strict raises |
| `SW-SKL-015` | Frontmatter missing or invalid (name, description) | low | medium | off | metadata only |
| `SW-SKL-019` | Fetches external URL content into context without an allowlist | medium | high | low | common in research and documentation skills; strict treats it as an injection path |
| `SW-SKL-031` | Missing license and version metadata | low | medium | off | metadata only |
| `SW-SKL-032` | Instructions lure the user into running a password-protected download or a pasted script | critical | critical | critical | malicious indicator |
| `SW-SKL-036` | Frontmatter pre-approves an unscoped shell or interpreter | medium | high | low | many benign skills pre-approve `Bash`; strict treats unscoped execution as a direct risk |
| `SW-SKL-037` | Executable downloaded from a moving reference and run without an integrity check | medium | high | low | the same pattern as SW-SKL-009 for executables; strict raises |
<!-- presets:end -->

### Checking A2A agent cards

A team that publishes an A2A agent keeps its agent card in the repository (`public/.well-known/agent-card.json`, or a file `a2a.cards` names). The scanner finds every card, reads it as strict JSON and checks it against A2A 1.0 (the `v1.0.1` proto) without a network: the required fields, plain `http://` endpoints, the deprecated OAuth flows, authorization code flows without PKCE, API keys in a URL, agents with no authentication, skills that inherit every scope, injected instructions, hidden characters and credentials in the card's text, and cards still in the 0.2 or 0.3 shape. The nineteen `SW-A2A` rules are in the table above; findings are ordinary findings (SARIF, the request comment, Code Quality, the baseline, `--fail-on`).

```yaml
# .spellwarden/config.yml
version: 1
a2a:
  cards:                      # files to check as cards, besides the names below (at most 50)
    - deploy/agent/card.json
  keys: .well-known/jwks.json # the only keys trusted to sign the repository's cards (a JWKS, at most 64 KiB and 20 keys)
  agents:                     # remote agents to fetch under --probe (at most 20)
    - https://agent.example.com/
    - https://example.com/agents/billing/card.json
```

**Which files are cards.** `.well-known/agent-card.json` at any depth and every path in `a2a.cards` are cards whatever they hold: one that cannot be read (not UTF-8, a byte-order mark, not strict JSON, a repeated key, nested deeper than 128 levels, not an object, over 1 MiB; or a symbolic link that leaves the scan root, points at nothing or at a link or a directory, which is reported as `unsafe_path`; or a file the operating system refuses to read, reported as `unreadable`) is the finding `SW-A2A-018` (high), which fails the default check but can be accepted in the baseline, and a file that parses but is not a card shape is `SW-A2A-001`. `.well-known/agent.json` and any other file named `agent-card.json` are cards only when they parse strictly and have the card shape; otherwise they get the notice `a2a_not_card` and nothing else, because other software uses those names. A repository of deliberately broken sample cards excludes them the usual way (`exclude: ["samples/**"]`). At most 300 cards are read per run; more is the error `a2a_cards_limit` and an incomplete scan (exit 2; see [Limits](#limits)), and a card with more entries than the scanner reads is the error `truncated`. Cards are read as strict JSON, which is what A2A clients accept: a comment, a trailing comma or a byte-order mark is refused here although `.mcp.json` accepts them.

**Proto field names.** A2A 1.0 JSON spells members in camelCase (`securityRequirements`), but protobuf's JSON reader, which `a2a-sdk` uses, also accepts a member's proto field name (`security_requirements`) and keeps the later of two spellings. The scanner reads a card the same way, so every rule judges what a protobuf client would use: a plain `http://` URL under `supported_interfaces` is `SW-A2A-004` like any other, and the finding names the member by its JSON name (`/supportedInterfaces/0/url`). A member spelled only with its proto field name is `SW-A2A-001` (`proto_field_name`): rename it. A member spelled both ways is `SW-A2A-019` (high), because readers disagree on which one is the card: a reader that knows only the JSON names keeps the camelCase spelling, a protobuf reader keeps the later one, and for an optional member such as `iconUrl` or one of a scheme's kinds such as `oauth2SecurityScheme` a protobuf reader refuses the card. So `security_requirements: []` appended after a card's requirements, which tells a protobuf client that no authentication is needed, is `SW-A2A-019` and `SW-A2A-007`. `SW-A2A-015` reads every value as served, so a credential under a spelling the reader drops is still found. **0.x members in snake_case.** Since 1.5.0 the members A2A 1.0 removed are read in their snake_case spelling too (`preferred_transport`, `additional_interfaces`, `protocol_version`, `supports_authenticated_extended_card`, `capabilities.state_transition_history`, and in a scheme of the 0.x `type` form `bearer_format`, `open_id_connect_url`, `oauth2_metadata_url`, the flow names `authorization_code` and `client_credentials` and a flow's `authorization_url`, `token_url` and `refresh_url`), the way `a2a-sdk` 0.3 reads a card: the snake_case name alone is the member, and of both spellings the camelCase one is kept whatever the order. Other clients disagree (`a2a-sdk` 1.2.3 ignores the snake_case spelling of the four top-level members, the JavaScript SDK reads camelCase only), so a 0.x member spelled only in snake_case is `SW-A2A-001` (`legacy_field_name`) and one spelled both ways is `SW-A2A-019` (`name_kept`). What it holds is judged like the camelCase member: a plain `http://` URL under `additional_interfaces` is `SW-A2A-004`, and `protocol_version` gives the card its format.

**Older cards and the checklist.** A card in the 0.2 or 0.3 shape (`SW-A2A-002`), at `/.well-known/agent.json` (`SW-A2A-003`), or with an OAuth implicit or password flow (`SW-A2A-005`) gets a migration status and a checklist in the report: `ready` (a 1.0 card with nothing left to change), `to_migrate` or `invalid` (not a card), and up to thirteen steps in a fixed order, from serving the card at `/.well-known/agent-card.json` to signing it again, the last always being to scan again. A patch number in `protocolVersion` ("1.0.1") is a checklist step, not a finding, as the specification says patch numbers SHOULD NOT be used. The OAuth implicit and password flows are deprecated in 1.0 and documented as removed, but the protocol's proto still carries them as deprecated fields, so they are a finding and not a parse error.

**Signatures.** A signed card is a JWS over the card without its `signatures`, canonicalised with RFC 8785 (`spellwarden_scan.jcs_canonicalize`). The scanner verifies ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, `Ed25519` (RFC 9864) and `EdDSA` with an Ed25519 key, with RSA keys of at least 2048 bits. `none` and unknown algorithms are refused (`SW-A2A-011`, high). `HS256`, `HS384` and `HS512` use a secret that only the agent holds, so no one else can check them: the signature is `unverified` and the rule is `SW-A2A-017` (medium), as is Ed448, which this release does not verify. A DER-encoded ECDSA signature, as cloud KMS and HSM signing APIs return, is reported as such (`SW-A2A-011`): a JWS needs the fixed-length `R || S` form of RFC 7518 3.4. A number outside what the scanner canonicalises (an integer above 2^53) makes the signature malformed with that detail. The scanner tries up to three forms of the signed bytes (the card as served, the card as a proto-based signer writes it, and the form `a2a-sdk` signs, which also leaves out empty values) and records which one matched and which members that form does not cover (`unsigned_members`). A legacy 0.x member that no form covers (`security`, `supportsAuthenticatedExtendedCard` and the others `SW-A2A-002` lists) makes the signature `invalid` (`SW-A2A-010`), because clients still read it. So does a member spelled with its proto field name (`supported_interfaces`, `security_requirements`, `preferred_transport`): protobuf's JSON reader accepts that spelling too and the later of two spellings wins, so such a member added after signing would replace the signed one for a proto-based client. So does a whole entry of `securityRequirements` (a card's or a skill's) that no form covers: the `a2a-sdk` form leaves out only `{}`, the alternative "no authentication", which would tell clients anonymous calls are allowed. A vendor member that no form covers, and any other empty value the `a2a-sdk` form leaves out (a scheme entry with no scopes, `schemes: {"bearer": {}}`), is only listed in `unsigned_members` and the signature stays `verified`; the Markdown report names them ("verified without these members"). `a2a-sdk` 1.2.3 cannot sign an empty value, so a card that must cover one, such as a requirement with no scopes, needs a signer that signs the card as served or in the proto form.

*Which key.* The report says which kind of key verified a signature, because only one of them says who signed. With `a2a.keys` set, that file is the only trusted source: a card signed by a key that is not in it is `untrusted_key` (`SW-A2A-010`, high), whatever its `jku` says, and no `jku` is fetched. A signature verified this way says the card was signed by a key the repository's base revision trusts. Every key needs a `kid`, because keys are matched to signatures by `kid` alone; a key without one gets the notice `a2a_key_without_kid` and is never used, and a key with a private member is dropped with the notice `a2a_private_key_in_jwks`. A keys file that is named but absent from the revision read is the notice `a2a_keys_missing` (the signed cards are `unverified`); one that is present and is not a key set is the error `settings_invalid` (exit 2), because a trusted key file that cannot be read must not become no keys. Without `a2a.keys`, under `--probe` the scanner fetches the key set a signature's `jku` names (HTTPS, a public address, at most 64 KiB and 20 keys, 20 key sets per run) and says "verified with the key set the card names" (a key set that cannot be fetched or read leaves the signature `unverified` with the notice `a2a_keys_unavailable`): that says only that whoever serves the key set signed the card, and for a `jku` on the card's own host, whoever controls the host. A `jku` on a host that is neither the card's host nor a subdomain of it is `SW-A2A-013` (medium), as is a key carried in the signature header itself (`jwk`, `x5c`, `x5u`), which is never trusted. Without `--probe` and without `a2a.keys` a signed card is `unverified` with the notice `a2a_signature_unverified`, which says how to verify it.

*Merge the keys first.* On a pull or merge request `a2a.keys` and the keys file are read from the base revision, never from the request. (A scan with `--staged` reads them from the index: see "What a scan reads".) A request that adds a keys file and a signed card together is therefore verified against a base where neither exists: its cards are `unverified` on that request and verified from the next one on. Merge the keys first, or accept one unverified run.

**Remote agents.** With `--probe`, each URL in `a2a.agents` is fetched from the runner with one `GET` and no header but `Accept` and the scanner's user agent: no `Authorization`, no cookie, nothing from your repository. A URL ending in `/` is a base URL at any path: the card is at the URL followed by `.well-known/agent-card.json` (`https://host/agents/billing/` gives `https://host/agents/billing/.well-known/agent-card.json`), and a `404` or `410` there is followed by one request for `.well-known/agent.json` (`SW-A2A-003`); any other URL is the card's own address and is fetched as given, so end a URL with `/` for discovery or give the card's full URL. Addresses must be public, a redirect to another host is `SW-A2A-016`, and the requests share the probe budget (300 requests and 120 seconds for the whole run, MCP servers first). An `http://` URL is never fetched (`SW-A2A-004` when its host is public by its text; an address such as `10.0.0.5`, `localhost` or `billing.internal` is a statement of fact and gets no finding). A remote agent that cannot be fetched is the report status `failed` and the notice `a2a_fetch_failed`, never an error: its outage must not fail your build. **Findings on a remote agent's card do not fail a pull or merge request**, because that card belongs to someone else and changes on its own schedule; they are reported, uploaded and counted on every other run (push, schedule, manual, local), where a team decides whether to keep calling the agent. Without `--probe` the agents are listed as skipped with the notice `a2a_agents_need_probe`; on a request from a fork nothing is fetched.

**What is not checked.** The extended card (it needs authentication), the agent's behaviour on the wire, TLS versions and HSTS of its endpoints, caching headers, and key expiry or revocation. The specification says "Expired or revoked keys MUST NOT be used for verification" (8.4.3) but defines no way to know a key is expired or revoked: the trusted key file is your own list, so removing a key from `a2a.keys` is how a repository revokes it.

**Installing.** The scanner verifies signatures with the `cryptography` package, a compiled dependency that is imported by one module only. It installs from wheels: on Linux (glibc and musl, x86_64 and aarch64), macOS and Windows; a platform without a wheel cannot install 1.3.0. The image and the Action's pinned requirements carry the same packages with their hashes. The Action runs on the Python 3.11 or newer it finds on the runner; the locked `cffi` ships wheels for Python 3.11 to 3.14 at the time of this release, so on a newer Python add `actions/setup-python` until a later scanner release.

### Description lint

Since 1.17.0 every repository scan checks the `description` of each skill it finds: the text an agent reads to decide whether to load the skill. Four checks, made without a model:

| Check | Notes a description that |
|---|---|
| `SW-LINT-001` | is missing, shorter than 40 characters or longer than 1,024 (agents read at most 1,024) |
| `SW-LINT-002` | has no use-when clause: none of "use when", "use this when", "when the user" or "triggers on", in any case |
| `SW-LINT-003` | names no trigger phrase: no quoted phrase (in straight or curly quotes or backticks) and no list of requests ("such as", "for example", "e.g.", "like", "including" or a colon, then two or more items split by a comma, the first of at most 120 characters) |
| `SW-LINT-004` | overlaps the description of another skill of the same scan: the Jaccard similarity of their word sets is 0.6 or more, after case folding and without common words such as "the", "use" and "when"; the note is on both skills, each naming the other |

A missing or blank description gets `SW-LINT-001` alone. The notes are informational: they are not findings, are not baselined, and never change the exit code, a rule count or the outcome of `--fail-on`. A message never quotes the description. The JSON report's `lint` lists every skill of the scan in path order, `{"skill", "notes": [{"id", "severity": "info", "message", "other_path"}], "left_out"}`, with an empty list of notes where a description triggers none, and the notice `description_lint` counts them. The text report shows them in a "Description lint" block, the Markdown report in a "Description lint" section, and SARIF as results of level `note` with `properties.description_lint: true`, whose four descriptors follow the rules at the end of the rule table. The GitLab Code Quality report, the CycloneDX document and the upload of connected mode carry none of them, and `scan --user` does not lint.

The library returns the single-skill notes too: `scan_skill_package` puts `SW-LINT-001` to `SW-LINT-003` in `SkillScanResult.lint` (each a `spellwarden_scan.model.LintNote`), and `spellwarden_scan.lint.check(skills)` runs all four over a list of `SkillMeta(path, name, description)`. What each check means and how to fix a description: [spellwarden.ai/docs/activation-checks](https://spellwarden.ai/docs/activation-checks?utm_source=scanner&utm_medium=cli&utm_campaign=description-lint).

### Model-assisted analyzer: `--analyze`

Off by default. Since 1.17.0, `spellwarden scan --analyze` also sends each skill's SKILL.md and scripts to a model endpoint you name, for an advisory review in eight categories: `instruction_override`, `data_exfiltration`, `credential_access`, `destructive_action`, `remote_code`, `obfuscation`, `deceptive_description` and `excessive_permission`.

```
SPELLWARDEN_MODEL_KEY=... spellwarden scan . --analyze --model-endpoint https://llm.example.com/v1 --model NAME
    [--analyze-max-bytes N] [--analyze-cache DIR]
```

- **Your endpoint and your key.** `--model-endpoint` is the base URL of an OpenAI-compatible API: the request goes to `<base>/chat/completions`, or to the URL as given when it already ends that way. The key comes from the environment variable `SPELLWARDEN_MODEL_KEY` only, never a flag, so it stays out of shell history and CI logs; it is sent as `Authorization: Bearer`, and without it no `Authorization` header is sent (a local server may need none). Nothing goes to Spellwarden. The key is never written to a report, a log line, the cache or an error message: an error of the endpoint is reported by its status and its message, masked and cut to 200 characters.
- **The address rules.** `https` for any host; `http` only for a loopback address (127.0.0.1, `[::1]` or `localhost`); no user name, password, query or fragment in the URL. The endpoint may be a private address, as a local LiteLLM or Ollama server is, because it is the one origin you configured, but never a link-local address such as the cloud metadata service. No redirect is followed and no proxy is used. The client waits 10 s to connect and 120 s for the answer, and refuses an answer over 1 MiB.
- **What is sent.** SKILL.md first, then the scripts in path order: files under `scripts/`, files with an executable mode and files ending in `.py`, `.sh`, `.bash`, `.js`, `.mjs`, `.ts`, `.ps1`, `.rb` or `.pl`, among the files the skill's package hash covers (a nested skill is left out). The executable mode of a file git tracks is the one in the index, on every system. On Windows a file git does not track has no executable mode, so such a script is chosen by its directory and extension only (the notice `exec_bits_unknown` says when that applies). Every file's text is masked with `mask_credentials` before it is sent. The files sit inside a block delimited by a random boundary, the model is told that the block is data and that an instruction inside it is evidence, and the answer must repeat a nonce. The nonce checks that the reply answers this request in the schema; it does not stop a skill that tells the model to repeat it, so it is no defence against a skill that steers the model: the defences are that the result is advisory, never a finding, and that the rules judge the same skill beside it (`rules_found`).
- **What comes back.** The JSON report gains `analysis`, one entry per skill: `skill_file` (the skill file as the repository writes it, a case variant such as `skills/x/skill.md` included; span paths and SARIF locations name it the same way), `status` (`analyzed`, `no_verdict`, `incomplete` or `not_analyzed`), `package_sha256`, `analyzer_version`, `model`, `measured`, `measured_on`, `way` (`endpoint`), `cached`, and for each category the `verdict` (`issue` or `none`), the `confidence` (`low`, `medium` or `high`), a `summary` of at most 300 characters, at most five quoted `spans` (`{"path", "line", "text"}`, 200 characters each) with the count left out, and `rules_found`, true when a rule found an open issue of that category in the same skill. An answer that is not one JSON object of the schema, lacks a category or the nonce, gives a category the verdict `issue` without a span or `none` with spans (`off_schema`, since 1.19.0), or quotes a span that is not at the line it names is `no_verdict` with its reason, never clean: a span must be at least 8 characters once whitespace is collapsed (`span_too_short` otherwise), and it must occur, whitespace collapsed, in the lines of the file it names from that line through its own line count plus one more (`span_not_in_source` otherwise), so the line a report shows holds the quoted text or sits one line above it; summaries and spans are masked again. The notice `model_assisted` counts what was analysed; the text and Markdown reports show each skill; SARIF lists each category with an issue as a result of level `note` with `properties.model_assisted: true` (rule ids `SW-ANALYZER-INSTRUCTION-OVERRIDE` and so on). The GitLab Code Quality report, the CycloneDX document and the upload of connected mode carry none of it, and `--analyze` cannot be used with `--user`.
- **Advisory, always.** An analysis is never a finding: its verdicts never change the exit code, a rule count, the outcome of `--fail-on` or what the baseline accepts (for a skill it could not read, see [Limits](#limits)). "No issue found by the model" is the most it says.
- **The cache.** `--analyze-cache DIR` keeps each analysed result in `DIR`, one file per package hash, analyzer version and model, and reuses it (`cached: true`). A file holds the categories only, never the key, the request or the answer as sent. A cache file that cannot be read is analysed again, and a directory that cannot be written is said in the notice `model_assisted`: neither fails the scan. A file there is read back as a result, so `DIR` must be a directory you trust, and it should sit outside the scanned repository, where a change to the repository could plant one; a cached result is checked like an answer, and one with a summary, span or span count past its cap, or a credential-shaped value `mask_credentials` would still mask, is analysed again.
- **In the GitLab component.** Its inputs `analyze` (`true` or `false`), `model-endpoint` (an `https://` address without spaces or line breaks) and `model` reach `spellwarden ci-run gitlab` as `SW_ANALYZE`, `SW_MODEL_ENDPOINT` and `SW_MODEL`; with `analyze` unset or `false` the job runs the scan it ran before. No input takes the key: add it as a masked CI/CD variable `SPELLWARDEN_MODEL_KEY` (Settings, CI/CD, Variables). With `analyze: true`, an empty or malformed endpoint or model, or a missing key, stops the job with a usage error (exit 2) before the scan, and an endpoint that holds a user name, password, query or fragment is refused without being shown. A merge request from a fork gets no masked variables: there a missing key is no error, the scan runs without the analyzer, and the notice `analyzer_no_key` says so in the report and the job log.
- **Measured rates.** None are published for analyzer version 1 yet, so every result says "Unmeasured model". The detection and false-positive rates will be measured on fresh held-out skills and published with a later release; from then on only a result from another model says "Unmeasured model".

How it works, what is sent and the rates: [spellwarden.ai/docs/model-assisted-analyzer](https://spellwarden.ai/docs/model-assisted-analyzer?utm_source=scanner&utm_medium=cli&utm_campaign=analyzer).

### Probing: `--probe`

Off by default. With `--probe`, the scanner also fetches the cards of the remote agents `a2a.agents` lists and the key sets the repository's signed cards name (see "Checking A2A agent cards"), under the same budget as the MCP probes, which come first. It sends the unauthenticated MCP probe of the hosted product to every remote server of an MCP configuration whose URL is `https://`, from your machine or runner, and adds the `SW-MCP` findings and the 2026-07-28 migration checklist to the report. Besides `tools/list` it asks a server that declares the capability for its prompts, resources and resource templates (`prompts/list`, `resources/list`, `resources/templates/list`, only when `tools/list` was not refused for want of a credential); since 1.16.1 it follows `nextCursor` for each list, at most 10 pages of one list and 12 later-page requests per server (see [Limits](#limits)); the prober sends no method outside a list of seven and so never `resources/read`, `prompts/get` or `tools/call`. It sends the URL and the protocol's own requests only: never a header, environment value or argument from the configuration, never an `Authorization` header or a cookie. Addresses must be public; at most 50 servers, 4 at a time, 300 requests and 120 seconds for the whole run. A URL holding a `${...}` reference is not probed. `--probe` is switched off on a pull or merge request from a fork or from Dependabot.

A server's answers are read as JSON. A string in them that holds a lone surrogate (a `\uD800` to `\uDFFF` escape without its pair, which JSON allows but no UTF-8 file can hold) is read with U+FFFD in its place, since 1.18.0, so the findings, the reports and the lock file show U+FFFD and the scan ends as it would without it. A pair written as two escapes is one character and is kept. Connected mode reads the service's answers the same way. When two keys of one object would become equal this way, both are kept: the later one gets U+FFFD and a number appended, so no value is dropped.

`--probe-private` (or `SPELLWARDEN_PROBE_PRIVATE=true`) also allows the private addresses of the configured servers themselves (never a link-local address such as the cloud metadata service, and never an address that a server's answer or redirect points to), but only on a local run or on a push, schedule or manual run of a protected branch or tag in GitHub Actions or GitLab CI; anywhere else it is ignored with the notice `probe_private_untrusted`, because whoever can push a revision controls the endpoints it names. It cannot be set in `.spellwarden/config.yml`.

### Scanning a workstation

`spellwarden scan --user` scans the agent configuration in your home directory instead of a repository: the MCP servers, skills, plugins and marketplaces, hooks and instruction files of Claude Code, Claude Desktop, Cursor, VS Code, Windsurf (Devin Desktop), Codex and Gemini CLI, on Linux, macOS and Windows. It reads the files of the table below for the running system, judges them with the rules of a repository scan (the `SW-MCP` rules need `--probe`, as always) and reports per client. The text and Markdown reports start with one line per client (`Claude Code: 4 servers, 2 skills, 1 plugin, 1 marketplace, 2 hooks, 2 instruction files`, or `not found`), the JSON report adds `clients` (`client`, `found`, `roots`) and each item's `clients`, and SARIF results carry `properties.clients`. Paths are shown relative to the home directory (`~/.claude.json`), or under the variable that moved them (`$CODEX_HOME/config.toml`), never as absolute paths. A Claude Code server configured for one project is the item `~/.claude.json#<project>#<name>`, and its `scope` is the project directory: `~/work/app` inside the home, `outside-home:<8 hex>/<last segment>` outside it, so no directory above the project is printed.

```
spellwarden scan --user [--inventory] [--format FMT [--output FILE]]... [--fail-on LEVEL] [--probe]
                 [--upload --device-label TEXT] [--quiet | --verbose]
```

It never changes a client file (every file is opened read-only), never starts a local server, probes remote servers only under `--probe`, sends no usage ping, and reads no `.spellwarden/config.yml`, baseline or lock: `--user` with a `PATH`, `--locked`, `--baseline` or `--config` is a usage error (exit 2). It never starts connected mode: `SPELLWARDEN_ORG`, `SPELLWARDEN_API_KEY` and the CI token variables are taken out of the environment and ignored. `--inventory` lists what is installed without judging it: no rule, no finding and no probe (`--probe` is a usage error), formats `text`, `json` and `cyclonedx` only, exit 0, or 2 when a file could not be read.

Secrets stay on the machine. An endpoint or a marketplace source is shown as `scheme://host[:port]/path`, without user name, query or fragment, with a credential in a path segment masked (since 1.16.2 also, for an endpoint, the value of a `name=value` segment whose name, read percent-decoded, ends in `key`, `apikey`, `token`, `secret`, `password`, `passwd`, `sig` or `signature`) and, since 1.16.2, every character an IRI does not allow there percent-encoded; a stdio server by its pinned command identity (`cmd:npx pkg@1.2.0 args=<hash>`) or the reason it has none; and a finding on a configuration document by its location, without an excerpt, because those files hold environment values, headers and tokens. No environment value, header, argument or `bearer_token_env_var` target is printed, written or uploaded.

Since 1.20.0 `SW-CFG-012` and `SW-CFG-013` also judge the MCP servers of Codex's `config.toml` and Gemini CLI's `settings.json`: a Gemini `trust: true`, a Codex `default_tools_approval_mode = "approve"` or a database or cluster server with write access is a high finding, so a workstation that passed can fail. `scan --user` takes no baseline: the way out is the client's own setting, or `--fail-on critical`. `--follow-links` is a usage error with `--user`: the scan already follows a link to a directory inside the home.

A symbolic link at a path of the table, at a directory the table lists entries of, or inside a skill is followed when its target is a regular file or a directory inside the home directory (the links a dotfile manager makes). The item keeps the path it was reached by, and each real file or directory is read once, so a skills directory that two clients read is one set of items with both clients. A link to a place outside the home directory that leads to files the scan reads, and a link to a directory inside a skill, is not followed and is the error `unreadable` (since 1.16.1): what it leads to is not judged, so the scan is incomplete; the error names the way out (see [Limits](#limits)). A link out of the home that leads to nothing the scan reads, and a link whose target is missing or a loop, is the notice `symlink_skipped`. With `--verbose`, a client with no file of the table is named on stderr (the notice `client_not_found`); the JSON report lists it with `found: false`. A client is found when a file or directory that only it reads exists: a directory that several clients read (`~/.agents/skills`, and `~/.claude/skills`, which VS Code reads too) is listed for the clients found, or for every client that reads it when none of them was found.

<!-- clients:start -->
| Client | Systems | Path | Reads | Source | Checked |
|---|---|---|---|---|---|
| Claude Code | all | `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json` when `CLAUDE_CONFIG_DIR` is set) | MCP servers of the user scope (`mcpServers`) and of each project (`projects.<directory>.mcpServers`) | <https://code.claude.com/docs/en/claude-directory> | 2026-11-14 |
| Claude Code | all | `$CLAUDE_CONFIG_DIR/settings.json` | hooks, permissions, `enabledPlugins`, `extraKnownMarketplaces` | <https://code.claude.com/docs/en/settings> | 2026-11-14 |
| Claude Code | all | `$CLAUDE_CONFIG_DIR/skills` | skills (`<name>/SKILL.md`) | <https://code.claude.com/docs/en/claude-directory> | 2026-11-14 |
| Claude Code | all | `$CLAUDE_CONFIG_DIR/CLAUDE.md` | instruction file (`claude-md`) | <https://code.claude.com/docs/en/claude-directory> | 2026-11-14 |
| Claude Code | all | `$CLAUDE_CONFIG_DIR/rules/**/*.md` | instruction files (`claude-rule`), subfolders included | <https://code.claude.com/docs/en/memory#user-level-rules> | 2026-11-23 |
| Claude Code | all | `$CLAUDE_CONFIG_DIR/commands/**/*.md` | commands (`claude-command`), subfolders included | <https://code.claude.com/docs/en/settings-reference> | 2026-11-23 |
| Claude Code | all | `$CLAUDE_CONFIG_DIR/agents/**/*.md` | subagents (`claude-agent`), subfolders included | <https://code.claude.com/docs/en/sub-agents> | 2026-11-23 |
| Claude Code | all | `$CLAUDE_CONFIG_DIR/output-styles/*.md` | output styles (`claude-output-style`) | <https://code.claude.com/docs/en/output-styles> | 2026-11-23 |
| Claude Code | all | `$CLAUDE_CONFIG_DIR/plugins/installed_plugins.json` | installed plugins, and in each plugin's directory its skills, commands (`claude-command`), subagents (`claude-agent`), `.mcp.json`, `hooks/hooks.json` and `.claude-plugin/plugin.json` (the layout of <https://code.claude.com/docs/en/plugins/manifest-reference>) | <https://code.claude.com/docs/en/plugins/loading> | 2026-11-23 |
| Claude Code | all | `$CLAUDE_CONFIG_DIR/plugins/known_marketplaces.json` | marketplaces and their sources | <https://code.claude.com/docs/en/plugins/loading> | 2026-11-14 |
| Claude Desktop | Linux | `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json` | MCP servers (`mcpServers`) | <https://modelcontextprotocol.io/docs/develop/connect-local-servers> | 2026-11-14 |
| Claude Desktop | macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` | MCP servers (`mcpServers`) | <https://modelcontextprotocol.io/docs/develop/connect-local-servers> | 2026-11-14 |
| Claude Desktop | Windows | `%APPDATA%/Claude/claude_desktop_config.json` | MCP servers (`mcpServers`) | <https://modelcontextprotocol.io/docs/develop/connect-local-servers> | 2026-11-14 |
| Cursor | all | `~/.cursor/mcp.json` | MCP servers (`mcpServers`) | <https://cursor.com/docs/context/mcp> | 2026-11-14 |
| Cursor | all | `~/.cursor/hooks.json` | hooks | <https://cursor.com/docs/agent/hooks> | 2026-11-14 |
| Cursor | all | `~/.cursor/skills` | skills (`<name>/SKILL.md`) | <https://cursor.com/docs/skills> | 2026-11-23 |
| Cursor | all | `~/.agents/skills` | skills (`<name>/SKILL.md`) | <https://cursor.com/docs/skills> | 2026-11-23 |
| Cursor | all | `~/.claude/skills` | skills (`<name>/SKILL.md`) | <https://cursor.com/docs/skills> | 2026-11-23 |
| Cursor | all | `~/.codex/skills` | skills (`<name>/SKILL.md`) | <https://cursor.com/docs/skills> | 2026-11-23 |
| Cursor | all | `~/.cursor/agents/*.md` | subagents (`cursor-agent`) | <https://cursor.com/docs/subagents> | 2026-11-23 |
| Cursor | all | `~/.claude/agents/*.md` | subagents (`claude-agent`) | <https://cursor.com/docs/subagents> | 2026-11-23 |
| Cursor | all | `~/.codex/agents/*.md` | subagents (`codex-agent`) | <https://cursor.com/docs/subagents> | 2026-11-23 |
| Cursor | all | `~/.cursor/plugins/local/*` | local plugins: each plugin's `.cursor-plugin/plugin.json` or `plugin.json`, `mcp.json`, `hooks/hooks.json`, skills, rules (`cursor-mdc`), subagents (`cursor-agent`) and commands (`cursor-command`) | <https://cursor.com/docs/plugins> | 2026-11-23 |
| VS Code | all | `$COPILOT_HOME/mcp-config.json` | MCP servers (`mcpServers`) | <https://code.visualstudio.com/docs/copilot/reference/mcp-configuration> | 2026-11-14 |
| VS Code | all | `$COPILOT_HOME/skills` | skills (`<name>/SKILL.md`) | <https://code.visualstudio.com/docs/copilot/customization/agent-skills> | 2026-11-14 |
| VS Code | all | `~/.claude/skills` | skills (`<name>/SKILL.md`) | <https://code.visualstudio.com/docs/copilot/customization/agent-skills> | 2026-11-14 |
| VS Code | all | `~/.agents/skills` | skills (`<name>/SKILL.md`) | <https://code.visualstudio.com/docs/copilot/customization/agent-skills> | 2026-11-14 |
| VS Code | all | `$COPILOT_HOME/copilot-instructions.md` | instruction file (`copilot-instructions`) | <https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference> | 2026-11-23 |
| VS Code | all | `$COPILOT_HOME/instructions/**/*.instructions.md` | instruction files (`github-instructions`), subfolders included | <https://code.visualstudio.com/docs/agents/reference/custom-instructions-reference> | 2026-11-23 |
| VS Code | all | `$COPILOT_HOME/agents/**/*.md` | custom agents (`github-agent`), subfolders included | <https://code.visualstudio.com/docs/agents/reference/custom-agent-file-reference> | 2026-11-23 |
| VS Code | all | `$COPILOT_HOME/hooks/*.json` | hooks (each `bash`, `powershell` and `command`) | <https://docs.github.com/en/copilot/reference/hooks-reference> | 2026-11-23 |
| VS Code | all | `$COPILOT_HOME/settings.json` | inline hooks, `enabledPlugins`, `extraKnownMarketplaces` | <https://docs.github.com/en/copilot/reference/hooks-reference> | 2026-11-23 |
| VS Code | all | `$COPILOT_HOME/installed-plugins/*/*` | installed plugins (`_direct/<source id>` included): each plugin's manifest, `.mcp.json`, hooks, skills and custom agents (`github-agent`) | <https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference> | 2026-11-23 |
| VS Code | all | `~/.claude/rules/**/*.md` | instruction files (`claude-rule`), subfolders included | <https://code.visualstudio.com/docs/agents/reference/ai-settings> | 2026-11-23 |
| VS Code | all | `~/.claude/CLAUDE.md` | instruction file (`claude-md`) | <https://code.visualstudio.com/docs/agents/reference/custom-instructions-reference> | 2026-11-23 |
| VS Code | all | `~/.claude/agents/**/*.md` | custom agents (`claude-agent`), subfolders included | <https://code.visualstudio.com/docs/agents/reference/custom-agent-file-reference> | 2026-11-23 |
| VS Code | Linux | `$XDG_CONFIG_HOME/Code/User/mcp.json`<br>`$XDG_CONFIG_HOME/Code/User/profiles/*/mcp.json`<br>`$XDG_CONFIG_HOME/Code - Insiders/User/mcp.json`<br>`$XDG_CONFIG_HOME/Code - Insiders/User/profiles/*/mcp.json` | MCP servers (`servers`) | <https://code.visualstudio.com/docs/copilot/reference/mcp-configuration> (the folder from <https://code.visualstudio.com/docs/configure/settings> and <https://code.visualstudio.com/docs/configure/profiles>) | 2026-11-15 |
| VS Code | macOS | `~/Library/Application Support/Code/User/mcp.json`<br>`~/Library/Application Support/Code/User/profiles/*/mcp.json`<br>`~/Library/Application Support/Code - Insiders/User/mcp.json`<br>`~/Library/Application Support/Code - Insiders/User/profiles/*/mcp.json` | MCP servers (`servers`) | <https://code.visualstudio.com/docs/copilot/reference/mcp-configuration> (the folder from <https://code.visualstudio.com/docs/configure/settings> and <https://code.visualstudio.com/docs/configure/profiles>) | 2026-11-15 |
| VS Code | Windows | `%APPDATA%/Code/User/mcp.json`<br>`%APPDATA%/Code/User/profiles/*/mcp.json`<br>`%APPDATA%/Code - Insiders/User/mcp.json`<br>`%APPDATA%/Code - Insiders/User/profiles/*/mcp.json` | MCP servers (`servers`) | <https://code.visualstudio.com/docs/copilot/reference/mcp-configuration> (the folder from <https://code.visualstudio.com/docs/configure/settings> and <https://code.visualstudio.com/docs/configure/profiles>) | 2026-11-15 |
| Windsurf (Devin Desktop) | Linux, macOS | `$XDG_CONFIG_HOME/devin/mcp_config.json` (and below `~/.config/` when `XDG_CONFIG_HOME` points elsewhere) | MCP servers (`mcpServers`, remote ones by `serverUrl` or `url`) | <https://docs.devin.ai/desktop/devin-local/customizations> | 2026-11-23 |
| Windsurf (Devin Desktop) | Windows | `%APPDATA%/devin/mcp_config.json` | MCP servers (`mcpServers`, remote ones by `serverUrl` or `url`) | <https://docs.devin.ai/desktop/devin-local/customizations> | 2026-11-23 |
| Windsurf (Devin Desktop) | all | `~/.devin/global_rules.md` | instruction file (`devin-rules`) | <https://docs.devin.ai/desktop/devin-local/customizations> | 2026-11-23 |
| Windsurf (Devin Desktop) | all | `~/.devin/rules/*.md` | instruction files (`devin-rules`) | <https://docs.devin.ai/desktop/devin-local/customizations> | 2026-11-23 |
| Windsurf (Devin Desktop) | Linux, macOS | `$XDG_CONFIG_HOME/devin/skills` (and below `~/.config/` when `XDG_CONFIG_HOME` points elsewhere) | skills (`<name>/SKILL.md`) | <https://docs.devin.ai/cli/extensibility/skills/overview> (the folder from <https://docs.devin.ai/desktop/devin-local/customizations>) | 2026-11-23 |
| Windsurf (Devin Desktop) | Windows | `%APPDATA%/devin/skills` | skills (`<name>/SKILL.md`) | <https://docs.devin.ai/cli/extensibility/skills/overview> (the folder from <https://docs.devin.ai/desktop/devin-local/customizations>) | 2026-11-23 |
| Windsurf (Devin Desktop) | Linux, macOS | `$XDG_CONFIG_HOME/devin/AGENTS.md`<br>`$XDG_CONFIG_HOME/devin/AGENT.md` (and below `~/.config/` when `XDG_CONFIG_HOME` points elsewhere) | instruction files (`agents-md`) | <https://docs.devin.ai/cli/extensibility/rules> (the folder from <https://docs.devin.ai/desktop/devin-local/customizations>) | 2026-11-23 |
| Windsurf (Devin Desktop) | Windows | `%APPDATA%/devin/AGENTS.md`<br>`%APPDATA%/devin/AGENT.md` | instruction files (`agents-md`) | <https://docs.devin.ai/cli/extensibility/rules> (the folder from <https://docs.devin.ai/desktop/devin-local/customizations>) | 2026-11-23 |
| Windsurf (Devin Desktop) | Linux, macOS | `$XDG_CONFIG_HOME/devin/agents/*.md`<br>`$XDG_CONFIG_HOME/devin/agents/*/AGENT.md` (and below `~/.config/` when `XDG_CONFIG_HOME` points elsewhere) | subagents (`devin-agent`) | <https://docs.devin.ai/cli/subagents> (the folder from <https://docs.devin.ai/desktop/devin-local/customizations>) | 2026-11-23 |
| Windsurf (Devin Desktop) | Windows | `%APPDATA%/devin/agents/*.md`<br>`%APPDATA%/devin/agents/*/AGENT.md` | subagents (`devin-agent`) | <https://docs.devin.ai/cli/subagents> (the folder from <https://docs.devin.ai/desktop/devin-local/customizations>) | 2026-11-23 |
| Windsurf (Devin Desktop) | Linux, macOS | `$XDG_CONFIG_HOME/devin/config.json` (and below `~/.config/` when `XDG_CONFIG_HOME` points elsewhere) | hooks (`hooks`) | <https://docs.devin.ai/cli/extensibility/hooks/overview> (the folder from <https://docs.devin.ai/desktop/devin-local/customizations>) | 2026-11-23 |
| Windsurf (Devin Desktop) | Windows | `%APPDATA%/devin/config.json` | hooks (`hooks`) | <https://docs.devin.ai/cli/extensibility/hooks/overview> (the folder from <https://docs.devin.ai/desktop/devin-local/customizations>) | 2026-11-23 |
| Windsurf (Devin Desktop) | all | `~/.agents/skills` | skills (`<name>/SKILL.md`) | <https://docs.devin.ai/cli/extensibility/skills/overview> | 2026-11-23 |
| Windsurf (Devin Desktop) | all | `~/.codeium/windsurf/mcp_config.json`<br>`~/.codeium/windsurf-next/mcp_config.json`<br>`~/.codeium/windsurf-insiders/mcp_config.json` | MCP servers (`mcpServers`, remote ones by `serverUrl` or `url`) | <https://docs.devin.ai/cli/reference/configuration/read-config-from> | 2026-11-23 |
| Windsurf (Devin Desktop) | all | `~/.codeium/windsurf/skills`<br>`~/.codeium/windsurf-next/skills`<br>`~/.codeium/windsurf-insiders/skills` | skills (`<name>/SKILL.md`) | <https://docs.devin.ai/cli/extensibility/skills/overview> | 2026-11-23 |
| Windsurf (Devin Desktop) | all | `~/.codex/skills` | skills (`<name>/SKILL.md`) | <https://docs.devin.ai/cli/reference/configuration/read-config-from> | 2026-11-23 |
| Windsurf (Devin Desktop) | all | `~/.copilot/skills` | skills (`<name>/SKILL.md`) | <https://docs.devin.ai/cli/reference/configuration/read-config-from> | 2026-11-23 |
| Codex | all | `$CODEX_HOME/config.toml` | MCP servers (`[mcp_servers.<id>]`), hooks (`[hooks]`, `notify`), plugins (`[plugins]`), marketplaces (`[marketplaces]`) | <https://learn.chatgpt.com/docs/config-file/config-reference> | 2026-11-14 |
| Codex | all | `$CODEX_HOME/hooks.json` | hooks | <https://learn.chatgpt.com/docs/hooks> | 2026-11-14 |
| Codex | all | `~/.agents/skills` | skills (`<name>/SKILL.md`) | <https://learn.chatgpt.com/docs/build-skills> | 2026-11-14 |
| Codex | all | `$CODEX_HOME/AGENTS.md`<br>`$CODEX_HOME/AGENTS.override.md` | instruction files (`codex-agents-md`) | <https://learn.chatgpt.com/docs/agent-configuration/agents-md> | 2026-11-14 |
| Codex | all | `$CODEX_HOME/prompts/*.md` | custom prompts (`codex-prompt`) | <https://learn.chatgpt.com/docs/custom-prompts> | 2026-11-23 |
| Codex | all | `$CODEX_HOME/plugins/cache/*/*/*` | installed plugins (`<marketplace>/<plugin>/<version>`): each plugin's `plugin.json` or `.codex-plugin/plugin.json`, `mcp.json` or `.mcp.json`, `hooks/hooks.json` and skills | <https://developers.openai.com/plugins/build/plugins> | 2026-11-23 |
| Gemini CLI | all | `~/.gemini/settings.json` | MCP servers (`mcpServers`; `url` is SSE, `httpUrl` streamable HTTP), hooks | <https://geminicli.com/docs/reference/configuration> | 2026-11-14 |
| Gemini CLI | all | `~/.gemini/extensions` | extensions (plugins): each `<name>/gemini-extension.json` with its MCP servers, `hooks/hooks.json`, the context files it names, its skills (`skills/<name>/SKILL.md`) and subagents (`agents/*.md`, `gemini-agent`) | <https://geminicli.com/docs/extensions/reference/> | 2026-11-23 |
| Gemini CLI | all | `~/.gemini/GEMINI.md` | instruction file (`gemini-md`) | <https://geminicli.com/docs/cli/gemini-md/> | 2026-11-14 |
| Gemini CLI | all | `~/.gemini/skills` | skills (`<name>/SKILL.md`) | <https://geminicli.com/docs/cli/skills/> | 2026-11-14 |
| Gemini CLI | all | `~/.agents/skills` | skills (`<name>/SKILL.md`) | <https://geminicli.com/docs/cli/skills/> | 2026-11-14 |
| Gemini CLI | all | `~/.gemini/agents/*.md` | subagents (`gemini-agent`) | <https://geminicli.com/docs/core/subagents/> | 2026-11-23 |

Not read:

- Windsurf's `~/.codeium/windsurf/memories/global_rules.md`: only an archived page from before the rename to Devin Desktop names it.
- Codex's `$CODEX_HOME/skills/` as Codex's own: no OpenAI page names it any more; Cursor and Devin Desktop document loading `~/.codex/skills/`, so it is read as their directory.
- The `mcp.json` files of VS Code's remote and WSL servers (under `~/.vscode-server/` and `~/.vscode-server-insiders/`): the documentation names no path for them.
- VS Code's user instruction files, prompt files and custom agents of the user profile (the deprecated Local harness keeps them in the profile's user data): the documentation names no path. Copilot's `$COPILOT_HOME/instructions/` and `$COPILOT_HOME/agents/` are read.
- Claude Code's plugins when `CLAUDE_CODE_PLUGIN_CACHE_DIR` moves them out of `$CLAUDE_CONFIG_DIR/plugins/`, the components a plugin declares outside its standard layout, a plugin's `output-styles/`, `workflows/`, `monitors/` and `.lsp.json`, and MCP bundles (`.mcpb`, `.dxt`).
- System-wide managed files outside the home directory (`/etc/claude-code/`, `/etc/gemini-cli/`, `C:\ProgramData\`), which belong to an administrator, not to the user.
- Cursor's `~/.cursor/rules/`: one help page names it without a format, and the rules page says user rules are kept in Cursor's settings, not in files.
- Claude Desktop extensions: no Anthropic page names where they are installed.
- Windsurf's global workflows (`~/.codeium/windsurf/global_workflows/`): they run only when the user asks, and Devin Local does not support them.
- Files that need a parser or a rule the scanner does not have: Codex's `rules/*.rules`, `agents/*.toml` and profile files `<name>.config.toml`; Gemini CLI's `commands/**/*.toml` and `policies/*.toml`, in the home and in extensions, and `GEMINI_CLI_HOME`; Copilot's `lsp-config.json` and the folders `skillDirectories` names; Claude Code's `workflows/*.js`; and the settings keys that run commands besides `hooks` (`statusLine`, `apiKeyHelper` and others).
<!-- clients:end -->

The table follows each client's own documentation: a row stays only while its source names the path, or names the file while the pages in the row give its folder (VS Code's user and profile `mcp.json`, and the Devin Desktop folder of the Windsurf rows), and carries the date it was checked; when a client moves its files (Windsurf became Devin Desktop), the old place moves to "Not read" until a release reads the new one. The tests read a fixture home for each system; CI runs on Linux and Windows, so macOS is covered by its fixture home.

#### Uploading a workstation inventory

An organisation on the Enterprise plan can collect these inventories. An owner or manager creates a key with access Workstation under Settings, API keys, and developers (or a device management tool) set two variables that only `scan --user --upload` reads:

```
SPELLWARDEN_WORKSTATION_ORG=<slug> SPELLWARDEN_WORKSTATION_KEY=swk_... spellwarden scan --user --upload --device-label "Anna's laptop"
```

They are not `SPELLWARDEN_ORG` and `SPELLWARDEN_API_KEY` on purpose: either of those switches every repository scan on the machine to connected mode, which a workstation key cannot establish, while a repository scan never reads the workstation variables (it only takes the key out of its environment). Either variable missing or malformed is the error `workstation_no_credential`, before any client file is read (exit 2). The upload is off unless `--upload` is given; `SPELLWARDEN_UPLOAD` and the settings file do not apply to `--user`.

The first upload needs `--device-label` (1 to 64 characters after control and zero-width characters are removed; else the error `workstation_label_missing`, exit 2). It creates the state file `workstation.json` in the user configuration directory (`$XDG_CONFIG_HOME/spellwarden/`, `~/Library/Application Support/spellwarden/` or `%APPDATA%\spellwarden\`, mode 0600 where the system has modes), holding a random install id and the label and no credential. Later uploads reuse both unless `--device-label` is given again, and deleting the file makes the next upload a new device. Only an upload run writes it.

After the scan and before any report is written, the command sends one request, `POST https://dash.spellwarden.ai/api/v1/orgs/<slug>/workstations/inventory`, with the network rules of connected mode (HTTPS, public addresses only, no redirect, 10 seconds, one retry after a 429 or a 5xx). The body holds the label and the install id, the operating system, the scanner and rules versions, whether the scan was complete, the clients found with at most 8 of their roots and the number of them (`roots_total`, since 1.16.2; a server that does not know the field ignores it), each item (kind, name, home-relative path, project directory, transport, endpoint, command identity or its reason, plugin, marketplace, instruction format and clients), each finding (its item, rule id, severity, line and whether a baseline accepted it) and the codes and paths of at most 50 errors and 50 notices with their totals. It holds no message, excerpt, environment value, header or argument. Success is the notice `workstation_uploaded`; any other answer is the error `workstation_upload_failed` with the server's code (`plan_required`, `device_limit`, `inventory_too_large`, `api_key_revoked`, `workstation_key_required`, `rate_limited`) and its message, exit 2, because an inventory you asked to send must not vanish silently; a failure of the command itself while it uploads is the same error with the code `crash`. Over 1 MiB, 2,000 items or 1,000 findings nothing is sent (`workstation_upload_too_large`, exit 2). Every report carries the outcome (since 1.16.0): the text and JSON reports list the notice or the error, the Markdown report lists the error, a CycloneDX document counts the error in its `spellwarden:errors` property and says `false` in `spellwarden:complete` and `2` in `spellwarden:exit_code`, the JSON report's `exit_code` is 2 after a failure, a SARIF file names the errors in its run's `invocations` when the upload failed, and a GitLab Code Quality file lists findings only, so there the exit code alone says that the upload failed. The reports hold no timestamp: the notice names the device, and the server's time of the upload is in the stderr line only. The outcome is also printed on stderr, after the reports are written.

### The usage ping

In CI, and only in CI, each `spellwarden scan` sends one request at the end to `https://dash.spellwarden.ai/api/public/ping`. It lets us count how many organisations run the free scanner and how many runs checked an A2A agent card. The ping is pseudonymous, not anonymous, and carries exactly six fields:

| Field | Value |
|---|---|
| `schema` | `1` |
| `version` | the scanner version |
| `rules_version` | the rules version |
| `ci` | `github`, `gitlab` or `other` |
| `org` | a SHA-256 hash of the installation identity, or `null` |
| `a2a` | `true` when the run checked at least one agent card (one of the repository's, or a remote agent's that was fetched), else `false` |

The installation identity is the forge host plus the GitHub account's numeric id (`github:github.com:1234567`), the GitLab top-level group's path (`gitlab:gitlab.com:acme`), or the owner in the `origin` remote elsewhere. It is hashed as `sha256("spellwarden-ping-v1:" + identity)`. Anyone who knows an identity can compute its hash, which is why we call it pseudonymous. One company on GitHub and on GitLab is two identities; a self-managed GitLab or GitHub Enterprise Server is its own; renaming a GitLab top-level group starts a new one. The identity cannot be joined to an organisation of the hosted product.

The server keeps one row per hashed identity and ISO week: the number of runs, the number of those that checked an agent card (`a2a_runs`), the first and last time seen, the last scanner and rules versions and the CI kind. The row holds no IP address and no user agent, and is deleted 400 days after the end of its week. To limit abuse, the rate limiter keeps the sending address for one hour. Like every request to the service, the ping also appears in the technical logs, kept for 90 days, with the address it arrived from (usually one of the content delivery network's). No repository content is sent; the ping carries one yes-or-no fact derived from it: whether the run checked an agent card, from the repository or from an agent you listed. No card, address or count of cards is sent. Nothing is sent from a local run, by `scan --user` (in CI too) or by `lock`, `baseline`, `rules` or `version`.

Switch it off with any of: `--no-telemetry`, `SPELLWARDEN_TELEMETRY=off` (or `0`, `false`, `no`), `DO_NOT_TRACK=1`, `telemetry: false` in `.spellwarden/config.yml`, or the `telemetry: false` input of the Action or the GitLab component. A failed or slow ping never changes a report or an exit code. `spellwarden scan --staged`, which the pre-commit hook runs since 1.19.0, never sends it.

### Connected mode

Connected mode links a scan to a Spellwarden organisation. The organisation's CI policy decides which rules and which policy pack the run applies, the registry gate (Enterprise) fails a run that adds or changes a skill, MCP server, plugin or marketplace the private registry does not admit, and the results go to the Repositories page of the dashboard. It needs a Team plan (a trial counts); the gate needs the Enterprise plan. Without a credential, without `SPELLWARDEN_ORG` and without `connected.required` the command is the free scanner of every section above, unchanged apart from the rules version and the three gate rules in the rules table. A `connected:` key in `.spellwarden/config.yml` is refused by a 1.0 or 1.1 scanner, so requiring connected mode presupposes 1.2.0 everywhere the repository is scanned.

#### Turning it on

There are two credentials, and a run uses one of them. Both set is the error `connected_config`.

- **A CI connection** (recommended). An administrator adds a CI connection for your GitHub account or organisation, or your GitLab group, under Settings, CI connections. The pipeline then proves who it is with the OIDC token its code host issues, and nothing secret is stored in the repository. Set `SPELLWARDEN_ORG` to the organisation's slug (`^[a-z0-9-]{2,64}$`, the part of the dashboard address after `dash.spellwarden.ai/`). On GitHub the job needs `permissions: id-token: write`, and the command asks the Actions token endpoint itself for a token whose audience is `https://dash.spellwarden.ai/ci/<slug>`. On GitLab the job declares `id_tokens` with that audience and passes it as `SPELLWARDEN_ID_TOKEN`. The GitHub Action takes the slug as its `org` input and the GitLab component as its `org` input.
- **A CI key.** For a pipeline that cannot use a CI connection, create a key with access CI under Settings, API keys, and pass it as the secret `SPELLWARDEN_API_KEY` (`swk_` and 40 characters). The key is a secret that every workflow of the repository can read, which a CI connection avoids. Results uploaded with a key are shown as reported with a CI key: they are not the repository's attested state and do not count in the trust score. The first upload binds the repository to the key; after the old key is revoked, the next upload rebinds it. A key for read or write access, a connector token (`swc_`) or a CI token (`swt_`) is refused.

The command reads these variables once, keeps them as secrets that print as `***`, removes them from its environment, and gives every program it starts an explicit environment. A workstation uploads its inventory with a key of another kind, through other variables, and never in connected mode: see "Uploading a workstation inventory". There is no flag and no settings key for a credential, and no message, report or upload body ever holds one.

```yaml
# .spellwarden/config.yml
connected:
  pack: 3f2a0c9d4b7e4d1f8a6b5c2e9d0f1a37@1.4   # optional: a pack id (baseline or 32 hex), optionally @version, from the organisation's allowed list
  upload: true                                  # optional, default true: upload the results in CI
  required: false                               # optional, default false: a run that cannot connect exits 2 instead of falling back to free mode
```

`upload` has the flags `--upload` and `--no-upload` and the variable `SPELLWARDEN_UPLOAD`; a flag wins over the variable, which wins over the file. `pack` and `required` are the repository's statement: they have no flag and no variable, and on a pull or merge request they are read from the base revision's `.spellwarden/config.yml`, even when `--config FILE` names another file (the notice `settings_from_base` says so). `--as-of` is refused in connected mode, because the server works out when baseline entries expire. In free mode the `connected` mapping is read, validated and ignored.

#### What is sent

Only these leave the runner: the token request to your code host, the exchange, the session and policy requests, the registry check and the upload. No whole file is ever sent. Every request is valid UTF-8: a name that is not valid UTF-8 (such as a file name in another encoding), or any text that holds a lone surrogate, is sent and shown in the upload with U+FFFD in its place, since 1.18.0; the reports written on the runner are unchanged. A finding carries an excerpt of at most 300 characters of the matched line, with credentials masked. An MCP server's address leaves only as a hash, and the link that asks for its admission carries the address without user name, query or fragment.

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
      - uses: spellwarden-ai/scan@<commit of v1.2.1>  # v1.2.1
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
      - uses: spellwarden-ai/scan@<commit of v1.2.1>  # v1.2.1
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

`schemas/` holds JSON Schemas (draft 2020-12) for the settings, the baseline, the lock file and the JSON report, including every closed list of values. Readers of the report must ignore fields they do not know; the settings and the baseline refuse them. From 1.0.0, removing or renaming a field or a value, or changing an exit code, is a major version; adding an optional field, a notice code or a rule is a minor one. Since 1.3.0 the report holds an optional `agents` list (one entry per A2A agent card the run read or fetched, written only when there is one), the rule-id pattern of the report and the baseline schema is `^SW-(SKL|MCP|CFG|REG|A2A|ORG)-[0-9]{3}$`, and the settings schema has the `a2a` mapping. A 1.2.x scanner refuses a settings file with an `a2a` mapping (`settings_invalid`, unknown key) and a baseline with an `SW-A2A` entry, as it would any later key or rule; a team that runs two scanner versions against one repository must upgrade both. In the same way a 1.3.x scanner refuses a baseline with an `SW-A2A-019` entry, the rule 1.4.0 added. Unlike `SW-A2A-019`, the rules 1.8.0 added (`SW-SKL-032`, `SW-SKL-036`, `SW-SKL-037`, `SW-CFG-012`, `SW-CFG-013`, rules version `2026.11.1`) keep an older baseline readable: a scanner older than 1.8.0 reads a baseline that names one of them without error, but the entry matches nothing there, so `baseline list` shows it as unmatched, `baseline prune` removes it, and the older scanner reports none of the new findings. `SW-SKL-032` is a malicious-indicator rule, so an entry for it may last at most 30 days from 1.8.0 on. Since 1.2.0 the report holds an optional `connected` block when a run was connected (the credential kind, the organisation, the run, the policy applied, the registry gate's counts and items, and the upload outcome), and `upload_truncated` and `upload_truncated_fields` after an upload that was cut; a free run adds none of them. Since 1.13.0 each finding of the report also holds `tags` (the framework ids of its rule: `owasp_agentic`, `owasp_mcp`, `nist`, `atlas`, `owasp_ast`), an item of kind `instructions` holds `format` and `front_matter`, the lock schema has the item kind `instructions`, and the settings schema has the key `instructions`; the report's `schema` stays 1. Since 1.15.0 the lock schema has the item kind `mcp-tools`, a change in the report's `lock` may name it, and the notice codes `tools_changed` and `tools_not_compared` are new. Since 1.18.0 the report holds an optional `preset` block and each finding an optional `preset_from`, both only when a preset other than `balanced` applied, and the settings schema has the key `preset`; a scanner older than 1.18.0 refuses a settings file with `preset` (`settings_invalid`, unknown key), so a team that runs two scanner versions against one repository upgrades both before setting it. Since 1.21.0 each finding of the report also holds `fix` (its rule's fix sentence) and `rule_url` (its rule's page), both null for an organisation rule, and a finding of SW-CFG-013, SW-A2A-006 or SW-MCP-003 may hold `fix_lines`; the report's `schema` stays 1.

Two more promises hold from 1.21.0. A rule id is never reused or renamed: a rule keeps its id for as long as it exists, its title may be reworded, and its id is never given to another rule. A deprecation is announced in this repository's `CHANGELOG.md` at least one minor version before it takes effect. A rule is retired that way: from the release the announcement names, it is no longer in `RuleSet.baseline()`, its id stays reserved and is never given to another rule, and it is listed in [The rules](#the-rules) with the release that retired it. `tests/test_compatibility_pledge.py` holds the scanner to both on every `make check`, and so in the release workflow's build job, against `tests/data/released_rule_ids.json`, the list of every rule id ever released with its title in the release it first shipped in.

## What Spellwarden keeps from your telemetry

Spellwarden's hosted product accepts OpenTelemetry traces and logs over OTLP/HTTP (protobuf or JSON, gzip or not) from agents and gateways at `https://otel.spellwarden.ai` (`/v1/traces` and `/v1/logs`), with an ingest key sent as `Authorization: Bearer` or `x-api-key`. Create the key in the dashboard under Settings, API keys (access Ingest); the page Settings, Runtime traces gives the settings for the OpenTelemetry SDK, Claude Code, the Claude Platform and the OpenTelemetry Collector. The code that decides what it keeps is this package's `spellwarden_scan.otel` (since 1.7.0, standard library only, with its own protobuf reader), and the same code runs on your machine:

```
spellwarden otel normalise PATH --signal traces|logs [--encoding auto|protobuf|json] [--content] [--max-records N] [--max-bytes N]
```

It reads one file (an OTLP/HTTP request body, as your exporter would send it), inflates it when it is gzip, and prints `{"stats", "resources", "records"}` as JSON: every record Spellwarden would keep and the counts of what it would ignore. `--signal` is required for protobuf, since a traces body and a logs body cannot be told apart on the wire; for JSON it is read from `resourceSpans` or `resourceLogs`. `--content` also prints the content Spellwarden keeps only when an owner of your organisation turns content storage on. The command opens no network connection and needs no key; it exits 0, or 2 on a usage error or a body it refuses (the reason is on stderr: `malformed`, `too_large`, `too_many_records`, `too_deep` or `unsupported_encoding`).

The rules, in short:

- **An allow-list.** A field is kept only if the list of fields below names it. Every other attribute, resource attribute, event, link and body is dropped, including `user.id`, `user.email`, `user.account_uuid`, `enduser.id`, `organization.id`, `client.address` and host names. Session ids are kept as sent (cut to 128 characters), except that one shaped like an email address is replaced by a hash.
- **Dialects** (`DIALECTS`), the first that matches: `claude_code` (span names `claude_code.*`, and Claude Code's log events), `claude_platform` (span names `anthropic.*` from the service `claude-platform`), `openinference` (`openinference.span.kind`), `genai_legacy` (`gen_ai.system` without `gen_ai.provider.name`), `genai` (`gen_ai.operation.name` or `gen_ai.provider.name`), `mcp` (`mcp.method.name`). A span of no dialect is ignored. Log records are kept for Claude Code's events (`api_request`, `api_error`, `tool_result`, `tool_decision`, `safety_event`, `skill_activated`, `mcp_server_connection`, `user_prompt`, `assistant_response`) and GenAI's content events.
- **Record kinds** (`RECORD_KINDS`): `agent`, `model`, `tool`, `mcp`, `decision`, `connection`, `skill`, `content`, `other`. A record is `counted` when its kind is one of the first seven, except Claude Code's beta spans (Claude Code is counted from its log events) and a `safety_event` with no `tool_decision` to fold into. `other` records (chains, retrievers, Claude Code's execution and hook spans) are kept up to 100 a request or twice the counted ones, whichever is more.
- **Fields of a record** (`Record`): the signal, dialect, kind, `counted` and the resource; the scope name; trace, span and parent span ids; the name; start, end and duration; MCP side (`client` or `server`); status (`ok`, `error`, `unset`), the error type and the JSON-RPC status code; the session (`conversation` or `session`, and its id); the GenAI operation, agent name, provider, model and token counts; the tool name, call id and type; the MCP method, server name, server address and port; the URL (scheme, host, port and path only, with path segments that look like tokens replaced by `***`) and its identity hash; the skill name and source URI; the decision kind, outcome, source, category, reason code and rule source; and `names_redacted`, true when the producer sent a placeholder instead of a real name. Identifiers and names are never masked: they have control characters removed, are NFC and are cut to a fixed length.
- **Resources** (`ResourceInfo`): `service.name` (or `unknown_service`), `service.version`, `deployment.environment.name` and `telemetry.sdk.language`. Nothing else.
- **Content** (`CONTENT_KINDS`: `system`, `input`, `output`, `tool_arguments`, `tool_result`, `prompt`, `response`) is a closed list of named attributes and events, such as `gen_ai.input.messages`, `gen_ai.tool.call.arguments`, OpenInference's `input.value` and Claude Code's `prompt`. It is built only when asked for (`normalise(request, content=True)`), cut to 32 KiB an item and 128 KiB a record, and returned apart from the record's fields. Spellwarden's service drops it unless your organisation turned content storage on, and masks credentials in it before storing it for 30 days.
- **Bounds** (`DEFAULT_LIMITS`): at most 20,000 records a request and values nested 16 deep (a request past either is refused); at most 512 attributes on any one item and 256 events on a span, and 1 MiB for one value (the rest is skipped or cut, and counted).

The receiver refuses bodies over 4 MiB as sent or 16 MiB decompressed: batch at 2,000 records, or turn gzip on.

## Versions

`spellwarden_scan.__version__` is the package version and `spellwarden_scan.RULES_VERSION` (`YYYY.MM.N`) the rule set's. A change to what any rule detects bumps both the rules version and the package minor version; a fix anywhere else bumps the patch. Every scan result carries both, so a stored finding always says which rules produced it. `jcs_canonicalize` is RFC 8785; `canonical_json` (the pack hash) and `canonical_sha256` (the package hash) are not, and no signature is ever checked against them.

## Releases

Releases are built and published by GitHub Actions through PyPI trusted publishing (OpenID Connect): a push of a tag `vX.Y.Z` whose version equals the one in `pyproject.toml` builds the sdist and the wheel and publishes them from the `pypi` environment. No API token exists anywhere. The sources are checked on Python 3.11, 3.12 and 3.13 on Linux, and on Python 3.13 on Windows, on every push; every workflow is checked with `actionlint`. Before anything is published, the release workflow's `gateway-exports` job runs ToolHive v0.65.0 and Docker MCP Gateway v0.44.3 on the baseline pack's exports in front of a fixture MCP server (Linux, with Docker). Before anything is published, the `rule-benchmark` job installs the built wheel on Linux and Windows, fetches the benchmark's sets from their sources, checks every file against its recorded hash and measures the rules; a failed fetch, a changed file or numbers that differ from the entry committed for the version stop the release, and the table is attached to the GitHub release as `rule-benchmark.json` and `rule-benchmark.md`.

## Development

```
make check     # ruff, pytest, uv build
```

`tests/test_pure.py` fails the build if any module of `spellwarden_scan` reaches for the network, the file system or the environment; `tests/test_network_boundary.py` fails it if any module of `spellwarden_cli` other than the prober's fetcher (`net.py`), the usage ping (`ping.py`), the comment poster (`forge.py`), the API client of connected mode (`api.py`) and, since 1.17.0, the model client of `--analyze` (`model_client.py`) can reach the network; `tests/test_fixture_coverage.py` fails it if a rule lacks a positive or a negative fixture. Every test runs offline: HTTP exchanges are recorded under `tests/recorded/` and git repositories are made by the tests.

`make benchmark` runs the rule benchmark with this checkout's scanner (it needs the network for the first fetch); `benchmarks/README.md` says how to run it against a released version.

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

**The dashboard line and the badge offer.** Both wrappers take an input `invite` (since 1.26.0, `true` by default): `false` leaves the dashboard line and the README badge offer out of the job summary and the comment, as `--no-invite` does. See "Links in the Markdown report".

**Anywhere else.** `pipx run spellwarden==1.0.0 scan`, or the image `ghcr.io/spellwarden-ai/spellwarden:1.0.0`.

### Pre-commit hook

Since 1.18.0 this repository is a hook repository of the [pre-commit framework](https://pre-commit.com) (`.pre-commit-hooks.yaml`; guide: [spellwarden.ai/docs/pre-commit](https://spellwarden.ai/docs/pre-commit?utm_source=github&utm_medium=readme&utm_campaign=pre-commit)). In your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/spellwarden-ai/spellwarden
    rev: v1.24.0
    hooks:
      - id: spellwarden
        # args: [--preset, low-noise]   # any `spellwarden scan` option
        # args: [--follow-links]        # also judge linked directories in instruction folders
```

The framework (pre-commit 3.2.0 or later) installs the scanner from the tagged release into an environment of its own and runs `spellwarden scan --staged` at the repository root, at the stages `pre-commit`, `pre-push` and `manual`, when a commit changes agent content: a `SKILL.md`, anything under a folder named `skills`, `.claude`, `.cursor`, `.codex`, `.gemini`, `.devin`, `.windsurf`, `.agents`, `.vscode`, `.claude-plugin`, `.spellwarden` or `.well-known` or under `.github/hooks`, `.github/instructions`, `.github/agents` or `.github/copilot`, an MCP configuration file, a plugin's `hooks/hooks.json`, an instruction file (`CLAUDE.local.md`, `AGENTS.override.md`, `AGENTS.local.md` and `AGENT.md` among them) or an agent card. Since 1.19.0 the hook judges the staged content only (see "What a scan reads"): the whole repository as the git index holds it, never an untracked file or a change that is not staged, with `.spellwarden/config.yml` and the baseline as staged, so a file left out of the commit can neither fail it nor exclude what it holds. At `pre-commit` that is the content being committed; at `pre-push` and `manual` (a `pre-commit run --all-files` in CI among them) it is the checked-out commit plus whatever is staged. On a pull or merge request in CI the hook therefore reads the request's own settings file and baseline, where the Action and the GitLab component read the base revision's: keep one of those, or a scan without `--staged`, as the check that decides a merge. A change the file filter misses is judged on the next run and in CI: a change to a local plugin's `commands/` or `agents/`, and, with `args: [--follow-links]`, a change inside the directory a followed link names (`shared-rules/`), is not matched by the file filter. The hook sends nothing to Spellwarden: it never uploads to connected mode, never sends the usage ping, in CI or outside it, and ignores `SPELLWARDEN_ORG` and `SPELLWARDEN_API_KEY` with a notice, and in CI says with another notice when the settings require connected mode (`connected.required: true`), which it does not evaluate; `--probe` and `--analyze` in the hook's `args` still reach the servers and the model endpoint you name. Its exit code is the scanner's: findings at `--fail-on` (default high) stop the commit (exit 1), and so does an incomplete scan (exit 2) or, with `--locked`, a stale lock (exit 3). To commit once without it: `SKIP=spellwarden git commit`.

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
