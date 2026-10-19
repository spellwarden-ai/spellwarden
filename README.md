# spellwarden

The Spellwarden scan engine: the baseline rules for agent skills and MCP servers, the probe classification against the 2026-07-28 MCP specification, the migration checklist and the curation score. It is the engine of the hosted product at [spellwarden.ai](https://spellwarden.ai) and is published so that the same rules run in your own tooling.

This package is pure code. It never opens a connection, reads a file or an environment variable: you hand it the bytes of a package or the recorded result of a probe, and it hands back findings. The command-line scanner, discovery in a repository and the CI wrappers arrive in a later release; this one is the library they are built on.

```
pip install spellwarden
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

Ids are `SW-SKL-NNN` (skill packages) and `SW-MCP-NNN` (MCP servers). Mappings use the OWASP Agentic Top 10 (ASI) and OWASP MCP Top 10 (MCP) identifiers and NIST SP 800-53 base controls, labelled as a provisional mapping to SP 800-53 base controls. Two rules are malicious indicators: an open finding from one of them quarantines the package.

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

Ids 016 to 018 and 020 to 030 are reserved. `RuleSet.baseline()` returns these rules; `ruleset.with_rules(extra)` adds your own `Rule` objects built with `spellwarden_scan.rules.make_rule`.

## Versions

`spellwarden_scan.__version__` is the package version and `spellwarden_scan.RULES_VERSION` (`YYYY.MM.N`) the rule set's. A change to what any rule detects bumps both the rules version and the package minor version; a fix anywhere else bumps the patch. Every scan result carries both, so a stored finding always says which rules produced it.

## Releases

Releases are built and published by GitHub Actions through PyPI trusted publishing (OpenID Connect): a push of a tag `vX.Y.Z` whose version equals the one in `pyproject.toml` builds the sdist and the wheel and publishes them from the `pypi` environment. No API token exists anywhere. The sources are checked on Python 3.11, 3.12 and 3.13 on every push.

## Development

```
make check     # ruff, pytest, uv build
```

`tests/test_pure.py` fails the build if any module reaches for the network, the file system or the environment; `tests/test_fixture_coverage.py` fails it if a rule lacks a positive or a negative fixture.

## License

Apache-2.0. See `LICENSE`.
