# Changelog

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
