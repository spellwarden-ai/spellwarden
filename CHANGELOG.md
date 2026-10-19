# Changelog

## 0.1.0 (unreleased)

The first release: the engine of the hosted Spellwarden product as a library.

- `scan_skill_package` with 17 skill rules (SW-SKL-001 to 015, 019, 031), the canonical package hash, frontmatter metadata, bounded findings (500 per scan, 100 per rule, worst severity first) and masked evidence.
- `evaluate_probe` with 11 MCP rules (SW-MCP-001 to 011), transport, authentication and spec-version classification, deprecated features, migration status and the twelve-item migration checklist.
- `curation_score`, `is_curated`, `is_quarantined`.
- `unpack_zip` with zip-slip, symlink, size and file-count protection; `canonical_sha256`; `parse_frontmatter`; `mask_credentials`.
- Rules version `2026.10.0`.
