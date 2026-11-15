"""Phase 3 batch 2b spec 10.2, 10.4 and 10.10 (claim T-5): the README describes the canonical tool hash exactly as
`spellwarden_scan.toolhash` computes it, the lock file's probed pins, their limits, the schema additions and the release
workflow's gateway check, and the changelog has the 1.15.0 entry above 1.14.0."""
from __future__ import annotations

from pathlib import Path

from spellwarden_scan import toolhash
from spellwarden_cli.report import NOTICE_CODES

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")


def section(start: str, end: str) -> str:
    return README[README.index(start):README.index(end, README.index(start))]


def entry() -> str:
    return CHANGELOG[CHANGELOG.index("## 1.15.0 ("):CHANGELOG.index("## 1.14.0 (")]


def test_the_hash_section_and_the_module_agree_on_the_constants():
    text = section("### Tool lists and SW-MCP-012", "## Curation score")
    assert toolhash.ITEM_PREFIX == b"spellwarden-tool-item-v1\x00" and "`spellwarden-tool-item-v1`, a NUL byte" in text
    assert toolhash.FORMAT == 1 and '`{"format": 1, "kinds": {kind: kind hash}}`' in text
    assert toolhash.KINDS == ("tools", "prompts", "resources", "resource_templates", "instructions")
    assert "(" + ", ".join(f"`{kind}`" for kind in toolhash.KINDS) + ")" in text
    assert toolhash.MAX_SCHEMA_DEPTH == 128 and "nested deeper than 128 levels" in text
    for needle in ("NFC", "`\\r\\n`", "9223372036854775807", "U+FFFD", "Tool annotations are not hashed", "`pinned`",
                   "at most 120 characters a side", "`server_tools`", "the one 1.14.0 gave", "never raises SW-MCP-012"):
        assert needle in text, needle


def test_the_lock_section_names_the_kind_the_commands_and_the_notices():
    text = section("### The lock file: `.spellwarden/lock.json`", "### The baseline file")
    for needle in ("`spellwarden lock --probe`", "`mcp-tools`", '"format": 1', "`changed mcp-tools .mcp.json#jira`", "exit 3",
                   "`tools_not_compared`", "`tools_changed`", "`lock --check` included", "refused by 1.14.0 and older"):
        assert needle in text, needle
    assert {"tools_changed", "tools_not_compared"} <= set(NOTICE_CODES)
    assert "spellwarden lock [PATH] [--check | --probe]\n" in README


def test_the_limits_section_records_the_remote_rule_for_the_pins_and_the_export_limits():
    text = section("### Limits", "### Settings:")
    for needle in ("`tools_not_compared`", "one page of at most 200 entries", "16 KiB", "nested deeper than 128 levels",
                   "120 characters", "1 MiB", "Capitalised and UPPER"):
        assert needle in text, needle


def test_the_schemas_and_releases_sections_name_the_additions():
    assert "the lock schema has the item kind `mcp-tools`" in section("### Schemas and compatibility", "## Versions")
    releases = section("## Releases", "## Development")
    assert "`gateway-exports` job runs ToolHive v0.65.0 and Docker MCP Gateway v0.44.3" in releases
    assert "macOS" not in releases


def test_the_changelog_has_the_1_15_0_entry_above_1_14_0():
    assert CHANGELOG.index("## 1.15.0 (") < CHANGELOG.index("## 1.14.0 (")
    body = entry()
    assert body.startswith("## 1.15.0 (2026-11-") and "Rules version 2026.11.7." in body
    for needle in ("`spellwarden_scan.toolhash`", "SW-MCP-012", "`baseline`, `listing` and `pinned`", "`mcp-tools`",
                   "refused by 1.14.0 and older", "`toolhive`", "`docker-mcp-gateway`", "Docker MCP Gateway v0.44.3",
                   "ToolHive v0.65.0", "Obot is not offered", "`tools_changed`", "`tools_not_compared`"):
        assert needle in body, needle


def test_the_new_text_has_no_dash_characters_and_no_exclamation_marks():
    for text in (entry(), section("### Tool lists and SW-MCP-012", "## Curation score"),
                 section("**ToolHive.**", "## The `spellwarden` command")):
        assert "\u2014" not in text and "\u2013" not in text and "!" not in text
