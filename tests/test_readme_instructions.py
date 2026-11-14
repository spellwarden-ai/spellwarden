"""Phase 3 batch 1 spec 11.5, 17: the README and the changelog say what 1.13.0 changes, including what an upgrade can break."""
from __future__ import annotations

from pathlib import Path

from spellwarden_scan import RULES_VERSION, __version__
from spellwarden_cli import instruction_files

ROOT = Path(__file__).resolve().parents[1]


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def test_the_readme_has_an_instruction_files_section_that_names_every_format_and_notice():
    text = read("README.md")
    section = text[text.index("### Instruction files"):text.index("### Exit codes")]
    for format in instruction_files.FORMATS:
        assert f"`{format}`" in section, format
    for needle in ("instructions_limit", "instructions_front_matter", "instructions: false", "spellwarden lock", "lock_unreadable",
                   "at most 200", "belongs to that skill", "`.github/instructions/*.instructions.md`"):
        assert needle in section, needle
    assert "instructions: true" in text  # the settings example shows the default
    assert "| Instruction file |" in text


def test_the_readme_says_how_the_probe_and_the_tags_changed():
    text = read("README.md")
    for needle in ("`prompts/list`, `resources/list`, `resources/templates/list`", "never `resources/read`, `prompts/get` or `tools/call`",
                   "`server_instructions`", "MCP server text contains instruction-like text", "docs/frameworks.md",
                   "OWASP incubator project under public review", "release 2026.10"):
        assert needle in text, needle


def test_the_changelog_has_the_1_13_0_entry_above_1_12_0():
    text = read("CHANGELOG.md")
    assert text.index(f"## {__version__} (") < text.index("## 1.12.0 (")
    entry = text[text.index(f"## {__version__} ("):text.index("## 1.12.0 (")]
    assert f"Rules version {RULES_VERSION}." in entry
    for needle in ("MCP probe.", "Framework tags.", "Instruction files.", "resources/read, prompts/get or\ntools/call",
                   "Precision on these four places has not been measured", "can fail after upgrading",
                   "unreadable to 1.12.0 and older", "`instructions: false`", "The report's `schema` stays 1"):
        assert needle in entry, needle
