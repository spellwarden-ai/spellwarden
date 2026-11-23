"""1.21.0 (P6-15 spec 6.11): the README's section "How to fix" says what each report shows, that setting lines are text to copy and
which rows write them (the rows of `rules.fix_lines.SOURCES`, one table row each, the TOML form of plan Q2 among them), and what
an organisation rule shows; "Schemas
and compatibility" names the three new optional fields in the spec's sentence."""
from __future__ import annotations

from pathlib import Path

from spellwarden_scan.rules import fix_lines

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")


def section(heading: str) -> str:
    start = README.index(heading)
    return README[start:README.index("\n### ", start + len(heading))]


def test_the_section_says_what_each_report_shows():
    text = " ".join(section("### How to fix").split())
    for needle in ("`Rule.fix`", "`Rule.page`", "`https://spellwarden.ai/docs/rules/<id in lower case>`",
                   "utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix", "| `json` |", "| `text` |", "| `markdown` |",
                   "| `html` |", "| `sarif` |", "| `cyclonedx` |", "| `gitlab-codequality` |", "`help`", "`helpUri`",
                   "`properties.fix_lines`", "`recommendation`", "the pull request comment and the merge request note",
                   "text to copy, never applied", "no `fixes` object", "never text from your files",
                   "`src/spellwarden_scan/rules/fix_lines.py`", "`@supabase/mcp-server-supabase`", "`kubernetes-mcp-server`",
                   "A line follows the syntax of the file its finding is in", "Codex's `config.toml`",
                   "`fix` and `rule_url` null", "leaves out `fix`, `rule_url` and `fix_lines`"):
        assert needle in text, needle
    for character in ("—", "–", "!"):
        assert character not in section("### How to fix")


def test_the_setting_lines_table_is_the_engine_s():
    rows = [[cell.strip() for cell in line.strip("|").split("|")] for line in section("### How to fix").splitlines()
            if line.startswith("| ")]
    rows = [cells for cells in rows if len(cells) == 4 and cells[1].startswith("SW-")]
    assert [cells[1:] for cells in rows] == [[source.rule_id, source.lines.where, f"`{source.lines.text}`"]
                                             for source in fix_lines.SOURCES]


def test_schemas_and_compatibility_names_the_new_fields():
    text = " ".join(section("### Schemas and compatibility").split())
    assert ("Since 1.21.0 each finding of the report also holds `fix` (its rule's fix sentence) and `rule_url` (its rule's page), "
            "both null for an organisation rule, and a finding of SW-CFG-013, SW-A2A-006 or SW-MCP-003 may hold `fix_lines`; the "
            "report's `schema` stays 1.") in text
