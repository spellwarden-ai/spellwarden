"""1.21.0 (P6-15 spec 6.5, 6.6, 4.5, 4.7; E-3, E-8): the text report's "How to fix" section and its "write in" lines, and the
Markdown report's "**How to fix**" section (the pull request comment and the merge request note): one entry per baseline rule
with an open finding, in rule id order, the organisation line when one applies, nothing without an open finding, and a bound
that does not grow with the number of findings."""
from __future__ import annotations

from fix_guidance_report import BASELINE, CFG_013, SKL_009, finding, report, report_of

from spellwarden_cli.output import FORMATS
from spellwarden_cli.output.fixes import ORG_LINE, rule_fixes
from spellwarden_cli.report import ReportFinding

CFG_013_PAGE = "https://spellwarden.ai/docs/rules/sw-cfg-013?utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix"
SKL_009_PAGE = "https://spellwarden.ai/docs/rules/sw-skl-009?utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix"
SKL_009_DOCS = "https://spellwarden.ai/docs/rules/sw-skl-009?utm_source=scanner&utm_medium=cli&utm_campaign=rule-docs"
CFG_013_TITLE = "Database or cluster MCP server with write access although a read-only mode exists"


def test_the_organisation_line_is_the_spec_s():
    assert ORG_LINE == ("Organisation rules (SW-ORG-) come from your organisation's policy pack, which holds no fix text: ask the "
                        "people who manage it.")


def test_the_text_report_lists_each_rule_once_then_the_organisation_line():
    lines = FORMATS["text"](report()).split("\n")
    start = lines.index("How to fix")
    assert lines[start:start + 7] == ["How to fix", f"  SW-CFG-013 {CFG_013}", f"    {CFG_013_PAGE}", f"  SW-SKL-009 {SKL_009}",
                                      f"    {SKL_009_PAGE}", f"  {ORG_LINE}", ""]
    assert lines[start - 1] == ""  # after the last item block
    at = lines.index(f"  high SW-CFG-013 .mcp.json:3 {CFG_013_TITLE}")
    assert lines[at + 1] == "    write in the query of the mcp.supabase.com address: read_only=true"
    assert sum(line.startswith("    write in ") for line in lines) == 1


def test_no_open_finding_no_section_but_the_setting_lines_stay_under_their_finding():
    text = FORMATS["text"](report(suppressed=True))
    assert "How to fix" not in text.split("\n")
    assert "    write in the query of the mcp.supabase.com address: read_only=true" in text.split("\n")
    assert "**How to fix**" not in FORMATS["markdown"](report(suppressed=True))


def test_the_markdown_report_has_the_section_under_its_table():
    lines = FORMATS["markdown"](report()).split("\n")
    start = lines.index("**How to fix**")
    assert lines[start - 1] == "" and lines[start - 2].startswith(f"| medium | [SW-SKL-009]({SKL_009_DOCS}) |")
    assert lines[start:start + 7] == [
        "**How to fix**", "",
        f"- **SW-CFG-013** {CFG_013} [Rule page]({CFG_013_PAGE})",
        "  - In the query of the mcp.supabase.com address, write: `read_only=true`",
        f"- **SW-SKL-009** {SKL_009} [Rule page]({SKL_009_PAGE})",
        f"- {ORG_LINE}", ""]


def test_the_markdown_section_escapes_the_sentence():
    rows = [ReportFinding(finding("SW-MCP-003", ".mcp.json#auth", "registration_endpoint https://auth.example/register"), ".mcp.json#auth")]
    text = FORMATS["markdown"](report_of(rows))
    assert "client\\_id\\_metadata\\_document\\_supported" in text and "client_id_metadata" not in text


def test_markdown_covers_the_shown_rows_only():
    rules = [rule for rule in BASELINE if rule.area in ("skill", "config")][:30]
    rows = [ReportFinding(finding(rule.id, f"skills/s/{n:02d}.sh", f"evidence {n}"), "skills/s") for n, rule in enumerate(rules)]
    text = FORMATS["markdown"](report_of(rows))
    assert len(rules) == 30
    assert sum(line.startswith("- **SW-") for line in text.split("\n")) == 25
    assert "5 more findings are in the JSON and SARIF reports." in text


def test_the_text_section_has_one_pair_for_400_findings_of_one_rule():
    rows = [ReportFinding(finding("SW-SKL-009", f"skills/s/{n:03d}.sh", f"pip install p{n}"), "skills/s") for n in range(400)]
    lines = FORMATS["text"](report_of(rows)).split("\n")
    start = lines.index("How to fix")
    assert lines[start:start + 4] == ["How to fix", f"  SW-SKL-009 {SKL_009}", f"    {SKL_009_PAGE}", ""]


def test_rule_fixes_skips_a_rule_the_set_lacks_and_keeps_distinct_lines_sorted():
    entries, organisation = rule_fixes(report(), report().unsuppressed())
    assert [entry.rule_id for entry in entries] == ["SW-CFG-013", "SW-SKL-009"] and organisation is True
    assert entries[0].lines[0].text == "read_only=true" and entries[1].lines == ()
