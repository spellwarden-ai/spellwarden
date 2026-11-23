"""tests/golden_fix.py takes out exactly what 1.21.0 adds to each report and puts the two corrected rule links back as 1.20.0 wrote
them (P6-15 spec 6.12 E-7); a report without any of it comes back unchanged, byte for byte."""
from __future__ import annotations

import json

from golden_fix import HELP_URI, before_fix_guidance, without_fix_guidance

PAGE = "https://spellwarden.ai/docs/rules/sw-cfg-013?utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix"
LINES = {"text": "read_only=true", "where": "the query of the mcp.supabase.com address"}


def _dump(document: dict, *, sort_keys: bool = True) -> str:
    return json.dumps(document, indent=2, sort_keys=sort_keys, ensure_ascii=True) + "\n"


def test_the_json_report_loses_the_three_keys_and_a_probe_finding_its_lines():
    old = {"findings": [{"rule_id": "SW-CFG-013", "tags": {}}], "probes": [{"findings": [{"rule_id": "SW-MCP-003"}]}]}
    new = {"findings": [{"rule_id": "SW-CFG-013", "tags": {}, "fix": "Add it.", "rule_url": PAGE, "fix_lines": LINES}],
           "probes": [{"findings": [{"rule_id": "SW-MCP-003", "fix_lines": LINES}]}]}
    assert without_fix_guidance("report.json", _dump(new)) == _dump(old)
    assert without_fix_guidance("report.json", _dump(old)) == _dump(old)


def test_the_text_report_loses_its_section_and_the_write_in_lines():
    new = ("x\n  high SW-CFG-013 .mcp.json:3 T\n    write in the server's env: \"A\": \"true\"\n\nHow to fix\n  SW-CFG-013 Add it.\n"
           f"    {PAGE}\n\nnotice n : m\n1 findings\n")
    assert without_fix_guidance("report.txt", new) == "x\n  high SW-CFG-013 .mcp.json:3 T\n\nnotice n : m\n1 findings\n"


def test_the_markdown_report_loses_its_section():
    table = "| Severity | Rule | Location | Title |\n|---|---|---|---|\n| high | SW-CFG-013 | `.mcp.json:3` | T |\n"
    new = (f"{table}\n**How to fix**\n\n- **SW-CFG-013** Add it. [Rule page]({PAGE})\n  - In the server's env, write: `x`\n"
           "- Organisation rules (SW-ORG-) come from your organisation's policy pack.\n\nSpellwarden 1.21.0\n")
    assert without_fix_guidance("report.md", new) == f"{table}\nSpellwarden 1.21.0\n"


def test_the_html_report_loses_the_three_elements_and_gets_the_upper_case_links_back():
    link = "https://spellwarden.ai/docs/rules/{}?utm_source=scanner&amp;utm_medium=html-report&amp;utm_campaign=rule-docs"
    new = ("<article>\n<p class=\"fix-sentence\">Add it.</p>\n<p class=\"fix-lines-where\">In x, write:</p>\n"
           f"<pre class=\"fix-lines\">y</pre>\n<p class=\"fix\">How to fix: <a href=\"{link.format('sw-cfg-013')}\">the rule page</a></p>\n"
           "</article>")
    old = f"<article>\n<p class=\"fix\">How to fix: <a href=\"{link.format('SW-CFG-013')}\">the rule page</a></p>\n</article>"
    assert without_fix_guidance("report.html", new) == old


def test_sarif_loses_help_its_own_help_uri_and_the_result_lines():
    old = {"runs": [{"tool": {"driver": {"rules": [{"id": "SW-CFG-013", "helpUri": HELP_URI}]}},
                     "results": [{"ruleId": "SW-CFG-013"}, {"ruleId": "SW-SKL-009", "properties": {"preset_from": "low"}}]}]}
    new = {"runs": [{"tool": {"driver": {"rules": [{"id": "SW-CFG-013", "helpUri": PAGE, "help": {"text": "Add it."}}]}},
                     "results": [{"ruleId": "SW-CFG-013", "properties": {"fix_lines": LINES}},
                                 {"ruleId": "SW-SKL-009", "properties": {"preset_from": "low", "fix_lines": LINES}}]}]}
    assert without_fix_guidance("report.sarif", _dump(new)) == _dump(old)


def test_cyclonedx_loses_the_recommendation_and_gets_the_upper_case_url_back():
    url = "https://spellwarden.ai/docs/rules/{}?utm_source=scanner&utm_medium=cyclonedx&utm_campaign=ai-bom"
    new = {"vulnerabilities": [{"id": "SW-CFG-013", "source": {"url": url.format("sw-cfg-013")}, "description": "T",
                                "recommendation": "Add it.", "analysis": {}}]}
    old = {"vulnerabilities": [{"id": "SW-CFG-013", "source": {"url": url.format("SW-CFG-013")}, "description": "T",
                                "analysis": {}}]}
    assert without_fix_guidance("report.cdx.json", _dump(new, sort_keys=False)) == _dump(old, sort_keys=False)


def test_code_quality_and_a_report_without_additions_stay_as_they_are():
    quality = '[\n  {\n    "description": "T: e"\n  }\n]\n'
    assert without_fix_guidance("gl-code-quality-report.json", quality) == quality
    assert before_fix_guidance("gitlab-codequality", quality.encode()) == quality.encode()
    assert without_fix_guidance("report.txt", "a\n\nb\n") == "a\n\nb\n"
