"""1.21.0 (P6-15 spec 6.7 to 6.9, O-12; E-3, E-4, E-10): the HTML report shows the fix sentence and the setting lines above the
rule page link, which now holds the rule id in lower case; each SARIF baseline rule has `help` and its own `helpUri`, and a result
its setting lines as `properties.fix_lines`, never a `fixes` object; each CycloneDX vulnerability of a baseline rule has
`recommendation` and a lower-case `source.url`; an organisation rule's finding gets none of these; Code Quality is unchanged; and
no output holds a rule page address with an upper-case letter in its path."""
from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
from fix_guidance_report import BASELINE, CFG_013, SKL_009, report
from html_checks import inert_problems

from spellwarden_cli import escape
from spellwarden_cli.output import FORMATS
from spellwarden_cli.output.sarif import HELP_URI
from spellwarden_cli.report import FIX_TAGS

SARIF_SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "sarif-schema-2.1.0.json"
HTML_LINK = "https://spellwarden.ai/docs/rules/{}?utm_source=scanner&amp;utm_medium=html-report&amp;utm_campaign=rule-docs"
CDX_LINK = "https://spellwarden.ai/docs/rules/{}?utm_source=scanner&utm_medium=cyclonedx&utm_campaign=ai-bom"
UPPER_PAGE = re.compile(r"spellwarden\.ai/docs/rules/[^?\"'\s<]*[A-Z]")


def _articles(text: str) -> dict[str, str]:
    """Each finding's article of the HTML report, by rule id."""
    found = {}
    for article in re.findall(r'<article class="finding[^"]*" id="finding-\d+">.*?</article>', text, re.DOTALL):
        found[re.search(r"SW-[A-Z0-9]{3}-\d{3}", article).group(0)] = article
    return found


def test_the_html_report_shows_the_sentence_and_the_lines_above_the_lower_case_rule_link():
    text = FORMATS["html"](report())
    assert inert_problems(text) == []
    articles = _articles(text)
    link = HTML_LINK.format("sw-cfg-013")
    assert ('<p class="fix-sentence">Add the server&#x27;s read-only switch, and give write access to a separate entry that stays '
            'disabled until the work needs it.</p>\n'
            '<p class="fix-lines-where">In the query of the mcp.supabase.com address, write:</p>\n'
            '<pre class="fix-lines">read_only=true</pre>\n'
            f'<p class="fix">How to fix: <a href="{link}">the rule page</a></p>') in articles["SW-CFG-013"]
    assert f'<a href="{link}">SW-CFG-013</a>' in articles["SW-CFG-013"]
    assert f'<p class="fix-sentence">{escape.html(SKL_009)}</p>' in articles["SW-SKL-009"]
    assert "fix-lines" not in articles["SW-SKL-009"]
    assert "fix-sentence" not in articles["SW-ORG-001"] and 'class="fix"' not in articles["SW-ORG-001"]


def test_each_sarif_baseline_rule_has_help_and_its_own_help_uri():
    document = json.loads(FORMATS["sarif"](report()))
    schema = json.loads(SARIF_SCHEMA.read_bytes().replace(b"\r\n", b"\n"))
    jsonschema.validators.validator_for(schema)(schema).validate(document)
    rules = {entry["id"]: entry for entry in document["runs"][0]["tool"]["driver"]["rules"]}
    for rule in BASELINE:
        url = f"{rule.page}?{FIX_TAGS}"
        assert rules[rule.id]["helpUri"] == url, rule.id
        assert rules[rule.id]["help"] == {"text": rule.fix,
                                          "markdown": f"{escape.markdown(rule.fix)}\n\n[How to fix {rule.id}]({url})"}, rule.id
    assert "client\\_id\\_metadata\\_document\\_supported" in rules["SW-MCP-003"]["help"]["markdown"]
    assert "help" not in rules["SW-ORG-001"] and rules["SW-ORG-001"]["helpUri"] == HELP_URI


def test_a_sarif_result_carries_its_setting_lines_and_no_fixes_object():
    results = json.loads(FORMATS["sarif"](report()))["runs"][0]["results"]
    by_rule = {result["ruleId"]: result for result in results}
    assert by_rule["SW-CFG-013"]["properties"]["fix_lines"] == {"text": "read_only=true",
                                                                 "where": "the query of the mcp.supabase.com address"}
    assert "properties" not in by_rule["SW-SKL-009"] and "properties" not in by_rule["SW-ORG-001"]
    assert all("fixes" not in result for result in results)


def test_each_cyclonedx_vulnerability_of_a_baseline_rule_has_the_recommendation_and_a_lower_case_url():
    vulnerabilities = {entry["id"]: entry for entry in json.loads(FORMATS["cyclonedx"](report()))["vulnerabilities"]}
    cfg = vulnerabilities["SW-CFG-013"]
    assert cfg["recommendation"] == CFG_013 and cfg["source"]["url"] == CDX_LINK.format("sw-cfg-013")
    assert list(cfg).index("recommendation") == list(cfg).index("description") + 1
    assert vulnerabilities["SW-SKL-009"]["recommendation"] == SKL_009
    assert "recommendation" not in vulnerabilities["SW-ORG-001"] and "url" not in vulnerabilities["SW-ORG-001"]["source"]


def test_code_quality_is_unchanged_and_no_output_holds_an_upper_case_rule_page():
    quality = FORMATS["gitlab-codequality"](report())
    assert "fix" not in quality and "rule-fix" not in quality and "recommendation" not in quality
    for name, render in FORMATS.items():
        assert UPPER_PAGE.search(render(report())) is None, name
