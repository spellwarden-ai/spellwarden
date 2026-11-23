"""1.21.0 (P6-15 spec 6.12 E-2, E-3, E-10): the seven reports of fixtures/fix-guidance are the recorded golden files
(tests/golden/record_1_21_0.py; record them again after a change and review the diff), and in them every rule page address is the
rule's `page` (the id in lower case) with that format's campaign tags; the fix sentence, the page and the setting lines are where
section 6 puts them; Code Quality holds none of them. The organisation rule's outputs are checked on a report built by hand
(tests/cli/test_fix_guidance_*.py): a scan in free mode has no organisation rule."""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest
from golden_fix import without_fix_guidance

from spellwarden_scan import RuleSet

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("record_1_21_0", ROOT / "tests" / "golden" / "record_1_21_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)
RULES = RuleSet.baseline()
TAGS = {"cli": "utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix",
        "html": "utm_source=scanner&amp;utm_medium=html-report&amp;utm_campaign=rule-docs",
        "cyclonedx": "utm_source=scanner&utm_medium=cyclonedx&utm_campaign=ai-bom"}
PAGE = re.compile(r"https://spellwarden\.ai/docs/rules/([^?\"'\s<)]+)(\?[^\"'\s<)]*)?")


@pytest.fixture(scope="module")
def produced(tmp_path_factory):
    return record.outputs(tmp_path_factory.mktemp("fix-guidance"))


def _golden(name: str) -> str:
    return (record.GOLDEN / name).read_bytes().replace(b"\r\n", b"\n").decode("utf-8")


@pytest.mark.parametrize("name", [name for _, name in record.reports.ALL_FORMATS])
def test_each_report_is_the_recorded_one(produced, name):
    code, written = produced
    assert code == 1
    assert written[name] == _golden(name), name


def test_every_rule_page_address_is_the_page_with_the_tags_of_its_format(produced):
    _, written = produced
    expected = {"report.json": TAGS["cli"], "report.txt": TAGS["cli"], "report.md": TAGS["cli"], "report.sarif": TAGS["cli"],
                "report.html": TAGS["html"], "report.cdx.json": TAGS["cyclonedx"]}
    pages = {rule.page for rule in RULES}
    for name, tags in expected.items():
        found = PAGE.findall(written[name])
        assert found, name
        for path, query in found:
            assert f"https://spellwarden.ai/docs/rules/{path}" in pages and path == path.lower(), (name, path)
            assert query == f"?{tags}", (name, path, query)


def test_the_sections_and_fields_are_where_section_6_puts_them(produced):
    _, written = produced
    findings = json.loads(written["report.json"])["findings"]
    assert {(f["rule_id"], f["location"]["line"], json.dumps(f.get("fix_lines"), sort_keys=True)) for f in findings} == {
        ("SW-CFG-013", 3, '{"text": "read_only=true", "where": "the query of the mcp.supabase.com address"}'),
        ("SW-CFG-013", 4, "null"),
        ("SW-CFG-013", 5, '{"text": "\\"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS\\": \\"true\\"", "where": "the server\'s env"}'),
        ("SW-SKL-009", 13, "null")}
    assert all(f["fix"] == RULES.get(f["rule_id"]).fix for f in findings)
    assert written["report.txt"].count("\nHow to fix\n") == 1 and written["report.txt"].count("    write in ") == 2
    markdown = written["report.md"]
    assert markdown.count("**How to fix**") == 1 and markdown.count("\n- **SW-CFG-013** ") == 1
    assert '  - In the server\'s env, write: `"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS": "true"`' in markdown
    assert written["report.html"].count('<p class="fix-sentence">') == 4 and written["report.html"].count('<pre class="fix-lines">') == 2
    vulnerabilities = json.loads(written["report.cdx.json"])["vulnerabilities"]
    assert all(v["recommendation"] == RULES.get(v["id"]).fix for v in vulnerabilities)
    assert len(json.loads(written["report.sarif"])["runs"][0]["tool"]["driver"]["rules"]) >= 66


def test_code_quality_is_what_1_20_0_wrote_and_the_rest_differs_only_in_the_fix_guidance(produced):
    _, written = produced
    quality = written["gl-code-quality-report.json"]
    assert without_fix_guidance("gl-code-quality-report.json", quality) == quality
    assert "rule-fix" not in quality and "recommendation" not in quality
    for name, text in written.items():
        if name != "gl-code-quality-report.json":
            assert without_fix_guidance(name, text) != text, name
