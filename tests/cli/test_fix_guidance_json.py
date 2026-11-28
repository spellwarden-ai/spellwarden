"""1.21.0 (P6-15 spec 6.4, 6.10, 4.5; E-5, E-6): each finding of the JSON report holds its rule's `fix` and `rule_url`, and
`fix_lines` where its rule wrote them; an organisation rule's finding holds `fix` and `rule_url` as null; the upload document holds
none of the three keys; the 1.21.0 report validates against the schema, and so does the same report without the three keys (what
1.20.0 wrote), while the schema refuses values over the bounds of spec 4.7."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
from fix_guidance_report import BASELINE, ORG, report

from spellwarden_cli import connected
from spellwarden_cli.output import json_out
from spellwarden_cli.report import FIX_TAGS, rule_fix, rule_url

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "schemas" / "report.schema.json").read_text(encoding="utf-8"))
LIMITS = {"upload_max_findings": 500, "upload_max_items": 2000, "upload_max_probes": 200, "upload_max_bytes": 1_048_576}


def document() -> dict:
    return json.loads(json_out.render(report()))


def by_rule(doc: dict) -> dict[str, dict]:
    return {entry["rule_id"]: entry for entry in doc["findings"]}


def test_each_finding_holds_its_rules_fix_and_tagged_page_and_its_setting_lines():
    found = by_rule(document())
    assert found["SW-SKL-009"]["fix"] == BASELINE.get("SW-SKL-009").fix
    assert found["SW-SKL-009"]["rule_url"] == ("https://spellwarden.ai/docs/rules/sw-skl-009?utm_source=scanner&utm_medium=cli"
                                               "&utm_campaign=rule-fix")
    assert "fix_lines" not in found["SW-SKL-009"]
    assert found["SW-CFG-013"]["fix_lines"] == {"text": "read_only=true", "where": "the query of the mcp.supabase.com address"}
    assert found["SW-ORG-001"]["fix"] is None and found["SW-ORG-001"]["rule_url"] is None
    assert "fix_lines" not in found["SW-ORG-001"]


def test_rule_fix_and_rule_url():
    assert FIX_TAGS == "utm_source=scanner&utm_medium=cli&utm_campaign=rule-fix"
    rule = BASELINE.get("SW-A2A-006")
    assert rule_fix(rule) == rule.fix and rule_url(rule) == f"https://spellwarden.ai/docs/rules/sw-a2a-006?{FIX_TAGS}"
    assert (rule_fix(ORG), rule_url(ORG)) == (None, None)
    assert (rule_fix(None), rule_url(None)) == (None, None)


def test_the_report_validates_with_the_new_keys_and_without_them():
    validator = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)
    doc = document()
    validator.validate(doc)
    older = copy.deepcopy(doc)
    for entry in older["findings"]:
        for key in ("fix", "rule_url", "fix_lines"):
            entry.pop(key, None)
    validator.validate(older)


def test_the_schema_refuses_values_over_the_bounds():
    validator = jsonschema.Draft202012Validator(SCHEMA)
    doc = document()
    index = next(n for n, entry in enumerate(doc["findings"]) if "fix_lines" in entry)
    long_fix, no_text, long_where = copy.deepcopy(doc), copy.deepcopy(doc), copy.deepcopy(doc)
    long_fix["findings"][index]["fix"] = "A" * 200 + "."
    del no_text["findings"][index]["fix_lines"]["text"]
    long_where["findings"][index]["fix_lines"]["where"] = "w" * 81
    for broken in (long_fix, no_text, long_where):
        assert list(validator.iter_errors(broken))


def test_the_upload_document_holds_none_of_the_three_keys():
    doc = document()
    body, dropped, cut = connected.reduce_report(doc, LIMITS)
    assert (dropped, cut) == (0, []) and len(body["findings"]) == 3
    assert all(not {"tags", "fix", "rule_url", "fix_lines"} & set(entry) for entry in body["findings"])
    assert connected.REPORT_ONLY_FINDING_KEYS == ("tags", "fix", "rule_url", "fix_lines", "in_tests")  # 1.28.0 adds in_tests
    assert all("fix" in entry for entry in doc["findings"])  # the report dict itself is not changed
