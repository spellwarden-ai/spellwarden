"""Engine 1.24.0 (speed and deadline spec 10.4, 11.3; claim T18): the error code `time_limit` is the last of `ERROR_CODES`, is in the
schema of the report, and every output prints it as an incomplete scan: the JSON, text, Markdown and HTML reports and SARIF (in the invocation's tool execution
notifications) with the code and the whole message; CycloneDX with `complete` false and the count of errors; the GitLab Code Quality
report, which carries no error, as the same report without the error."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from test_outputs import make_finding, make_report, sarif_validator

from spellwarden_cli.output import FORMATS
from spellwarden_cli.report import ERROR_CODES, Notice

ROOT = Path(__file__).resolve().parents[2]
MESSAGE = ("the scan's time limit was reached while reading docs/guide.md; this skill was not judged, so the scan is incomplete: "
           "split the content, leave the file out with `exclude` in .spellwarden/config.yml, or raise --time-limit")
ERROR = Notice("time_limit", "skills/setup", MESSAGE)


def test_time_limit_is_the_last_error_code_and_is_in_the_schema_of_the_report():
    assert ERROR_CODES[-1] == "time_limit" and ERROR_CODES.count("time_limit") == 1 and ERROR_CODES[-2] == "staged_unavailable"
    schema = json.loads((ROOT / "schemas" / "report.schema.json").read_text(encoding="utf-8"))
    codes = schema["$defs"]["error"]["properties"]["code"]["enum"]
    assert codes[-2:] == ["staged_unavailable", "time_limit"] and len(codes) == len(set(codes))
    assert set(ERROR_CODES) <= set(codes)


def test_a_report_with_the_error_validates_against_the_schema_and_exits_2():
    schema = json.loads((ROOT / "schemas" / "report.schema.json").read_text(encoding="utf-8"))
    report = make_report([make_finding()], errors=[ERROR])
    jsonschema.validators.validator_for(schema)(schema).validate(json.loads(FORMATS["json"](report)))
    assert report.exit_code() == 2


def test_the_json_report_carries_the_error_as_written():
    document = json.loads(FORMATS["json"](make_report(errors=[ERROR])))
    assert document["errors"] == [{"code": "time_limit", "path": "skills/setup", "message": MESSAGE}] and document["exit_code"] == 2


def test_sarif_names_it_in_the_invocation_as_a_tool_execution_notification():
    """`sarif.INVOCATION_ERRORS` are the codes whose errors SARIF names: the two upload ones and, since 1.24.0, `time_limit`. A SARIF
    file of any other report is as it was, and so is one without errors."""
    document = json.loads(FORMATS["sarif"](make_report(errors=[ERROR])))
    sarif_validator().validate(document)  # the full SARIF 2.1.0 schema
    run = document["runs"][0]
    (invocation,) = run["invocations"]
    assert invocation["executionSuccessful"] is False
    (notification,) = invocation["toolExecutionNotifications"]
    assert notification["descriptor"] == {"id": "time_limit"} and notification["level"] == "error"
    assert "time limit was reached while reading docs/guide.md" in notification["message"]["text"]
    other = make_report(errors=[Notice("unreadable", "skills/setup", "not read")])
    assert "invocations" not in json.loads(FORMATS["sarif"](other))["runs"][0]


def test_the_json_text_markdown_and_html_reports_print_the_code_and_the_whole_message():
    report = make_report(errors=[ERROR])
    for name in ("text", "markdown", "html"):
        rendered = FORMATS[name](report)
        assert "time_limit" in rendered, name
        assert "time limit was reached while reading docs/guide.md" in rendered, name
        assert "split the content" in rendered and "or raise --time-limit" in rendered, name


def test_cyclonedx_says_the_scan_is_incomplete_and_counts_the_errors_without_the_code_or_the_message():
    document = json.loads(FORMATS["cyclonedx"](make_report(errors=[ERROR, ERROR])))
    properties = {entry["name"]: entry["value"] for entry in document["metadata"]["properties"]}
    assert properties["spellwarden:complete"] == "false" and properties["spellwarden:errors"] == "2"
    assert "time_limit" not in json.dumps(document)


def test_gitlab_code_quality_carries_no_error_so_the_report_is_that_of_the_same_scan_without_it():
    findings = [make_finding()]
    assert FORMATS["gitlab-codequality"](make_report(findings, errors=[ERROR])) == FORMATS["gitlab-codequality"](make_report(findings))
