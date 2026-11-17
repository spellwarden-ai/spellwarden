"""What 1.17.0 adds to a repository scan's reports without `--analyze` (Phase 4 batch B spec 11.4, claim E-1): the description
lint, as the `lint` section and the notice `description_lint` of the JSON report, the SW-LINT notes and their four descriptors
at the end of the SARIF rule table, the "Description lint" block of the text report and its section in the Markdown report.
`without_lint` takes exactly those out again, so the golden tests prove every other byte of the older reports unchanged."""
from __future__ import annotations

import json

LINT_IDS = ("SW-LINT-001", "SW-LINT-002", "SW-LINT-003", "SW-LINT-004")
TEXT_HEADING = "Description lint (informational, never changes the exit code)"
MARKDOWN_HEADING = "**Description lint (informational, never changes the exit code):**"


def _dump(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def without_lint(name: str, text: str) -> str:
    """`text`, the report `name` of a repository scan with skills, without what the description lint added to it."""
    if name == "report.json":
        document = json.loads(text)
        assert isinstance(document.pop("lint"), list), "a scan with skills has a lint section"
        notices = [notice for notice in document["notices"] if notice["code"] != "description_lint"]
        assert len(notices) == len(document["notices"]) - 1, "and one description_lint notice"
        document["notices"] = notices
        return _dump(document)
    if name == "report.sarif":
        document = json.loads(text)
        run = document["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        if any(rule["id"] in LINT_IDS for rule in rules):
            assert [rule["id"] for rule in rules[-4:]] == list(LINT_IDS), "appended at the end: no other index moved"
            run["tool"]["driver"]["rules"] = rules[:-4]
        run["results"] = [result for result in run["results"] if result["ruleId"] not in LINT_IDS]
        return _dump(document)
    if name == "report.txt":
        lines = text.split("\n")
        if TEXT_HEADING in lines:
            start = lines.index(TEXT_HEADING)
            del lines[start:lines.index("", start) + 1]
        return "\n".join(line for line in lines if not line.startswith("notice description_lint "))
    if name == "report.md":
        lines = text.split("\n")
        starts = [index for index, line in enumerate(lines) if line.startswith(MARKDOWN_HEADING)]
        if starts:
            end = starts[0] + 2  # the heading and the blank line under it
            while end < len(lines) and lines[end].startswith("|"):
                end += 1
            if end + 1 < len(lines) and lines[end] == "" and lines[end + 1].endswith("more notes are in the JSON report."):
                end += 2
            del lines[starts[0]:end + 1]  # through the blank line that ends the section
        return "\n".join(lines)
    return text
