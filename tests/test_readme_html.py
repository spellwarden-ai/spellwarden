"""1.18.0: the README describes the HTML report: the Reports table row, the section "HTML report" (self-contained, escaped, no
script, the Content-Security-Policy, no network request) and, in "Limits", that it has no size cap of its own."""
from __future__ import annotations

from pathlib import Path

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")


def section(heading: str) -> str:
    start = README.index(heading)
    return README[start:README.index("\n### ", start + len(heading))]


def test_the_readme_describes_the_html_report():
    text = section("### HTML report")
    for needle in ("`--format html`", "self-contained", "`<script>`", "Content-Security-Policy", "no network request",
                   "no script element", "no size cap of its own", "rule pages"):
        assert needle in text, needle
    for character in ("—", "–", "!"):
        assert character not in text
    assert "| `html` |" in section("### Reports")
    assert "The HTML report (since 1.18.0) has no size cap of its own" in section("### Limits")


def test_the_readme_says_what_the_html_report_leaves_to_the_json_report():
    """The HTML report holds the content of the spec's list, not the whole JSON report: the README says which parts are in the
    JSON report only, and nowhere says the HTML report holds what the JSON report holds."""
    text = " ".join(section("### HTML report").split())
    for needle in ("the scanner and rules versions and the date, the preset when one other than `balanced` applied, the outcome "
                   "and exit code, the counts by severity, the notices and errors, then every finding grouped by item",
                   "the description lint. Under `--analyze` it also holds the analysis.",
                   "It does not hold everything the JSON report holds: the connected-mode details (the credential, the "
                   "organisation, the run, the policy applied, the registry gate and the upload outcome) and the "
                   "instruction-file scopes (when the agent applies each instruction file) are not in the HTML report. They "
                   "are in the JSON report (its `connected` block, and each instruction file's `format` and `front_matter`), "
                   "and the text and Markdown reports show them. The notices of a connected run, the upload's among them, are "
                   "in the HTML report with every other notice."):
        assert needle in text, needle
    limits = " ".join(section("### Limits").split())
    assert ("The HTML report (since 1.18.0) has no size cap of its own: it holds every finding, notice and error of the JSON "
            "report, under the caps above") in limits
    assert "holds what the JSON report holds" not in " ".join(README.split())
