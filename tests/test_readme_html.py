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
