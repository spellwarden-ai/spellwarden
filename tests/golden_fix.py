"""What 1.21.0 adds to a scan's reports (P6-15 fix guidance, spec 6.4 to 6.9), and the one value it corrects (O-12):
`without_fix_guidance` takes exactly those out again and puts the corrected value back as the older releases wrote it, so the
golden tests of 1.0.0, 1.13.0, 1.17.0, 1.18.0, 1.19.0 and 1.20.0 prove every other byte of their reports unchanged (E-7).

What it takes out: each finding's `fix`, `rule_url` and `fix_lines` in the JSON report (and `fix_lines` in a probe's findings);
the "How to fix" section and the "    write in" lines of the text report; the "**How to fix**" section of the Markdown report; the
`fix-sentence`, `fix-lines-where` and `fix-lines` elements of the HTML report; each SARIF rule's `help`, its own `helpUri` (back to
the README's rules table) and each result's `properties.fix_lines`; each CycloneDX vulnerability's `recommendation`. What it puts
back: the upper-case rule id in the rule links of the HTML report and in the CycloneDX `source.url`. The Code Quality report is
unchanged. A report without any of these comes back as the very same text."""
from __future__ import annotations

import json
import re

from golden_new_rules import without_new_rules

HELP_URI = "https://github.com/spellwarden-ai/spellwarden#the-rules"  # what every SARIF rule linked up to 1.20.0
RULE_PAGE = "https://spellwarden.ai/docs/rules/"
TEXT_HEADING = "How to fix"
MARKDOWN_HEADING = "**How to fix**"
FINDING_KEYS = ("fix", "rule_url", "fix_lines")
HTML_ELEMENTS = ('<p class="fix-sentence">', '<p class="fix-lines-where">', '<pre class="fix-lines">')
_LOWER_LINK = re.compile(r"(https://spellwarden\.ai/docs/rules/)(sw-(?:skl|mcp|cfg|reg|a2a)-[0-9]{3})(?=\?)")
# the file name of each format, as the golden recorders write them (fixture_reports.ALL_FORMATS)
NAMES = {"json": "report.json", "sarif": "report.sarif", "markdown": "report.md", "gitlab-codequality": "gl-code-quality-report.json",
         "text": "report.txt", "cyclonedx": "report.cdx.json", "html": "report.html"}


def _upper(text: str) -> str:
    return _LOWER_LINK.sub(lambda match: match.group(1) + match.group(2).upper(), text)


def _json(document: dict, *, sort_keys: bool) -> str:
    return json.dumps(document, indent=2, sort_keys=sort_keys, ensure_ascii=True) + "\n"


def _report(text: str) -> str:
    document = json.loads(text)
    changed = False
    findings = list(document.get("findings", []))
    for probe in document.get("probes", []):
        findings += probe.get("findings", [])
    for finding in findings:
        for key in FINDING_KEYS:
            if key in finding:
                del finding[key]
                changed = True
    return _json(document, sort_keys=True) if changed else text


def _sarif(text: str) -> str:
    document = json.loads(text)
    changed = False
    for run in document.get("runs", []):
        for rule in run["tool"]["driver"]["rules"]:
            if "help" in rule:
                del rule["help"]
                changed = True
            if rule.get("helpUri", "").startswith(RULE_PAGE):
                rule["helpUri"] = HELP_URI
                changed = True
        for result in run.get("results", []):
            properties = result.get("properties", {})
            if "fix_lines" in properties:
                del properties["fix_lines"]
                if not properties:
                    del result["properties"]
                changed = True
    return _json(document, sort_keys=True) if changed else text


def _cyclonedx(text: str) -> str:
    document = json.loads(text)
    changed = False
    for vulnerability in document.get("vulnerabilities", []):
        if "recommendation" in vulnerability:
            del vulnerability["recommendation"]
            changed = True
    if not changed:
        return _upper(text)
    return _upper(_json(document, sort_keys=False))


def _text(text: str) -> str:
    lines = text.split("\n")
    if TEXT_HEADING in lines:
        start = lines.index(TEXT_HEADING)
        del lines[start:lines.index("", start) + 1]
    return "\n".join(line for line in lines if not line.startswith("    write in "))


def _markdown(text: str) -> str:
    lines = text.split("\n")
    if MARKDOWN_HEADING in lines:
        start = lines.index(MARKDOWN_HEADING)
        end = start + 2  # the heading and the blank line under it
        while end < len(lines) and lines[end] != "":
            end += 1
        del lines[start - 1:end]  # from the blank line above the heading through the last bullet
    return "\n".join(lines)


def _html(text: str) -> str:
    lines = [line for line in text.split("\n") if not line.startswith(HTML_ELEMENTS)]
    return _upper("\n".join(lines))


_BY_NAME = {"report.json": _report, "report.sarif": _sarif, "report.cdx.json": _cyclonedx, "report.txt": _text,
            "report.md": _markdown, "report.html": _html}


def without_fix_guidance(name: str, text: str) -> str:
    """`text`, the report `name` (a golden recorder's file name), as a scanner before 1.21.0 would have written it."""
    strip = _BY_NAME.get(name)
    return text if strip is None else strip(text)


def before_fix_guidance(fmt: str, data: bytes) -> bytes:
    """`without_fix_guidance` for a format name of `fixture_reports` and the bytes of its report, and (1.25.0) without the SARIF
    descriptors of the rules that release added (`golden_new_rules`)."""
    return without_new_rules(NAMES[fmt], without_fix_guidance(NAMES[fmt], data.decode("utf-8"))).encode("utf-8")


__all__ = ["before_fix_guidance", "without_fix_guidance"]
