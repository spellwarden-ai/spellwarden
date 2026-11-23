"""What every test of the HTML report (1.18.0) checks: the document is inert (`inert_problems`: no script, no event attribute, no
external asset, no form, no frame, no image, one style in the head without `url(`, the Content-Security-Policy meta, links only to
`#` anchors and the tagged rule pages, attributes only the scanner's own), and it holds every finding, notice and error the JSON
report holds (`missing_from_html`)."""
from __future__ import annotations

import re
from html.parser import HTMLParser

from spellwarden_cli import escape

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
RULE_LINK = re.compile(r"https://spellwarden\.ai/docs/rules/sw-(skl|mcp|cfg|reg|a2a)-[0-9]{3}"
                       r"\?utm_source=scanner&utm_medium=html-report&utm_campaign=rule-docs")
ALLOWED_TAGS = frozenset({"html", "head", "meta", "title", "style", "body", "main", "h1", "h2", "h3", "p", "span", "a", "code",
                          "pre", "table", "tr", "th", "td", "ul", "li", "section", "article", "br"})
ALLOWED_ATTRIBUTES = frozenset({"lang", "charset", "http-equiv", "content", "name", "class", "id", "href"})
ALLOWED_METAS = ({"charset": "utf-8"}, {"http-equiv": "Content-Security-Policy", "content": CSP},
                 {"name": "viewport", "content": "width=device-width, initial-scale=1"})
RAW_NEEDLES = ("<script", "<link", "<iframe", "<img", "<object", "<embed", "<form", "<base")
_VOID = frozenset({"meta", "br"})


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str | None], tuple[str, ...]]] = []
        self.stack: list[str] = []
        self.style_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs), tuple(self.stack)))
        if tag not in _VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.elements.append((tag, dict(attrs), tuple(self.stack)))

    def handle_endtag(self, tag):
        if tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass

    def handle_data(self, data):
        if self.stack and self.stack[-1] == "style":
            self.style_text.append(data)


def inert_problems(text: str) -> list[str]:
    """Every way `text` falls short of an inert, self-contained report; empty when it is one."""
    problems = []
    if not text.startswith("<!doctype html>\n"):
        problems.append("the document does not start with <!doctype html>")
    lowered = text.lower()
    problems += [f"raw {needle}" for needle in RAW_NEEDLES if needle in lowered]
    parser = _Collector()
    parser.feed(text)
    parser.close()
    styles = [element for element in parser.elements if element[0] == "style"]
    if len(styles) != 1 or styles[0][2] != ("html", "head"):
        problems.append("not exactly one style element, in the head")
    css = "".join(parser.style_text).lower()
    if "url(" in css or "@import" in css:
        problems.append("url( or @import in the style")
    metas = [attrs for tag, attrs, _ in parser.elements if tag == "meta"]
    if {"http-equiv": "Content-Security-Policy", "content": CSP} not in metas:
        problems.append("no Content-Security-Policy meta")
    problems += [f"meta {attrs}" for attrs in metas if attrs not in ALLOWED_METAS]
    for tag, attrs, _ in parser.elements:
        if tag not in ALLOWED_TAGS:
            problems.append(f"element {tag}")
        for name, value in attrs.items():
            value = value or ""
            if name.startswith("on"):
                problems.append(f"event attribute {name} on {tag}")
            elif name not in ALLOWED_ATTRIBUTES:
                problems.append(f"attribute {name} on {tag}")
            elif name == "href" and not value.startswith("#") and RULE_LINK.fullmatch(value) is None:
                problems.append(f"link to {value!r}")
            elif name == "class" and re.fullmatch(r"[a-z0-9 -]+", value) is None:
                problems.append(f"class {value!r}")
            elif name == "id" and re.fullmatch(r"finding-[0-9]+", value) is None:
                problems.append(f"id {value!r}")
    return problems


def missing_from_html(text: str, report: dict) -> list[str]:
    """The findings (by fingerprint), notices and errors (by code and message, as `escape.html` writes them) of the JSON report
    `report` that the HTML report `text` does not hold."""
    missing = [f"finding {entry['rule_id']} {entry['fingerprint'][:12]}" for entry in report["findings"]
               if entry["fingerprint"] not in text]
    for kind in ("notices", "errors"):
        for entry in report[kind]:
            if escape.html(entry["code"]) not in text or escape.html(entry["message"]) not in text:
                missing.append(f"{kind[:-1]} {entry['code']}")
    return missing
