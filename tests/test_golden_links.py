"""Scan links back (spec 9, claim C16): `golden_links.without_links_back` turns what a local run's Markdown report gained back into
the bytes an older scanner wrote, and returns every other text unchanged."""
from __future__ import annotations

from golden_fix import without_fix_guidance
from golden_links import DASHBOARD_LINE, without_links_back

LINKED = ("| high | [SW-CFG-001](https://spellwarden.ai/docs/rules/sw-cfg-001?utm_source=scanner&utm_medium=cli&utm_campaign=rule-docs)"
          " | `.mcp.json:3` | Remote MCP server over plain HTTP |")
PLAIN = "| high | SW-CFG-001 | `.mcp.json:3` | Remote MCP server over plain HTTP |"
NEW_FOOTER = ("Spellwarden 1.25.0, rules 2026.11.10. [What each rule checks](https://spellwarden.ai/docs/rules?utm_source=scanner"
              "&utm_medium=cli&utm_campaign=rule-docs), [source code](https://github.com/spellwarden-ai/spellwarden)")
OLD_FOOTER = "Spellwarden 1.25.0, rules 2026.11.10. [What each rule checks](https://github.com/spellwarden-ai/spellwarden#the-rules)"


def test_a_new_report_becomes_the_old_bytes():
    new = f"<!-- spellwarden-scan -->\nverdict\n\n{LINKED}\n\n{DASHBOARD_LINE}\n\n{NEW_FOOTER}\n"
    old = f"<!-- spellwarden-scan -->\nverdict\n\n{PLAIN}\n\n{OLD_FOOTER}\n"
    assert without_links_back("report.md", new) == old
    assert without_fix_guidance("report.md", new) == old  # the older goldens' transform takes the links back out first


def test_anything_else_comes_back_unchanged():
    other = LINKED.replace("utm_medium=cli", "utm_medium=github-action")  # only a local run's links are taken out
    footer = NEW_FOOTER.replace("utm_medium=cli", "utm_medium=ci")
    for text in (f"{PLAIN}\n\n{OLD_FOOTER}\n", f"{other}\n{footer}\n", f"x {LINKED}\n", f"{DASHBOARD_LINE}\nnot blank\n"):
        assert without_links_back("report.md", text) == text
    for name in ("report.json", "report.txt", "report.sarif", "report.html", "report.cdx.json", "gl-code-quality-report.json"):
        assert without_links_back(name, f"{LINKED}\n{NEW_FOOTER}\n") == f"{LINKED}\n{NEW_FOOTER}\n"


def test_the_dashboard_line_is_the_one_a_local_run_writes():
    from spellwarden_cli.output import markdown

    assert DASHBOARD_LINE == markdown.dashboard_line("cli")
