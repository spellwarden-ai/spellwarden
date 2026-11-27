"""What the Markdown report gained when it began to link back (scan links back spec 9, claim C16): each baseline rule id of the
findings table linked to its page, the dashboard line of a local run, and the footer that points at spellwarden.ai and the source
code. `without_links_back` takes exactly those out again, as a local run (`utm_medium=cli`) writes them, so the golden tests of
1.0.0 to 1.22.0 prove every other byte of their Markdown reports unchanged. Every other report, and a text without these, comes
back as the very same text."""
from __future__ import annotations

import re

_ROW_LINK = re.compile(r"\[(SW-(?:SKL|MCP|CFG|REG|A2A)-[0-9]{3})\]\(https://spellwarden\.ai/docs/rules/(sw-(?:skl|mcp|cfg|reg|a2a)-[0-9]{3})"
                       r"\?utm_source=scanner&utm_medium=cli&utm_campaign=rule-docs\)")
DASHBOARD_LINE = ("**Spellwarden dashboard:** see the findings of all your repositories in one place and turn on a live status badge "
                  "for each one. [Create an account](https://dash.spellwarden.ai/signup?utm_source=scanner&utm_medium=cli"
                  "&utm_campaign=dashboard). To leave this line out, add `--no-invite`.")
NEW_FOOTER = ("[What each rule checks](https://spellwarden.ai/docs/rules?utm_source=scanner&utm_medium=cli&utm_campaign=rule-docs), "
              "[source code](https://github.com/spellwarden-ai/spellwarden)")
OLD_FOOTER = "[What each rule checks](https://github.com/spellwarden-ai/spellwarden#the-rules)"


def _plain(match: re.Match) -> str:
    return match.group(1) if match.group(2) == match.group(1).lower() else match.group(0)


def without_links_back(name: str, text: str) -> str:
    """`text`, the report `name` (a golden recorder's file name), as a scanner before the links back would have written it."""
    if name != "report.md":
        return text
    out: list[str] = []
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        line = lines[index]
        if line == DASHBOARD_LINE and index + 1 < len(lines) and lines[index + 1] == "":
            index += 2  # the line and the blank line under it
            continue
        if line.startswith("| "):
            line = _ROW_LINK.sub(_plain, line)
        elif line.startswith("Spellwarden ") and line.endswith(NEW_FOOTER):
            line = line[:-len(NEW_FOOTER)] + OLD_FOOTER
        out.append(line)
        index += 1
    return "\n".join(out)


__all__ = ["without_links_back"]
