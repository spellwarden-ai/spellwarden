#!/usr/bin/env python3
"""The title and the body of the Discussions thread of one release (docs/specs/2026-11-25-community-reports.md, section 9.1),
built from CHANGELOG.md with no model and no network:

    python scripts/release_discussion.py title X.Y.Z
    python scripts/release_discussion.py body X.Y.Z [--changelog CHANGELOG.md]

`.github/workflows/release-discussion.yml` runs both and posts the thread; this script only prints text. The text is UTF-8 with LF
line endings and is the same every time. A version without a CHANGELOG section, a malformed version or a CHANGELOG that cannot be
read is one line on stderr, exit 2 and nothing on stdout. Credit text comes only from the CHANGELOG lines, never from
`fixtures/community/`. Standard library only."""
from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

REPOSITORY_URL = "https://github.com/spellwarden-ai/spellwarden"
RULE_PAGE = "https://spellwarden.ai/docs/rules/{}?utm_source=github&utm_medium=discussion&utm_campaign=release-thread"
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
RULE_ID = re.compile(r"SW-(?:SKL|MCP|CFG|REG|A2A)-[0-9]{3}")
NO_CHANGELOG_RULES = "The CHANGELOG entry of this release says what changed."
NO_RULE_CHANGED = "No rule changed in this release."
NONE_NAMED = "Rules named in it: none; the CHANGELOG entry says what changed."
NO_COMMUNITY = "No community report was fixed in this release."
CLOSING = (f"To report a miss or a false alarm, open an issue with [one of the forms]({REPOSITORY_URL}/issues/new/choose). "
           "Reports are unpaid, and a reporter is named only if they ask to be. A working way past a rule goes to "
           f"[private reporting]({REPOSITORY_URL}/security/advisories/new) or to security@spellwarden.ai, not to an issue. "
           "Questions that are not a bug can be asked in a comment below or in the other categories of these Discussions.")


class Unusable(Exception):
    """The one-line reason nothing was printed."""


def _manifest_module():
    spec = importlib.util.spec_from_file_location("spellwarden_release_manifest", Path(__file__).with_name("release_manifest.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def title(version: str) -> str:
    """The title of the thread; the workflow compares it, exactly, with the titles of the threads that exist."""
    _check(version)
    return f"Release {version}: what changed in the rules"


def _check(version: str) -> None:
    if VERSION.fullmatch(version) is None:
        raise Unusable(f"the version {version[:40]!r} is not of the form X.Y.Z")


def _release_date(changelog: str, version: str) -> str | None:
    match = re.search(rf"^## {re.escape(version)} \(([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})\)[ \t]*$", changelog, re.M)
    return match.group(1) if match else None


def _first_paragraph(section: str) -> str:
    return section.strip("\n").split("\n\n", 1)[0]


def _opening_clause(paragraph: str) -> str:
    """The text up to the first `: ` or `. `; a version such as 2026.11.9 holds no space after its dots."""
    ends = [index for index in (paragraph.find(": "), paragraph.find(". ")) if index != -1]
    return paragraph[:min(ends)] if ends else paragraph


def _community_lines(section: str) -> list[str]:
    """Every entry of the section that starts `Community report `, as written: the text of a bullet or a line, with the lines it
    wraps onto (indented, as the CHANGELOG wraps a bullet) joined by one space."""
    found: list[str] = []
    wrapping = False
    for line in section.split("\n"):
        stripped = line.strip()
        text = stripped[2:].lstrip() if stripped.startswith("- ") else stripped
        if text.startswith("Community report "):
            found.append(text)
            wrapping = True
        elif wrapping and stripped and line[:1] in " \t" and not stripped.startswith("- "):
            found[-1] += " " + stripped
        else:
            wrapping = False
    return found


def body(changelog: str, version: str) -> str:
    """The text of the thread for `version`, built from the text of CHANGELOG.md (5 parts, 9.1)."""
    _check(version)
    changelog = changelog.replace("\r\n", "\n")
    try:
        section = _manifest_module().changelog_section(changelog, version)
    except ValueError:
        raise Unusable(f"CHANGELOG.md has no section for {version}") from None
    date = _release_date(changelog, version)
    label = f"Release {version}, {date}" if date else f"Release {version}"
    parts = [f"[{label}]({REPOSITORY_URL}/releases/tag/v{version})"]
    paragraph = " ".join(_first_paragraph(section).split())
    if paragraph.startswith("Rules version"):
        parts.append(paragraph)
        if "unchanged" in _opening_clause(paragraph):
            parts.append(NO_RULE_CHANGED)
        else:
            ids = sorted(set(RULE_ID.findall(paragraph)))
            parts.append("Rules named in it: " + ", ".join(f"[{rule}]({RULE_PAGE.format(rule.lower())})" for rule in ids)
                         if ids else NONE_NAMED)
    else:
        parts += [NO_CHANGELOG_RULES, NONE_NAMED]
    lines = _community_lines(section)
    parts.append("From the community\n\n" + ("\n".join(f"- {line}" for line in lines) if lines else NO_COMMUNITY))
    parts.append(CLOSING)
    return "\n\n".join(parts) + "\n"


def main(argv: list[str] | None = None) -> int:
    command = argparse.ArgumentParser(prog="release_discussion.py")
    commands = command.add_subparsers(dest="command", required=True)
    commands.add_parser("title").add_argument("version")
    body_parser = commands.add_parser("body")
    body_parser.add_argument("version")
    body_parser.add_argument("--changelog", default="CHANGELOG.md")
    args = command.parse_args(argv)
    try:
        if args.command == "title":
            text = title(args.version) + "\n"
        else:
            _check(args.version)
            try:
                changelog = Path(args.changelog).read_bytes().decode("utf-8")
            except (OSError, UnicodeDecodeError):
                raise Unusable(f"{Path(args.changelog).name} cannot be read as UTF-8 text") from None
            text = body(changelog, args.version)
    except Unusable as problem:
        print(f"release_discussion: {problem}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(text.encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
