"""Scan links back (spec 5.12, claim C18): the README's synopsis, its "Reports" sentence as the owner amended it (spec section 14,
Q1), the rows of "Reports" and "How to fix", the subsection "Links in the Markdown report", the paragraph of "Use it in CI", the
`invite` section of wrappers/README.md and the CHANGELOG entry. Plain English: no em dash, no en dash; no exclamation mark in the
CHANGELOG entry or the wrappers note, and in the README subsection none but the marker's."""
from __future__ import annotations

import re
from pathlib import Path

from spellwarden_cli.output import markdown

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
WRAPPERS = (ROOT / "wrappers" / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
RELEASE = "1.26.0"


def section(heading: str) -> str:
    start = README.index(heading)
    end = README.find("\n### ", start + len(heading))
    return README[start:end if end != -1 else len(README)]


def flat(text: str) -> str:
    return " ".join(text.split())


def test_the_synopsis_names_the_flag():
    command = README[README.index("## The `spellwarden` command"):README.index("### What a scan reads")]
    assert "[--no-telemetry] [--no-invite] [--upload | --no-upload]" in command


def test_the_reports_sentence_is_amended_for_the_markdown_report_only():
    reports = flat(section("### Reports"))
    assert ("Every report is byte-identical for the same files, settings and `--as-of` date and, for the Markdown report, the same "
            "CI service and run kind, which its links and lines depend on (see \"Links in the Markdown report\")") in reports
    assert ("links to each rule's page and, in free mode, a line about the dashboard; see \"Links in the Markdown report\""
            in reports)
    assert "The report is byte-identical for the same files, settings and `--as-of` date." in flat(section("### HTML report"))
    assert "its links carry `utm_medium` of the CI service (`cli` for a local run)" in flat(section("### How to fix"))


def test_the_subsection_says_what_a_markdown_report_depends_on_and_what_it_holds():
    raw = section("### Links in the Markdown report")
    text = flat(raw)
    assert README.index("### How to fix") < README.index("### Links in the Markdown report") < README.index("### Presets")
    for needle in ("on the CI service (GitHub Actions, GitLab CI/CD, another CI service, or none for a local run)",
                   "on the kind of run (a pull or merge request, the default branch, another branch)",
                   "on GitHub, on whether the repository is public or private", "No other format depends on any of these",
                   "| GitHub Actions | `github-action` |", "| GitLab CI/CD | `gitlab-component` |", "| another CI service | `ci` |",
                   "| no CI service (a local run) | `cli` |", "`utm_source=scanner`",
                   "`rule-docs`", "`rule-fix`", "`description-lint`", "`analyzer`", "`presets`", "`dashboard`", "`badge`",
                   "the report is in free mode", "the run is on GitHub Actions", "it is a run of the default branch",
                   "the repository is public", "not that the scan passed", "`<!-- spellwarden-summary-only -->`",
                   "`spellwarden ci comment` and `spellwarden ci-run gitlab` post the report without it",
                   "that text anywhere else in a report cuts nothing", "`--no-invite`", "`SW_INVITE`", "input `invite`",
                   "The scanner sends nothing for any of this"):
        assert needle in text, needle
    assert markdown.dashboard_line("github-action") in raw
    assert "To leave this line out, add `--no-invite`." in text
    assert raw.count("!") == raw.count("<!-- spellwarden-summary-only -->") == 1  # the marker's is the only one
    for character in ("—", "–"):
        assert character not in raw


def test_use_it_in_ci_names_the_input_of_both_wrappers():
    ci_section = flat(README[README.index("## Use it in CI"):README.index("### Pre-commit hook")])
    assert ("Both wrappers take an input `invite` (since 1.26.0, `true` by default): `false` leaves the dashboard line and the "
            "README badge offer out of the job summary and the comment, as `--no-invite` does. See \"Links in the Markdown "
            "report\".") in ci_section


def test_the_wrappers_note_states_the_invite_input():
    start = WRAPPERS.index(f"## The `invite` input ({RELEASE})")
    note = WRAPPERS[start:]
    for needle in ('"false to leave the dashboard line and the badge offer out of the job summary and the comment; true by default"',
                   "invite: {default: true, type: boolean}", "`SW_INVITE`", "`--no-invite` when `false`",
                   "an empty or unset `SW_INVITE`", "as a usage problem", "Links in the Markdown report"):
        assert needle in note, needle
    for character in ("—", "–", "!"):
        assert character not in WRAPPERS


def test_the_changelog_entry_follows_the_rules_version_paragraph():
    start = CHANGELOG.index(f"## {RELEASE} (")
    raw = CHANGELOG[start:CHANGELOG.index("\n## ", start + 1)]
    assert re.match(rf"## {re.escape(RELEASE)} \((\d{{4}}-\d{{2}}-\d{{2}}|2026-\d{{2}}-NN)\)\n\nRules version ", raw)
    paragraphs = [flat(part) for part in raw.split("\n\n")[1:] if part.strip()]
    assert paragraphs[0].startswith("Rules version 2026.11.10, unchanged (68 rules)")
    (entry,) = [paragraph for paragraph in paragraphs if paragraph.startswith("Links in the Markdown report.")]
    assert paragraphs.index(entry) > 0
    for needle in ("links each baseline rule id in its findings table to the rule's page", "spellwarden.ai/docs/rules",
                   "`utm_medium`", "`github-action`", "`gitlab-component`", "`ci`", "`cli`", "one line about the Spellwarden dashboard",
                   "default-branch run of a public GitHub repository", "not that it passed",
                   "the pull or merge request comment never carries the offer", "`--no-invite`", "`SW_INVITE`", "No rule changed",
                   "The JSON, SARIF, text, CycloneDX, HTML and Code Quality reports are unchanged"):
        assert needle in entry, needle
    for character in ("—", "–", "!"):
        assert character not in raw
    assert markdown.SUMMARY_MARKER not in raw
