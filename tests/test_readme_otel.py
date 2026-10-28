"""The README and the changelog on runtime traces (runtime traces spec 4.8, 11.3): the section names the command and
every dialect, record kind and content kind the code has, the command list carries the command's usage line, the
1.7.0 entry says that scan results, exports and rules are 1.6.0's, and the new text holds no dash characters and no
exclamation marks."""
from __future__ import annotations

from pathlib import Path

from spellwarden_scan.otel import CONTENT_KINDS, DIALECTS, RECORD_KINDS, OTEL_NAMES

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
USAGE = "spellwarden otel normalise PATH --signal traces|logs [--encoding auto|protobuf|json] [--content] [--max-records N] [--max-bytes N]"


def section() -> str:
    start = README.index("## What Spellwarden keeps from your telemetry")
    return README[start:README.index("## Versions", start)]


def entry() -> str:
    return CHANGELOG[CHANGELOG.index("## 1.7.0"):CHANGELOG.index("## 1.6.0")]


def test_the_section_shows_the_command_and_the_tables():
    text = section()
    assert USAGE in text
    for name in DIALECTS + RECORD_KINDS + CONTENT_KINDS:
        assert f"`{name}`" in text, name
    for name in ("DIALECTS", "RECORD_KINDS", "CONTENT_KINDS", "DEFAULT_LIMITS", "Record", "ResourceInfo"):
        assert f"`{name}`" in text, name


def test_no_hosted_endpoint_is_named_before_the_hosted_receiver_is_live():
    # 1.7.0 ships before the hosted receiver (the owner's decision Q1 of 2026-10-28); the hosted plan replaces this test
    # with the endpoint once the production check has passed.
    for text in (section(), entry()):
        assert "otel.spellwarden.ai" not in text
        assert "receiver reads" not in text and "receiver at" not in text


def test_the_command_list_has_the_usage_line():
    commands = README[README.index("## The `spellwarden` command"):README.index("### What a scan reads")]
    assert USAGE in commands


def test_the_changelog_has_the_1_7_0_entry_above_1_6_0():
    assert CHANGELOG.index("## 1.7.0") < CHANGELOG.index("## 1.6.0")
    text = entry()
    for name in OTEL_NAMES:
        assert f"`{name}`" in text, name
    for phrase in ("spellwarden otel normalise", "those of 1.6.0", "2026.10.6", "opentelemetry-proto"):
        assert phrase in text, phrase


def test_the_new_text_has_no_dash_characters_and_no_exclamation_marks():
    for text in (section(), entry()):
        assert "–" not in text and "—" not in text and "!" not in text
