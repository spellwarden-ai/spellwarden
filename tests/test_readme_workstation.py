"""Phase 3 batch 2a spec 11.6, 11.7 and 17: the README says what `scan --user`, the workstation upload and `--format cyclonedx`
do, names every new code and records every new limit, and the changelog has the 1.14.0 entry above 1.13.0."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NEW_CODES = ("user_instructions_limit", "user_skills_limit", "workstation_no_credential", "workstation_label_missing",
             "workstation_upload_too_large", "workstation_upload_failed", "workstation_uploaded", "client_not_found")


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def test_the_workstation_section_names_the_codes_variables_and_promises():
    text = read("README.md")
    section = text[text.index("### Scanning a workstation"):text.index("### The usage ping")]
    for code in NEW_CODES:
        assert f"`{code}`" in text, code
    for needle in ("SPELLWARDEN_WORKSTATION_ORG", "SPELLWARDEN_WORKSTATION_KEY", "--device-label", "--inventory",
                   "never changes a client file", "never starts a local server", "sends no usage ping", "workstation.json",
                   "mode 0600", "outside-home:<8 hex>/<last segment>", "/workstations/inventory", "symlink_skipped",
                   "never starts connected mode", "macOS is covered by its fixture home"):
        assert needle in section, needle


def test_the_limits_section_records_each_new_limit():
    text = read("README.md")
    limits = text[text.index("### Limits"):text.index("### Settings:")]
    for needle in ("at most 300 instruction files per client", "at most 1,000 skills per skills directory",
                   "200 Gemini CLI extensions", "read up to 10 MiB", "1 MiB, 2,000 items and 1,000 findings",
                   "at most 50 errors and 50 notices"):
        assert needle in limits, needle


def test_the_reports_table_has_cyclonedx_and_the_releases_name_no_macos_runner():
    text = read("README.md")
    reports = text[text.index("### Reports"):text.index("### Checking A2A agent cards")]
    assert "| `cyclonedx` |" in reports and "CycloneDX 1.7" in reports
    assert "on Python 3.13 on Windows, on every push" in text


def test_the_changelog_has_the_1_14_0_entry_above_1_13_0():
    text = read("CHANGELOG.md")
    assert text.index("## 1.14.0 (") < text.index("## 1.13.0 (")
    entry = text[text.index("## 1.14.0 ("):text.index("## 1.13.0 (")]
    for needle in ("`spellwarden scan --user`", "--inventory", "SPELLWARDEN_WORKSTATION_KEY", "`--format cyclonedx`",
                   "`spellwarden_scan.cyclonedx`", "same reports as 1.13.0"):
        assert needle in entry, needle


def test_the_upload_paragraph_says_the_request_comes_before_the_reports():
    """Phase 3 batch 2c spec 11.2 (F1): the request is sent before the reports are written, and every report carries it."""
    text = read("README.md")
    section = text[text.index("#### Uploading a workstation inventory"):text.index("### The usage ping")]
    assert "the reports were written before the request" not in section
    for needle in ("before any report is written", "Every report carries the outcome", "`exit_code` is 2 after a failure",
                   "the code `crash`", "`invocations` when the upload failed", "the Markdown report lists the error",
                   "`spellwarden:errors`", "a GitLab Code Quality file lists findings only",
                   "The reports hold no timestamp", "printed on stderr, after the reports are written"):
        assert needle in section, needle
