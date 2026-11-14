"""Phase 3 batch 2a spec 11.6, 11.7 and 17: the README says what `scan --user`, the workstation upload and `--format cyclonedx`
do, names every new code and records every new limit, and the changelog has the 1.14.0 entry above 1.13.0."""
from __future__ import annotations

from pathlib import Path

from spellwarden_scan import __version__

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
    assert text.index(f"## {__version__} (") < text.index("## 1.13.0 (")
    entry = text[text.index(f"## {__version__} ("):text.index("## 1.13.0 (")]
    for needle in ("`spellwarden scan --user`", "--inventory", "SPELLWARDEN_WORKSTATION_KEY", "`--format cyclonedx`",
                   "`spellwarden_scan.cyclonedx`", "same reports as 1.13.0"):
        assert needle in entry, needle
