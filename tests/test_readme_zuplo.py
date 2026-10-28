"""The README and the changelog on the Zuplo export (Zuplo export spec 11): the Zuplo paragraph names every file of the export,
its example is the beginning of the baseline's policies file (the engine version and the two digests written as
placeholders), the enforcement table and the `PLANNED_TARGETS` sentence say what the code says, and the new text holds no
dash characters and no exclamation marks."""
from __future__ import annotations

import re
from pathlib import Path

from spellwarden_scan import EXPORT_TARGETS, PLANNED_TARGETS, baseline_pack, build_export

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")
BUILT = "2026-12-01T00:00:00Z"


def zuplo_paragraph() -> str:
    start = README.index("**Zuplo.**")
    return README[start:README.index("## The `spellwarden` command")]


def test_the_paragraph_names_every_file_of_the_export():
    for path in build_export(baseline_pack(), "zuplo", built_at=BUILT):
        assert f"`{path}`" in zuplo_paragraph(), path


def test_the_example_is_the_beginning_of_the_baseline_policies_file():
    block = zuplo_paragraph().split("<!-- zuplo-example:start -->\n```json\n")[1].split("```\n<!-- zuplo-example:end -->")[0]
    built = build_export(baseline_pack(), "zuplo", built_at=BUILT)["zuplo/config/spellwarden-policies.json"].decode("ascii")
    built = re.sub(r'("engine": )"[^"]*"', r'\1"<engine version>"', built)
    built = re.sub(r'("guard_sha256": )"[0-9a-f]{64}"', r'\1"<sha256 of the guard file>"', built)
    built = re.sub(r'("options_sha256": )"[0-9a-f]{64}"', r'\1"<sha256 of the canonical options>"', built)
    assert built.startswith(block)


def test_the_export_sentence_and_the_enforcement_table():
    assert EXPORT_TARGETS == ("claude-code-hooks", "kong", "zuplo") and PLANNED_TARGETS == ("agentcore-policy", "cloudflare-egress")
    assert ("`target` is one of `EXPORT_TARGETS` (`claude-code-hooks`, `kong`, `zuplo`), and `PLANNED_TARGETS` "
            "(`agentcore-policy`, `cloudflare-egress`) are not available yet.") in README
    row = next(line for line in README.splitlines() if line.startswith("| `SW-GW-004` |"))
    assert row.endswith("| Kong, prompts only; Zuplo, MCP server responses |")
    assert "the Zuplo export includes a script that checks it at deploy" in next(line for line in README.splitlines() if line.startswith("| `SW-GW-003` |"))
    assert "`kong` and `zuplo` (any pattern rule" in README


def test_the_changelog_has_the_1_6_0_entry_above_1_5_0():
    assert CHANGELOG.index("## 1.6.0") < CHANGELOG.index("## 1.5.0")
    entry = CHANGELOG[CHANGELOG.index("## 1.6.0"):CHANGELOG.index("## 1.5.0")]
    for text in ("Zuplo", "SW-GW-004", "SW-GW-003", "TARGET_SINCE", "fixtures/export_hashes_1.5.0.json", "make check-node", "2026.10.6"):
        assert text in entry, text


def test_the_new_text_has_no_dash_characters_and_no_exclamation_marks():
    entry = CHANGELOG[CHANGELOG.index("## 1.6.0"):CHANGELOG.index("## 1.5.0")]
    for text in (re.sub(r"<!--.*?-->", "", zuplo_paragraph(), flags=re.S), entry):
        assert "–" not in text and "—" not in text and "!" not in text
