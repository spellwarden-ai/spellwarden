"""1.18.0: the README's "Pre-commit hook" section (the configuration lines, the tagged guide link, what the hook runs and when,
that it never uploads, its exit codes and how to skip it once) and `wrappers/README.md` (the wrappers' `preset` input)."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
GUIDE = "https://spellwarden.ai/docs/pre-commit?utm_source=github&utm_medium=readme&utm_campaign=pre-commit"


def section(heading: str) -> str:
    start = README.index(heading)
    return README[start:README.index("\n### ", start + len(heading))]


def test_the_readme_explains_the_hook():
    text = section("### Pre-commit hook")
    for needle in (GUIDE, "repo: https://github.com/spellwarden-ai/spellwarden", "rev: v1.18.0", "id: spellwarden",
                   "`spellwarden scan --no-upload`", "pre-commit 3.2.0 or later", "`pre-commit`, `pre-push` and `manual`",
                   "never uploads", "exit 1", "exit 2", "exit 3", "`SKIP=spellwarden git commit`"):
        assert needle in text, needle
    for character in ("—", "–", "!"):
        assert character not in text


def test_the_readme_says_when_a_hook_run_sends_the_usage_ping():
    """The hook's scan is a scan like any other: outside CI it sends no usage ping, in CI it sends it under the rule and the
    switches of "The usage ping"."""
    text = " ".join(section("### Pre-commit hook").split())
    assert ("The hook never uploads to connected mode. Outside CI a hook run sends no usage ping; when the hook runs in CI (a "
            "`pre-commit run` in a CI job), its scan sends the usage ping like any scan in CI, and `--no-telemetry` in the "
            "hook's `args`, or any other switch in \"The usage ping\", turns it off.") in text
    assert "sends no usage ping (the ping is sent only in CI)" not in text
    assert "### The usage ping" in README


def test_the_wrappers_note_states_the_preset_input():
    text = (ROOT / "wrappers" / "README.md").read_text(encoding="utf-8")
    for needle in ('"strict, balanced or low-noise; empty uses the scanner\'s settings"',
                   'preset: {default: "", options: ["", "strict", "balanced", "low-noise"]}', "`SW_PRESET`", "`--preset VALUE`",
                   "`scan-action.ref`", "Linux and Windows"):
        assert needle in text, needle
    for character in ("—", "–", "!"):
        assert character not in text
