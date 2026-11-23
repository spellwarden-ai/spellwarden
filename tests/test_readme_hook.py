"""1.18.0 and 1.19.0: the README's "Pre-commit hook" section (the configuration lines, the tagged guide link, what the hook runs
and when, that it judges the staged content only and sends nothing to Spellwarden, its exit codes and how to skip it once), what
"What a scan reads" says of `--staged`, and `wrappers/README.md` (the wrappers' `preset` input)."""
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
    for needle in (GUIDE, "repo: https://github.com/spellwarden-ai/spellwarden", "rev: v1.20.0", "id: spellwarden",
                   "`spellwarden scan --staged`", "pre-commit 3.2.0 or later", "`pre-commit`, `pre-push` and `manual`",
                   "never uploads", "exit 1", "exit 2", "exit 3", "`SKIP=spellwarden git commit`"):
        assert needle in text, needle
    for character in ("—", "–", "!"):
        assert character not in text


def test_the_readme_says_the_hook_judges_the_staged_content_and_sends_nothing():
    text = " ".join(section("### Pre-commit hook").split())
    for needle in ("Since 1.19.0 the hook judges the staged content only",
                   "never an untracked file or a change that is not staged",
                   "At `pre-commit` that is the content being committed; at `pre-push` and `manual` (a `pre-commit run "
                   "--all-files` in CI among them) it is the checked-out commit plus whatever is staged.",
                   "The hook sends nothing to Spellwarden: it never uploads to connected mode, never sends the usage ping, in CI "
                   "or outside it",
                   "On a pull or merge request in CI the hook therefore reads the request's own settings file and baseline, "
                   "where the Action and the GitLab component read the base revision's",
                   "as the check that decides a merge",
                   "`--probe` and `--analyze` in the hook's `args` still reach the servers and the model endpoint you name"):
        assert needle in text, needle
    assert "its scan sends the usage ping like any scan in CI" not in text and "offline" not in text
    assert "### The usage ping" in README


def test_the_readme_says_what_staged_reads_and_sends():
    text = " ".join(section("### What a scan reads").split())
    for needle in ("`--staged` (since 1.19.0; the pre-commit hook runs it) reads the git index instead",
                   "never an untracked file or a change that is not staged", "`git ls-files -s -z`", "`git cat-file --batch`",
                   "the lock file are read from the index too", "`--staged` sends nothing to Spellwarden",
                   "`staged_credentials_ignored`", "`staged_unavailable` (exit 2)",
                   "`--probe` and `--analyze` still reach the servers and the model endpoint you name"):
        assert needle in text, needle
    assert "offline" not in text and "offline" not in section("### Pre-commit hook")  # "sends nothing to Spellwarden" instead
    assert "[--staged]" in README
    assert "`spellwarden scan --staged`, which the pre-commit hook runs since 1.19.0, never sends it." in README


def test_the_readme_says_that_staged_reads_a_request_s_own_settings():
    """On a pull or merge request a scan reads the settings file, the baseline and the keys file from the base revision;
    `--staged` reads them from the index, the request's own commit, and every place that states the rule says so."""
    reads = " ".join(section("### What a scan reads").split())
    for needle in ("This holds on a pull or merge request in CI too",
                   "from the index, which is the request's own commit, never from the base revision (see \"Settings\")",
                   "keep a scan without `--staged` (the Action, the GitLab component) as the check that decides a merge"):
        assert needle in reads, needle
    settings = " ".join(section("### Settings: `.spellwarden/config.yml`").split())
    assert ("A scan with `--staged` (since 1.19.0; the pre-commit hook runs it) is the exception: it reads this file, the "
            "baseline and the `a2a.keys` file from the git index on a request too (see \"What a scan reads\"), so it is not "
            "the check to rely on for a merge.") in settings
    cards = " ".join(section("### Checking A2A agent cards").split())
    assert "(A scan with `--staged` reads them from the index: see \"What a scan reads\".)" in cards


def test_the_wrappers_note_states_the_preset_input():
    text = (ROOT / "wrappers" / "README.md").read_text(encoding="utf-8")
    for needle in ('"strict, balanced or low-noise; empty uses the scanner\'s settings"',
                   'preset: {default: "", options: ["", "strict", "balanced", "low-noise"]}', "`SW_PRESET`", "`--preset VALUE`",
                   "`scan-action.ref`", "Linux and Windows"):
        assert needle in text, needle
    for character in ("—", "–", "!"):
        assert character not in text
