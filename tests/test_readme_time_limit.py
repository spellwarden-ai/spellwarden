"""Engine 1.24.0 (speed and deadline spec 12.1, claim T20): the README says the `--time-limit` flag, the exit code 2 it adds, the
library argument `deadline` and the exception `TimeLimit`, the entry points that take none and why, the Limits bullet (what the limit
covers and does not, whole or not at all, the way out, the granularity) and one sentence in "What a scan reads"; the roadmap moves
the item to Shipped; the figure of the granularity is the CHANGELOG's. Plain English: no em dash, no en dash, no exclamation mark."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")


def section(heading: str) -> str:
    start = README.index(heading)
    end = README.find("\n### ", start + len(heading))
    return " ".join(README[start:end if end != -1 else len(README)].split())


def _plain(text: str) -> None:
    for character in ("\u2014", "\u2013", "!"):
        assert character not in text, character


def test_the_synopsis_and_the_exit_code_name_the_flag():
    command = README[README.index("## The `spellwarden` command"):README.index("### What a scan reads")]
    assert "[--follow-links] [--time-limit SECONDS] [--no-telemetry]" in command
    exit_codes = section("### Exit codes")
    assert "a package the scan did not finish because `--time-limit` was reached (since 1.24.0)" in exit_codes
    _plain(exit_codes)


def test_scanning_a_skill_package_says_the_argument_the_exception_and_the_entry_points_that_take_none():
    text = " ".join(README[README.index("## Scanning a skill package"):README.index("## Evaluating an MCP server probe")].split())
    for needle in ("`deadline` (since 1.24.0; keyword-only, default `None`) is a `Deadline`, made with `Deadline.after(seconds)`",
                   "the call raises `TimeLimit`", "`path`", "`stage`", "`before`, `reading`, `normalising` or `judging`",
                   "returns nothing for that package", "a package that was not read whole never looks like a pass",
                   "once for every 64 KiB of line text", "the default clock is `time.monotonic`", "Without `deadline` nothing changes",
                   "The other entry points take none, because what they read is bounded already", "`scan_agent_config`",
                   "`evaluate_agent_card`", "`evaluate_probe`", "`unpack_zip` and `list_zip`",
                   "An entry point that reads content of unbounded size takes a deadline"):
        assert needle in text, needle
    _plain(text)


def test_what_a_scan_reads_says_the_reading_can_be_bounded_in_time():
    text = section("### What a scan reads")
    assert "The reading of skills and instruction files can be bounded in time: `--time-limit SECONDS` (since 1.24.0, see [Limits](#limits))." in text
    _plain(text)


def test_limits_says_what_the_time_limit_covers_what_it_does_not_and_the_way_out():
    text = section("### Limits")
    for needle in ("**How long the scan reads** (the time limit, since 1.24.0)", "`--time-limit SECONDS` (default: no limit",
                   "no environment variable and no settings key", "a file in the repository cannot raise or remove it",
                   "listing files and discovering items included", "the engine's reading of skills and instruction files",
                   "the configuration documents, the remote probes and agent-card fetches, the model-assisted analyzer, the baseline, "
                   "the lock and the output have their own bounds", "is the error `time_limit` and is not judged",
                   "a package is judged whole or not at all", "Every skill and instruction file after it is named by an error of its own",
                   "The packages judged before the limit keep their findings", "the scan is incomplete (exit 2)",
                   "split the content, leave a file out with `exclude` in `.spellwarden/config.yml`, or raise the limit",
                   "once for every 64 KiB of line text", "about the time one rule needs for one line of 10 MiB",
                   "the hosted step is about three times slower", "`scan --user` takes no limit",
                   "**content the scanner leaves unread never looks like a pass.**"):
        assert needle in text, needle
    _plain(text)


def test_the_granularity_figure_is_the_changelogs():
    readme = re.search(r"at most (\d+\.\d+) s past the limit on the machine of the 1.24.0 release run", README)
    changelog = re.search(r"at most (\d+\.\d+) s past the limit on this machine", CHANGELOG[CHANGELOG.index("## 1.24.0 ("):])
    assert readme and changelog and readme.group(1) == changelog.group(1)


def test_the_roadmap_moves_the_item_to_shipped():
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    shipped = roadmap[roadmap.index("## Shipped\n"):roadmap.index("## Being built now")]
    assert "Since 1.24.0 a scan can be given a time limit: `spellwarden scan --time-limit SECONDS` ends a scan that reaches it incomplete" in shipped
    assert "naming every skill and instruction file it did not read" in shipped and "the normalised scan is faster" in shipped
    _plain(shipped)
