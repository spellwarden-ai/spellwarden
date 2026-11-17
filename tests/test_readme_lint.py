"""Phase 4 batch B spec 11.4, 4.8 and 4.10: the README's "Description lint" section describes the four checks as
`spellwarden_scan.lint` makes them, links the guide with its campaign tags, and "Limits" records the cap of 20 notes per skill."""
from __future__ import annotations

import re
from pathlib import Path

from spellwarden_scan import lint

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
GUIDE = "https://spellwarden.ai/docs/activation-checks?utm_source=scanner&utm_medium=cli&utm_campaign=description-lint"


def section(heading: str) -> str:
    start = README.index(heading)
    return README[start:README.index("\n### ", start + len(heading))]


def test_the_section_names_each_check_with_the_module_s_numbers():
    text = section("### Description lint")
    for note_id in lint.LINT_IDS:
        assert f"`{note_id}`" in text, note_id
    assert (lint.DESCRIPTION_MIN, lint.OVERLAP_MIN) == (40, 0.6)
    for needle in ("shorter than 40 characters or longer than 1,024", '"use when", "use this when", "when the user" or "triggers on"',
                   "Jaccard similarity", "0.6 or more", "never change the exit code", "`SkillScanResult.lint`",
                   "`spellwarden_scan.lint.check(skills)`", "`SkillMeta(path, name, description)`", "`description_lint`",
                   "level `note`", "`scan --user` does not lint"):
        assert needle in text, needle
    assert f"]({GUIDE})" in text
    assert not re.search("[–—!]", text)


def test_limits_records_the_cap_with_the_count_left_out():
    text = section("### Limits")
    assert lint.MAX_NOTES_PER_SKILL == 20 and "at most 20 notes per skill" in text and "`left_out`" in text
