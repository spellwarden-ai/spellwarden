"""The description lint (Phase 4 batch B spec 11.4): four checks of a skill's `description`, the text an agent reads to decide
whether to load the skill, made without a model. Informational: a note is never a finding and never changes an exit code, a
rule count or a `--fail-on` outcome. SW-LINT-001 to SW-LINT-003 judge one skill; SW-LINT-004 compares the skills scanned
together. A message never quotes the description (scanned content is hostile data, spec 6.5): it names counts and paths only.
Pure: no I/O."""
from __future__ import annotations

import re
from collections.abc import Sequence

from spellwarden_scan.frontmatter import DESCRIPTION_MAX
from spellwarden_scan.model import LintNote, SkillMeta

LINT_IDS = ("SW-LINT-001", "SW-LINT-002", "SW-LINT-003", "SW-LINT-004")
TITLES = {
    "SW-LINT-001": "Description shorter than 40 or longer than 1024 characters",
    "SW-LINT-002": "Description has no use-when clause",
    "SW-LINT-003": "Description names no trigger phrase",
    "SW-LINT-004": "Descriptions of two skills overlap",
}
DESCRIPTION_MIN = 40
OVERLAP_MIN = 0.6
# The output cap of spec 4.8 ("Lint findings listed per skill: 20"): the notes kept per skill; the count left out is shown.
MAX_NOTES_PER_SKILL = 20
USE_WHEN = re.compile(r"\b(?:use when|use this when|when the user|triggers on)\b", re.IGNORECASE)
# A description is scanned content of any length, so each matcher below reads a repeated-prefix text in linear time (the rule
# of tests/test_linear_time.py): a quoted phrase cannot hold its own opening quote, and a list's first item is bounded.
# A quoted phrase: two or more characters inside straight or curly double quotes, curly single quotes, backticks, or straight
# single quotes that are not an apostrophe (no letter, digit or quote right outside them).
_QUOTED = re.compile(r"\"[^\"\n]{2,}\"|\u201c[^\u201c\u201d\n]{2,}\u201d|\u2018[^\u2018\u2019\n]{2,}\u2019|`[^`\n]{2,}`"
                     r"|(?<![\w'])'[^'\n]{2,}'(?![\w'])")
# A listed request: "such as", "for example", "e.g.", "like", "including" or a colon, then at least two items split by a comma,
# the first of at most 120 characters.
_LISTED = re.compile(r"(?:\bsuch as|\bfor example|\be\.g\.|\blike|\bincluding|:)[^.;:\n,]{1,120},[^.;:\n]", re.IGNORECASE)
_WORD = re.compile(r"[a-z0-9]+")
STOP_WORDS = frozenset((
    "a", "an", "and", "any", "are", "as", "at", "be", "by", "can", "do", "does", "for", "from", "has", "have", "how", "i",
    "if", "in", "into", "is", "it", "its", "may", "me", "my", "not", "of", "on", "or", "our", "should", "so", "such", "than",
    "that", "the", "their", "them", "then", "there", "these", "they", "this", "those", "to", "triggers", "use", "used",
    "user", "uses", "using", "via", "was", "we", "what", "when", "where", "which", "while", "who", "will", "with", "you",
    "your", "skill", "skills",
))

MISSING = ("The description is missing. Agents choose a skill by its description: write one of at least 40 characters that "
           "says what the skill does and when to use it.")
NO_USE_WHEN = ("The description has no use-when clause (\"use when\", \"use this when\", \"when the user\" or \"triggers on\"), "
               "so an agent has to guess when the skill applies.")
NO_TRIGGER = ("The description names no trigger phrase: no quoted phrase and no list of requests, so an agent has few words "
              "to match a request against.")


def _short(length: int) -> str:
    return (f"The description is {length} characters. Agents choose a skill by its description: give it at least 40 characters "
            "that say what the skill does and when to use it.")


def _long(length: int) -> str:
    return f"The description is {length:,} characters. Agents read at most 1,024: shorten it."


def _overlap(percent: int) -> str:
    return (f"The description overlaps {percent}% with the description of another skill scanned with it, so an agent may "
            "load the wrong one: say what sets each apart.")


def single(skill: SkillMeta) -> list[LintNote]:
    """SW-LINT-001 to SW-LINT-003 for one skill, in id order. A missing or blank description gets SW-LINT-001 alone (the other
    two would only repeat it). The length is counted on the description without its outer whitespace, the bound of 1,024 on
    the text as written, as SW-SKL-015 counts it."""
    description = skill.description or ""
    if not description.strip():
        return [LintNote("SW-LINT-001", skill.path, MISSING)]
    notes: list[LintNote] = []
    length = len(description.strip())
    if length < DESCRIPTION_MIN:
        notes.append(LintNote("SW-LINT-001", skill.path, _short(length)))
    elif len(description) > DESCRIPTION_MAX:
        notes.append(LintNote("SW-LINT-001", skill.path, _long(len(description))))
    if USE_WHEN.search(description) is None:
        notes.append(LintNote("SW-LINT-002", skill.path, NO_USE_WHEN))
    if _QUOTED.search(description) is None and _LISTED.search(description) is None:
        notes.append(LintNote("SW-LINT-003", skill.path, NO_TRIGGER))
    return notes


def words(description: str | None) -> frozenset[str]:
    """The words SW-LINT-004 compares: runs of ASCII letters and digits after case folding, without `STOP_WORDS`."""
    return frozenset(word for word in _WORD.findall((description or "").casefold()) if word not in STOP_WORDS)


def similarity(left: frozenset[str], right: frozenset[str]) -> float:
    """Jaccard similarity of two word sets; 0.0 when either is empty."""
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def counted(skills: Sequence[SkillMeta], *, max_per_skill: int | None = MAX_NOTES_PER_SKILL
            ) -> tuple[list[LintNote], dict[str, int]]:
    """Every note of the four checks over `skills`, sorted by (path, id, other path), and per path the count of notes left
    out by `max_per_skill` (None keeps every note). SW-LINT-004 names both skills: one note on each, naming the other. The
    single-skill notes (at most three) always fit under the cap; overlap notes past it are counted, never built."""
    notes = [note for skill in skills for note in single(skill)]
    kept = {skill.path: 0 for skill in skills}
    for note in notes:
        kept[note.path] += 1
    left_out: dict[str, int] = {}

    def add(path: str, other: str, percent: int) -> None:
        if max_per_skill is not None and kept[path] >= max_per_skill:
            left_out[path] = left_out.get(path, 0) + 1
            return
        kept[path] += 1
        notes.append(LintNote("SW-LINT-004", path, _overlap(percent), other))

    sets = [(skill.path, words(skill.description)) for skill in skills]
    for index, (left_path, left_words) in enumerate(sets):
        for right_path, right_words in sets[index + 1:]:
            score = similarity(left_words, right_words)
            if left_path != right_path and score >= OVERLAP_MIN:
                percent = int(score * 100)
                add(left_path, right_path, percent)
                add(right_path, left_path, percent)
    notes.sort(key=lambda note: (note.path, note.id, note.other_path or ""))
    return notes, left_out


def check(skills: Sequence[SkillMeta]) -> list[LintNote]:
    """Spec 11.4: every note of the four checks over `skills`, sorted by (path, id, other path), none left out."""
    return counted(skills, max_per_skill=None)[0]


__all__ = ["DESCRIPTION_MIN", "LINT_IDS", "MAX_NOTES_PER_SKILL", "OVERLAP_MIN", "STOP_WORDS", "TITLES", "USE_WHEN", "check",
           "counted", "similarity", "single", "words"]
