"""1.19.0: the front-matter limits of the engine. A front matter is read up to 64 KiB of text, 2,000 YAML nodes, a nesting depth
of 32 and 50 aliases; at each limit it is read, one past it `parse_frontmatter` raises `FrontmatterLimit` before loading it, and
`metadata_of` and `scan_skill_package` raise it naming the file (unread customer content is the caller's error, never a finding).
A front matter too deep for the YAML reader's stack was an internal error before; now it is that refusal. Each limit is at least
ten times the largest front matter of the repository's own fixtures, and the README records the four limits."""
from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

from spellwarden_scan import RuleSet, scan_skill_package
from spellwarden_scan.frontmatter import (FRONTMATTER_MAX_ALIASES, FRONTMATTER_MAX_BYTES, FRONTMATTER_MAX_DEPTH,
                                          FRONTMATTER_MAX_NODES, FrontmatterError, FrontmatterLimit, measure, metadata_of,
                                          parse_frontmatter, split_frontmatter)

ROOT = Path(__file__).resolve().parents[1]
RULES = RuleSet.baseline()
SKILL = b"---\nname: x\ndescription: A demo.\n---\n\nRead.\n"


def document(block: str) -> str:
    return f"---\n{block}---\nbody\n"


def sized(total: int) -> str:
    """A block of exactly `total` UTF-8 bytes: one key whose value fills it."""
    return "k: " + "a" * (total - 4) + "\n"


def listed(count: int) -> str:
    """A block of exactly `count` YAML nodes: the mapping, its key, the list and `count - 3` items."""
    return "k: [" + ", ".join(["a"] * (count - 3)) + "]\n"


def nested(depth: int) -> str:
    """A block nested exactly `depth` deep: the mapping and `depth - 1` lists inside one another."""
    return "k: " + "[" * (depth - 1) + "]" * (depth - 1) + "\n"


def aliased(count: int) -> str:
    """A block of exactly `count` aliases of one anchor."""
    return "a: &a x\nb: [" + ", ".join(["*a"] * count) + "]\n"


def test_the_limits_are_the_documented_ones():
    assert (FRONTMATTER_MAX_BYTES, FRONTMATTER_MAX_NODES, FRONTMATTER_MAX_DEPTH, FRONTMATTER_MAX_ALIASES) == (65_536, 2_000, 32, 50)


def test_the_helpers_build_what_their_names_say():
    assert measure(sized(FRONTMATTER_MAX_BYTES))[0] == FRONTMATTER_MAX_BYTES
    assert measure(listed(FRONTMATTER_MAX_NODES))[1] == FRONTMATTER_MAX_NODES
    assert measure(nested(FRONTMATTER_MAX_DEPTH))[2] == FRONTMATTER_MAX_DEPTH
    assert measure(aliased(FRONTMATTER_MAX_ALIASES))[3] == FRONTMATTER_MAX_ALIASES


@pytest.mark.parametrize("make, limit, at", [(sized, "bytes", FRONTMATTER_MAX_BYTES), (listed, "nodes", FRONTMATTER_MAX_NODES),
                                             (nested, "depth", FRONTMATTER_MAX_DEPTH),
                                             (aliased, "aliases", FRONTMATTER_MAX_ALIASES)])
def test_at_each_limit_the_front_matter_is_read_and_one_past_it_is_refused(make, limit, at):
    mapping, body = parse_frontmatter(document(make(at)))
    assert body == "body\n" and set(mapping) & {"k", "b"}
    with pytest.raises(FrontmatterLimit) as raised:
        parse_frontmatter(document(make(at + 1)))
    refusal = raised.value
    assert (refusal.limit, refusal.reason, refusal.path) == (limit, "over_limit", None)
    assert isinstance(refusal, FrontmatterError) and isinstance(refusal, ValueError) and refusal.detail


def test_a_front_matter_too_deep_for_the_yaml_reader_is_refused_not_a_crash():
    """1.18.0 raised RecursionError here, an internal error of the scan; the depth limit refuses it in one linear pass."""
    started = time.perf_counter()
    with pytest.raises(FrontmatterLimit) as raised:
        parse_frontmatter(document(nested(30_000)))
    assert raised.value.limit == "depth" and time.perf_counter() - started < 2.0


def test_metadata_of_names_the_skill_file_and_makes_no_metadata_problem_of_it():
    with pytest.raises(FrontmatterLimit) as raised:
        metadata_of({"skills/x/SKILL.md": document(listed(2_001)).encode("utf-8")}, "skills/x")
    assert (raised.value.path, raised.value.limit) == ("skills/x/SKILL.md", "nodes")


def test_scan_skill_package_raises_it_for_skill_md_and_for_a_command_file():
    with pytest.raises(FrontmatterLimit) as raised:
        scan_skill_package({"skills/x/SKILL.md": document(nested(40)).encode("utf-8")}, RULES, root="skills/x")
    assert raised.value.path == "skills/x/SKILL.md"
    files = {"skills/x/SKILL.md": SKILL, "skills/x/commands/run.md": document(aliased(51)).encode("utf-8")}
    with pytest.raises(FrontmatterLimit) as raised:
        scan_skill_package(files, RULES, root="skills/x")
    assert (raised.value.path, raised.value.limit) == ("skills/x/commands/run.md", "aliases")


def test_a_markdown_file_whose_front_matter_the_engine_never_parses_is_not_refused():
    files = {"skills/x/SKILL.md": SKILL, "skills/x/docs/notes.md": document(aliased(51)).encode("utf-8")}
    result = scan_skill_package(files, RULES, root="skills/x")
    assert result.files_scanned == 2


def _front_matters():
    for base in (ROOT / "fixtures", ROOT / "tests"):
        for path in sorted(base.rglob("*")):
            if path.suffix.lower() not in (".md", ".mdc") or not path.is_file():
                continue
            try:
                block, _ = split_frontmatter(path.read_bytes().decode("utf-8", "replace"))
                yield path, measure(block)
            except (FrontmatterError, yaml.YAMLError):
                continue


def test_each_limit_has_tenfold_headroom_over_the_repository_s_own_front_matter():
    measured = list(_front_matters())
    assert len(measured) >= 50
    limits = (FRONTMATTER_MAX_BYTES, FRONTMATTER_MAX_NODES, FRONTMATTER_MAX_DEPTH, FRONTMATTER_MAX_ALIASES)
    for index, limit in enumerate(limits):
        largest = max(sizes[index] for _, sizes in measured)
        assert largest * 10 <= limit, (index, largest)


def test_the_readme_records_the_four_limits_with_their_kind_and_way_out():
    readme = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    start = readme.index("### Limits")
    text = " ".join(readme[start:readme.index("\n### ", start + 1)].split())
    for needle in ("**SKILL.md front matter**", "64 KiB of text, 2,000 YAML nodes, a nesting depth of 32 and 50 aliases",
                   "the error `unreadable`", "never reported as a finding", "`exclude` in `.spellwarden/config.yml`",
                   "at least ten times the largest front matter"):
        assert needle in text, needle
    assert "a front matter past its limits" in readme[readme.index("### Exit codes"):start]
