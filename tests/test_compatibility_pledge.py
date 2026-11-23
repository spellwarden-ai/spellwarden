"""The compatibility pledge (roadmap P6-16, README "Schemas and compatibility", since 1.21.0): a rule id is never reused or
renamed, and a deprecation is announced in the CHANGELOG at least one minor version before it takes effect. `make check`, and so
the release workflow's build job, runs this test against tests/data/released_rule_ids.json, the frozen list of every rule id ever
released with its title in the release it first shipped in (the file's `how` says how it was built).

How the test tells a renamed title from a reused id: a rule keeps its id, its area (the id's prefix) and its title. A changed title
is allowed only when the file's `renamed` list records it (the id, the release, the old title and the new one), which a reviewer
reads in the same pull request; any other change of title fails as a possible reuse, and a different rule then needs a new id. An
id whose area no longer matches its prefix fails as a reuse whatever its title.

How the test holds a retirement to its announcement: an id joins the file's `retired` list in the release that takes its rule out
of the rule set (`retired_in`, never a release after the one being built, so a rule cannot leave early under a later date), and
the CHANGELOG entry of `announced_in`, a release at least one minor version before `retired_in`, holds the sentence
"<id> is deprecated". A mention of the id alone is not an announcement: the entry of 1.21.0 names three rules it does not
deprecate."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from spellwarden_scan import RuleSet, __version__

ROOT = Path(__file__).resolve().parents[1]
BASELINE_FILE = ROOT / "tests" / "data" / "released_rule_ids.json"
AREA_OF_PREFIX = {"SKL": "skill", "MCP": "mcp", "CFG": "config", "REG": "registry", "A2A": "a2a"}
RULE_ID = re.compile(r"^SW-(SKL|MCP|CFG|REG|A2A)-[0-9]{3}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _changelog_section(changelog: str, version: str) -> str:
    """The CHANGELOG entry of `version`, from its heading to the next one; "" when there is none."""
    start = changelog.find(f"## {version} (")
    if start < 0:
        return ""
    end = changelog.find("\n## ", start + 1)
    return changelog[start:] if end < 0 else changelog[start:end]


def _announced(changelog: str, version: str, rule_id: str) -> bool:
    """Whether the CHANGELOG entry of `version` holds the sentence "<id> is deprecated" (the entry wraps its lines, so white
    space is joined before the search)."""
    return f"{rule_id} is deprecated" in " ".join(_changelog_section(changelog, version).split())


def pledge_problems(baseline: dict, rules: dict[str, tuple[str, str]], version: str, changelog: str) -> list[str]:
    """Every way `rules` ({id: (title, area)}, the rule set of version `version`) breaks the pledge against `baseline` (the frozen
    file's content), with `changelog` the text of CHANGELOG.md. Empty when the pledge holds."""
    problems: list[str] = []
    released = baseline["rules"]
    retired = {entry["id"]: entry for entry in baseline["retired"]}
    titles = {rule_id: row["title"] for rule_id, row in released.items()}
    for rule_id, row in released.items():
        if RULE_ID.match(rule_id) is None or VERSION.match(row["first_released"]) is None:
            problems.append(f"{rule_id}: not a rule id with a release of the form X.Y.Z")
        elif _version(row["first_released"]) > _version(version):
            problems.append(f"{rule_id}: first released in {row['first_released']}, after this version {version}")
    for entry in baseline["renamed"]:
        if entry["id"] not in released or titles[entry["id"]] != entry["from"]:
            problems.append(f"{entry['id']}: the rename to {entry['to']!r} does not start from its recorded title")
            continue
        titles[entry["id"]] = entry["to"]
    for rule_id, entry in retired.items():
        if rule_id not in released:
            problems.append(f"{rule_id}: retired but never released")
        elif _version(entry["retired_in"]) > _version(version):
            problems.append(f"{rule_id}: listed as retired in {entry['retired_in']}, a release after this version {version}; an "
                            "id is listed as retired in the release that takes its rule out of the rule set")
        elif _version(entry["announced_in"])[:2] >= _version(entry["retired_in"])[:2]:
            problems.append(f"{rule_id}: retired in {entry['retired_in']}, not at least one minor version after the "
                            f"announcement in {entry['announced_in']}")
        elif not _announced(changelog, entry["announced_in"], rule_id):
            problems.append(f"{rule_id}: the CHANGELOG entry of {entry['announced_in']} does not announce its deprecation; it "
                            f"needs the sentence \"{rule_id} is deprecated\"")
    for rule_id in released:
        if rule_id not in rules and rule_id not in retired:
            problems.append(f"{rule_id}: released in {released[rule_id]['first_released']}, missing from the rule set and not "
                            "listed as retired")
    for rule_id, (title, area) in sorted(rules.items()):
        if rule_id in retired:
            problems.append(f"{rule_id}: retired in {retired[rule_id]['retired_in']} and back in the rule set; a retired id is "
                            "never given to a rule again")
        elif rule_id not in released:
            problems.append(f"{rule_id}: not in {BASELINE_FILE.name}; add it with the release it first ships in")
        elif AREA_OF_PREFIX[rule_id.split("-")[1]] != area:
            problems.append(f"{rule_id}: its area is {area}, not the one its id names; a different rule needs a new id")
        elif title != titles[rule_id]:
            problems.append(f"{rule_id}: its title changed from {titles[rule_id]!r} to {title!r}; record the rename in "
                            f"{BASELINE_FILE.name} if it is the same rule, or give a different rule a new id")
    return problems


def _baseline() -> dict:
    return json.loads(BASELINE_FILE.read_text(encoding="utf-8"))


def _rules() -> dict[str, tuple[str, str]]:
    return {rule.id: (rule.title, rule.area) for rule in RuleSet.baseline()}


def _changelog() -> str:
    return (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").replace("\r\n", "\n")


def test_the_scanner_keeps_the_pledge():
    assert pledge_problems(_baseline(), _rules(), __version__, _changelog()) == []


def test_the_frozen_file_holds_the_66_rules_released_up_to_1_20_0():
    baseline = _baseline()
    assert set(baseline) == {"how", "renamed", "retired", "rules"}
    assert len(baseline["rules"]) == 66 and baseline["retired"] == []
    assert {row["first_released"] for row in baseline["rules"].values()} == {"1.0.0", "1.2.0", "1.3.0", "1.4.0", "1.8.0", "1.15.0"}
    assert baseline["rules"]["SW-MCP-011"] == {"first_released": "1.0.0", "title": "Tool description contains instruction-like text"}
    assert baseline["renamed"] == [{"from": "Tool description contains instruction-like text", "id": "SW-MCP-011",
                                    "release": "1.13.0", "to": "MCP server text contains instruction-like text"}]
    text = BASELINE_FILE.read_text(encoding="utf-8")
    assert text == json.dumps(baseline, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _small(**more) -> dict:
    baseline = {"how": "test", "renamed": [], "retired": [],
                "rules": {"SW-SKL-001": {"first_released": "1.0.0", "title": "Old title"},
                          "SW-CFG-001": {"first_released": "1.0.0", "title": "Plain HTTP"}}}
    baseline.update(more)
    return baseline


RULES_NOW = {"SW-SKL-001": ("Old title", "skill"), "SW-CFG-001": ("Plain HTTP", "config")}


def test_a_released_id_missing_without_being_retired_fails():
    problems = pledge_problems(_small(), {"SW-SKL-001": ("Old title", "skill")}, "1.21.0", "")
    assert problems == ["SW-CFG-001: released in 1.0.0, missing from the rule set and not listed as retired"]


def test_a_retired_id_that_comes_back_fails_and_one_that_stays_away_passes():
    changelog = "## 1.22.0 (2026-12-01)\n\n- SW-CFG-001 is deprecated and goes in 1.23.0.\n"
    retired = [{"announced_in": "1.22.0", "id": "SW-CFG-001", "retired_in": "1.23.0"}]
    assert pledge_problems(_small(retired=retired), {"SW-SKL-001": ("Old title", "skill")}, "1.23.0", changelog) == []
    problems = pledge_problems(_small(retired=retired), RULES_NOW, "1.23.0", changelog)
    assert problems == ["SW-CFG-001: retired in 1.23.0 and back in the rule set; a retired id is never given to a rule again"]


@pytest.mark.parametrize("announced, retired_in, changelog, expected", [
    ("1.22.0", "1.22.3", "## 1.22.0 (x)\n\nSW-CFG-001 is deprecated.\n", "not at least one minor version after"),
    ("1.22.0", "1.23.0", "## 1.22.0 (x)\n\nNothing.\n", "does not announce its deprecation"),
    # a mention of the id is not an announcement, and an id is not listed as retired before the release that retires it
    ("1.22.0", "1.23.0", "## 1.22.0 (x)\n\nSW-CFG-001 reads more files.\n", "does not announce its deprecation"),
    ("1.22.0", "1.24.0", "## 1.22.0 (x)\n\nSW-CFG-001 is deprecated.\n", "a release after this version 1.23.0"),
])
def test_a_retirement_needs_an_announcement_one_minor_version_before(announced, retired_in, changelog, expected):
    retired = [{"announced_in": announced, "id": "SW-CFG-001", "retired_in": retired_in}]
    (problem,) = pledge_problems(_small(retired=retired), {"SW-SKL-001": ("Old title", "skill")}, "1.23.0", changelog)
    assert problem.startswith("SW-CFG-001: ") and expected in problem


def test_a_reused_id_fails_and_a_recorded_rename_passes():
    renamed = {"SW-SKL-001": ("New title", "skill"), "SW-CFG-001": ("Plain HTTP", "config")}
    (problem,) = pledge_problems(_small(), renamed, "1.21.0", "")
    assert problem.startswith("SW-SKL-001: its title changed from 'Old title' to 'New title'")
    record = [{"from": "Old title", "id": "SW-SKL-001", "release": "1.21.0", "to": "New title"}]
    assert pledge_problems(_small(renamed=record), renamed, "1.21.0", "") == []
    moved = {"SW-SKL-001": ("Old title", "config"), "SW-CFG-001": ("Plain HTTP", "config")}
    (problem,) = pledge_problems(_small(), moved, "1.21.0", "")
    assert problem == "SW-SKL-001: its area is config, not the one its id names; a different rule needs a new id"


def test_a_new_rule_needs_its_row():
    more = {**RULES_NOW, "SW-SKL-040": ("New rule", "skill")}
    assert pledge_problems(_small(), more, "1.21.0", "") == [
        "SW-SKL-040: not in released_rule_ids.json; add it with the release it first ships in"]
    row = {"first_released": "1.22.0", "title": "New rule"}
    rules = {**_small()["rules"], "SW-SKL-040": row}
    assert pledge_problems(_small(rules=rules), more, "1.22.0", "") == []
    assert pledge_problems(_small(rules=rules), more, "1.21.0", "") == [
        "SW-SKL-040: first released in 1.22.0, after this version 1.21.0"]


def test_the_readme_lists_the_retired_rules():
    readme = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    rules_section = readme[readme.index("## The rules"):readme.index("## Measured rates")]
    retired = _baseline()["retired"]
    if not retired:
        assert "Retired rules: none." in rules_section
    for entry in retired:
        assert f"{entry['id']} (retired in {entry['retired_in']})" in rules_section, entry["id"]
