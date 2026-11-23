"""Engine 1.20.0 (task 6.1; claims C40, C41): for every fixture root where 1.20.0 reads nothing new, the seven reports are the
released 1.19.0's byte for byte once the scanner's version and the rules version are set back where a report prints them (and a
CycloneDX document's `serialNumber` is left out), with the same exit code. Where it reads more (`CHANGED_IN_1_20_0`, computed from
the fixture trees), every 1.19.0 item and finding is kept, every new item is newly read by a rule of spec 7.1, 7.3, 7.7 or 7.8, and
every new finding is on a new item. The `scan --user` report of each fixture home is 1.19.0's but for the items of the new rows,
the clients new shared rows add, and on Windows the `~/.config/devin/` items no longer read. tests/golden/record_release_1_19_0.py
recorded both from the tag v1.19.0 over this release's fixture trees; this test runs offline on Linux and Windows, every scan
without `--follow-links`."""
from __future__ import annotations

import importlib.util
import json
import re
from datetime import date
from pathlib import Path

import pytest

from spellwarden_scan import __version__
from spellwarden_cli import userscan
from spellwarden_cli.output import json_out
from spellwarden_cli.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("record_release_1_19_0", ROOT / "tests" / "golden" / "record_release_1_19_0.py")
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)
RECORDED_PATH = record.GOLDEN / "outputs.json"
HOMES_PATH = record.GOLDEN / "homes.json"

# Spec 7.1 and 7.8: the configuration documents 1.20.0 reads and 1.19.0 does not (a folded path; an item's path before `#`)
NEW_DOCUMENTS = re.compile(r"(^|/)(\.codex/(config\.toml|hooks\.json)|\.gemini/settings\.json|\.(cursor|windsurf)/hooks\.json"
                           r"|\.devin/(mcp_config(\.local)?|hooks\.v1|config(\.local)?)\.json|\.github/hooks/[^/]+\.json"
                           r"|\.github/copilot/settings(\.local)?\.json|\.github/mcp\.json)$")
# Spec 7.3: the instruction files 1.20.0 reads and 1.19.0 does not (a folded path)
NEW_INSTRUCTIONS = re.compile(r"(^|/)((claude\.local|agents\.override|agents\.local|agent)\.md"
                              r"|\.claude/(rules|commands|agents)/.+\.md|\.claude/output-styles/[^/]+\.md"
                              r"|\.(windsurf|devin)/rules/[^/]+/.+\.md|\.(windsurf|devin)/global_rules\.md"
                              r"|\.github/instructions/.+\.instructions\.md|\.(cursor|codex|gemini)/agents/[^/]+\.md"
                              r"|\.(devin|agents)/agents/([^/]+\.md|[^/]+/agent\.md)|\.github/agents/.+\.md)$")
# Spec 7.7: a local plugin's commands and agents (an item that carries a plugin's name)
LOCAL_PLUGIN = re.compile(r"(^|/)(commands|agents)/.+\.md$")
# Owner decision spec:Q1: roots where SW-CFG-012 or SW-CFG-013 judge a server of a settings document that 1.19.0 already read,
# each with the finding that explains it; checked like a root of `CHANGED_IN_1_20_0`, with only such findings new. Expected to
# stay empty (spec C40): should a root's byte comparison fail for that reason, it joins here by hand.
RULES_CHANGED_IN_1_20_0: dict[str, str] = {}
# Spec 7.9: the home paths of the rows 1.20.0 adds; `NEW_HOME` the nested ones
NEW_HOME_PREFIXES = ("~/.claude/commands", "~/.claude/agents", "~/.claude/output-styles", "~/.cursor/skills", "~/.cursor/agents",
                     "~/.cursor/plugins", "~/.codex/skills", "~/.codex/agents", "~/.codex/prompts", "~/.codex/plugins",
                     "~/.copilot/copilot-instructions.md", "~/.copilot/instructions", "~/.copilot/agents", "~/.copilot/hooks",
                     "~/.copilot/settings.json", "~/.copilot/installed-plugins", "~/.config/devin/AGENTS.md",
                     "~/.config/devin/AGENT.md", "~/.config/devin/agents", "~/.config/devin/config.json",
                     "~/AppData/Roaming/devin", "~/.codeium", "~/.gemini/agents")
NEW_HOME = re.compile(r"^~/(\.claude/rules/[^/]+/|\.claude/plugins/cache/.+/(commands|agents)/"
                      r"|\.gemini/extensions/[^/]+/(skills|agents)(/|$))")
SHARED_CLIENTS = {"cursor", "vscode", "windsurf"}  # the clients of the shared rows 1.20.0 adds


def newly_read_file(relative: str) -> bool:
    folded = relative.lower()
    return NEW_DOCUMENTS.search(folded) is not None or NEW_INSTRUCTIONS.search(folded) is not None


def newly_read(kind: str, path: str, plugin: str) -> bool:
    folded = path.split("#", 1)[0].lower()
    if kind == "instructions":
        return NEW_INSTRUCTIONS.search(folded) is not None or (plugin != "" and LOCAL_PLUGIN.search(folded) is not None)
    return NEW_DOCUMENTS.search(folded) is not None


def newly_read_home(path: str) -> bool:
    base = path.split("#", 1)[0]
    return any(base == prefix or base.startswith(prefix + "/") for prefix in NEW_HOME_PREFIXES) or bool(NEW_HOME.search(base))


def changed_roots() -> set[str]:
    """The fixture roots that hold a path 1.20.0 newly reads (C40): computed, never trusted from a list."""
    found = set()
    for root in record.scan_roots():
        if root in record.ADDED_AFTER_1_19_0:  # not in the record, so there is nothing of 1.19.0 to compare it with
            continue
        base = ROOT / root
        if any(path.is_file() and newly_read_file(path.relative_to(base).as_posix()) for path in base.rglob("*")):
            found.add(root)
    return found


CHANGED_IN_1_20_0 = changed_roots()


def _recorded() -> dict:
    return json.loads(RECORDED_PATH.read_text(encoding="utf-8"))


def _roots() -> list[str]:
    return sorted(_recorded()["roots"]) if RECORDED_PATH.exists() else ["(not recorded)"]


def test_the_record_is_the_release_and_covers_every_fixture_root():
    recorded = _recorded()
    assert (recorded["scanner_version"], recorded["release_tag"], recorded["as_of"]) == ("1.19.0", "v1.19.0", record.reports.AS_OF)
    assert set(recorded["roots"]) == set(record.scan_roots()) - set(record.ADDED_AFTER_1_19_0)
    assert "fixtures/selection" in recorded["roots"]
    formats = {fmt for fmt, _ in record.reports.ALL_FORMATS}
    assert all(set(entry["outputs"]) == formats and {"items", "findings"} <= set(entry) for entry in recorded["roots"].values())
    homes = json.loads(HOMES_PATH.read_text(encoding="utf-8"))
    assert (homes["release_tag"], homes["as_of"], sorted(homes["homes"])) == ("v1.19.0", record.HOME_AS_OF,
                                                                               ["linux", "macos", "windows"])


def test_the_roots_where_1_20_0_reads_more_are_the_three_known_ones():
    assert CHANGED_IN_1_20_0 == {"fixtures/selection", "tests/fixtures/homes/common", "tests/fixtures/homes/windows"}
    assert RULES_CHANGED_IN_1_20_0 == {}


@pytest.mark.parametrize("root", _roots())
def test_each_report_is_the_1_19_0_report_or_a_checked_superset_of_it(root, tmp_path):
    expected = _recorded()["roots"][root]
    code, outputs = record.reports.render(record.reports.build_repo(root, tmp_path / "repo"), tmp_path / "out",
                                          formats=record.reports.ALL_FORMATS)
    if root not in CHANGED_IN_1_20_0 and root not in RULES_CHANGED_IN_1_20_0:
        got = {fmt: record.digest(record.reports.as_version(fmt, data, __version__, record.RECORDED_VERSION))
               for fmt, data in outputs.items()}
        assert code == expected["exit_code"]
        assert got == expected["outputs"]
        return
    now = record.summary(outputs["json"])
    old_items, new_items = {tuple(item) for item in expected["items"]}, {tuple(item) for item in now["items"]}
    assert old_items <= new_items, sorted(old_items - new_items)
    added = new_items - old_items
    assert [item for item in added if not newly_read(*item)] == []
    old_findings, new_findings = {tuple(f) for f in expected["findings"]}, {tuple(f) for f in now["findings"]}
    assert old_findings <= new_findings, sorted(old_findings - new_findings)
    added_paths = {path for _kind, path, _plugin in added}
    if root in RULES_CHANGED_IN_1_20_0:
        assert all(rule in ("SW-CFG-012", "SW-CFG-013") for rule, _fp, _item in new_findings - old_findings)
    else:
        assert [f for f in new_findings - old_findings if f[2] not in added_paths] == []


@pytest.mark.parametrize("system", ["linux", "macos", "windows"])
def test_scan_user_of_each_fixture_home_is_the_1_19_0_report_but_for_the_new_rows(system, tmp_path):
    old = json.loads(HOMES_PATH.read_text(encoding="utf-8"))["homes"][system]
    home = record.homes.make_home(tmp_path, system)
    report, _ = userscan.scan(str(home), record.PLATFORMS[system], {}, settings=Settings(telemetry=False),
                              as_of=date.fromisoformat(record.HOME_AS_OF), inventory=False)
    new = record.normalised_home_report(json_out.render(report))

    def gone(path: str) -> bool:  # Windows no longer reads `~/.config/devin/` (spec 7.9, D19)
        return system == "windows" and path.startswith("~/.config/devin/")

    old_items = {item["path"]: item for item in old["items"] if not gone(item["path"])}
    new_items = {item["path"]: item for item in new["items"]}
    assert set(old_items) <= set(new_items), sorted(set(old_items) - set(new_items))
    for path, item in old_items.items():
        now = new_items[path]
        assert {k: v for k, v in now.items() if k != "clients"} == {k: v for k, v in item.items() if k != "clients"}, path
        assert set(item["clients"]) <= set(now["clients"]), path
        assert set(now["clients"]) - set(item["clients"]) <= SHARED_CLIENTS, path
    assert sorted(path for path in set(new_items) - set(old_items) if not newly_read_home(path)) == []
    old_findings = {(f["rule_id"], f["fingerprint"], f["item"]) for f in old["findings"] if not gone(f["item"])}
    new_findings = {(f["rule_id"], f["fingerprint"], f["item"]) for f in new["findings"]}
    assert old_findings <= new_findings
    assert sorted(f for f in new_findings - old_findings if not newly_read_home(f[2])) == []
    old_clients = {entry["client"]: entry for entry in old["clients"]}
    known_roots = {root for entry in old["clients"] for root in entry["roots"]}
    for entry in new["clients"]:
        before = old_clients[entry["client"]]
        assert entry["found"] or not before["found"], entry["client"]
        kept = {root for root in before["roots"] if not gone(root)}
        assert kept <= set(entry["roots"]), entry["client"]
        extra = set(entry["roots"]) - kept
        assert sorted(root for root in extra if not (newly_read_home(root) or root in known_roots)) == [], entry["client"]
    for key in set(old) | set(new):
        if key not in ("items", "findings", "clients"):
            assert new.get(key) == old.get(key), key
