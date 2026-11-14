"""Phase 3 batch 1 spec 10.1 to 10.5, 11.4 and claims T-47, T-48: the scanner finds instruction files, pins each in the lock,
scans each as an instruction file and reports it; `instructions: false` leaves them out, and a repository without any is reported
as on 1.12.0."""
from __future__ import annotations

import json
import os
import sys
from datetime import date
from pathlib import Path

import jsonschema
import pytest
from conftest import git, write_tree
from instruction_fixture import DECOYS, FILES, INJECTION, INSTRUCTION_FILES, PLAIN, SKILL

from spellwarden_scan import canonical_sha256
from spellwarden_cli import connected, discover, files, run
from spellwarden_cli.settings import Flags, Settings, SettingsError, load_settings

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"
AS_OF = "2026-11-14"


def scan(run_cli, repo, *args: str):
    code, out, err = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--as-of", AS_OF, *args])
    return code, json.loads(out), err


def instruction_items(report: dict) -> list[dict]:
    return [item for item in report["items"] if item["kind"] == "instructions"]


def make(make_repo, tmp_path: Path, tree: dict, name: str = "repo") -> Path:
    return make_repo(tmp_path / name, tree)


def test_every_planted_file_is_an_item_of_kind_instructions_with_its_format(make_repo, tmp_path, run_cli):
    repo = make(make_repo, tmp_path, {**PLAIN, **FILES, **DECOYS})
    code, report, err = scan(run_cli, repo)
    assert (code, err) == (1, "")
    items = instruction_items(report)
    assert [(item["path"], item["format"]) for item in items] == sorted((path, kind) for path, (kind, _text) in INSTRUCTION_FILES.items())
    assert all(list(item) == ["format", "front_matter", "kind", "name", "path", "plugin"] and item["plugin"] is None for item in items)
    assert {item["path"]: item["name"] for item in items}["svc/.devin/rules/deploy.md"] == "deploy.md"
    by_path = {item["path"]: item["front_matter"] for item in items}
    assert by_path[".cursor/rules/style.mdc"] == {"description": "Style rules", "globs": ["src/**", "tests/**"], "always_apply": False,
                                                   "trigger": None}
    assert by_path["app/.cursor/rules/sub/api.mdc"] == {"description": None, "globs": ["*.ts"], "always_apply": None, "trigger": None}
    assert by_path[".windsurf/rules/team.md"] == {"description": None, "globs": None, "always_apply": None, "trigger": "always_on"}
    assert by_path["svc/.devin/rules/deploy.md"]["description"] == "Deploy steps"
    assert by_path["AGENTS.md"] is None and by_path[".cursorrules"] is None and by_path[".windsurfrules"] is None


def test_each_file_is_scanned_as_an_instruction_file_and_the_look_alikes_are_not(make_repo, tmp_path, run_cli):
    repo = make(make_repo, tmp_path, {**PLAIN, **FILES, **DECOYS})
    _code, report, _err = scan(run_cli, repo)
    found = [f for f in report["findings"] if f["rule_id"] == "SW-SKL-001"]
    assert sorted(f["item"] for f in found) == sorted(FILES)
    assert all(f["location"]["path"] == f["item"] and f["severity"] == "high" for f in found)
    assert not any(f["item"] in DECOYS or f["location"]["path"] in DECOYS for f in report["findings"])
    # the two SKILL.md rules about metadata do not run on an instruction file, so a file with no front matter is no finding
    assert {f["rule_id"] for f in report["findings"] if f["item"] in FILES} == {"SW-SKL-001"}


def test_a_file_inside_a_skill_directory_belongs_to_the_skill_and_is_scanned_once(make_repo, tmp_path, run_cli):
    tree = {**PLAIN, "skills/setup/AGENTS.md": "# Agents\n\n" + INJECTION, "skills/setup/docs/CLAUDE.md": "# C\n\n" + INJECTION,
            "AGENTS.md": "# Agents\n\n" + INJECTION}
    _code, report, _err = scan(run_cli, make(make_repo, tmp_path, tree))
    assert [item["path"] for item in instruction_items(report)] == ["AGENTS.md"]
    inside = [f for f in report["findings"] if f["rule_id"] == "SW-SKL-001" and f["location"]["path"].startswith("skills/setup/")]
    assert sorted((f["item"], f["location"]["path"]) for f in inside) == [("skills/setup", "skills/setup/AGENTS.md"),
                                                                           ("skills/setup", "skills/setup/docs/CLAUDE.md")]


def test_a_plugin_directory_does_not_scan_its_files_so_its_instruction_file_is_listed(make_repo, tmp_path, run_cli):
    marketplace = json.dumps({"name": "m", "plugins": [{"name": "infra", "source": "./plugins/infra"}]})
    manifest = json.dumps({"name": "infra", "description": "d"})
    tree = {**PLAIN, ".claude-plugin/marketplace.json": marketplace, "plugins/infra/.claude-plugin/plugin.json": manifest,
            "plugins/infra/AGENTS.md": "# A\n\n" + INJECTION}
    _code, report, _err = scan(run_cli, make(make_repo, tmp_path, tree))
    assert [item["path"] for item in instruction_items(report)] == ["plugins/infra/AGENTS.md"]


def test_a_root_skill_owns_every_file_so_no_instruction_file_is_listed(make_repo, tmp_path, run_cli):
    _code, report, _err = scan(run_cli, make(make_repo, tmp_path, {"SKILL.md": SKILL, "AGENTS.md": "# A\n\n" + INJECTION}))
    assert instruction_items(report) == []
    assert [f["item"] for f in report["findings"] if f["rule_id"] == "SW-SKL-001"] == ["."]


def test_over_200_files_give_the_notice_and_the_rest_are_not_read(make_repo, tmp_path, run_cli):
    tree = {**PLAIN, **{f"d{number:03d}/AGENTS.md": "# A\n\n" + INJECTION for number in range(201)}}
    code, report, _err = scan(run_cli, make(make_repo, tmp_path, tree))
    assert len(instruction_items(report)) == 200 and "d200/AGENTS.md" not in {item["path"] for item in report["items"]}
    notices = [n for n in report["notices"] if n["code"] == "instructions_limit"]
    assert [(n["path"], n["message"]) for n in notices] == [("", "1 more instruction files were not read: the scanner reads at most "
                                                                "200 per scan root")]
    assert len([f for f in report["findings"] if f["rule_id"] == "SW-SKL-001"]) == 200 and code == 1


def test_a_front_matter_that_cannot_be_read_still_scans_and_has_a_notice(make_repo, tmp_path, run_cli):
    tree = {**PLAIN, ".cursor/rules/broken.mdc": "---\ndescription: never closed\n" + INJECTION,
            ".cursor/rules/ok.mdc": "---\nglobs: *.ts\n---\n" + INJECTION}
    _code, report, _err = scan(run_cli, make(make_repo, tmp_path, tree))
    by_path = {item["path"]: item["front_matter"] for item in instruction_items(report)}
    assert by_path[".cursor/rules/broken.mdc"] is None and by_path[".cursor/rules/ok.mdc"]["globs"] == ["*.ts"]
    assert [(n["code"], n["path"]) for n in report["notices"] if n["code"] == "instructions_front_matter"] == [
        ("instructions_front_matter", ".cursor/rules/broken.mdc")]
    assert {f["item"] for f in report["findings"] if f["rule_id"] == "SW-SKL-001"} == {".cursor/rules/broken.mdc", ".cursor/rules/ok.mdc"}


def test_a_phrase_planted_in_each_rule_file_that_does_not_end_in_md_is_found(make_repo, tmp_path, run_cli):
    tree = {".cursor/rules/x.mdc": INJECTION, ".cursorrules": INJECTION, ".windsurfrules": INJECTION}
    _code, report, _err = scan(run_cli, make(make_repo, tmp_path, tree))
    assert sorted(f["location"]["path"] for f in report["findings"] if f["rule_id"] == "SW-SKL-001") == [
        ".cursor/rules/x.mdc", ".cursorrules", ".windsurfrules"]


def test_the_lock_pins_each_file_and_names_a_change_an_addition_and_a_removal(make_repo, tmp_path, run_cli):
    repo = make(make_repo, tmp_path, {**PLAIN, **FILES})
    code, out, err = run_cli(["lock", str(repo)])
    assert (code, err) == (0, "") and out == f"Wrote .spellwarden/lock.json with {len(FILES) + 3} items.\n"  # + document, server, skill
    lock = json.loads((repo / ".spellwarden" / "lock.json").read_text(encoding="utf-8"))
    pinned = {item["path"]: item for item in lock["items"] if item["kind"] == "instructions"}
    assert sorted(pinned) == sorted(FILES)
    first = pinned["docs/CLAUDE.md"]
    assert list(first) == ["format", "kind", "path", "sha256"] and first["format"] == "claude-md"
    assert first["sha256"] == canonical_sha256({"CLAUDE.md": FILES["docs/CLAUDE.md"].encode("utf-8")})  # the name, not the directory
    assert [item["kind"] for item in lock["items"]] == sorted(item["kind"] for item in lock["items"])
    schema = json.loads((SCHEMAS / "lock.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(lock)
    assert run_cli(["lock", "--check", str(repo)])[0] == 0
    code, report, _ = scan(run_cli, repo, "--locked", "--fail-on", "never")
    assert report["lock"]["status"] == "ok" and code == 0
    # a changed file, an added file and a removed file
    (repo / "AGENTS.md").write_text("# Agents\n\nNothing here.\n", encoding="utf-8")
    write_tree(repo, {"GEMINI.md": "# Gemini\n"})
    (repo / ".cursorrules").unlink()
    code, report, _ = scan(run_cli, repo, "--locked", "--fail-on", "never")
    assert report["lock"]["status"] == "stale" and code == 3
    assert report["lock"]["changed"] == [{"kind": "instructions", "path": "AGENTS.md"}]
    assert report["lock"]["added"] == [{"kind": "instructions", "path": "GEMINI.md"}]
    assert report["lock"]["removed"] == [{"kind": "instructions", "path": ".cursorrules"}]


def test_a_repository_with_a_lock_from_before_sees_the_instruction_files_as_added(make_repo, tmp_path, run_cli):
    repo = make(make_repo, tmp_path, PLAIN)
    assert run_cli(["lock", str(repo)])[0] == 0
    write_tree(repo, {"AGENTS.md": "# Agents\n"})
    code, report, _ = scan(run_cli, repo, "--locked", "--fail-on", "never")
    assert code == 3 and report["lock"] == {"status": "stale", "added": [{"kind": "instructions", "path": "AGENTS.md"}],
                                            "removed": [], "changed": []}


def test_a_repository_without_instruction_files_is_reported_as_on_1_12_0(make_repo, tmp_path, run_cli):
    repo = make(make_repo, tmp_path, PLAIN)
    assert run_cli(["lock", str(repo)])[0] == 0
    code, report, _ = scan(run_cli, repo, "--locked")
    assert (code, report["lock"]["status"]) == (1, "ok")  # the plain `http://` server fails it; the lock is current
    assert all(set(item) == {"kind", "path", "name", "plugin"} for item in report["items"])
    assert not any(n["code"].startswith("instructions") for n in report["notices"] + report["errors"])
    lock = json.loads((repo / ".spellwarden" / "lock.json").read_text(encoding="utf-8"))
    assert {item["kind"] for item in lock["items"]} == {"document", "mcp-server", "skill"}


def test_instructions_false_leaves_the_files_out_and_the_report_is_the_one_without_them(make_repo, tmp_path, run_cli):
    off = "version: 1\ninstructions: false\n"
    with_files = make(make_repo, tmp_path, {**PLAIN, **FILES, ".spellwarden/config.yml": off}, "with")
    without = make(make_repo, tmp_path, {**PLAIN, ".spellwarden/config.yml": off}, "without")
    assert run_cli(["lock", str(with_files)])[0] == 0 and run_cli(["lock", str(without)])[0] == 0
    code_a, report_a, _ = scan(run_cli, with_files, "--locked")
    code_b, report_b, _ = scan(run_cli, without, "--locked")
    assert (code_a, report_a) == (code_b, report_b)
    lock_a = (with_files / ".spellwarden" / "lock.json").read_bytes()
    assert lock_a == (without / ".spellwarden" / "lock.json").read_bytes() and b"instructions" not in lock_a


def test_instructions_is_a_boolean_setting_that_defaults_to_true(tmp_path):
    def load(text: str | None = None, **more):
        if text is not None:
            write_tree(tmp_path, {".spellwarden/config.yml": text})
        return load_settings(str(tmp_path), config=None, flags=Flags(), env={}, **more)

    assert Settings().instructions is True and load().instructions is True
    assert load("version: 1\ninstructions: false\n").instructions is False
    assert load("version: 1\ninstructions: true\n").instructions is True
    for bad in ("'no'", "0", "[]"):
        with pytest.raises(SettingsError, match="`instructions` must be true or false"):
            load(f"version: 1\ninstructions: {bad}\n")
    # on a pull or merge request the base revision's file is read, like every key: a request cannot switch off its own scanning
    base = load_settings(str(tmp_path), config=None, flags=Flags(), env={},
                         read=lambda _path, _limit: b"version: 1\ninstructions: false\n")
    assert base.instructions is False
    schema = json.loads((SCHEMAS / "settings.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate({"version": 1, "instructions": False})
    assert list(jsonschema.Draft202012Validator(schema).iter_errors({"version": 1, "instructions": "no"}))


def test_the_report_with_instruction_files_validates_against_the_report_schema(make_repo, tmp_path, run_cli):
    repo = make(make_repo, tmp_path, {**PLAIN, **FILES})
    _code, report, _err = scan(run_cli, repo)
    schema = json.loads((SCHEMAS / "report.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER).validate(report)


def discovery(repo: Path, **options):
    return discover.discover(files.list_files(str(repo), Settings()), **options)


def test_the_registry_gate_does_not_consider_an_instruction_file(make_repo, tmp_path):
    """SW-REG-003 (and every gate finding) is about skills, servers, plugins and marketplaces; an instruction item is none."""
    found = discovery(make(make_repo, tmp_path, {"AGENTS.md": "# A\n", ".cursor/rules/a.mdc": "x\n", "CLAUDE.md": "# C\n"}))
    assert len(found.instruction_files) == 3 and found.skills == () and found.documents == ()
    options = run.ScanOptions(root=str(tmp_path / "repo"), settings=Settings(), as_of=date(2026, 11, 14), env={})
    assert connected._skill_candidates(found, options, None) == []
    assert connected._config_candidates(found, {"stdio": True, "plugins": True}, {}, []) == []
    mixed = discovery(make(make_repo, tmp_path, {**PLAIN, "AGENTS.md": "# A\n"}, "mixed"))
    paths = {candidate.path for candidate in connected._skill_candidates(mixed, options, None)}
    assert paths == {"skills/setup"}


def test_discovery_with_the_switch_off_finds_no_instruction_file(make_repo, tmp_path):
    repo = make(make_repo, tmp_path, {**PLAIN, "AGENTS.md": "# A\n"})
    assert [f.path for f in discovery(repo).instruction_files] == ["AGENTS.md"]
    off = discovery(repo, instructions=False)
    assert off.instruction_files == () and [item.kind for item in off.items] == ["mcp-config", "mcp-server", "skill"]


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege on Windows")
def test_a_link_at_an_instruction_file_name_is_followed_and_one_that_cannot_be_is_the_notice_it_was(tmp_path, run_cli):
    repo = tmp_path / "repo"
    repo.mkdir()
    write_tree(repo, {**PLAIN, "AGENTS.md": "# Agents\n\n" + INJECTION})
    os.symlink("AGENTS.md", repo / "CLAUDE.md")
    os.symlink("/etc/hostname", repo / "GEMINI.md")  # an absolute target is never followed
    git(repo, "init", "-q")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fixture")
    code, report, _ = scan(run_cli, repo)
    assert [(item["path"], item["format"]) for item in instruction_items(report)] == [("AGENTS.md", "agents-md"), ("CLAUDE.md", "claude-md")]
    assert sorted(f["item"] for f in report["findings"] if f["rule_id"] == "SW-SKL-001") == ["AGENTS.md", "CLAUDE.md"]
    assert [(n["code"], n["path"]) for n in report["notices"] if n["code"] == "symlink_skipped"] == [("symlink_skipped", "GEMINI.md")]
    assert report["errors"] == [] and code == 1
