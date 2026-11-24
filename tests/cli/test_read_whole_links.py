"""P6-10 spec 7.7 (1.23.0; claims T13, T13a, T13b): the owner's answers spec:Q1 to spec:Q3 in the command. A link inside a skill
or a local plugin directory, or a linked instruction folder under `--follow-links`, whose target leaves the scan root is the
error `unsafe_path` and an incomplete scan (exit 2), and `spellwarden lock` writes no lock (spec:Q1); an instruction file that is
a link the scan cannot follow stays the notice `symlink_skipped` (spec:Q2); a member link to a file elsewhere inside the scan root
is still read at its target (spec:Q3)."""
from __future__ import annotations

import json
import os
import posixpath
from pathlib import Path

import pytest
from conftest import scan_json

from spellwarden_cli.discover import discover
from spellwarden_cli.files import list_files
from spellwarden_cli.settings import Settings

SKILL = "---\nname: demo\ndescription: A demo skill.\n---\n\nRead the task.\n"
SAFE_SCRIPT = "#!/bin/sh\necho hello\n"
MEMBER_OUTSIDE = ("symbolic link to a place outside the scan root; not followed, so the scan is incomplete: replace the link with "
                  "the file it names, or leave it out with `exclude` in .spellwarden/config.yml")
FOLDER_OUTSIDE = ("symbolic link to a place outside the scan root; not followed, so the scan is incomplete: replace the link with "
                  "the files it should hold, or leave it out with `exclude` in .spellwarden/config.yml")


def _symlink(target: str, link: Path) -> None:
    """A link to a directory, or to a file when the target text ends in a file suffix."""
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link, target_is_directory=not posixpath.splitext(target)[1])
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")


def _errors(found) -> list[tuple[str, str, str]]:
    return [(error.code, error.path, error.message) for error in found.errors]


def test_a_skill_link_out_of_the_scan_root_is_an_error_exit_2_and_no_lock(make_repo, run_cli, tmp_path):
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL})
    (tmp_path / "outside.sh").write_text(SAFE_SCRIPT, encoding="utf-8")
    _symlink("../../../outside.sh", repo / "skills" / "x" / "run.sh")
    found = discover(list_files(str(repo), Settings()))
    assert _errors(found) == [("unsafe_path", "skills/x/run.sh", MEMBER_OUTSIDE)]
    assert found.skills == () and not [n for n in found.notices if n.code == "symlink_skipped"]
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 2
    assert ("unsafe_path", "skills/x/run.sh") in {(e["code"], e["path"]) for e in report["errors"]}
    assert run_cli(["lock", str(repo)])[0] == 2
    assert not (repo / ".spellwarden" / "lock.json").exists()


def test_the_same_link_left_out_with_exclude_no_longer_stops_the_scan(make_repo, run_cli, tmp_path):
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL,
                                         ".spellwarden/config.yml": "version: 1\nexclude:\n  - skills/x/run.sh\n"})
    _symlink("../../../outside.sh", repo / "skills" / "x" / "run.sh")
    found = discover(list_files(str(repo), Settings(exclude=("skills/x/run.sh",))))
    assert found.errors == () and [skill.path for skill in found.skills] == ["skills/x"]
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 0 and report["errors"] == []


def test_a_local_plugin_link_out_of_the_scan_root_is_an_error_exit_2(make_repo, run_cli, tmp_path):
    repo = make_repo(tmp_path / "repo", {
        ".claude-plugin/marketplace.json": json.dumps({"plugins": [{"name": "p", "source": "./p"}]}),
        "p/.claude-plugin/plugin.json": json.dumps({"name": "p"})})
    _symlink("../../../outside.sh", repo / "p" / "bin" / "out.sh")
    found = discover(list_files(str(repo), Settings()))
    assert _errors(found) == [("unsafe_path", "p/bin/out.sh", MEMBER_OUTSIDE)]
    assert scan_json(run_cli, repo)[0] == 2


def test_a_linked_instruction_folder_out_of_the_scan_root_under_follow_links_is_an_error(make_repo, run_cli, tmp_path):
    repo = make_repo(tmp_path / "repo", {"README.md": "# x\n"})
    (tmp_path / "outside-rules").mkdir()
    (tmp_path / "outside-rules" / "a.md").write_text("# A\n", encoding="utf-8")
    _symlink("../../../outside-rules", repo / ".claude" / "rules" / "out")
    found = discover(list_files(str(repo), Settings()), follow_links=True)
    assert _errors(found) == [("unsafe_path", ".claude/rules/out", FOLDER_OUTSIDE)]
    assert scan_json(run_cli, repo, None, "--follow-links")[0] == 2
    # without the argument it stays the notice of the owner's decision of 2026-11-23, and the scan can pass
    found = discover(list_files(str(repo), Settings()), follow_links=False)
    assert found.errors == () and [n.path for n in found.notices if n.code == "symlink_skipped"] == [".claude/rules/out"]
    assert scan_json(run_cli, repo)[0] == 0


@pytest.mark.parametrize("link, target", [("CLAUDE.md", "../outside.md"), (".claude/rules/a.md", "nothing.md"),
                                          ("AGENTS.md", "d")])
def test_an_instruction_file_that_is_a_link_the_scan_cannot_follow_stays_a_notice(link, target, make_repo, run_cli, tmp_path):
    """T13a (owner spec:Q2, kept): as on 1.22.0, the notice `symlink_skipped` and exit 0."""
    repo = make_repo(tmp_path / "repo", {"README.md": "# x\n", "d/x.txt": "x\n"})
    (tmp_path / "outside.md").write_text("# O\n", encoding="utf-8")
    _symlink(target, repo.joinpath(*link.split("/")))
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 0 and report["errors"] == []
    assert link in {n["path"] for n in report["notices"] if n["code"] == "symlink_skipped"}


@pytest.mark.parametrize("link", [".claude/rules/a.md", ".claude/commands/c.md", ".claude/agents/g.md", "CLAUDE.md"])
def test_an_instruction_file_link_out_of_the_scan_root_stays_a_notice_under_follow_links(link, make_repo, run_cli, tmp_path):
    """T13a with `--follow-links` (r0:F1, owner spec:Q2): the link is an instruction file, not a folder, so as on 1.22.0 it is
    the notice `symlink_skipped` and exit 0; only a link that is no instruction file is a folder candidate (spec:Q1)."""
    repo = make_repo(tmp_path / "repo", {"README.md": "# x\n"})
    (tmp_path / "outside.md").write_text("# O\n", encoding="utf-8")
    _symlink("../" * (link.count("/") + 1) + "outside.md", repo.joinpath(*link.split("/")))
    found = discover(list_files(str(repo), Settings()), follow_links=True)
    assert found.errors == () and link in [n.path for n in found.notices if n.code == "symlink_skipped"]
    code, report, _out, _err = scan_json(run_cli, repo, None, "--follow-links")
    assert code == 0 and report["errors"] == []


def test_a_member_link_to_a_file_elsewhere_inside_the_scan_root_is_still_read(make_repo, run_cli, tmp_path):
    """T13b (owner spec:Q3, kept): the command's tree is the scan root, as since 1.19.0."""
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": SKILL, "docs/a.md": "# Guide\n"})
    _symlink("../../docs/a.md", repo / "skills" / "x" / "ref.md")
    found = discover(list_files(str(repo), Settings()))
    assert found.errors == () and found.skills[0].files["skills/x/ref.md"] == b"# Guide\n"
    code, report, _out, _err = scan_json(run_cli, repo)
    assert code == 0 and report["errors"] == []
