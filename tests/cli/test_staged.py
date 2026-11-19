"""1.19.0 `scan --staged` (the file set first, the command's tests below it): `files.StagedIndex` lists the git index under the
scan root, never an untracked file or an unstaged change; it reads each file's staged blob and its executable mode from the
index, and the settings file, the baseline and the lock from the index; it refuses outside a work tree and reports an unresolved
merge conflict. Every repository here is local."""
from __future__ import annotations

import os
import subprocess

import pytest
from conftest import GIT, git, write_tree

from spellwarden_cli import paths
from spellwarden_cli.discover import discover
from spellwarden_cli.files import FILE_MAX, StagedIndex, StagedUnavailable, list_files
from spellwarden_cli.settings import Settings


def _object(repo, content: bytes) -> str:
    done = subprocess.run([*GIT, "-C", str(repo), "hash-object", "-w", "--stdin"], input=content, capture_output=True,
                          check=True)
    return done.stdout.decode("ascii").strip()


def _stage_link(repo, path: str, target: str) -> None:
    """A symbolic link in the index only (mode 120000), on every OS: no link is made in the working tree."""
    git(repo, "update-index", "--add", "--cacheinfo", f"120000,{_object(repo, target.encode('utf-8'))},{path}")


def _staged_repo(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"kept.md": "committed\n", "gone.md": "removed from the index\n",
                                         "edited.md": "staged text\n", "deleted-on-disk.md": "still staged\n",
                                         "tool.sh": "#!/bin/sh\necho hi\n"}, modes={"tool.sh": "100755"})
    write_tree(repo, {"new.md": "new and staged\n"})
    git(repo, "add", "new.md")
    git(repo, "rm", "-q", "--cached", "gone.md")  # removed from the index, still on disk
    write_tree(repo, {"edited.md": "unstaged text\n", "untracked.md": "never added\n"})
    os.remove(repo / "deleted-on-disk.md")  # deleted in the working tree only
    return repo


def test_the_file_set_is_the_index_only(make_repo, tmp_path):
    repo = _staged_repo(make_repo, tmp_path)
    fileset = StagedIndex(str(repo)).fileset(Settings())
    assert [entry.path for entry in fileset.entries] == ["deleted-on-disk.md", "edited.md", "kept.md", "new.md", "tool.sh"]
    assert all(entry.tracked for entry in fileset.entries) and fileset.repo_prefix == ""
    assert {entry.path: entry.executable for entry in fileset.entries} == {
        "deleted-on-disk.md": False, "edited.md": False, "kept.md": False, "new.md": False, "tool.sh": True}
    assert fileset.read("edited.md") == b"staged text\n" and fileset.read("deleted-on-disk.md") == b"still staged\n"
    assert fileset.errors == () and fileset.index is not None
    plain = [entry.path for entry in list_files(str(repo), Settings()).entries]  # the working tree's file set, for contrast
    assert "untracked.md" in plain and "gone.md" in plain and "deleted-on-disk.md" not in plain


def test_a_scan_root_below_the_top_sees_its_part_of_the_index(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"top.md": "t", "services/agent/SKILL.md": "s", "services/agent/x/y.sh": "y",
                                         "services/other/z.md": "z"})
    write_tree(repo, {"services/agent/untracked.md": "u"})
    fileset = StagedIndex(str(repo / "services" / "agent")).fileset(Settings())
    assert [entry.path for entry in fileset.entries] == ["SKILL.md", "x/y.sh"] and fileset.repo_prefix == "services/agent/"


def test_include_and_exclude_narrow_the_staged_set(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a/x.md": "x", "b/y.md": "y"})
    fileset = StagedIndex(str(repo)).fileset(Settings(exclude=("b/**",)))
    assert [entry.path for entry in fileset.entries] == ["a/x.md"] and fileset.deselected == ("b/y.md",)


def test_settings_baseline_and_lock_are_read_from_the_index(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".spellwarden/config.yml": "version: 1\nfail-on: medium\n", "a.md": "a"})
    write_tree(repo, {".spellwarden/config.yml": "version: 1\nfail-on: low\n",
                      ".spellwarden/baseline.yml": "version: 1\nentries: []\n"})
    index = StagedIndex(str(repo))
    assert index.read(".spellwarden/config.yml", 65536) == b"version: 1\nfail-on: medium\n"
    with pytest.raises(FileNotFoundError):
        index.read(".spellwarden/baseline.yml", 2**20)  # on disk, never staged: absent
    with pytest.raises(paths.TooLarge):
        index.read(".spellwarden/config.yml", 4)
    with pytest.raises(paths.UnsafePath):
        index.read("a.md/inner.yml", 100)  # a file of the index where a directory of the path should be
    _stage_link(repo, ".spellwarden/lock.json", "elsewhere.json")
    with pytest.raises(paths.UnsafePath):
        StagedIndex(str(repo)).read(".spellwarden/lock.json", FILE_MAX)


def test_a_link_in_the_index_is_a_listed_link_read_from_its_blob(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"docs/real.md": "real\n"})
    _stage_link(repo, "docs/alias.md", "real.md")
    fileset = StagedIndex(str(repo)).fileset(Settings())
    assert [(link.path, link.tracked) for link in fileset.links] == [("docs/alias.md", True)]
    assert fileset.link_target("docs/alias.md") == b"real.md"
    assert [entry.path for entry in fileset.entries] == ["docs/real.md"]


def test_a_staged_file_over_the_size_limit_is_too_large_and_not_read(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"small.md": "s"})
    with open(repo / "AGENTS.md", "wb") as handle:
        handle.truncate(FILE_MAX + 1)
    git(repo, "add", "AGENTS.md")
    fileset = StagedIndex(str(repo)).fileset(Settings())
    assert fileset.too_large == ("AGENTS.md",) and [entry.path for entry in fileset.entries] == ["small.md"]


def test_outside_a_work_tree_or_without_git_it_is_unavailable(make_repo, tmp_path):
    plain = write_tree(tmp_path / "plain", {"a.md": "a"})
    with pytest.raises(StagedUnavailable, match=r"^--staged needs a git repository\.$"):
        StagedIndex(str(plain))
    repo = make_repo(tmp_path / "repo", {"a.md": "a"})
    with pytest.raises(StagedUnavailable, match="git was not found"):
        StagedIndex(str(repo), git="")


def test_an_unresolved_merge_conflict_is_unreadable(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a.md": "a", "c.md": "base"})
    oid = _object(repo, b"side\n")
    lines = f"0 {'0' * 40}\tc.md\n" + "".join(f"100644 {oid} {stage}\tc.md\n" for stage in (1, 2, 3))
    subprocess.run([*GIT, "-C", str(repo), "update-index", "--index-info"], input=lines.encode("ascii"), check=True,
                   capture_output=True)
    fileset = StagedIndex(str(repo)).fileset(Settings())
    assert [entry.path for entry in fileset.entries] == ["a.md"]
    assert [(error.code, error.path) for error in fileset.errors] == [("unreadable", "c.md")]


def test_an_untracked_lock_on_disk_is_not_the_lock_of_a_staged_scan(make_repo, tmp_path):
    """A lock file never staged is absent for a staged scan, whatever the working tree holds: a skill member link to it is the
    package's own link to the lock before it exists, as in a scan before the first `spellwarden lock`."""
    repo = make_repo(tmp_path / "repo", {"skills/x/SKILL.md": "---\nname: x\ndescription: A demo.\n---\n\nRead.\n"})
    _stage_link(repo, "skills/x/state.json", "../../.spellwarden/lock.json")
    write_tree(repo, {".spellwarden/lock.json": "{}\n"})  # on disk, never staged
    found = discover(StagedIndex(str(repo)).fileset(Settings()))
    assert found.errors == ()
    assert any(notice.path == "skills/x/state.json" and "does not exist yet" in notice.message for notice in found.notices)
