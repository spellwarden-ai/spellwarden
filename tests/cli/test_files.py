"""Spec 6.4 and claim C5: the file set from git (or a walk), narrowed to the
scan root, with skips, notices, errors and executable bits."""
from __future__ import annotations

import os
import subprocess
import sys

import pytest
from conftest import GIT, git, write_tree

from spellwarden_cli import files, paths
from spellwarden_cli.discover import discover
from spellwarden_cli.files import FILE_MAX, list_files, work_tree_top
from spellwarden_cli.settings import Settings


def _paths(fileset):
    return [entry.path for entry in fileset.entries]


def _codes(notices):
    return sorted(notice.code for notice in notices)


def _symlink(target, link):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be created here")


def test_git_lists_tracked_and_untracked_unignored_files(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a.md": "a", ".gitignore": "ignored.txt\n"})
    write_tree(repo, {"new.md": "n", "ignored.txt": "i"})
    fileset = list_files(str(repo), Settings())
    assert _paths(fileset) == [".gitignore", "a.md", "new.md"]
    assert [e.tracked for e in fileset.entries] == [True, True, False]
    assert fileset.repo_prefix == ""
    assert "git_unavailable" not in _codes(fileset.notices)


def test_a_scan_below_the_repository_root_sees_only_its_subtree(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"top.md": "t", "services/agent/SKILL.md": "s", "services/agent/x/y.sh": "y",
                                "services/other/z.md": "z"})
    fileset = list_files(str(repo / "services" / "agent"), Settings())
    assert _paths(fileset) == ["SKILL.md", "x/y.sh"]
    assert fileset.repo_prefix == "services/agent/"


def test_git_runs_with_safe_directory_set_to_the_work_tree_top_only(make_repo, tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo", {"sub/a.md": "a"})
    seen = []
    real = subprocess.run

    def spy(command, *args, **kwargs):
        seen.append(command)
        return real(command, *args, **kwargs)

    monkeypatch.setattr(files.subprocess, "run", spy)
    list_files(str(repo / "sub"), Settings())
    assert seen
    top = str(repo).replace(os.sep, "/")
    for command in seen:
        assert command[1:3] == ["-c", f"safe.directory={top}"]
        assert "safe.directory=*" not in command
        assert command[command.index("-C") + 1] == str(repo / "sub")


def test_a_repository_owned_by_another_user_is_listed_through_git(make_repo, tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo", {"a.md": "a"})
    # Git's own test switch makes the ownership check fail as it does for a workspace another uid owns.
    monkeypatch.setenv("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
    plain = subprocess.run(["git", "-C", str(repo), "ls-files"], capture_output=True)
    if plain.returncode == 0:
        pytest.skip("this git does not honour GIT_TEST_ASSUME_DIFFERENT_OWNER")
    fileset = list_files(str(repo), Settings())
    assert _paths(fileset) == ["a.md"]
    assert "git_unavailable" not in _codes(fileset.notices)


def test_work_tree_top_finds_a_gitdir_file_and_runs_no_git(tmp_path):
    (tmp_path / "wt" / "sub").mkdir(parents=True)
    (tmp_path / "wt" / ".git").write_text("gitdir: /elsewhere/.git/worktrees/wt\n")
    assert work_tree_top(str(tmp_path / "wt" / "sub")) == str(tmp_path / "wt")


def test_a_failing_git_falls_back_to_the_walk_with_a_notice(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a.md": "a"})
    fileset = list_files(str(repo), Settings(), git=str(tmp_path / "no-such-git"))
    assert _paths(fileset) == ["a.md"]
    assert "git_unavailable" in _codes(fileset.notices)
    assert fileset.repo_prefix == ""


def test_skip_dirs_are_the_engines_after_git():
    from spellwarden_scan import identity

    assert files.SKIP_DIRS == (".git", *identity.SKIP_DIRS)


def test_the_walk_skips_dependency_and_cache_directories(tmp_path):
    write_tree(tmp_path, {"a.md": "a", "node_modules/x/SKILL.md": "x", ".venv/y": "y", "venv/z": "z",
                          "__pycache__/c.pyc": "c", ".git/config": "g", "b/c.md": "c"})
    fileset = list_files(str(tmp_path), Settings(), git="")
    assert _paths(fileset) == ["a.md", "b/c.md"]
    assert fileset.repo_prefix == ""  # the `.git` directory makes this the top of a work tree; git was not run


def test_outside_a_repository_there_is_no_prefix_and_a_notice(tmp_path):
    write_tree(tmp_path / "plain", {"a.md": "a"})
    if work_tree_top(str(tmp_path / "plain")) is not None:
        pytest.skip("the temporary directory is inside a git work tree")
    fileset = list_files(str(tmp_path / "plain"), Settings())
    assert fileset.repo_prefix is None
    # Windows records no executable bit, and outside git no index supplies it.
    assert [(n.code, n.path) for n in fileset.notices] == [
        ("upload_paths_scan_root", "."), *([("exec_bits_unknown", "")] if os.name == "nt" else [])]


def test_symlinks_and_oversized_files_are_skipped_with_notices(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a.md": "a"})
    _symlink(repo / "a.md", repo / "link.md")
    with open(repo / "big.bin", "wb") as handle:
        handle.truncate(FILE_MAX + 1)
    fileset = list_files(str(repo), Settings())
    assert _paths(fileset) == ["a.md"]
    assert _codes(fileset.notices) == ["file_too_large"]
    # a listed link is kept aside, never read as a file; discovery follows a link at an agent-content path only and
    # gives every other link the notice (owner decision on symbolic links)
    assert fileset.links == (files.LinkEntry("link.md", False),)
    assert [(n.code, n.path) for n in discover(fileset).notices if n.code == "symlink_skipped"] == [
        ("symlink_skipped", "link.md")]


def test_a_link_committed_as_a_plain_file_is_a_link(make_repo, tmp_path):
    # Windows or `core.symlinks=false`: the index says 120000, the working tree holds the target text as a file.
    repo = make_repo(tmp_path / "repo", {"a.md": "a"})
    blob = subprocess.run([*GIT, "-C", str(repo), "hash-object", "-w", "--stdin"], input="a.md", capture_output=True,
                          text=True, check=True).stdout.strip()
    git(repo, "update-index", "--add", "--cacheinfo", f"120000,{blob},link.md")
    write_tree(repo, {"link.md": "a.md"})
    fileset = list_files(str(repo), Settings())
    assert _paths(fileset) == ["a.md"]
    assert fileset.links == (files.LinkEntry("link.md", True),)
    assert fileset.link_target("link.md") == b"a.md"


@pytest.mark.parametrize("dir_fd", [True, False])
def test_a_link_target_is_read_without_following_a_linked_directory(dir_fd, tmp_path, monkeypatch):
    # `False` is the Windows branch, run on every OS as the plan's rule for `open_contained` asks.
    monkeypatch.setattr(paths, "_HAS_DIR_FD", dir_fd and paths._HAS_DIR_FD)
    root = write_tree(tmp_path / "root", {"d/a.json": "{}"})
    write_tree(tmp_path / "outside", {"x.json": "{}"})
    _symlink("a.json", root / "d" / "link.json")
    _symlink(str(tmp_path / "outside"), root / "linked")
    assert paths.read_link(str(root), "d/link.json", max_bytes=4096) == b"a.json"
    with pytest.raises(paths.UnsafePath):
        paths.read_link(str(root), "linked/x.json", max_bytes=4096)
    with pytest.raises(paths.TooLarge):
        paths.read_link(str(root), "d/link.json", max_bytes=3)


@pytest.mark.skipif(sys.platform != "linux", reason="only Linux file systems accept names that are not UTF-8")
def test_non_utf8_names_are_skipped_with_a_notice(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a.md": "a"})
    with open(os.path.join(os.fsencode(repo), b"bad\xff.md"), "wb") as handle:
        handle.write(b"x")
    for git_binary in (None, ""):
        fileset = list_files(str(repo), Settings(), git=git_binary)
        assert _paths(fileset) == ["a.md"]
        assert "non_utf8_path" in _codes(fileset.notices)


def test_tracked_executable_bit_comes_from_the_index(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"scripts/run.bin": "x", "plain.sh": "y"}, modes={"scripts/run.bin": "100755"})
    if sys.platform != "win32":
        os.chmod(repo / "scripts" / "run.bin", 0o644)  # the working tree says otherwise; the index wins
        os.chmod(repo / "plain.sh", 0o755)
    for platform in ("linux", "darwin", "win32"):
        fileset = list_files(str(repo), Settings(), platform=platform)
        assert {e.path: e.executable for e in fileset.entries} == {"plain.sh": False, "scripts/run.bin": True}
        assert "exec_bits_unknown" not in _codes(fileset.notices)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_untracked_files_follow_st_mode_on_posix_and_are_never_executable_on_windows(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a.md": "a"})
    write_tree(repo, {"tool": "x"})
    os.chmod(repo / "tool", 0o755)
    assert {e.path: e.executable for e in list_files(str(repo), Settings()).entries}["tool"] is True
    windows = list_files(str(repo), Settings(), platform="win32")
    assert {e.path: e.executable for e in windows.entries}["tool"] is False
    assert _codes(windows.notices).count("exec_bits_unknown") == 1


def _case_insensitive(tmp_path) -> bool:
    (tmp_path / "probe-case").write_text("x")
    return (tmp_path / "PROBE-CASE").exists()


def test_case_colliding_paths_are_errors(tmp_path):
    if _case_insensitive(tmp_path):
        pytest.skip("this file system folds case")
    write_tree(tmp_path / "w", {"Skill/SKILL.md": "a", "skill/SKILL.md": "b", "ok.md": "c", "café.md": "d",
                                "café.md": "e"})
    fileset = list_files(str(tmp_path / "w"), Settings(), git="")
    assert _paths(fileset) == ["ok.md"]
    assert sorted((e.code, e.path) for e in fileset.errors) == sorted(
        ("case_collision", p) for p in ("Skill/SKILL.md", "skill/SKILL.md", "café.md", "café.md"))


def test_include_and_exclude_apply_after_listing(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a/x.json": "1", "a/y.md": "2", "tests/fixtures/z.json": "3"})
    fileset = list_files(str(repo), Settings(include=("**/*.json",), exclude=("tests/fixtures/**",)))
    assert _paths(fileset) == ["a/x.json"]


def test_a_deleted_tracked_file_is_skipped_with_a_notice(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a.md": "a", "gone.md": "g"})
    (repo / "gone.md").unlink()
    fileset = list_files(str(repo), Settings())
    assert _paths(fileset) == ["a.md"]
    assert "file_missing" in _codes(fileset.notices)


def test_submodule_entries_are_not_entered(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"a.md": "a"})
    blob = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{blob},vendor/sub")
    assert _paths(list_files(str(repo), Settings())) == ["a.md"]


def test_git_gets_an_explicit_environment_and_never_ours_by_reference(make_repo, tmp_path, monkeypatch):
    """O3 invariant 2: every subprocess receives an explicit environment, the one `list_files` was given."""
    repo = make_repo(tmp_path / "r", {"README.md": "x\n"})
    seen: list = []
    real = files.subprocess.run

    def spy(command, *args, **kwargs):
        seen.append(kwargs.get("env"))
        return real(command, *args, **kwargs)

    monkeypatch.setattr(files.subprocess, "run", spy)
    given = {**os.environ, "MARKER_FOR_TEST": "1"}
    files.list_files(str(repo), Settings(), env=given)
    assert seen and all(env is not None and env.get("MARKER_FOR_TEST") == "1" and env is not given for env in seen)
    seen.clear()
    files.list_files(str(repo), Settings())
    assert seen and all(isinstance(env, dict) and "MARKER_FOR_TEST" not in env for env in seen)


def test_the_walk_records_the_skip_dirs_it_did_not_enter(tmp_path):
    # O3 spec 6.6, P48: a directory the walk skipped under a skill makes the skill unhashable.
    write_tree(tmp_path, {"a.md": "a", "s/SKILL.md": "x", "s/node_modules/x/y.js": "y", "s/sub/.venv/z": "z", ".git/config": "g",
                          "venv/q": "q"})
    fileset = list_files(str(tmp_path), Settings(), git="")
    assert fileset.skipped_dirs == ("s/node_modules", "s/sub/.venv", "venv")  # `.git` is no skill content: not recorded


def test_git_mode_lists_dependency_directories_through_the_index_and_records_no_skipped_dir(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"s/SKILL.md": "x", "s/node_modules/x.js": "y"})
    fileset = list_files(str(repo), Settings())
    assert "s/node_modules/x.js" in _paths(fileset) and fileset.skipped_dirs == ()


def test_deselected_holds_every_path_include_or_exclude_dropped(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {"s/SKILL.md": "x", "s/run.js": "y", "docs/a.md": "a"})
    fileset = list_files(str(repo), Settings(exclude=("**/*.js",)))
    assert fileset.deselected == ("s/run.js",) and "s/run.js" not in _paths(fileset)
    narrowed = list_files(str(repo), Settings(include=("**/*.md",)))
    assert narrowed.deselected == ("s/run.js",)
    assert list_files(str(repo), Settings()).deselected == ()
