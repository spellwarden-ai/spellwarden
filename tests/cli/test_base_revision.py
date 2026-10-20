"""Spec 6.3, 6.7, 6.11 and D35 (owner, 2026-10-20): on a pull or merge request, `.spellwarden/config.yml` and
`.spellwarden/baseline.yml` are read from the base revision, never from the scanned (head) revision, so a request
cannot exclude or baseline its own finding. Local runs, pushes and schedules read the working tree as before. A base
revision that cannot be read gives the defaults and the notice `base_unavailable`; `--config` and `--baseline` named
by the operator are honoured as given. Every repository is a temporary one under `tmp_path`; nothing is networked
(the fetch case uses a `file://` remote)."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest
from conftest import GIT, git, write_tree

from spellwarden_cli import ci, paths, safe_yaml

MCP = json.dumps({"mcpServers": {"plain": {"url": "http://mcp.example.com/mcp"}}}, indent=2) + "\n"  # SW-CFG-001, high
EXCLUDE_MCP = 'version: 1\nexclude: [".mcp.json"]\n'
README = {"README.md": "agents\n"}


def commit(repo: Path, files: dict[str, str | bytes | None], message: str = "head") -> str:
    """Writes `files` (None deletes the path), commits everything and returns the new commit's sha."""
    for path, content in files.items():
        if content is None:
            git(repo, "rm", "-q", "--", path)
    write_tree(repo, {path: content for path, content in files.items() if content is not None})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD").strip()


def two_commits(make_repo, tmp_path: Path, base: dict, head: dict) -> tuple[Path, str]:
    repo = make_repo(tmp_path / "repo", {**README, **base})
    base_sha = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, head)
    return repo, base_sha


def github_env(tmp_path: Path, event: str = "pull_request", payload: dict | None = None) -> dict[str, str]:
    path = tmp_path / f"event-{event}.json"
    path.write_text(json.dumps(payload if payload is not None else {}), encoding="utf-8")
    return {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": event, "GITHUB_EVENT_PATH": str(path),
            "GITHUB_REPOSITORY": "acme/agents", "GITHUB_REF_PROTECTED": "false"}


def pull_request(tmp_path: Path, base_sha: str | None) -> dict[str, str]:
    pull: dict = {"number": 7, "head": {"repo": {"full_name": "acme/agents"}}}
    if base_sha is not None:
        pull["base"] = {"sha": base_sha}
    return github_env(tmp_path, "pull_request", {"pull_request": pull})


def push(tmp_path: Path) -> dict[str, str]:
    return github_env(tmp_path, "push", {"ref": "refs/heads/main"})


def merge_request(base_sha: str) -> dict[str, str]:
    return {"CI": "true", "GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "merge_request_event", "CI_PROJECT_ID": "42",
            "CI_MERGE_REQUEST_IID": "5", "CI_MERGE_REQUEST_SOURCE_PROJECT_ID": "42",
            "CI_MERGE_REQUEST_DIFF_BASE_SHA": base_sha}


def scan(run_cli, repo: Path, env: dict | None = None, *extra: str) -> tuple[int, dict]:
    code, out, err = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--as-of", "2026-12-01", *extra],
                             env=env)
    assert out, err
    return code, json.loads(out)


def codes(entries: list[dict]) -> list[str]:
    return [entry["code"] for entry in entries]


def rules(report: dict, *, suppressed: bool = False) -> list[str]:
    return [f["rule_id"] for f in report["findings"] if f["suppressed"] is suppressed]


def notice(report: dict, code: str) -> dict:
    return next(entry for entry in report["notices"] if entry["code"] == code)


# --- the attack: a request that excludes or baselines its own finding --------------------------------------------

def test_a_request_cannot_exclude_its_own_finding(make_repo, run_cli, tmp_path):
    repo, base = two_commits(make_repo, tmp_path, {}, {".mcp.json": MCP, ".spellwarden/config.yml": EXCLUDE_MCP})
    code, report = scan(run_cli, repo, pull_request(tmp_path, base))
    assert code == 1 and rules(report) == ["SW-CFG-001"]
    message = notice(report, "settings_from_base")["message"]
    assert base[:12] in message and ".spellwarden/config.yml" in message and ".spellwarden/baseline.yml" in message
    assert "base_unavailable" not in codes(report["notices"])
    # The same revision on a push and on a local run reads its own settings file, as before.
    for env in (push(tmp_path), None):
        code, report = scan(run_cli, repo, env)
        assert code == 0 and report["findings"] == [] and "settings_from_base" not in codes(report["notices"])


def _fingerprint(run_cli, repo: Path) -> str:
    _, report = scan(run_cli, repo)
    return next(f["fingerprint"] for f in report["findings"] if f["rule_id"] == "SW-CFG-001")


def _baseline(fingerprint: str) -> str:
    return (f'version: 1\naccepted:\n  - fingerprint: "{fingerprint}"\n    rule: SW-CFG-001\n    path: .mcp.json\n'
            f"    reason: Ours.\n    added: 2026-11-30\n    expires: 2026-12-30\n")


def test_a_request_cannot_baseline_its_own_finding(make_repo, run_cli, tmp_path):
    repo, base = two_commits(make_repo, tmp_path, {}, {".mcp.json": MCP})
    commit(repo, {".spellwarden/baseline.yml": _baseline(_fingerprint(run_cli, repo))})
    code, report = scan(run_cli, repo, pull_request(tmp_path, base))
    assert code == 1 and rules(report) == ["SW-CFG-001"] and rules(report, suppressed=True) == []
    code, report = scan(run_cli, repo, push(tmp_path))
    assert code == 0 and rules(report, suppressed=True) == ["SW-CFG-001"]


def test_a_baseline_at_the_base_applies_on_the_request(make_repo, run_cli, tmp_path):
    repo, base = two_commits(make_repo, tmp_path, {".mcp.json": MCP}, {})
    fingerprint = _fingerprint(run_cli, repo)
    base = commit(repo, {".spellwarden/baseline.yml": _baseline(fingerprint)}, "base")
    commit(repo, {".spellwarden/baseline.yml": None})  # the request deletes the acceptance: still the base's
    code, report = scan(run_cli, repo, pull_request(tmp_path, base))
    assert code == 0 and rules(report, suppressed=True) == ["SW-CFG-001"]


def test_the_base_settings_file_applies_on_the_request(make_repo, run_cli, tmp_path):
    repo, base = two_commits(make_repo, tmp_path, {".spellwarden/config.yml": 'version: 1\nexclude: ["vendor/**"]\n'},
                             {"vendor/.mcp.json": MCP, ".spellwarden/config.yml": "version: 1\n"})
    code, report = scan(run_cli, repo, pull_request(tmp_path, base))
    assert code == 0 and report["findings"] == []
    assert scan(run_cli, repo)[0] == 1  # locally, the head file (no exclude) applies


def test_no_settings_file_at_the_base_means_the_defaults(make_repo, run_cli, tmp_path):
    repo, base = two_commits(make_repo, tmp_path, {}, {".mcp.json": MCP, ".spellwarden/config.yml": "version: 1\nfail-on: never\n"})
    code, report = scan(run_cli, repo, pull_request(tmp_path, base))
    assert code == 1 and report["fail_on"] == "high"
    assert "settings_from_base" in codes(report["notices"])


def test_a_gitlab_merge_request_reads_the_diff_base(make_repo, run_cli, tmp_path):
    repo, base = two_commits(make_repo, tmp_path, {}, {".mcp.json": MCP, ".spellwarden/config.yml": EXCLUDE_MCP})
    code, report = scan(run_cli, repo, merge_request(base))
    assert code == 1 and base[:12] in notice(report, "settings_from_base")["message"]


def test_a_gitlab_child_pipeline_of_a_merge_request_cannot_exclude_its_own_finding(make_repo, run_cli, tmp_path):
    """Review r2 F5: a child pipeline (`parent_pipeline`) started by a merge request pipeline runs the request's code;
    it was not a request, so the request's own settings excluded its own finding."""
    repo, _ = two_commits(make_repo, tmp_path, {}, {".mcp.json": MCP, ".spellwarden/config.yml": EXCLUDE_MCP})
    child = {"CI": "true", "GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "parent_pipeline", "CI_PROJECT_ID": "42",
             "CI_COMMIT_REF_PROTECTED": "false"}
    code, report = scan(run_cli, repo, child)
    assert code == 1 and rules(report) == ["SW-CFG-001"] and "base_unavailable" in codes(report["notices"])
    code, report = scan(run_cli, repo, {**child, "CI_COMMIT_REF_PROTECTED": "true"})  # the protected branch's own
    assert code == 0 and rules(report) == [] and {"base_unavailable", "settings_from_base"}.isdisjoint(
        codes(report["notices"]))


def test_the_base_settings_are_validated_as_the_head_ones(make_repo, run_cli, tmp_path):
    """An invalid file at the base is the same exit 2, and the notice still says where the file came from."""
    repo, base = two_commits(make_repo, tmp_path, {".spellwarden/config.yml": "version: 1\nprobe-private: true\n"},
                             {".spellwarden/config.yml": "version: 1\n"})
    code, report = scan(run_cli, repo, pull_request(tmp_path, base))
    assert code == 2 and codes(report["errors"]) == ["settings_invalid"]
    assert "probe-private" in report["errors"][0]["message"]
    assert "settings_from_base" in codes(report["notices"])


def test_the_lock_is_read_from_the_request_and_computed_with_the_base_patterns(make_repo, run_cli, tmp_path):
    """The lock file stays the request's (a change to agent content must update it); its items are computed over the
    file set the base's `include` and `exclude` select, so a request that changes the patterns and the lock together
    is stale until the settings change is merged."""
    secure = json.dumps({"mcpServers": {"docs": {"url": "https://mcp.example.com/mcp"}}}) + "\n"
    repo, base = two_commits(make_repo, tmp_path, {"vendor/.mcp.json": secure},
                             {".spellwarden/config.yml": 'version: 1\nexclude: ["vendor/**"]\n'})
    assert run_cli(["lock", str(repo)])[0] == 0  # the author locks with the request's own settings
    commit(repo, {})
    _, report = scan(run_cli, repo, push(tmp_path), "--locked")
    assert report["lock"]["status"] == "ok"
    _, report = scan(run_cli, repo, pull_request(tmp_path, base), "--locked")
    assert report["lock"]["status"] == "stale"
    assert [item["path"] for item in report["lock"]["added"]][:1] == ["vendor/.mcp.json"]


# --- fail closed: no base revision -------------------------------------------------------------------------------

def _guarded(make_repo, tmp_path):
    """A base whose settings file legitimately excludes `vendor/`, and a request that changes nothing there."""
    return two_commits(make_repo, tmp_path, {".spellwarden/config.yml": 'version: 1\nexclude: ["vendor/**"]\n',
                                             "vendor/.mcp.json": MCP}, {"docs.md": "more\n"})


def test_a_request_without_a_base_sha_uses_the_defaults(make_repo, run_cli, tmp_path):
    repo, _ = _guarded(make_repo, tmp_path)
    code, report = scan(run_cli, repo, pull_request(tmp_path, None))
    assert code == 1 and rules(report) == ["SW-CFG-001"]
    message = notice(report, "base_unavailable")["message"]
    assert "names no base commit" in message and "default settings" in message


def test_an_unknown_base_sha_uses_the_defaults(make_repo, run_cli, tmp_path):
    repo, _ = _guarded(make_repo, tmp_path)
    code, report = scan(run_cli, repo, pull_request(tmp_path, "ab" * 20))
    assert code == 1 and rules(report) == ["SW-CFG-001"]
    message = notice(report, "base_unavailable")["message"]
    assert "abababababab" in message and "fetch-depth: 0" in message


def test_without_git_the_request_uses_the_defaults(make_repo, run_cli, tmp_path, monkeypatch):
    repo, base = _guarded(make_repo, tmp_path)
    monkeypatch.setattr(ci, "_which_git", lambda: None)
    code, report = scan(run_cli, repo, pull_request(tmp_path, base))
    assert code == 1 and "git is not available" in notice(report, "base_unavailable")["message"]


def test_a_gitlab_hint_names_git_depth(make_repo, run_cli, tmp_path):
    repo, _ = _guarded(make_repo, tmp_path)
    code, report = scan(run_cli, repo, merge_request("cd" * 20))
    assert code == 1 and "GIT_DEPTH" in notice(report, "base_unavailable")["message"]


# --- refusals at the base are the head's refusals ------------------------------------------------------------------

def test_an_oversized_file_at_the_base_is_refused(make_repo, run_cli, tmp_path):
    big = "version: 1\n" + "# x\n" * (safe_yaml.CONFIG_MAX // 4)
    repo, base = two_commits(make_repo, tmp_path, {".spellwarden/config.yml": big}, {".spellwarden/config.yml": "version: 1\n"})
    code, report = scan(run_cli, repo, pull_request(tmp_path, base))
    assert code == 2 and "refused (too_large)" in report["errors"][0]["message"]
    huge = "version: 1\n" + "# x\n" * (safe_yaml.BASELINE_MAX // 4)
    repo2, base2 = two_commits(make_repo, tmp_path / "b", {".spellwarden/baseline.yml": huge}, {".spellwarden/baseline.yml": None})
    code, report = scan(run_cli, repo2, pull_request(tmp_path, base2))
    assert code == 2 and codes(report["errors"]) == ["baseline_invalid"]
    assert "larger than" in report["errors"][0]["message"]


def _link_at(repo: Path, path: str, target: str) -> str:
    """Commits a symbolic link through the index (no link on disk, so it runs on every OS); returns the sha."""
    oid = _hash(repo, target)
    git(repo, "update-index", "--add", "--cacheinfo", f"120000,{oid},{path}")
    git(repo, "commit", "-q", "-m", "link")
    return git(repo, "rev-parse", "HEAD").strip()


def _hash(repo: Path, text: str) -> str:
    blob = repo.parent / f"{repo.name}-blob"
    blob.write_text(text, encoding="utf-8")
    return git(repo, "hash-object", "-w", str(blob)).strip()


@pytest.mark.parametrize("link", [".spellwarden/config.yml", ".spellwarden"])
def test_a_symbolic_link_at_the_base_is_refused(link, make_repo, run_cli, tmp_path):
    repo = make_repo(tmp_path / "repo", README)
    base = _link_at(repo, link, "/etc/hostname")
    git(repo, "rm", "-q", "--cached", "--", link)
    commit(repo, {".spellwarden/config.yml": "version: 1\n"})
    code, report = scan(run_cli, repo, pull_request(tmp_path, base))
    assert code == 2 and codes(report["errors"]) == ["settings_invalid"] and "symlink" in report["errors"][0]["message"]


# --- the operator's explicit files ---------------------------------------------------------------------------------

def test_explicit_config_and_baseline_are_honoured_on_a_request(make_repo, run_cli, tmp_path):
    repo, base = two_commits(make_repo, tmp_path, {}, {".mcp.json": MCP})
    chosen = tmp_path / "operator.yml"
    chosen.write_text(EXCLUDE_MCP, encoding="utf-8")
    code, report = scan(run_cli, repo, pull_request(tmp_path, base), "--config", str(chosen))
    assert code == 0 and report["findings"] == []
    assert ".spellwarden/config.yml" not in notice(report, "settings_from_base")["message"]
    commit(repo, {".spellwarden/baseline.yml": _baseline(_fingerprint(run_cli, repo))})
    code, report = scan(run_cli, repo, pull_request(tmp_path, base), "--baseline", ".spellwarden/baseline.yml")
    assert code == 0 and rules(report, suppressed=True) == ["SW-CFG-001"]
    code, report = scan(run_cli, repo, pull_request(tmp_path, base), "--config", str(chosen),
                        "--baseline", ".spellwarden/baseline.yml")
    assert code == 0 and "settings_from_base" not in codes(report["notices"])


# --- a shallow clone fetches the base once ------------------------------------------------------------------------

def test_a_shallow_clone_fetches_the_missing_base_once(make_repo, run_cli, tmp_path):
    upstream, base = two_commits(make_repo, tmp_path, {".spellwarden/config.yml": 'version: 1\nexclude: ["vendor/**"]\n'},
                                 {"vendor/.mcp.json": MCP, ".spellwarden/config.yml": "version: 1\n"})
    clone = tmp_path / "clone"
    git(tmp_path, "clone", "-q", "--depth", "1", upstream.as_uri(), str(clone))
    assert _has(clone, base) is False
    code, report = scan(run_cli, clone, pull_request(tmp_path, base))
    assert code == 0 and report["findings"] == [] and "settings_from_base" in codes(report["notices"])
    assert _has(clone, base) is True


def _has(repo: Path, sha: str) -> bool:
    return subprocess.run([*GIT, "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True).returncode == 0


def test_a_temporary_directory_that_cannot_be_made_gives_the_defaults(make_repo, run_cli, tmp_path, monkeypatch):
    """Review r2 F4: the empty hooks directory of the fetch could not be created (`tempfile.tempdir` missing), the
    `OSError` escaped outside the crash guard and no output was written (spec 6.2)."""
    import tempfile

    upstream, base = two_commits(make_repo, tmp_path, {".spellwarden/config.yml": 'version: 1\nexclude: ["vendor/**"]\n'},
                                 {"vendor/.mcp.json": MCP})
    clone = tmp_path / "clone"
    git(tmp_path, "clone", "-q", "--depth", "1", upstream.as_uri(), str(clone))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "missing"))
    code, report = scan(run_cli, clone, pull_request(tmp_path, base))
    assert code == 1 and rules(report) == ["SW-CFG-001"] and "base_unavailable" in codes(report["notices"])


def test_a_crash_while_choosing_the_revision_still_writes_every_output(make_repo, run_cli, tmp_path, monkeypatch):
    """Spec 6.2: a crash writes what it can and exits 2, also when it happens before the settings are read."""
    repo = make_repo(tmp_path / "repo", README)

    def crash(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(ci, "revision_source", crash)
    code, report = scan(run_cli, repo, pull_request(tmp_path, "ab" * 20))
    assert code == 2 and codes(report["errors"]) == ["crash"] and "boom" in report["errors"][0]["message"]


def test_a_failed_fetch_is_attempted_once_and_gives_the_defaults(make_repo, tmp_path, monkeypatch):
    repo, _ = _guarded(make_repo, tmp_path)
    git(repo, "remote", "add", "origin", (tmp_path / "nowhere").as_uri())
    calls: list[tuple[str, ...]] = []
    real = ci._run_git

    def spy(executable, top, root, *args, **kwargs):
        calls.append(args)
        return real(executable, top, root, *args, **kwargs)

    monkeypatch.setattr(ci, "_run_git", spy)
    ctx = ci.detect(pull_request(tmp_path, "ef" * 20))
    source = ci.revision_source(str(repo), ctx, config=True, baseline=True)
    assert [n.code for n in source.notices] == ["base_unavailable"]
    assert sum(1 for args in calls if "fetch" in args) == 1
    with pytest.raises(FileNotFoundError):
        source.read(".spellwarden/config.yml", safe_yaml.CONFIG_MAX)


# --- read_at_revision -----------------------------------------------------------------------------------------------

def test_read_at_revision(make_repo, tmp_path):
    repo, base = two_commits(make_repo, tmp_path, {"sub/.spellwarden/config.yml": "version: 1\n", "sub/x.sh": "#!/bin/sh\n"},
                             {"sub/.spellwarden/config.yml": "version: 1\nfail-on: never\n"})
    sub = str(repo / "sub")
    assert ci.read_at_revision(sub, base, ".spellwarden/config.yml", max_bytes=100) == b"version: 1\n"
    assert ci.read_at_revision(sub, base, ".spellwarden/baseline.yml", max_bytes=100) is None
    assert ci.read_at_revision(str(repo), base, ".spellwarden/config.yml", max_bytes=100) is None  # the scan root's prefix
    with pytest.raises(paths.TooLarge):
        ci.read_at_revision(sub, base, ".spellwarden/config.yml", max_bytes=5)
    with pytest.raises(paths.UnsafePath):
        ci.read_at_revision(sub, base, "../x.sh", max_bytes=100)
    with pytest.raises(ci.RevisionUnavailable):
        ci.read_at_revision(sub, "12" * 20, ".spellwarden/config.yml", max_bytes=100)
    with pytest.raises(ci.RevisionUnavailable):
        ci.read_at_revision(sub, "HEAD", ".spellwarden/config.yml", max_bytes=100)
    with pytest.raises(ci.RevisionUnavailable):
        ci.read_at_revision(sub, base, ".spellwarden/config.yml", max_bytes=100, git="")


def test_read_at_revision_refuses_a_directory_and_a_submodule(make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {".spellwarden/config.yml/inner": "x\n"})
    sha = git(repo, "rev-parse", "HEAD").strip()
    with pytest.raises(paths.UnsafePath):
        ci.read_at_revision(str(repo), sha, ".spellwarden/config.yml", max_bytes=100)
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{sha},.spellwarden/baseline.yml")
    git(repo, "commit", "-q", "-m", "gitlink")
    sha = git(repo, "rev-parse", "HEAD").strip()
    with pytest.raises(paths.UnsafePath):
        ci.read_at_revision(str(repo), sha, ".spellwarden/baseline.yml", max_bytes=100)


def test_outside_git_a_request_uses_the_defaults(tmp_path):
    write_tree(tmp_path / "plain", {".spellwarden/config.yml": EXCLUDE_MCP})
    source = ci.revision_source(str(tmp_path / "plain"), ci.detect(pull_request(tmp_path, "ab" * 20)), config=True,
                                baseline=True)
    assert [n.code for n in source.notices] == ["base_unavailable"]
    assert "not inside a git work tree" in source.notices[0].message


def test_local_and_push_runs_read_the_working_tree(tmp_path):
    assert ci.revision_source(str(tmp_path), ci.LOCAL, config=True, baseline=True) == ci.WORKING_TREE
    assert ci.revision_source(str(tmp_path), ci.detect(push(tmp_path)), config=True, baseline=True) == ci.WORKING_TREE
    assert ci.revision_source(str(tmp_path), ci.detect({"CI": "true"}, git_remote=lambda: None), config=True,
                              baseline=True) == ci.WORKING_TREE


def test_a_sha_that_is_not_hex_never_reaches_git(make_repo, tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo", README)
    calls: list = []
    monkeypatch.setattr(ci, "_run_git", lambda *args, **_kwargs: calls.append(args))
    for sha in ("--output=x", "-c", "ab" * 19, "ab" * 20 + "\n", "HEAD~1"):
        with pytest.raises(ci.RevisionUnavailable):
            ci.read_at_revision(str(repo), sha, ".spellwarden/config.yml", max_bytes=10)
    assert calls == []


# --- the timeout of a git call is hard: the whole process tree goes (review r2 F10) ---------------------------------

def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:  # a zombie still answers signal 0 until it is reaped
        with open(f"/proc/{pid}/stat", encoding="ascii") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return True


@pytest.mark.skipif(os.name == "nt", reason="a POSIX shell script stands in for git")
def test_a_git_call_past_its_timeout_kills_the_whole_process_tree(tmp_path):
    """A fetch's helper (`git-remote-https`) is a grandchild that holds git's stdout and stderr: past the timeout it
    must go too, and the call must not wait on what it holds."""
    pid_file = tmp_path / "grandchild.pid"
    fake = tmp_path / "bin" / "git"
    fake.parent.mkdir()
    fake.write_text(f"#!/bin/sh\nsleep 60 &\necho $! > '{pid_file}'\nsleep 60\n", encoding="utf-8")
    fake.chmod(0o755)
    started = time.monotonic()
    with pytest.raises(OSError, match="took longer than"):
        ci._run_git(str(fake), str(tmp_path), str(tmp_path), "fetch", timeout=1)
    assert time.monotonic() - started < 15
    grandchild = int(pid_file.read_text(encoding="ascii"))
    deadline = time.monotonic() + 5
    while _alive(grandchild) and time.monotonic() < deadline:
        time.sleep(0.05)
    alive = _alive(grandchild)
    if alive:
        os.kill(grandchild, signal.SIGKILL)
    assert not alive


def test_on_windows_the_tree_is_killed_with_taskkill(monkeypatch):
    calls: list[list[str]] = []

    class Process:
        pid = 4242

        def kill(self):
            calls.append(["kill"])

        def wait(self, timeout=None):  # noqa: ARG002 -- the shape of Popen.wait
            return -9

    monkeypatch.setattr(ci, "_WINDOWS", True)
    monkeypatch.setattr(ci.subprocess, "run", lambda argv, **_kwargs: calls.append(list(argv)))
    ci._kill_tree(Process())
    assert os.path.basename(calls[0][0]).lower().startswith("taskkill")
    assert calls[0][1:] == ["/T", "/F", "/PID", "4242"] and calls[1] == ["kill"]
