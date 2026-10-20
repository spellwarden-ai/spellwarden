"""Spec 10.2a and claim C17: `spellwarden ci-run gitlab`, the GitLab component's whole job script. Its `SW_*`
variables are validated as step 1 of the Action does (spec 9.2), every boolean reaches the scan as an explicit
positive or negative flag, the four report files land in the job's directory, and the exit code is the scan's."""
from __future__ import annotations

import json

import pytest

from spellwarden_cli import ci

VALID = {"SW_PATH": ".", "SW_FAIL_ON": "high", "SW_LOCKED": "auto", "SW_PROBE": "false", "SW_PROBE_PRIVATE": "false",
         "SW_COMMENT": "false", "SW_TELEMETRY": "true"}


def test_valid_inputs_become_explicit_flags(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    argv, problems, comment = ci.gitlab_argv(VALID)
    assert problems == [] and comment is False
    assert argv[:4] == ["scan", ".", "--fail-on", "high"]
    assert "--no-probe" in argv and "--no-probe-private" in argv and "--locked" not in argv and "--no-telemetry" not in argv
    pairs = [(argv[i + 1], argv[i + 3]) for i, token in enumerate(argv[:-3]) if token == "--format" and argv[i + 2] == "--output"]
    assert pairs == list(ci.GITLAB_OUTPUTS) and argv[-2:] == ["--format", "text"]
    flipped, _, comment = ci.gitlab_argv({**VALID, "SW_PROBE": "true", "SW_PROBE_PRIVATE": "true", "SW_TELEMETRY": "false",
                                          "SW_LOCKED": "true", "SW_COMMENT": "true"})
    assert {"--probe", "--probe-private", "--no-telemetry", "--locked"} <= set(flipped) and comment is True


def test_locked_auto_follows_the_lock_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".spellwarden").mkdir()
    (tmp_path / ".spellwarden" / "lock.json").write_text("{}", encoding="utf-8")
    assert "--locked" in ci.gitlab_argv(VALID)[0]
    assert "--locked" not in ci.gitlab_argv({**VALID, "SW_LOCKED": "false"})[0]


@pytest.mark.parametrize(("name", "value", "label"), [
    ("SW_FAIL_ON", "severe", "fail-on"), ("SW_LOCKED", "maybe", "locked"), ("SW_PROBE", "yes", "probe"),
    ("SW_PROBE_PRIVATE", "1", "probe-private"), ("SW_COMMENT", "", "comment"), ("SW_TELEMETRY", "off", "telemetry"),
])
def test_an_invalid_input_exits_2_naming_it_and_writes_nothing(name, value, label, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert ci.run_gitlab({**VALID, name: value}) == 2
    assert f"input {label}:" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_a_hostile_input_is_printed_escaped(capsys):
    assert ci.run_gitlab({**VALID, "SW_FAIL_ON": "high\n\x1b[31mok"}) == 2
    err = capsys.readouterr().err
    assert "\x1b" not in err and "\\x1b" in err


def test_the_job_scans_writes_the_four_reports_and_exits_with_the_scan_code(tmp_path, monkeypatch, make_repo):
    repo = make_repo(tmp_path / "project", {
        ".mcp.json": json.dumps({"mcpServers": {"plain": {"url": "http://mcp.example.com/mcp"}}}, indent=2),
    })
    monkeypatch.chdir(repo)
    code = ci.run_gitlab({**VALID, "SW_TELEMETRY": "false"})
    assert code == 1  # SW-CFG-001 is high, the default threshold
    for _, output in ci.GITLAB_OUTPUTS:
        assert (repo / output).is_file(), output
    quality = json.loads((repo / "gl-code-quality-report.json").read_text(encoding="utf-8"))
    assert [issue["check_name"] for issue in quality] == ["SW-CFG-001"]
    assert json.loads((repo / "spellwarden.json").read_text(encoding="utf-8"))["exit_code"] == 1
    assert ci.run_gitlab({**VALID, "SW_TELEMETRY": "false", "SW_FAIL_ON": "never"}) == 0


def test_the_comment_needs_a_merge_request(tmp_path, monkeypatch, make_repo, capsys):
    repo = make_repo(tmp_path / "project", {"README.md": "nothing to scan\n"})
    monkeypatch.chdir(repo)
    assert ci.run_gitlab({**VALID, "SW_TELEMETRY": "false", "SW_COMMENT": "true", "GITLAB_CI": "true",
                          "CI_PIPELINE_SOURCE": "push"}) == 0
    assert "comment_no_request" in capsys.readouterr().err
