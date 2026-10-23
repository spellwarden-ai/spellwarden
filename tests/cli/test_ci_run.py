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
    argv, problems, comment, updates = ci.gitlab_argv(VALID)
    assert problems == [] and comment is False and updates == {}
    assert argv[:4] == ["scan", ".", "--fail-on", "high"]
    assert "--no-probe" in argv and "--no-probe-private" in argv and "--locked" not in argv and "--no-telemetry" not in argv
    pairs = [(argv[i + 1], argv[i + 3]) for i, token in enumerate(argv[:-3]) if token == "--format" and argv[i + 2] == "--output"]
    assert pairs == list(ci.GITLAB_OUTPUTS) and argv[-2:] == ["--format", "text"]
    flipped, _, comment, _ = ci.gitlab_argv({**VALID, "SW_PROBE": "true", "SW_PROBE_PRIVATE": "true", "SW_TELEMETRY": "false",
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


# --- The comment posts only the report this job wrote (spec 10.2a, 6.13) ----------------------------------------

MR = {"GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "merge_request_event", "CI_MERGE_REQUEST_IID": "5",
      "CI_MERGE_REQUEST_SOURCE_PROJECT_ID": "42", "CI_PROJECT_ID": "42"}
COMMENTING = {**VALID, "SW_TELEMETRY": "false", "SW_COMMENT": "true", **MR}


@pytest.fixture
def posted(monkeypatch):
    from spellwarden_cli import forge

    bodies: list[str] = []
    monkeypatch.setattr(forge, "post_comment", lambda _provider, body, **_kwargs: bodies.append(body))
    return bodies


def _fake_scan(monkeypatch, code: int, then=None):
    """Replace the scan with one that writes no output (as a scan that stops before writing would) and returns
    `code`; `then` runs in its place, after the job removed the reserved output names."""
    from spellwarden_cli import main as cli

    def scan(_argv):
        if then is not None:
            then()
        return code

    monkeypatch.setattr(cli, "main", scan)


def test_the_normal_path_posts_the_report_the_scan_wrote(tmp_path, monkeypatch, make_repo, posted):
    repo = make_repo(tmp_path / "project", {"README.md": "nothing to scan\n"})
    monkeypatch.chdir(repo)
    assert ci.run_gitlab(COMMENTING) == 0
    assert len(posted) == 1 and posted[0].startswith("<!-- spellwarden-scan -->") and "PLANTED" not in posted[0]


def test_a_committed_report_is_never_posted_when_the_scan_exits_2(tmp_path, monkeypatch, make_repo, posted, capsys):
    repo = make_repo(tmp_path / "project", {"spellwarden.md": "<!-- spellwarden-scan -->\nPLANTED\n",
                                            ".spellwarden/config.yml": "no-such-key: 1\n"})  # D11: exit 2
    monkeypatch.chdir(repo)
    assert ci.run_gitlab(COMMENTING) == 2
    assert posted == [] and "comment_failed" in capsys.readouterr().err


def test_a_planted_report_is_removed_before_a_scan_that_writes_nothing(tmp_path, monkeypatch, posted, capsys):
    monkeypatch.chdir(tmp_path)
    for code in (0, 2):
        for _, output in ci.GITLAB_OUTPUTS:
            (tmp_path / output).write_text("<!-- spellwarden-scan -->\nPLANTED\n", encoding="utf-8")
        _fake_scan(monkeypatch, code)
        assert ci.run_gitlab(COMMENTING) == code
        assert posted == [] and "comment_failed" in capsys.readouterr().err
        assert [output for _, output in ci.GITLAB_OUTPUTS if (tmp_path / output).exists()] == []


def test_a_planted_symlink_is_never_read(tmp_path, monkeypatch, posted, capsys):
    secret = tmp_path / "environ"
    secret.write_text("<!-- spellwarden-scan -->\nCI_JOB_TOKEN=secret\n", encoding="utf-8")
    job = tmp_path / "job"
    job.mkdir()
    try:
        (job / "spellwarden.md").symlink_to(secret)
    except OSError:
        pytest.skip("symbolic links cannot be created here")
    monkeypatch.chdir(job)
    _fake_scan(monkeypatch, 0)
    assert ci.run_gitlab(COMMENTING) == 0
    assert posted == [] and not (job / "spellwarden.md").is_symlink() and secret.is_file()
    # A link that appears after the job removed the reserved names is refused when the report is read.
    _fake_scan(monkeypatch, 0, then=lambda: (job / "spellwarden.md").symlink_to(secret))
    assert ci.run_gitlab(COMMENTING) == 0
    assert posted == [] and "comment_failed" in capsys.readouterr().err


def test_a_reserved_name_that_cannot_be_removed_stops_the_job(tmp_path, monkeypatch, posted, capsys):
    (tmp_path / "spellwarden.md").mkdir()
    monkeypatch.chdir(tmp_path)
    assert ci.run_gitlab(COMMENTING) == 2
    assert posted == [] and "spellwarden.md" in capsys.readouterr().err


# --- O3 spec 11, P12, claim E12: SW_ORG and SW_UPLOAD ------------------------------------------------------------

def test_gitlab_argv_maps_sw_org_and_sw_upload():
    argv, problems, _, updates = ci.gitlab_argv({**VALID, "SW_ORG": "acme"})
    assert problems == [] and updates == {"SPELLWARDEN_ORG": "acme"}
    assert "--upload" not in argv and "--no-upload" not in argv  # an empty or absent SW_UPLOAD adds no flag
    assert ci.gitlab_argv({**VALID, "SW_ORG": ""})[3] == {} and ci.gitlab_argv({**VALID, "SW_ORG": "  "})[3] == {}
    off = ci.gitlab_argv({**VALID, "SW_UPLOAD": "false"})[0]
    on = ci.gitlab_argv({**VALID, "SW_UPLOAD": "true"})[0]
    assert "--no-upload" in off and "--upload" not in off and "--upload" in on and "--no-upload" not in on
    assert on.index("--upload") < on.index("--format")  # before the output flags, like the other booleans
    assert "--upload" not in ci.gitlab_argv({**VALID, "SW_UPLOAD": ""})[0]


@pytest.mark.parametrize(("name", "value", "label"), [
    ("SW_ORG", "Acme", "org"), ("SW_ORG", "a", "org"), ("SW_ORG", "acme corp", "org"), ("SW_ORG", "a" * 65, "org"),
    ("SW_ORG", "acme\nSPELLWARDEN_API_KEY=x", "org"), ("SW_UPLOAD", "yes", "upload"), ("SW_UPLOAD", "1", "upload")])
def test_an_invalid_org_or_upload_is_a_problem_naming_the_input(name, value, label):
    argv, problems, _, updates = ci.gitlab_argv({**VALID, name: value})
    assert len(problems) == 1 and f"input {label}:" in problems[0] and updates == {}


def test_run_gitlab_applies_the_environment_updates_before_the_scan(tmp_path, monkeypatch):
    import os

    from spellwarden_cli import main as cli

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(os, "environ", dict(os.environ))
    os.environ.pop("SPELLWARDEN_ORG", None)
    seen: list = []
    monkeypatch.setattr(cli, "main", lambda argv: (seen.append((argv, os.environ.get("SPELLWARDEN_ORG"))), 0)[1])
    assert ci.run_gitlab({**VALID, "SW_ORG": "acme", "SW_UPLOAD": "false"}) == 0
    assert len(seen) == 1 and seen[0][1] == "acme" and "--no-upload" in seen[0][0]
    seen.clear()
    del os.environ["SPELLWARDEN_ORG"]
    assert ci.run_gitlab(VALID) == 0 and seen[0][1] is None  # an empty org sets nothing
    assert ci.run_gitlab({**VALID, "SW_ORG": "Not Valid"}) == 2 and len(seen) == 1  # a problem stops the job before the scan
