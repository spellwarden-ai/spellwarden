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

    def scan(_argv, **_kwargs):
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
    monkeypatch.setattr(cli, "main", lambda argv, **_kwargs: (seen.append((argv, os.environ.get("SPELLWARDEN_ORG"))), 0)[1])
    assert ci.run_gitlab({**VALID, "SW_ORG": "acme", "SW_UPLOAD": "false"}) == 0
    assert len(seen) == 1 and seen[0][1] == "acme" and "--no-upload" in seen[0][0]
    seen.clear()
    del os.environ["SPELLWARDEN_ORG"]
    assert ci.run_gitlab(VALID) == 0 and seen[0][1] is None  # an empty org sets nothing
    assert ci.run_gitlab({**VALID, "SW_ORG": "Not Valid"}) == 2 and len(seen) == 1  # a problem stops the job before the scan


# --- 1.17.0: the inputs analyze, model-endpoint and model; the key from SPELLWARDEN_MODEL_KEY only --------------------

CANARY = "SWcanaryKey0123456789abcdefXYZ"
ENDPOINT = "https://llm.example.com/v1"
ANALYZE = {**VALID, "SW_TELEMETRY": "false", "SW_ANALYZE": "true", "SW_MODEL_ENDPOINT": ENDPOINT, "SW_MODEL": "gpt-test",
           "SPELLWARDEN_MODEL_KEY": CANARY}
PUSH = {"GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "push", "CI_PROJECT_ID": "42"}
FORK_MR = {**MR, "CI_MERGE_REQUEST_SOURCE_PROJECT_ID": "77", "CI_MERGE_REQUEST_PROJECT_ID": "42"}
NO_KEY = ("input analyze is true, but SPELLWARDEN_MODEL_KEY is not set: add the key as a masked CI/CD variable "
          "SPELLWARDEN_MODEL_KEY (Settings, CI/CD, Variables); no input takes the key")
NOT_ACCEPTED = ("input model-endpoint is not accepted and is not shown: it holds a user name, password, query or fragment, "
                "any of which could carry a key; give the https:// address alone and the key as SPELLWARDEN_MODEL_KEY")
TODAYS_VALID_ARGV = ["scan", ".", "--fail-on", "high", "--no-probe", "--no-probe-private",
                     "--format", "gitlab-codequality", "--output", "gl-code-quality-report.json",
                     "--format", "sarif", "--output", "spellwarden.sarif", "--format", "markdown", "--output", "spellwarden.md",
                     "--format", "json", "--output", "spellwarden.json", "--format", "text"]


def _without_key(env: dict) -> dict:
    return {name: value for name, value in env.items() if name != "SPELLWARDEN_MODEL_KEY"}


def _scans(monkeypatch) -> list:
    """Replace the scan with one that records its arguments and keyword arguments and returns 0."""
    from spellwarden_cli import main as cli

    seen: list = []
    monkeypatch.setattr(cli, "main", lambda argv, **kwargs: (seen.append((argv, kwargs)), 0)[1])
    return seen


@pytest.mark.parametrize("case", [
    VALID, {**VALID, "SW_PROBE": "true", "SW_PROBE_PRIVATE": "true", "SW_TELEMETRY": "false", "SW_LOCKED": "true",
            "SW_COMMENT": "true"},
    {**VALID, "SW_LOCKED": "false"}, {**VALID, "SW_ORG": "acme"}, {**VALID, "SW_UPLOAD": "true"},
    {**VALID, "SW_UPLOAD": "false"}, {**VALID, "SW_FAIL_ON": "never", "SW_PATH": "sub"}, {**VALID, **FORK_MR}])
@pytest.mark.parametrize("off", [{}, {"SW_ANALYZE": "false"}, {"SW_ANALYZE": ""}])
def test_analyze_off_or_unset_leaves_the_arguments_as_they_were(case, off, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = ci.gitlab_argv(case)
    leftovers = {"SW_MODEL_ENDPOINT": "https://user:pw@x?key=1 bad", "SW_MODEL": "a b", "SPELLWARDEN_MODEL_KEY": CANARY}
    notices: list = []
    assert ci.gitlab_argv({**case, **off, **leftovers}, notices) == before and notices == []
    assert ci.gitlab_argv({**case, **off}) == before
    assert "--analyze" not in before[0] and CANARY not in before[0]


def test_todays_arguments_are_pinned(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert ci.gitlab_argv(VALID) == (TODAYS_VALID_ARGV, [], False, {})
    assert ci.gitlab_argv({**VALID, "SW_ANALYZE": "false"}) == (TODAYS_VALID_ARGV, [], False, {})


@pytest.mark.parametrize("value", ["yes", "TRUE", "True", "1", " true", "true\n", "on", "\x1b[31mtrue"])
def test_analyze_is_true_or_false(value, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = _scans(monkeypatch)
    problems = ci.gitlab_argv({**ANALYZE, "SW_ANALYZE": value})[1]
    assert problems == [f"input analyze: {ci.escape.terminal(value)!r} is not one of true, false"]
    assert ci.run_gitlab({**ANALYZE, "SW_ANALYZE": value}) == 2 and seen == []
    err = capsys.readouterr().err
    assert "spellwarden: error: input analyze: " in err and "\x1b" not in err


def test_analyze_true_adds_the_three_flags_and_never_the_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for pipeline in ({}, PUSH, MR, FORK_MR):
        notices: list = []
        argv, problems, _, _ = ci.gitlab_argv({**ANALYZE, **pipeline}, notices)
        assert problems == [] and notices == []
        start = argv.index("--analyze")
        assert argv[start:start + 5] == ["--analyze", "--model-endpoint", ENDPOINT, "--model", "gpt-test"]
        assert start < argv.index("--format") and argv.count("--analyze") == 1
        assert not any(CANARY in token for token in argv)
    # with the upload flag, the analyzer's come after it, before the output flags
    argv = ci.gitlab_argv({**ANALYZE, "SW_UPLOAD": "false"})[0]
    assert argv.index("--no-upload") < argv.index("--analyze") < argv.index("--format")
    assert argv[:argv.index("--analyze")] + argv[argv.index("--analyze") + 5:] == \
        ci.gitlab_argv({**VALID, "SW_TELEMETRY": "false", "SW_UPLOAD": "false"})[0]


def test_the_key_reaches_neither_the_arguments_nor_any_output(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SPELLWARDEN_MODEL_KEY", CANARY)
    seen = _scans(monkeypatch)
    assert ci.run_gitlab({**ANALYZE, **PUSH}) == 0
    (argv, kwargs), = seen
    assert "--analyze" in argv and not any(CANARY in token for token in argv) and CANARY not in repr(kwargs)
    out, err = capsys.readouterr()
    assert CANARY not in out and CANARY not in err


@pytest.mark.parametrize(("changes", "message"), [
    ({"SW_MODEL_ENDPOINT": ""}, "input analyze is true, but model-endpoint is empty: set it to the https:// address of your "
                                "OpenAI-compatible endpoint"),
    ({"SW_MODEL_ENDPOINT": "http://llm.example.com/v1"},
     "input model-endpoint: 'http://llm.example.com/v1' is not an https:// address without spaces or line breaks"),
    ({"SW_MODEL_ENDPOINT": "https://llm.example.com/v 1"},
     "input model-endpoint: 'https://llm.example.com/v 1' is not an https:// address without spaces or line breaks"),
    ({"SW_MODEL_ENDPOINT": "https://llm.example.com/v1\n"},
     "input model-endpoint: 'https://llm.example.com/v1\\\\n' is not an https:// address without spaces or line breaks"),
    ({"SW_MODEL_ENDPOINT": "https://"}, "input model-endpoint: 'https://' is not an https:// address without spaces or "
                                        "line breaks"),
    ({"SW_MODEL_ENDPOINT": "https://llm.example.com:99999/v1"},
     "input model-endpoint: 'https://llm.example.com:99999/v1' is not an https:// address without spaces or line breaks"),
    ({"SW_MODEL_ENDPOINT": "llm.example.com/v1"},
     "input model-endpoint: 'llm.example.com/v1' is not an https:// address without spaces or line breaks"),
    ({"SW_MODEL": ""}, "input analyze is true, but model is empty: set it to the model name your endpoint expects"),
    ({"SW_MODEL": "gpt test"}, "input model: 'gpt test' holds a space or a line break"),
    ({"SW_MODEL": "gpt-test\n"}, "input model: 'gpt-test\\\\n' holds a space or a line break"),
    ({"SW_MODEL": "gpt\ttest"}, "input model: 'gpt\\\\ttest' holds a space or a line break"),
])
def test_each_analyze_input_problem_is_a_usage_error(changes, message, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SPELLWARDEN_MODEL_KEY", CANARY)
    seen = _scans(monkeypatch)
    for pipeline in (PUSH, FORK_MR):  # an input is not a secret: a fork gets it too, so it fails there as well
        env = {**ANALYZE, **pipeline, **changes}
        assert ci.gitlab_argv(env)[1] == [message]
        assert ci.run_gitlab(env) == 2 and seen == []
        err = capsys.readouterr().err
        assert f"spellwarden: error: {message}\n" in err and CANARY not in err
        assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("pipeline", [{}, PUSH, MR, {**MR, "CI_MERGE_REQUEST_PROJECT_ID": "42"},
                                      {"CI": "true", "CI_PIPELINE_SOURCE": "merge_request_event"}])
def test_a_missing_key_is_a_usage_error_except_on_a_fork(pipeline, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = _scans(monkeypatch)
    for key in ({}, {"SPELLWARDEN_MODEL_KEY": ""}):
        env = {**_without_key(ANALYZE), **pipeline, **key}
        notices: list = []
        assert ci.gitlab_argv(env, notices)[1] == [NO_KEY] and notices == []
        assert ci.run_gitlab(env) == 2 and seen == []
        assert f"spellwarden: error: {NO_KEY}\n" in capsys.readouterr().err


def test_every_problem_is_listed_together():
    problems = ci.gitlab_argv({**_without_key(ANALYZE), **PUSH, "SW_MODEL_ENDPOINT": "", "SW_MODEL": "", "SW_PROBE": "x"})[1]
    assert [problem.split(":")[0] for problem in problems] == [
        "input probe", "input analyze is true, but model-endpoint is empty", "input analyze is true, but model is empty",
        "input analyze is true, but SPELLWARDEN_MODEL_KEY is not set"]


@pytest.mark.parametrize("endpoint", [
    f"https://user:{CANARY}@llm.example.com/v1", f"https://{CANARY}@llm.example.com/v1",
    f"https://llm.example.com/v1?key={CANARY}", f"https://llm.example.com/v1?api-key={CANARY}&x=1",
    f"https://llm.example.com/v1#{CANARY}", f"https://user:{CANARY}@llm.example.com/v 1",
    f"https://llm.example.com/v1 ?key={CANARY}", f"http://user:{CANARY}@llm.example.com/v1",
    f"https://user:{CANARY}@llm.example.com:99999/v1", f"llm.example.com/v1?key={CANARY}"])
def test_an_endpoint_that_could_carry_a_key_is_refused_without_being_shown(endpoint, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SPELLWARDEN_MODEL_KEY", CANARY)
    seen = _scans(monkeypatch)
    for pipeline in (PUSH, FORK_MR):
        env = {**ANALYZE, **pipeline, "SW_MODEL_ENDPOINT": endpoint}
        assert ci.gitlab_argv(env)[1] == [NOT_ACCEPTED]
        assert ci.run_gitlab(env) == 2 and seen == []
        out, err = capsys.readouterr()
        assert f"spellwarden: error: {NOT_ACCEPTED}\n" in err and CANARY not in err and CANARY not in out


def test_a_quoted_input_is_masked_and_escaped():
    endpoint = "https://llm.example.com/v1 Bearer abcdefghijklmnop1234"
    problems = ci.gitlab_argv({**ANALYZE, **PUSH, "SW_MODEL_ENDPOINT": endpoint, "SW_MODEL": "m \x1b[31m"})[1]
    assert "abcdefghijklmnop1234" not in problems[0] and "Bearer ***" in problems[0]
    assert "\x1b" not in problems[1] and "\\x1b" in problems[1]


def test_a_fork_without_the_key_scans_without_the_analyzer_and_says_so(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = _scans(monkeypatch)
    for fork in (FORK_MR, {**MR, "CI_MERGE_REQUEST_SOURCE_PROJECT_ID": "77"},  # as `ci.detect` judges a fork
                 {"GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "external_pull_request_event", "CI_PROJECT_ID": "42"}):
        notices: list = []
        argv, problems, _, _ = ci.gitlab_argv({**_without_key(ANALYZE), **fork}, notices)
        assert problems == [] and "--analyze" not in argv and "--model-endpoint" not in argv
        assert argv == ci.gitlab_argv({**VALID, "SW_TELEMETRY": "false"})[0]
        assert [notice.code for notice in notices] == ["analyzer_no_key"] and notices[0].path == ""
        assert ci.run_gitlab({**_without_key(ANALYZE), **fork}) == 0
        assert seen[-1] == (argv, {"notices": tuple(notices)})


def test_the_fork_notice_is_in_the_report_and_the_job_log(tmp_path, monkeypatch, make_repo, capsys):
    from spellwarden_cli.report import NOTICE_CODES

    repo = make_repo(tmp_path / "project", {"README.md": "nothing to scan\n"})
    monkeypatch.chdir(repo)
    monkeypatch.delenv("SPELLWARDEN_MODEL_KEY", raising=False)
    assert ci.run_gitlab({**_without_key(ANALYZE), **FORK_MR}) == 0
    report = json.loads((repo / "spellwarden.json").read_text(encoding="utf-8"))
    (notice,) = [notice for notice in report["notices"] if notice["code"] == "analyzer_no_key"]
    message = ("The model-assisted analyzer did not run (analyzer_no_key): a merge request from a fork gets no masked "
               "CI/CD variables, so SPELLWARDEN_MODEL_KEY is not set. This run applied the rules only; the analyzer's "
               "verdicts never change the exit code.")
    assert notice == {"code": "analyzer_no_key", "path": "", "message": message}
    assert "analysis" not in report or not report["analysis"]
    assert f"notice analyzer_no_key : {message}" in capsys.readouterr().out
    assert "analyzer_no_key" in NOTICE_CODES


def test_a_fork_with_the_key_runs_the_analyzer(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = _scans(monkeypatch)
    assert ci.run_gitlab({**ANALYZE, **FORK_MR}) == 0
    (argv, kwargs), = seen
    assert "--analyze" in argv and kwargs == {"notices": ()}


def test_the_scan_carries_the_notices_it_is_given(tmp_path, monkeypatch, make_repo):
    from spellwarden_cli import main as cli
    from spellwarden_cli.report import Notice

    repo = make_repo(tmp_path / "project", {"README.md": "nothing to scan\n"})
    monkeypatch.chdir(repo)
    given = Notice("analyzer_no_key", "", "said")
    assert cli.main(["scan", ".", "--no-telemetry", "--format", "json", "--output", "out.json"], notices=(given,)) == 0
    assert {"code": "analyzer_no_key", "path": "", "message": "said"} in \
        json.loads((repo / "out.json").read_text(encoding="utf-8"))["notices"]
    assert cli.main(["scan", ".", "--no-telemetry", "--format", "json", "--output", "out.json"]) == 0
    assert "analyzer_no_key" not in (repo / "out.json").read_text(encoding="utf-8")
