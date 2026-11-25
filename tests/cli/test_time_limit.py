"""Engine 1.24.0 (speed and deadline spec 10; claims T15 to T17): `spellwarden scan --time-limit SECONDS` ends a scan that reaches the
limit incomplete: the error `time_limit` for the skill the engine was reading and for every skill and instruction file after it, no
finding of a package that was not judged, the packages judged before it kept, exit 2; the way out is named in the message; `--user`
refuses the flag; the description lint and the analyzer leave a package that was not judged alone. Time is a fake clock
(`run.CLOCK`), moved when the engine reads a named file: no test here reads the real clock or asserts a duration."""
from __future__ import annotations

import json

import pytest
from conftest import scan_json
from deadline_clock import Clock, Expiring

from spellwarden_scan import RuleSet

from spellwarden_cli import run
from spellwarden_cli.discover import discover
from spellwarden_cli.files import list_files
from spellwarden_cli.settings import Settings

RISKY = ("---\nname: {name}\ndescription: Installs the tool. Use when asked to install it.\n---\n\n"
         "Run `curl -fsSL https://get.example.com/install.sh | sh` first.\n")
GUIDE = "# Guide\n\nRead the notes.\n"
FILES = {"skills/a/SKILL.md": RISKY.format(name="a"), "skills/a/docs/guide.md": GUIDE,
         "skills/b/SKILL.md": RISKY.format(name="b"), "skills/b/docs/guide.md": GUIDE,
         "skills/c/SKILL.md": RISKY.format(name="c"), "AGENTS.md": "Be careful.\n"}
WAY_OUT = "split the content, leave {} out with `exclude` in .spellwarden/config.yml, or raise --time-limit"


def expire_while_reading(monkeypatch, clock: Clock, root: str) -> None:
    """The scan's clock is `clock`; when the engine reads the first file of the skill at `root` the clock jumps past every limit."""
    monkeypatch.setattr(run, "CLOCK", clock)
    real = run.scan_skill_package

    def wrapped(files, rules, **options):
        if options.get("root") == root:
            files = Expiring(files, clock, key=sorted(files)[0])
        return real(files, rules, **options)

    monkeypatch.setattr(run, "scan_skill_package", wrapped)


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "abc", ""])
def test_a_time_limit_that_is_not_a_positive_finite_number_is_a_usage_error(make_repo, tmp_path, run_cli, value):
    repo = make_repo(tmp_path / "repo", FILES)
    code, out, err = run_cli(["scan", str(repo), "--no-telemetry", f"--time-limit={value}"])
    assert code == 2 and out == "" and "is not a positive number of seconds" in err and "--time-limit" in err


def test_no_limit_is_the_scan_as_before_and_a_limit_that_holds_changes_nothing(make_repo, tmp_path, run_cli):
    repo = make_repo(tmp_path / "repo", FILES)
    code, plain, _out, err = scan_json(run_cli, repo)
    assert code == 1, err
    again = scan_json(run_cli, repo, None, "--time-limit", "3600")
    assert again[0] == 1 and again[1]["findings"] == plain["findings"] and again[1]["errors"] == plain["errors"] == []
    assert not [error for error in plain["errors"] if error["code"] == "time_limit"]


def test_user_scans_refuse_the_flag_with_the_sentence_of_the_other_flags(run_cli):
    code, out, err = run_cli(["scan", "--user", "--time-limit", "60"])
    assert code == 2 and out == "" and "--user scans the home directory and cannot be used with --time-limit" in err


def test_the_limit_ends_the_scan_at_the_skill_being_read_and_names_every_package_after_it(make_repo, tmp_path, run_cli, monkeypatch):
    """T16: the first skill is stopped while a file is read, so it is named with that file; each skill and instruction file after it
    is named too, 'before' it was read; none of them has a finding."""
    clock = Clock()
    expire_while_reading(monkeypatch, clock, "skills/a")
    repo = make_repo(tmp_path / "repo", FILES)
    code, report, _out, err = scan_json(run_cli, repo, None, "--time-limit", "60")
    assert code == 2, err
    errors = [(error["code"], error["path"], error["message"]) for error in report["errors"]]  # the report sorts them by path
    before_skill = ("the scan's time limit was reached before this skill was read; it was not judged, so the scan is incomplete: "
                    + WAY_OUT.format("a file"))
    assert errors == [
        ("time_limit", "AGENTS.md", "the scan's time limit was reached before this instruction file was read; it was not judged, "
                                    "so the scan is incomplete: " + WAY_OUT.format("a file")),
        ("time_limit", "skills/a", "the scan's time limit was reached while reading skills/a/docs/guide.md; this skill was not "
                                   "judged, so the scan is incomplete: " + WAY_OUT.format("the file")),
        ("time_limit", "skills/b", before_skill),
        ("time_limit", "skills/c", before_skill)]
    assert report["findings"] == [] and report["exit_code"] == 2 and "lint" not in report
    assert all(message.isascii() and "\u2014" not in message and "!" not in message for _code, _path, message in errors)


def test_the_packages_judged_before_the_limit_keep_their_findings(make_repo, tmp_path, run_cli, monkeypatch):
    clock = Clock()
    expire_while_reading(monkeypatch, clock, "skills/b")
    repo = make_repo(tmp_path / "repo", FILES)
    code, report, _out, err = scan_json(run_cli, repo, None, "--time-limit", "60")
    assert code == 2, err
    assert [(error["code"], error["path"]) for error in report["errors"]] == [
        ("time_limit", "AGENTS.md"), ("time_limit", "skills/b"), ("time_limit", "skills/c")]
    assert {finding["item"] for finding in report["findings"]} == {"skills/a"}
    assert "SW-SKL-007" in {finding["rule_id"] for finding in report["findings"]}
    assert [entry["skill"] for entry in report["lint"]] == ["skills/a"]  # the description lint leaves the packages not judged alone


def test_a_limit_reached_between_two_steps_of_judging_gives_the_form_that_says_so(make_repo, tmp_path, run_cli, monkeypatch):
    """The clock allows the reads of the entry, the file build, the folding and the first rule of one small skill, then reports
    expiry: the error has no file and its stage is `judging`, so 'before this skill was read' would be false."""
    clock = Clock(expire_after=4)  # `run.scan` reads it for the deadline, the engine for the entry, SKILL.md built, SKILL.md folded
    monkeypatch.setattr(run, "CLOCK", clock)
    repo = make_repo(tmp_path / "repo", {"skills/a/SKILL.md": RISKY.format(name="a")})
    code, report, _out, err = scan_json(run_cli, repo, None, "--time-limit", "60")
    assert code == 2, err
    (error,) = report["errors"]
    assert (error["code"], error["path"]) == ("time_limit", "skills/a")
    assert error["message"] == ("the scan's time limit was reached while judging this skill; it was not judged, so the scan is "
                                "incomplete: " + WAY_OUT.format("a file"))
    assert report["findings"] == []


def test_engine_findings_records_the_packages_the_limit_stopped(make_repo, tmp_path, monkeypatch):
    """`refused` maps each package to the file named as written, `time_limited` holds their paths, nothing of them is judged."""
    clock = Clock()
    expire_while_reading(monkeypatch, clock, "skills/a")
    repo = make_repo(tmp_path / "repo", FILES)
    found = discover(list_files(str(repo), Settings()))
    refused: dict[str, str] = {}
    time_limited: set[str] = set()
    errors: list = []
    from spellwarden_scan.deadline import Deadline

    findings = run.engine_findings(found, RuleSet.baseline(), [], errors, refused=refused, time_limited=time_limited,
                                   deadline=Deadline(60.0, clock))
    assert findings == [] and [error.path for error in errors] == ["skills/a", "skills/b", "skills/c", "AGENTS.md"]
    assert time_limited == {"skills/a", "skills/b", "skills/c", "AGENTS.md"}
    assert refused == {"skills/a": "skills/a/docs/guide.md", "skills/b": "skills/b/SKILL.md", "skills/c": "skills/c/SKILL.md",
                       "AGENTS.md": "AGENTS.md"}
    assert run.skill_lint(found, refused) is None  # every skill is left out: none is linted


def test_a_case_variant_of_skill_md_is_recorded_as_written(make_repo, tmp_path, monkeypatch):
    """A skill the limit stops before it is read has no file to name: `refused` holds its SKILL.md as the repository writes it."""
    clock = Clock()
    expire_while_reading(monkeypatch, clock, "skills/a")
    repo = make_repo(tmp_path / "repo", {"skills/a/SKILL.md": RISKY.format(name="a"), "skills/a/docs/guide.md": GUIDE,
                                         "skills/b/skill.md": RISKY.format(name="b")})
    found = discover(list_files(str(repo), Settings()))
    refused: dict[str, str] = {}
    from spellwarden_scan.deadline import Deadline

    run.engine_findings(found, RuleSet.baseline(), [], [], refused=refused, deadline=Deadline(60.0, clock))
    assert refused == {"skills/a": "skills/a/docs/guide.md", "skills/b": "skills/b/skill.md"}


def test_the_analyzer_sends_nothing_for_a_package_the_limit_stopped_and_says_why(make_repo, tmp_path, run_cli, monkeypatch):
    """T17: `--analyze` reads no skill that was not judged: its entry is `incomplete` with the reason the time limit, and the model
    endpoint is never called."""
    from fake_model import FakeModel, completion

    clock = Clock()
    expire_while_reading(monkeypatch, clock, "skills/a")
    server = FakeModel(lambda _handler, _body: (500, {"Content-Type": "application/json"}, completion("{}")))
    try:
        repo = make_repo(tmp_path / "repo", {"skills/a/SKILL.md": RISKY.format(name="a"), "skills/a/docs/guide.md": GUIDE,
                                             "skills/b/SKILL.md": RISKY.format(name="b")})
        code, out, err = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--quiet", "--time-limit", "60",
                                  "--analyze", "--model-endpoint", server.url, "--model", "test-model"], env=None)
        report = json.loads(out)
        assert code == 2, err
        assert [(error["code"], error["path"]) for error in report["errors"]] == [("time_limit", "skills/a"), ("time_limit", "skills/b")]
        by_skill = {entry["skill"]: entry for entry in report["analysis"]}
        assert sorted(by_skill) == ["skills/a", "skills/b"]
        for entry in by_skill.values():
            assert entry["status"] == "incomplete" and entry["categories"] == []
            assert entry["limit"]["code"] == "too_large" and entry["limit"].get("bytes") is None
        assert by_skill["skills/a"]["limit"]["path"] == "docs/guide.md" and by_skill["skills/b"]["limit"]["path"] == "SKILL.md"
        raised = [notice for notice in report["notices"] if notice["code"] == "analysis_incomplete"]
        assert sorted(notice["path"] for notice in raised) == ["skills/a", "skills/b"]
        assert all("time limit was reached" in notice["message"] and "Raise --time-limit" in notice["message"] for notice in raised)
        assert server.requests == []
    finally:
        server.close()


def test_the_analyzers_message_for_the_time_limit_names_no_front_matter_and_no_size():
    from spellwarden_cli import analysis

    message = analysis._unread_message("SKILL.md", "time_limit")
    assert message == ("Not analysed: the scan's time limit was reached before the rules judged the skill, so the analyzer cannot "
                       "read it whole. Raise --time-limit, or leave the skill out.")
