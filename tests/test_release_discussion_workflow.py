"""Community reports spec 11, claims W-1 to W-3: `.github/workflows/release-discussion.yml` has only the two token scopes the thread
needs, three triggers for one job, a fixed concurrency group, pinned actions and no event value interpolated into a shell script;
its version step and its posting step run here against a stand-in `gh`, offline; `release.yml` keeps its token scopes. `.github/`
is not in an sdist, so this file skips there."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
if not WORKFLOWS.is_dir():
    pytest.skip(".github/ is not in an sdist", allow_module_level=True)

TEXT = (WORKFLOWS / "release-discussion.yml").read_text(encoding="utf-8")
WORKFLOW = yaml.safe_load(TEXT)
JOB = WORKFLOW["jobs"]["thread"]
TRIGGERS = WORKFLOW.get("on", WORKFLOW.get(True))  # PyYAML reads the key `on` as the boolean True
BASH = shutil.which("bash")
POSIX = os.name != "nt" and BASH is not None


def step(name_part: str) -> dict:
    return next(candidate for candidate in JOB["steps"] if name_part in candidate.get("name", ""))


# --- W-1: the shape of the workflow -----------------------------------------------------------------------------------------------

def test_w1_the_workflow_and_the_job_have_exactly_contents_read_and_discussions_write():
    assert WORKFLOW["permissions"] == {"contents": "read", "discussions": "write"}
    assert JOB["permissions"] == {"contents": "read", "discussions": "write"}
    assert list(WORKFLOW["jobs"]) == ["thread"]


def test_w1_three_triggers_feed_the_one_job():
    assert set(TRIGGERS) == {"release", "workflow_run", "workflow_dispatch"}
    assert TRIGGERS["release"] == {"types": ["published"]}
    assert TRIGGERS["workflow_run"] == {"workflows": ["release"], "types": ["completed"]}
    version = TRIGGERS["workflow_dispatch"]["inputs"]["version"]
    assert version["required"] is True and version["type"] == "string"


def test_w1_one_fixed_concurrency_group_that_never_cancels():
    assert WORKFLOW["concurrency"] == {"group": "release-discussion", "cancel-in-progress": False}
    assert "concurrency" not in JOB


def test_w1_every_action_is_pinned_to_a_commit_with_a_version_comment_and_no_runner_is_macos():
    uses = [line for line in TEXT.splitlines() if line.strip().startswith(("- uses:", "uses:"))]
    assert uses
    for line in uses:
        assert re.search(r"uses: [\w./-]+@[0-9a-f]{40}  # v\d+\.\d+\.\d+$", line), line
    assert "macos" not in TEXT.lower() and JOB["runs-on"] == "ubuntu-latest"


def test_w1_no_expression_is_interpolated_into_a_shell_script_and_the_values_pass_through_env():
    for candidate in JOB["steps"]:
        assert "${{" not in candidate.get("run", ""), candidate.get("name")
    assert {"EVENT", "RELEASE_TAG", "RUN_BRANCH", "INPUT_VERSION", "REPOSITORY", "GH_TOKEN"} <= set(JOB["env"])
    assert JOB["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert re.findall(r"secrets\.", TEXT) == []


def test_w1_the_default_branch_is_checked_out_without_persisting_credentials():
    checkout = next(candidate for candidate in JOB["steps"] if str(candidate.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"] == {"ref": "${{ github.event.repository.default_branch }}", "persist-credentials": False}


def test_w1_the_graphql_call_passes_the_body_as_a_variable_and_searches_for_the_title_before_it_creates():
    run = step("Post the thread")["run"]
    assert "createDiscussion" in run and '-F body=@"$RUNNER_TEMP/body.md"' in run and "$body: String!" in run
    assert "body: $body" in run and "$RUNNER_TEMP/body.md" not in run.split("mutation(")[1]
    # r0:F3: the existing thread is found by listing the category's threads, every page, and comparing titles exactly; a ranked
    # search could leave it out once many threads share the title's words, and a second thread would be created
    assert "search(" not in run and "--paginate" in run
    assert "discussions(categoryId: $category, first: 100, after: $endCursor)" in run and "pageInfo { hasNextPage endCursor }" in run
    assert run.index("discussions(categoryId") < run.index("createDiscussion") and "jq -r -s --arg title" in run
    assert 'select(.name == "Announcements")' in run and "select(.title == $title)" in run
    assert "hasDiscussionsEnabled" in run
    # CI's actionlint job runs shellcheck on every `run:` script and fails on any finding, info included (release.yml:616
    # disables SC2016 for the same reason): the GraphQL text is single-quoted on purpose.
    lines = run.splitlines()
    graphql = [index for index, line in enumerate(lines) if "gh api graphql" in line]
    assert len(graphql) == 3 and all(lines[index - 1].strip().startswith("# shellcheck disable=SC2016") for index in graphql)


# --- W-2: the version step ------------------------------------------------------------------------------------------------------

def test_w2_a_run_of_the_release_workflow_that_did_not_succeed_makes_no_thread():
    assert JOB["if"] == "github.event_name != 'workflow_run' || github.event.workflow_run.conclusion == 'success'"


def resolve(tmp_path: Path, **environment: str) -> tuple[int, dict[str, str], str]:
    output = tmp_path / "output.txt"
    output.write_text("", encoding="utf-8")
    env = {"PATH": os.environ["PATH"], "GITHUB_OUTPUT": str(output), **environment}
    done = subprocess.run([BASH, "-c", step("Resolve the version")["run"]], env=env, capture_output=True, text=True, check=False)
    values = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    return done.returncode, values, done.stdout + done.stderr


@pytest.mark.skipif(not POSIX, reason="the step is a bash script: run where bash and POSIX paths are available")
def test_w2_the_version_comes_from_the_event_and_a_ref_that_is_not_a_release_tag_is_rejected(tmp_path):
    assert resolve(tmp_path, EVENT="release", RELEASE_TAG="v1.24.0")[:2] == (0, {"skip": "false", "version": "1.24.0"})
    assert resolve(tmp_path, EVENT="workflow_run", RUN_BRANCH="v2.0.10")[:2] == (0, {"skip": "false", "version": "2.0.10"})
    assert resolve(tmp_path, EVENT="workflow_dispatch", INPUT_VERSION="1.23.0")[:2] == (0, {"skip": "false", "version": "1.23.0"})
    code, values, text = resolve(tmp_path, EVENT="workflow_run", RUN_BRANCH="main")
    assert (code, values) == (0, {"skip": "true"}) and "not a release tag" in text
    assert resolve(tmp_path, EVENT="workflow_run", RUN_BRANCH="v1.2.3-rc1")[:2] == (0, {"skip": "true"})
    for environment in ({"EVENT": "release", "RELEASE_TAG": "latest"}, {"EVENT": "workflow_dispatch", "INPUT_VERSION": "v1.23.0"},
                        {"EVENT": "workflow_dispatch", "INPUT_VERSION": "1.23"}, {"EVENT": "workflow_dispatch", "INPUT_VERSION": "1.2.3; id"},
                        {"EVENT": "push"}):
        code, values, text = resolve(tmp_path, **environment)
        assert code == 1 and values == {} and "::error::" in text, environment


# --- the posting step, against a stand-in for gh --------------------------------------------------------------------------------

FAKE_GH = """#!/bin/sh
printf '%s\\n' "$(printf '%s' "$*" | tr '\\n' ' ')" >> "$FAKE_DIR/calls.log"
for argument in "$@"; do
  case "$argument" in body=@*) cp "${argument#body=@}" "$FAKE_DIR/posted-body.md" ;; esac
done
case "$*" in
  *createDiscussion*) printf '%s\\n' "https://example.test/discussions/7" ;;
  *"discussions(categoryId"*) case "$*" in *--paginate*) cat "$FAKE_DIR/pages.json" ;; *) exit 1 ;; esac ;;
  *discussionCategories*) cat "$FAKE_DIR/repository.json" ;;
  *) echo "unexpected call" >&2; exit 1 ;;
esac
"""
CATEGORIES = [{"id": "C_1", "name": "General"}, {"id": "C_2", "name": "Announcements"}]


def post(tmp_path: Path, *, enabled: bool = True, categories=CATEGORIES, found=()) -> tuple[int, str, list[str], Path]:
    fake_dir, bin_dir = tmp_path / "fake", tmp_path / "bin"
    fake_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    (fake_dir / "calls.log").write_text("", encoding="utf-8")
    (fake_dir / "repository.json").write_text(json.dumps({"data": {"repository": {
        "id": "R_1", "hasDiscussionsEnabled": enabled, "discussionCategories": {"nodes": categories}}}}), encoding="utf-8")
    # gh --paginate prints one JSON document per page; the first page holds only the first thread, so a title on a later page is
    # found only when every page is read (r0:F3)
    found = list(found)
    pages = [found[:1], found[1:]] if found else [[]]
    (fake_dir / "pages.json").write_text("".join(json.dumps({"data": {"repository": {"discussions": {
        "nodes": page, "pageInfo": {"hasNextPage": index + 1 < len(pages), "endCursor": f"c{index}"}}}}}) + "\n"
        for index, page in enumerate(pages)), encoding="utf-8")
    gh = bin_dir / "gh"
    gh.write_text(FAKE_GH, encoding="utf-8")
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    temp = tmp_path / "runner-temp"
    temp.mkdir(parents=True, exist_ok=True)
    (temp / "title.txt").write_text("Release 1.23.0: what changed in the rules\n", encoding="utf-8")
    (temp / "body.md").write_text("The body, with `code` and $dollars and \"quotes\".\n", encoding="utf-8")
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_DIR": str(fake_dir), "RUNNER_TEMP": str(temp),
           "REPOSITORY": "spellwarden-ai/spellwarden", "GH_TOKEN": "not-a-token"}
    done = subprocess.run([BASH, "-c", step("Post the thread")["run"]], env=env, capture_output=True, text=True, check=False)
    calls = (fake_dir / "calls.log").read_text(encoding="utf-8").split("\n")
    return done.returncode, done.stdout + done.stderr, calls, fake_dir


needs_tools = pytest.mark.skipif(not POSIX or shutil.which("jq") is None, reason="the step needs bash and jq")


@needs_tools
def test_the_thread_is_created_in_announcements_with_the_body_from_the_file_when_none_exists(tmp_path):
    code, out, calls, fake_dir = post(tmp_path)
    assert code == 0 and out.strip() == "https://example.test/discussions/7"
    create = [call for call in calls if "createDiscussion" in call]
    assert len(create) == 1
    assert "repo=R_1" in create[0] and "category=C_2" in create[0] and "title=Release 1.23.0: what changed in the rules" in create[0]
    assert "body=@" in create[0] and "$dollars" not in create[0] and "The body" not in create[0]
    assert (fake_dir / "posted-body.md").read_text(encoding="utf-8") == "The body, with `code` and $dollars and \"quotes\".\n"


@needs_tools
def test_a_thread_of_that_exact_title_is_left_alone(tmp_path):
    other = {"title": "Release 1.23.0: what changed in the rules and more", "url": "https://example.test/discussions/3"}
    same = {"title": "Release 1.23.0: what changed in the rules", "url": "https://example.test/discussions/5"}
    code, out, calls, _fake = post(tmp_path / "a", found=[other, same, same])
    assert code == 0 and out.strip() == "the thread exists: https://example.test/discussions/5"
    assert not [call for call in calls if "createDiscussion" in call]
    code, out, calls, _fake = post(tmp_path / "b", found=[other])
    assert code == 0 and [call for call in calls if "createDiscussion" in call]


@needs_tools
def test_a_missing_category_or_discussions_turned_off_is_a_named_error_and_posts_nothing(tmp_path):
    code, out, calls, _fake = post(tmp_path / "a", categories=[{"id": "C_1", "name": "General"}])
    assert code == 1 and "the discussion category Announcements does not exist" in out
    assert not [call for call in calls if "createDiscussion" in call or "discussions(categoryId" in call]
    code, out, calls, _fake = post(tmp_path / "b", enabled=False)
    assert code == 1 and "Discussions is not turned on for spellwarden-ai/spellwarden" in out
    assert not [call for call in calls if "createDiscussion" in call]


# --- W-3: the release job and its token stay as they are ------------------------------------------------------------------------

def test_w3_release_yml_keeps_its_token_scopes():
    release = yaml.safe_load((WORKFLOWS / "release.yml").read_text(encoding="utf-8"))
    assert release["permissions"] == {"contents": "read"}
    assert release["jobs"]["github-release"]["permissions"] == {"contents": "write"}
    for name, job in release["jobs"].items():
        assert "discussions" not in job.get("permissions", {}), name
    assert "discussions" not in (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert not [name for name in release["jobs"] if "discussion" in name]
