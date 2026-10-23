"""Spec 6.11, 6.8 and 6.10, claims C14 (the trust rule) and C15 (the identity vectors): CI detection from the
environment and the event file, the trust rule for private probing, and the pseudonymous installation identity."""
from __future__ import annotations

import json
import os

import pytest

from spellwarden_cli import ci

EVENT = "/runner/event.json"


def github(event: str, *, payload: dict | None = None, protected: str = "false", **more: str):
    env = {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": event, "GITHUB_EVENT_PATH": EVENT,
           "GITHUB_REPOSITORY": "acme/agents", "GITHUB_REF_PROTECTED": protected, "GITHUB_SERVER_URL": "https://github.com",
           "GITHUB_REPOSITORY_OWNER_ID": "1234567", "GITHUB_ACTOR": "octo", **more}
    text = json.dumps(payload if payload is not None else {})
    return ci.detect(env, read_text=lambda path: text if path == EVENT else (_ for _ in ()).throw(OSError(path)))


def pull(head: str = "acme/agents", number: int = 7) -> dict:
    return {"pull_request": {"number": number, "head": {"repo": {"full_name": head}}}}


def gitlab(source: str, *, protected: str = "false", **more: str):
    env = {"CI": "true", "GITLAB_CI": "true", "CI_PIPELINE_SOURCE": source, "CI_PROJECT_ID": "42",
           "CI_COMMIT_REF_PROTECTED": protected, "CI_SERVER_HOST": "gitlab.com", "CI_PROJECT_ROOT_NAMESPACE": "acme", **more}
    return ci.detect(env)


def test_a_local_run_is_no_ci():
    assert ci.detect({}) == ci.LOCAL and ci.detect({"CI": "false"}).provider is None


def test_a_github_pull_request_reads_the_event_file():
    ctx = github("pull_request", payload=pull())
    assert (ctx.provider, ctx.event, ctx.is_request, ctx.request_number, ctx.fork, ctx.dependabot) == (
        "github", "pull_request", True, 7, False, False)
    assert ctx.identity == "github:github.com:1234567"
    assert github("pull_request", payload=pull(head="mallory/agents")).fork is True


def test_an_unreadable_event_file_is_a_pull_request_from_a_fork():
    env = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": EVENT, "GITHUB_REF_PROTECTED": "true"}
    for read in (lambda _path: (_ for _ in ()).throw(OSError("gone")), lambda _path: "{not json"):
        ctx = ci.detect(env, read_text=read)
        assert ctx.is_request and ctx.fork and not ci.private_probe_trusted(ctx)


def test_dependabot_is_recognised():
    assert github("pull_request", payload=pull(), GITHUB_ACTOR="dependabot[bot]").dependabot is True


def test_a_gitlab_merge_request():
    ctx = gitlab("merge_request_event", CI_MERGE_REQUEST_IID="5", CI_MERGE_REQUEST_SOURCE_PROJECT_ID="42")
    assert (ctx.provider, ctx.is_request, ctx.request_number, ctx.fork) == ("gitlab", True, 5, False)
    assert gitlab("merge_request_event", CI_MERGE_REQUEST_IID="5", CI_MERGE_REQUEST_SOURCE_PROJECT_ID="99").fork is True
    assert ctx.identity == "gitlab:gitlab.com:acme"


@pytest.mark.parametrize("ctx", [
    pytest.param(lambda: github("pull_request", payload=pull(), protected="true"), id="github same-repository pull request"),
    pytest.param(lambda: github("pull_request", payload=pull(head="mallory/agents"), protected="true"), id="github fork"),
    pytest.param(lambda: github("pull_request_target", payload=pull(), protected="true"), id="github pull_request_target"),
    pytest.param(lambda: github("merge_group", payload={}, protected="true"), id="github merge queue"),
    pytest.param(lambda: github("", payload={}, protected="true"), id="github unknown event"),
    pytest.param(lambda: github("push", payload={}, protected="false"), id="github push to an unprotected branch"),
    pytest.param(lambda: github("workflow_dispatch", payload={}, protected="false"), id="github manual run, unprotected ref"),
    pytest.param(lambda: gitlab("merge_request_event", protected="true"), id="gitlab merge request"),
    pytest.param(lambda: gitlab("external_pull_request_event", protected="true"), id="gitlab external pull request"),
    pytest.param(lambda: gitlab("push", protected="false"), id="gitlab push to an unprotected branch"),
    pytest.param(lambda: gitlab("web", protected="false"), id="gitlab manual run, unprotected ref"),
    pytest.param(lambda: gitlab("", protected="true"), id="gitlab unknown source"),
    pytest.param(lambda: ci.detect({"CI": "true"}, git_remote=lambda: None), id="other CI"),
    # An allowlist, not a denylist: every event outside push, schedule and a manual run is untrusted, even on a
    # protected ref, because its payload or its checkout can come from whoever opened a pull request.
    pytest.param(lambda: github("issue_comment", payload={"issue": {"number": 7, "pull_request": {}}}, protected="true"),
                 id="github comment on a pull request"),
    pytest.param(lambda: github("issue_comment", payload={"issue": {"number": 8}}, protected="true"),
                 id="github comment on an issue"),
    pytest.param(lambda: github("workflow_run", payload=run_of("pull_request", "mallory/agents"), protected="true"),
                 id="github workflow_run of a fork pull request"),
    pytest.param(lambda: github("workflow_run", payload=run_of("push", "acme/agents"), protected="true"),
                 id="github workflow_run of a push"),
    pytest.param(lambda: github("pull_request_review", payload=pull(), protected="true"), id="github pull_request_review"),
    pytest.param(lambda: github("pull_request_review_comment", payload=pull(), protected="true"),
                 id="github pull_request_review_comment"),
    *[pytest.param(lambda event=event: github(event, payload={}, protected="true"), id=f"github {event}")
      for event in ("release", "repository_dispatch", "workflow_call", "check_run", "deployment", "create", "delete",
                    "discussion", "fork", "watch", "made_up_event")],
    *[pytest.param(lambda source=source: gitlab(source, protected="true"), id=f"gitlab {source}")
      for source in ("api", "trigger", "pipeline", "parent_pipeline", "chat", "webide", "security_orchestration_policy",
                     "ondemand_dast_scan", "made_up_source")],
])
def test_private_probing_is_not_trusted(ctx):
    assert ci.private_probe_trusted(ctx()) is False


@pytest.mark.parametrize("ctx", [
    pytest.param(lambda: github("push", payload={}, protected="true"), id="github push to a protected branch"),
    pytest.param(lambda: github("schedule", payload={}, protected="true"), id="github schedule on a protected branch"),
    pytest.param(lambda: github("workflow_dispatch", payload={}, protected="true"), id="github manual run, protected ref"),
    pytest.param(lambda: gitlab("push", protected="true"), id="gitlab push to a protected branch"),
    pytest.param(lambda: gitlab("schedule", protected="true"), id="gitlab schedule on a protected branch"),
    pytest.param(lambda: gitlab("web", protected="true"), id="gitlab manual run, protected ref"),
    pytest.param(lambda: ci.detect({}), id="local run"),
])
def test_private_probing_is_trusted(ctx):
    assert ci.private_probe_trusted(ctx()) is True


def run_of(event: str, head: str | None) -> dict:
    run: dict = {"event": event}
    if head is not None:
        run["head_repository"] = {"full_name": head}
    return {"workflow_run": run}


def test_a_workflow_run_of_a_pull_request_is_a_request_and_its_fork_is_the_head_repository():
    same = github("workflow_run", payload=run_of("pull_request", "acme/agents"))
    assert (same.is_request, same.fork) == (True, False)
    forked = github("workflow_run", payload=run_of("pull_request_target", "mallory/agents"))
    assert (forked.is_request, forked.fork) == (True, True)
    unknown = github("workflow_run", payload=run_of("pull_request", None))
    assert (unknown.is_request, unknown.fork) == (True, True)  # no head repository: fail closed
    pushed = github("workflow_run", payload=run_of("push", "acme/agents"))
    assert (pushed.is_request, pushed.fork) == (False, False)


def test_a_comment_on_a_pull_request_is_a_request_from_a_fork():
    on_pull = github("issue_comment", payload={"issue": {"number": 7, "pull_request": {"url": "u"}}})
    assert (on_pull.is_request, on_pull.fork) == (True, True)  # the payload names no head repository: fail closed
    on_issue = github("issue_comment", payload={"issue": {"number": 8}})
    assert (on_issue.is_request, on_issue.fork) == (False, False)


def test_a_review_event_is_a_request_with_the_fork_of_its_pull_request():
    review = github("pull_request_review", payload=pull(head="mallory/agents"))
    assert (review.is_request, review.request_number, review.fork) == (True, 7, True)
    assert github("pull_request_review_comment", payload=pull()).fork is False


# Precomputed: sha256("spellwarden-ping-v1:" + identity). Documented behaviour, not a wish (spec 6.10).
VECTORS = {
    "github:github.com:1234567": "6ece64f2db0ecee34de1a73b2ad0effdf128e6b7a1a2babdb36203d72f61a785",
    "github:ghe.acme.example:42": "1fa26c724e42f2b75fe1278dfb3ceef0391b4f8e14ac8dc657736be25057d771",
    "gitlab:gitlab.com:acme": "fbbc0e57daddaf289c78c89238bfe132770a6121be23267e64f569ee7b7c3b0e",
    "gitlab:gitlab.acme.example:platform": "d2cc76bcac1828a6e44829722b749b5a81825e0a0ba387c670e803a58ca3e1ff",
    "other:bitbucket.org/acme": "47d60ecf9cd7fa9467eca0ffe35d5efa3f26a7bfc9768ceba3dc24591bfeef80",
    "gitlab:gitlab.com:acme-renamed": "a4fec882637bccd05896ab276ea34f6e917a4de33888391970c5136adc6611cd",
}


def test_identity_hashes_equal_the_precomputed_vectors():
    for identity, digest in VECTORS.items():
        assert ci.org_hash(identity) == digest
    assert ci.org_hash(None) is None


def test_each_forge_and_host_gives_its_own_identity():
    assert github("push", GITHUB_SERVER_URL="https://GHE.acme.example", GITHUB_REPOSITORY_OWNER_ID="42").identity == \
        "github:ghe.acme.example:42"  # GitHub Enterprise Server
    assert gitlab("push", CI_SERVER_HOST="gitlab.acme.example", CI_PROJECT_ROOT_NAMESPACE="platform").identity == \
        "gitlab:gitlab.acme.example:platform"  # self-managed GitLab
    on_github = ci.org_hash(github("push", GITHUB_REPOSITORY_OWNER_ID="1234567").identity)
    on_gitlab = ci.org_hash(gitlab("push").identity)
    assert on_github != on_gitlab  # one company on two forges is two identities
    assert ci.org_hash(gitlab("push", CI_PROJECT_ROOT_NAMESPACE="acme-renamed").identity) == VECTORS["gitlab:gitlab.com:acme-renamed"]
    assert ci.org_hash(gitlab("push", CI_PROJECT_ROOT_NAMESPACE="acme-renamed").identity) != on_gitlab  # a group rename is new
    assert github("push", GITHUB_REPOSITORY="acme-renamed/agents").identity == "github:github.com:1234567"  # numeric owner id


@pytest.mark.parametrize(("remote", "identity"), [
    ("https://bitbucket.org/acme/agents.git", "other:bitbucket.org/acme"),
    ("https://user:tok@Bitbucket.org/acme/agents", "other:bitbucket.org/acme"),
    ("git@bitbucket.org:acme/agents.git", "other:bitbucket.org/acme"),
    ("ssh://git@bitbucket.org:7999/acme/agents.git", "other:bitbucket.org/acme"),
    ("/srv/git/agents.git", None),
    ("not a url", None),
    (None, None),
])
def test_other_ci_identity_comes_from_the_origin_remote(remote, identity):
    assert ci.detect({"CI": "true"}, git_remote=lambda: remote).identity == identity


CI_MARKERS = {
    "Jenkins": {"JENKINS_URL": "https://jenkins.acme.example/"},
    "Azure Pipelines": {"TF_BUILD": "True"}, "TeamCity": {"TEAMCITY_VERSION": "2025.03"},
    "Buildkite": {"BUILDKITE": "true"}, "CircleCI": {"CIRCLECI": "true"},
    "Bitbucket Pipelines": {"BITBUCKET_BUILD_NUMBER": "17"}, "AWS CodeBuild": {"CODEBUILD_BUILD_ID": "proj:1234"},
    "Drone": {"DRONE": "true"}, "Travis CI": {"TRAVIS": "true"},
    # Woodpecker documents `CI=woodpecker` and `CI_SYSTEM_NAME=woodpecker` (woodpecker-ci.org/docs/usage/environment).
    "Woodpecker": {"CI_SYSTEM_NAME": "woodpecker"},
}


@pytest.mark.parametrize("marker", CI_MARKERS.values(), ids=CI_MARKERS.keys())
def test_a_ci_that_does_not_set_ci_true_is_still_ci_and_never_trusted(marker):
    """Spec 6.11: detection fails closed. A run that carries a CI system's own marker is `other` CI even without
    `CI=true` (or with `CI=false`): never trusted for private probing (6.8), and `ci: other` in the ping (6.10).
    Plain `--probe` stays on there: `other` CI is not a pull request and not a fork (owner decision)."""
    for env in (marker, {**marker, "CI": "false"}):
        ctx = ci.detect(env, git_remote=lambda: "https://bitbucket.org/acme/agents.git")
        assert (ctx.provider, ctx.is_request, ctx.fork, ctx.dependabot) == ("other", False, False, False)
        assert ctx.identity == "other:bitbucket.org/acme"
        assert ci.private_probe_trusted(ctx) is False


def test_the_markers_are_the_ones_the_tests_cover():
    assert sorted(ci.CI_MARKERS) == sorted(name for marker in CI_MARKERS.values() for name in marker)


@pytest.mark.parametrize("value", ["woodpecker", "drone", "True", "anything", " 1 "])
def test_any_ci_value_that_is_not_false_is_ci_and_never_trusted(value):
    """Review r2 F3: `CI=woodpecker` (Woodpecker) and `CI=drone` were taken for a local run, so a pull-request
    pipeline was trusted for private probing. Any non-empty `CI` that is not a false value means CI."""
    ctx = ci.detect({"CI": value, "CI_PIPELINE_EVENT": "pull_request"}, git_remote=lambda: None)
    assert ctx.provider == "other" and ci.private_probe_trusted(ctx) is False


@pytest.mark.parametrize("value", ["", "  ", "0", "false", "FALSE", "no", "No", " off "])
def test_an_empty_or_false_ci_value_is_no_ci(value):
    assert ci.detect({"CI": value}) == ci.LOCAL


@pytest.mark.parametrize(("source", "protected", "more", "is_request"), [
    pytest.param("parent_pipeline", "false", {}, True, id="child pipeline, unprotected ref"),
    pytest.param("parent_pipeline", "", {}, True, id="child pipeline, protection unknown"),
    pytest.param("parent_pipeline", "true", {}, False, id="child pipeline of a protected branch"),
    pytest.param("parent_pipeline", "true", {"CI_MERGE_REQUEST_IID": "5"}, True,
                 id="child pipeline of a merge request on a protected source branch"),
    pytest.param("api", "true", {"CI_MERGE_REQUEST_IID": "5"}, True, id="any source with a merge request"),
    pytest.param("push", "true", {"CI_MERGE_REQUEST_IID": ""}, False, id="an empty merge request IID"),
    pytest.param("pipeline", "false", {}, False, id="a multi-project pipeline stays as it was"),
])
def test_a_gitlab_child_pipeline_of_a_merge_request_is_a_request(source, protected, more, is_request):
    """Review r2 F5: a child pipeline started by a merge request pipeline runs the request's code, so it is a request
    (failing closed to the defaults when it names no base) unless its ref is protected; any pipeline that carries a
    merge request IID is one."""
    ctx = gitlab(source, protected=protected, **more)
    assert ctx.is_request is is_request
    assert ci.private_probe_trusted(ctx) is (source == "push")  # the allowlist is unchanged
    if is_request and not more:
        assert ctx.fork is True and ctx.base_sha is None


def test_a_generic_build_id_alone_is_no_ci():
    """`BUILD_ID` is set by local tools too; Jenkins always sets `JENKINS_URL`, so a local shell stays local."""
    assert ci.detect({"BUILD_ID": "42"}) == ci.LOCAL


def test_an_empty_marker_is_no_ci():
    assert ci.detect({name: "" for marker in CI_MARKERS.values() for name in marker}) == ci.LOCAL


def test_missing_identity_parts_give_none():
    assert github("push", GITHUB_REPOSITORY_OWNER_ID="").identity is None
    assert gitlab("push", CI_PROJECT_ROOT_NAMESPACE="").identity is None


# Spec 6.11 and D35: the base revision of a pull or merge request, from which its settings file and baseline are read.
BASE = "0123456789abcdef0123456789abcdef01234567"
BASE256 = "ab" * 32


def pull_on(base: object) -> dict:
    return {"pull_request": {"number": 7, "head": {"repo": {"full_name": "acme/agents"}}, "base": {"sha": base}}}


def merge_request(**more: str):
    return gitlab("merge_request_event", CI_MERGE_REQUEST_IID="5", CI_MERGE_REQUEST_SOURCE_PROJECT_ID="42", **more)


@pytest.mark.parametrize(("ctx", "base_sha"), [
    pytest.param(lambda: github("pull_request", payload=pull_on(BASE)), BASE, id="github pull_request"),
    pytest.param(lambda: github("pull_request_target", payload=pull_on(BASE)), BASE, id="github pull_request_target"),
    pytest.param(lambda: github("pull_request_review", payload=pull_on(BASE)), BASE, id="github pull_request_review"),
    pytest.param(lambda: github("pull_request_review_comment", payload=pull_on(BASE)), BASE,
                 id="github pull_request_review_comment"),
    pytest.param(lambda: github("pull_request", payload=pull_on(BASE.upper())), BASE, id="github upper-case is lowered"),
    pytest.param(lambda: github("pull_request", payload=pull_on(BASE256)), BASE256, id="github SHA-256 repository"),
    pytest.param(lambda: github("merge_group", payload={"merge_group": {"base_sha": BASE}}), BASE, id="github merge queue"),
    pytest.param(lambda: github("merge_group", payload=pull_on(BASE)), None, id="github merge queue without merge_group"),
    pytest.param(lambda: github("workflow_run", payload={**run_of("pull_request", "acme/agents"), **pull_on(BASE)}), None,
                 id="github workflow_run"),
    pytest.param(lambda: github("issue_comment", payload={"issue": {"number": 7, "pull_request": {}}, **pull_on(BASE)}),
                 None, id="github issue_comment"),
    pytest.param(lambda: github("push", payload=pull_on(BASE)), None, id="github push"),
    pytest.param(lambda: github("pull_request", payload=pull_on("main")), None, id="github branch name"),
    pytest.param(lambda: github("pull_request", payload=pull_on(BASE[:-1])), None, id="github 39 characters"),
    pytest.param(lambda: github("pull_request", payload=pull_on(BASE + "\n")), None, id="github trailing newline"),
    pytest.param(lambda: github("pull_request", payload=pull_on("g" * 40)), None, id="github not hex"),
    pytest.param(lambda: github("pull_request", payload=pull_on(int(BASE[:12], 16))), None, id="github a number"),
    pytest.param(lambda: github("pull_request", payload=pull()), None, id="github no base"),
    pytest.param(lambda: github("pull_request", payload={"pull_request": {"base": "x"}}), None, id="github base not a mapping"),
    pytest.param(lambda: merge_request(CI_MERGE_REQUEST_DIFF_BASE_SHA=BASE), BASE, id="gitlab diff base"),
    pytest.param(lambda: merge_request(CI_MERGE_REQUEST_TARGET_BRANCH_SHA=BASE), BASE, id="gitlab target branch sha"),
    pytest.param(lambda: merge_request(CI_MERGE_REQUEST_DIFF_BASE_SHA=BASE, CI_MERGE_REQUEST_TARGET_BRANCH_SHA=BASE256),
                 BASE, id="gitlab diff base first"),
    pytest.param(lambda: merge_request(CI_MERGE_REQUEST_DIFF_BASE_SHA="main", CI_MERGE_REQUEST_TARGET_BRANCH_SHA=BASE),
                 BASE, id="gitlab invalid diff base, valid target"),
    pytest.param(lambda: merge_request(CI_MERGE_REQUEST_DIFF_BASE_SHA=BASE[:-1]), None, id="gitlab 39 characters"),
    pytest.param(lambda: merge_request(), None, id="gitlab no sha"),
    pytest.param(lambda: gitlab("external_pull_request_event", CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_SHA=BASE), BASE,
                 id="gitlab external pull request"),
    pytest.param(lambda: gitlab("external_pull_request_event", CI_MERGE_REQUEST_DIFF_BASE_SHA=BASE), None,
                 id="gitlab external pull request reads only its own variable"),
    pytest.param(lambda: gitlab("push", CI_MERGE_REQUEST_DIFF_BASE_SHA=BASE), None, id="gitlab push"),
    pytest.param(lambda: gitlab("", CI_MERGE_REQUEST_DIFF_BASE_SHA=BASE), None, id="gitlab unknown source"),
    pytest.param(lambda: gitlab("parent_pipeline"), None, id="gitlab child pipeline without merge request variables"),
    pytest.param(lambda: gitlab("parent_pipeline", CI_MERGE_REQUEST_DIFF_BASE_SHA=BASE), BASE,
                 id="gitlab child pipeline with the diff base"),
    pytest.param(lambda: gitlab("parent_pipeline", CI_MERGE_REQUEST_TARGET_BRANCH_SHA=BASE), BASE,
                 id="gitlab child pipeline with the target branch sha"),
    pytest.param(lambda: gitlab("parent_pipeline", protected="true", CI_MERGE_REQUEST_DIFF_BASE_SHA=BASE), None,
                 id="gitlab child pipeline of a protected branch"),
    pytest.param(lambda: gitlab("api", CI_MERGE_REQUEST_IID="5", CI_MERGE_REQUEST_DIFF_BASE_SHA=BASE), BASE,
                 id="gitlab any source with a merge request"),
    pytest.param(lambda: ci.detect({"CI": "true"}, git_remote=lambda: None), None, id="other CI"),
    pytest.param(lambda: ci.detect({}), None, id="local run"),
])
def test_the_base_sha_of_each_event(ctx, base_sha):
    assert ctx().base_sha == base_sha


def test_git_remote_of_gets_an_explicit_environment(make_repo, tmp_path, monkeypatch):
    """O3 invariant 2: the subprocess of `git_remote_of` gets the environment it was given, not ours by inheritance."""
    repo = make_repo(tmp_path / "r", {"README.md": "x\n"})
    seen: list = []
    real = ci.subprocess.run

    def spy(command, *args, **kwargs):
        seen.append(kwargs.get("env"))
        return real(command, *args, **kwargs)

    monkeypatch.setattr(ci.subprocess, "run", spy)
    given = {**os.environ, "MARKER_FOR_TEST": "1"}
    ci.git_remote_of(str(repo), env=given)
    assert len(seen) == 1 and seen[0]["MARKER_FOR_TEST"] == "1" and seen[0] is not given
    ci.git_remote_of(str(repo))
    assert isinstance(seen[1], dict) and "MARKER_FOR_TEST" not in seen[1]


def test_the_base_revision_reads_run_git_with_the_given_environment(make_repo, tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "r", {"README.md": "x\n"})
    seen: list = []
    real = ci._run_git

    def spy(*args, **kwargs):
        seen.append(kwargs.get("env"))
        return real(*args, **kwargs)

    monkeypatch.setattr(ci, "_run_git", spy)
    sha = ci.subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True,
                            check=True).stdout.strip()
    given = {**os.environ, "MARKER_FOR_TEST": "1"}
    assert ci.read_at_revision(str(repo), sha, "README.md", max_bytes=100, env=given) == b"x\n"
    assert seen and all(env is not None and env.get("MARKER_FOR_TEST") == "1" for env in seen)


# --- O3 spec 6.8: the run context (claim E12) -----------------------------------------------------------------------

SHA = "1" * 40
HEAD = "2" * 40


def push_payload(**repository: object) -> dict:
    return {"repository": {"default_branch": "main", "visibility": "private", **repository}}


GITHUB_RUN = {"GITHUB_SHA": SHA, "GITHUB_REF_NAME": "main", "GITHUB_RUN_ID": "9001", "GITHUB_RUN_ATTEMPT": "2",
              "GITHUB_JOB": "scan", "GITHUB_REPOSITORY": "Acme/Tools"}


def test_github_run_context_on_push():
    ctx = github("push", payload=push_payload(visibility="internal"), **GITHUB_RUN)
    assert ctx.repository_url == "https://github.com/Acme/Tools"  # the URL keeps its case, the identity does not
    assert ctx.repository_identity == "github:github.com/acme/tools"
    assert (ctx.sha, ctx.ref_name, ctx.default_branch) == (SHA, "main", "main")
    assert ctx.visibility == "private"  # `internal` is not public everywhere
    assert ctx.run_url == "https://github.com/Acme/Tools/actions/runs/9001"
    assert (ctx.job, ctx.attempt) == ("scan", 2)
    assert (ctx.head_sha, ctx.head_ref) == (None, None)
    assert github("push", payload=push_payload(visibility="public"), **GITHUB_RUN).visibility == "public"
    assert github("push", payload=push_payload(visibility="private"), **GITHUB_RUN).visibility == "private"
    assert github("push", payload={}, **GITHUB_RUN).visibility == "private"  # an unreadable payload is not public
    assert github("push", payload={}, **GITHUB_RUN).default_branch is None


def test_github_enterprise_identity_keeps_a_non_default_port_and_attempt_defaults_to_one():
    ctx = github("push", payload={}, GITHUB_SERVER_URL="https://GHE.acme.example:8443", GITHUB_REPOSITORY="acme/tools")
    assert ctx.repository_identity == "github:ghe.acme.example:8443/acme/tools"
    assert ctx.repository_url == "https://GHE.acme.example:8443/acme/tools"
    assert ctx.attempt == 1 and ctx.job is None and ctx.run_url is None  # no run id: no run URL
    assert github("push", payload={}, GITHUB_SERVER_URL="https://ghe.acme.example:443").repository_identity == \
        "github:ghe.acme.example/acme/agents"


def test_github_request_context():
    payload = {"pull_request": {**pull()["pull_request"], "head": {"repo": {"full_name": "acme/agents"}, "sha": HEAD,
                                                                   "ref": "feature/x"}},
               **push_payload()}
    for event in ("pull_request", "pull_request_target"):
        ctx = github(event, payload=payload, **{**GITHUB_RUN, "GITHUB_HEAD_REF": "feature/x", "GITHUB_REF_NAME": "7/merge"})
        assert ctx.is_request and ctx.ref_name == "feature/x"
        assert (ctx.head_sha, ctx.head_ref) == (HEAD, "feature/x") and ctx.request_number == 7
    review = github("pull_request_review", payload=payload, **GITHUB_RUN)
    assert (review.head_sha, review.head_ref) == (HEAD, "feature/x")
    queue = github("merge_group", payload={"merge_group": {"base_sha": BASE}}, **GITHUB_RUN)
    assert queue.is_request and queue.ref_name == "main" and queue.head_sha is None  # no GITHUB_HEAD_REF in a merge queue
    bad = github("pull_request", payload={"pull_request": {"head": {"repo": {"full_name": "acme/agents"}, "sha": "abc"}}})
    assert bad.head_sha is None


def test_spellwarden_default_branch_wins_over_the_payload():
    ctx = github("push", payload=push_payload(default_branch="trunk"), SPELLWARDEN_DEFAULT_BRANCH="release", **GITHUB_RUN)
    assert ctx.default_branch == "release"
    assert github("push", payload=push_payload(default_branch="trunk"), SPELLWARDEN_DEFAULT_BRANCH="", **GITHUB_RUN
                  ).default_branch == "trunk"
    assert gitlab("push", SPELLWARDEN_DEFAULT_BRANCH="release", CI_DEFAULT_BRANCH="main").default_branch == "release"
    assert ci.detect({"CI": "true", "SPELLWARDEN_DEFAULT_BRANCH": "release"}, git_remote=lambda: None
                     ).default_branch == "release"


GITLAB_RUN = {"CI_PROJECT_URL": "https://gitlab.com/Acme/Group/Tools", "CI_COMMIT_SHA": SHA, "CI_COMMIT_REF_NAME": "main",
              "CI_DEFAULT_BRANCH": "main", "CI_PROJECT_VISIBILITY": "internal",
              "CI_JOB_URL": "https://gitlab.com/Acme/Group/Tools/-/jobs/77", "CI_JOB_NAME": "spellwarden"}


def test_gitlab_run_context():
    ctx = gitlab("push", **GITLAB_RUN)
    assert ctx.repository_url == "https://gitlab.com/Acme/Group/Tools"
    assert ctx.repository_identity == "gitlab:gitlab.com/acme/group/tools"
    assert (ctx.sha, ctx.ref_name, ctx.default_branch, ctx.visibility) == (SHA, "main", "main", "private")
    assert (ctx.run_url, ctx.job, ctx.attempt) == ("https://gitlab.com/Acme/Group/Tools/-/jobs/77", "spellwarden", 1)
    assert gitlab("push", **{**GITLAB_RUN, "CI_PROJECT_VISIBILITY": "public"}).visibility == "public"
    request = gitlab("merge_request_event", CI_MERGE_REQUEST_IID="5", CI_MERGE_REQUEST_SOURCE_PROJECT_ID="42",
                     CI_MERGE_REQUEST_SOURCE_BRANCH_NAME="feature/x", CI_MERGE_REQUEST_SOURCE_BRANCH_SHA=HEAD, **GITLAB_RUN)
    assert request.ref_name == "feature/x" and (request.head_sha, request.head_ref) == (HEAD, "feature/x")
    merged = gitlab("merge_request_event", CI_MERGE_REQUEST_IID="5", CI_MERGE_REQUEST_SOURCE_PROJECT_ID="42",
                    CI_MERGE_REQUEST_SOURCE_BRANCH_NAME="feature/x", **GITLAB_RUN)
    assert merged.head_sha == SHA  # no source branch sha: CI_COMMIT_SHA
    assert (gitlab("push", **GITLAB_RUN).head_sha, gitlab("push", **GITLAB_RUN).head_ref) == (None, None)


def test_gitlab_relative_url_is_kept_in_repository_url_and_identity():
    ctx = gitlab("push", **{**GITLAB_RUN, "CI_PROJECT_URL": "https://git.corp.example:8443/gitlab/Group/Sub/Tools"})
    assert ctx.repository_url == "https://git.corp.example:8443/gitlab/Group/Sub/Tools"
    assert ctx.repository_identity == "gitlab:git.corp.example:8443/gitlab/group/sub/tools"
    bare = gitlab("push", CI_SERVER_URL="https://git.corp.example/gitlab", CI_PROJECT_PATH="group/tools")
    assert bare.repository_url == "https://git.corp.example/gitlab/group/tools"
    assert bare.repository_identity == "gitlab:git.corp.example/gitlab/group/tools"
    assert gitlab("push").repository_url is None and gitlab("push").repository_identity is None


@pytest.mark.parametrize(("remote", "url", "identity"), [
    ("git@bitbucket.org:Acme/agents.git", "https://bitbucket.org/Acme/agents", "other:bitbucket.org/acme/agents"),
    ("git@bitbucket.org:/acme/agents.git", "https://bitbucket.org/acme/agents", "other:bitbucket.org/acme/agents"),
    ("ssh://u:t0ken@git.corp.example:2222/x/y.git", "https://git.corp.example/x/y", "other:git.corp.example/x/y"),
    ("ssh://git@git.corp.example/x/y", "https://git.corp.example/x/y", "other:git.corp.example/x/y"),
    ("https://git.corp.example:8443/x/y.git", "https://git.corp.example:8443/x/y", "other:git.corp.example:8443/x/y"),
    ("https://user:tok@Git.Corp.Example/x/y/z?x=1#frag", "https://git.corp.example/x/y/z", "other:git.corp.example/x/y/z"),
    ("https://git.corp.example:443/x/y", "https://git.corp.example/x/y", "other:git.corp.example/x/y"),
    ("https://git.corp.example/x/y/", "https://git.corp.example/x/y", "other:git.corp.example/x/y"),
    ("/srv/git/agents.git", None, None), ("not a url", None, None), ("https://git.corp.example/solo", None, None),
    (None, None, None),
])
def test_other_ci_from_the_origin_remote(remote, url, identity):
    ctx = ci.detect({"CI": "true"}, git_remote=lambda: remote)
    assert (ctx.repository_url, ctx.repository_identity) == (url, identity)
    assert "t0ken" not in repr(ctx) and "tok@" not in repr(ctx)
    assert ctx.visibility == "private" and ctx.run_url is None and ctx.job is None and ctx.attempt == 1
    assert ctx.default_branch is None


def test_other_ci_takes_sha_and_branch_from_git():
    ctx = ci.detect({"CI": "true", "SPELLWARDEN_DEFAULT_BRANCH": "main"}, git_remote=lambda: None, git_head=lambda: SHA,
                    git_branch=lambda: "main")
    assert (ctx.sha, ctx.ref_name) == (SHA, "main") and ctx.run_kind() == "default_branch"
    assert ci.detect({"CI": "true"}, git_remote=lambda: None).sha is None  # no lookup unless asked for


def test_github_sha_falls_back_to_git_head_only_when_the_variable_is_missing():
    env = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": SHA}
    assert ci.detect(env, read_text=lambda _p: "{}", git_head=lambda: HEAD).sha == SHA
    assert ci.detect({**env, "GITHUB_SHA": ""}, read_text=lambda _p: "{}", git_head=lambda: HEAD).sha == HEAD
    assert ci.detect({**env, "GITHUB_SHA": "nonsense"}, read_text=lambda _p: "{}", git_head=lambda: None).sha is None


def test_scan_scope_has_no_trailing_slash_and_refuses_the_grammar(make_repo, tmp_path):
    env = dict(os.environ)
    repo = make_repo(tmp_path / "repo", {"services/agent/README.md": "x\n", "a b/c/README.md": "x\n", "top.md": "x\n",
                                         "x/.hidden/f.md": "x\n"})
    assert ci.scan_scope(str(repo / "services" / "agent"), git=None, env=env) == "services/agent"
    assert ci.scan_scope(str(repo / "services" / "agent") + os.sep, git=None, env=env) == "services/agent"
    assert ci.scan_scope(str(repo), git=None, env=env) == ""
    assert ci.scan_scope(str(repo / "x" / ".hidden"), git=None, env=env) == "x/.hidden"
    assert ci.scan_scope(str(repo / "a b" / "c"), git=None, env=env) is None
    bare = tmp_path / "outside"
    bare.mkdir()
    assert ci.scan_scope(str(bare), git=None, env=env) == ""  # outside a repository
    assert ci.scan_scope(str(repo / "services" / "agent"), git="", env=env) == "services/agent"  # git is not needed


@pytest.mark.parametrize(("ctx", "kind"), [
    pytest.param(lambda: github("pull_request", payload=pull(), **GITHUB_RUN), "request", id="pull_request"),
    pytest.param(lambda: github("merge_group", payload={}, **GITHUB_RUN), "request", id="merge_group"),
    pytest.param(lambda: gitlab("merge_request_event", CI_MERGE_REQUEST_IID="5", CI_MERGE_REQUEST_SOURCE_PROJECT_ID="42",
                                **GITLAB_RUN), "request", id="merge request"),
    pytest.param(lambda: github("push", payload=push_payload(), **GITHUB_RUN), "default_branch", id="push to the default"),
    pytest.param(lambda: github("schedule", payload=push_payload(), **GITHUB_RUN), "default_branch", id="schedule"),
    pytest.param(lambda: github("workflow_dispatch", payload=push_payload(), **GITHUB_RUN), "default_branch",
                 id="workflow_dispatch"),
    pytest.param(lambda: github("push", payload=push_payload(), **{**GITHUB_RUN, "GITHUB_REF_NAME": "dev"}), "branch",
                 id="push to another branch"),
    pytest.param(lambda: github("push", payload={}, **GITHUB_RUN), "branch", id="unknown default branch"),
    pytest.param(lambda: github("release", payload=push_payload(), **GITHUB_RUN), "branch", id="untrusted event on main"),
    pytest.param(lambda: gitlab("push", **GITLAB_RUN), "default_branch", id="gitlab push"),
    pytest.param(lambda: gitlab("web", **GITLAB_RUN), "default_branch", id="gitlab web"),
    pytest.param(lambda: gitlab("api", **GITLAB_RUN), "branch", id="gitlab api"),
    pytest.param(lambda: gitlab("push", **{**GITLAB_RUN, "CI_COMMIT_REF_NAME": "dev"}), "branch", id="gitlab other branch"),
    pytest.param(lambda: ci.detect({"CI": "true", "SPELLWARDEN_DEFAULT_BRANCH": "main"}, git_remote=lambda: None,
                                   git_branch=lambda: "main"), "default_branch", id="other on the named branch"),
    pytest.param(lambda: ci.detect({"CI": "true", "SPELLWARDEN_DEFAULT_BRANCH": "main"}, git_remote=lambda: None,
                                   git_branch=lambda: "dev"), "branch", id="other on another branch"),
    pytest.param(lambda: ci.detect({"CI": "true"}, git_remote=lambda: None, git_branch=lambda: "main"), "branch",
                 id="other with no default branch"),
    pytest.param(lambda: ci.LOCAL, "branch", id="local"),
])
def test_run_kinds(ctx, kind):
    assert ctx().run_kind() == kind


def test_workflow_run_and_issue_comment_are_requests_for_the_command():
    run = github("workflow_run", payload={**run_of("pull_request", "acme/agents"), **push_payload()}, **GITHUB_RUN)
    comment = github("issue_comment", payload={"issue": {"number": 7, "pull_request": {}}, **push_payload()}, **GITHUB_RUN)
    assert run.run_kind() == "request" and comment.run_kind() == "request"
    plain = github("workflow_run", payload={"workflow_run": {"event": "push"}, **push_payload()}, **GITHUB_RUN)
    assert plain.is_request is False and plain.run_kind() == "branch"  # an event outside the trusted list is never a default run


def test_fork_and_dependabot_flags_unchanged_by_the_new_fields():
    ctx = github("pull_request", payload=pull(head="mallory/agents"), GITHUB_ACTOR="dependabot[bot]", **GITHUB_RUN)
    assert (ctx.fork, ctx.dependabot, ctx.identity, ctx.base_sha) == (True, True, "github:github.com:1234567", None)
    assert ci.LOCAL.attempt == 1 and ci.LOCAL.repository_url is None and ci.LOCAL.run_kind() == "branch"
