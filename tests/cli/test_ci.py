"""Spec 6.11, 6.8 and 6.10, claims C14 (the trust rule) and C15 (the identity vectors): CI detection from the
environment and the event file, the trust rule for private probing, and the pseudonymous installation identity."""
from __future__ import annotations

import json

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


def test_a_generic_build_id_alone_is_no_ci():
    """`BUILD_ID` is set by local tools too; Jenkins always sets `JENKINS_URL`, so a local shell stays local."""
    assert ci.detect({"BUILD_ID": "42"}) == ci.LOCAL


def test_an_empty_marker_is_no_ci():
    assert ci.detect({name: "" for marker in CI_MARKERS.values() for name in marker}) == ci.LOCAL


def test_missing_identity_parts_give_none():
    assert github("push", GITHUB_REPOSITORY_OWNER_ID="").identity is None
    assert gitlab("push", CI_PROJECT_ROOT_NAMESPACE="").identity is None
