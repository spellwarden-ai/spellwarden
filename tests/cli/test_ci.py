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
])
def test_private_probing_is_not_trusted(ctx):
    assert ci.private_probe_trusted(ctx()) is False


@pytest.mark.parametrize("ctx", [
    pytest.param(lambda: github("push", payload={}, protected="true"), id="github push to a protected branch"),
    pytest.param(lambda: github("schedule", payload={}, protected="true"), id="github schedule on a protected branch"),
    pytest.param(lambda: gitlab("push", protected="true"), id="gitlab push to a protected branch"),
    pytest.param(lambda: ci.detect({}), id="local run"),
])
def test_private_probing_is_trusted(ctx):
    assert ci.private_probe_trusted(ctx()) is True


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


def test_missing_identity_parts_give_none():
    assert github("push", GITHUB_REPOSITORY_OWNER_ID="").identity is None
    assert gitlab("push", CI_PROJECT_ROOT_NAMESPACE="").identity is None
