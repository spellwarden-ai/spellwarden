"""O3 spec 6.2 to 6.5 and 6.8, claims E8 and E9 (session half): how a run connects, what the `required` decision does
before the session, and that every failure after it exits 2. The API is `FakeApi` behind the transport seams of
`connected.py`; no test opens a socket or waits."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import (EXCHANGE_PATH, HEAD, KEY_PATH, POLICY_PATH, SHA, connected_github, connected_gitlab, credential, git,
                      orgs_answer, policy_answer, scan_json, session_answer, write_tree)

from spellwarden_scan import __version__
from spellwarden_cli import connected, run
from spellwarden_cli.discover import discover
from spellwarden_cli.files import list_files
from spellwarden_cli.secret import Credentials, Secret
from spellwarden_cli.settings import Connected, Settings

SKILL = "---\nname: deploy\ndescription: Deploys.\nversion: 1.0.0\nlicense: Apache-2.0\n---\n\nRun it.\n"
REQUIRED = "version: 1\nconnected:\n  required: true\n"
NOT_REQUIRED = "version: 1\nconnected:\n  required: false\n"
ID_TOKEN = "id.jwt." + "x" * 20


def repo_of(make_repo, tmp_path: Path, files: dict | None = None) -> Path:
    return make_repo(tmp_path / "repo", {"README.md": "agents\n", **(files or {})})


def codes(entries: list[dict]) -> list[str]:
    return [entry["code"] for entry in entries]


def notice(report: dict, code: str) -> dict:
    return next(entry for entry in report["notices"] if entry["code"] == code)


def commit(repo: Path, files: dict[str, str | None], message: str = "head") -> str:
    for path, content in files.items():
        if content is None:
            git(repo, "rm", "-q", "--", path)
    write_tree(repo, {path: content for path, content in files.items() if content is not None})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD").strip()


def request_env(tmp_path: Path, base: str, *, head_repo: str = "acme/tools", **more: str) -> dict[str, str]:
    payload = {"pull_request": {"number": 3, "head": {"repo": {"full_name": head_repo}, "sha": HEAD, "ref": "feature/x"},
                                "base": {"sha": base}}, "repository": {"default_branch": "main"}}
    return connected_github(tmp_path, "pull_request", payload, GITHUB_HEAD_REF="feature/x", GITHUB_REF_NAME="3/merge", **more)


# --- the session ---------------------------------------------------------------------------------------------------

def test_org_with_gitlab_id_token_exchanges_and_uses_the_ci_token(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    swt = credential("swt")
    run_of_server = {"identity": "gitlab:gitlab.com/acme/tools", "event": "push", "sha": SHA}
    fake.script("POST", EXCHANGE_PATH, 201, session_answer(swt, run_of_server))
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    code, report, out, err = scan_json(run_cli, repo_of(make_repo, tmp_path), connected_gitlab(
        SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN), "--no-upload")  # the upload is test_connected_upload's
    assert code == 0
    exchange, policy = fake.requests
    assert exchange[:2] == ("POST", EXCHANGE_PATH) and "Authorization" not in exchange[2]
    assert exchange[3] == {"schema": 1, "org": "acme", "token": ID_TOKEN,
                           "client": {"scope": "", "default_branch": "main"}}  # a field the CI does not give is left out
    assert policy[:2] == ("GET", f"{POLICY_PATH}?scanner={__version__}") and policy[2]["Authorization"] == f"Bearer {swt}"
    block = report["connected"]
    assert block["credential"] == "oidc" and block["org"] == {"slug": "acme", "name": "Acme"}
    assert block["run"]["identity"] == "gitlab:gitlab.com/acme/tools" and block["run"]["scope"] == ""  # the server's run
    assert (block["run"]["kind"], block["run"]["event"], block["run"]["ref_name"]) == ("default_branch", "push", "main")
    assert block["registry"]["checked"] == 0 and block["registry"]["items"] == [] and block["upload"] == {
        "status": "skipped", "reason": "disabled"}  # the gate ran
    assert [e for e in report["errors"]] == [] and "connected_fallback" not in codes(report["notices"])
    for secret in (swt, ID_TOKEN):
        assert secret not in out + err


def test_org_on_github_requests_the_token_then_exchanges(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    url = fake.token_endpoint(200, {"value": "gh.provider.jwt"})
    fake.script("POST", EXCHANGE_PATH, 201, session_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    env = connected_github(tmp_path, SPELLWARDEN_ORG="acme", ACTIONS_ID_TOKEN_REQUEST_URL=url,
                           ACTIONS_ID_TOKEN_REQUEST_TOKEN="runner-request-token")
    code, report, out, err = scan_json(run_cli, repo_of(make_repo, tmp_path), env, "--verbose", "--no-upload")
    assert code == 0 and report["connected"]["credential"] == "oidc"
    token_request, exchange, _policy = fake.requests
    assert token_request[:2] == ("GET", "/idtoken?api-version=2.0&audience=https://dash.spellwarden.ai/ci/acme")
    assert token_request[2]["Authorization"] == "bearer runner-request-token"
    assert exchange[3]["token"] == "gh.provider.jwt" and exchange[3]["client"] == {"scope": "", "default_branch": "main"}
    for secret in ("gh.provider.jwt", "runner-request-token", url, credential("swt")):
        assert secret not in out + err
    assert "api: POST dash.spellwarden.ai/public/ci/token 201" in err  # --verbose shows the call, never a credential


def test_the_exchange_carries_the_request_fields_of_the_run(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = repo_of(make_repo, tmp_path)
    base = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, {"README.md": "changed\n"})
    fake.script("POST", EXCHANGE_PATH, 201, session_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    code, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base, SPELLWARDEN_ORG="acme",
                                                              SPELLWARDEN_ID_TOKEN=ID_TOKEN))
    assert code == 0
    assert fake.requests[0][3]["client"] == {"scope": "", "request_number": 3, "head_sha": HEAD, "default_branch": "main"}
    assert report["connected"]["run"]["kind"] == "request" and report["connected"]["run"]["head_sha"] == HEAD


def test_org_without_any_token_is_connected_no_credential_with_the_fix_message(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = repo_of(make_repo, tmp_path, {".spellwarden/config.yml": REQUIRED})
    code, report, _, _ = scan_json(run_cli, repo, connected_github(tmp_path, SPELLWARDEN_ORG="acme"))
    (error,) = report["errors"]
    assert code == 2 and error["code"] == "connected_required" and fake.requests == []
    assert "connected_no_credential" in error["message"] and "permissions: id-token: write" in error["message"]
    assert "id_tokens" in error["message"] and "use a CI key" in error["message"]


def test_key_session_is_get_orgs_with_caller_access_ci(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    swk = credential("swk")
    fake.script("GET", KEY_PATH, 200, orgs_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    code, report, out, err = scan_json(run_cli, repo_of(make_repo, tmp_path), connected_github(tmp_path, SPELLWARDEN_API_KEY=swk),
                                       "--no-upload")
    assert code == 0 and report["connected"]["credential"] == "key" and report["connected"]["org"]["name"] == "Acme"
    assert [request[0:2] for request in fake.requests] == [("GET", KEY_PATH), ("GET", f"{POLICY_PATH}?scanner={__version__}")]
    assert all(request[2]["Authorization"] == f"Bearer {swk}" for request in fake.requests)
    assert report["connected"]["run"]["identity"] == "github:github.com/acme/tools"  # the command's own run context
    assert swk not in out + err


@pytest.mark.parametrize(("answer", "expected"), [
    (orgs_answer(orgs=[]), "connected_auth"),
    (orgs_answer(orgs=[{"slug": "acme", "name": "A", "plan": "team", "billing_state": "active", "reachable": True},
                       {"slug": "beta", "name": "B", "plan": "team", "billing_state": "active", "reachable": True}]),
     "connected_auth"),
    (orgs_answer(access="read"), "connected_ci_key_required"), (orgs_answer(access="write"), "connected_ci_key_required"),
    (orgs_answer(access="owner"), "connected_auth"),
    (orgs_answer(orgs=[{"slug": "acme", "name": "Acme", "plan": "team", "billing_state": "read_only", "reachable": False}]),
     "connected_subscription"),
    ({"orgs": "nope"}, "connected_auth"),
])
def test_a_key_session_that_is_not_one_organisation_with_ci_access_follows_required(make_repo, run_cli, tmp_path, api_double,
                                                                                   answer, expected):
    fake, _ = api_double
    fake.script("GET", KEY_PATH, 200, answer)
    env = connected_github(tmp_path, SPELLWARDEN_API_KEY=credential("swk"))
    code, report, _, _ = scan_json(run_cli, repo_of(make_repo, tmp_path), env)  # required false: free mode
    assert code == 0 and "connected" not in report
    assert f"({expected})" in notice(report, "connected_fallback")["message"]
    assert [request[1] for request in fake.requests] == [KEY_PATH]  # no policy call without a session


@pytest.mark.parametrize(("status", "body", "expected"), [
    (401, {"error": "api_key_invalid"}, "connected_auth"), (402, {"error": "subscription_required"}, "connected_subscription"),
    (403, {"error": "ci_key_required"}, "connected_ci_key_required"), (403, {"error": "audience_mismatch"}, "connected_auth"),
    (503, {"error": "internal"}, "connected_unavailable"), (404, {"error": "not_found"}, "connected_unavailable"),
    (404, {"error": "org_not_found"}, "connected_auth"), (429, {"error": "rate_limited", "message": "slow"}, "connected_rate_limited"),
])
@pytest.mark.parametrize("required", [False, True])
def test_pre_session_failures_follow_required(make_repo, run_cli, tmp_path, api_double, status, body, expected, required):
    """P45 included: the exchange's 402 for a read-only organisation is pre-session like the other refusals."""
    fake, _ = api_double
    fake.script("POST", EXCHANGE_PATH, status, body, times=2)
    repo = repo_of(make_repo, tmp_path, {".spellwarden/config.yml": REQUIRED if required else NOT_REQUIRED})
    code, report, _, _ = scan_json(run_cli, repo, connected_gitlab(SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN))
    if required:
        (error,) = report["errors"]
        assert code == 2 and error["code"] == "connected_required" and expected in error["message"]
        assert error["message"].startswith("This repository requires connected mode (.spellwarden/config.yml) and the run could "
                                           "not connect: ")
    else:
        assert code == 0 and report["errors"] == [] and f"({expected})" in notice(report, "connected_fallback")["message"]
    assert all(request[1] == EXCHANGE_PATH for request in fake.requests)
    assert "connected" not in report


@pytest.mark.usefixtures("api_double")
def test_required_true_turns_the_decision_into_exit_2_with_detail(make_repo, run_cli, tmp_path):
    repo = repo_of(make_repo, tmp_path, {".spellwarden/config.yml": REQUIRED})
    env = connected_github(tmp_path)  # nothing was passed to the job: a dropped input, an empty secret
    code, report, out, _ = scan_json(run_cli, repo, env)
    (error,) = report["errors"]
    assert code == 2 and error["code"] == "connected_required" and "connected_no_credential" in error["message"]
    assert error["detail"] == "connected_no_credential"  # 6.9: `detail` carries the underlying code (r0:F5)
    assert "SPELLWARDEN_ORG" in error["message"] and "SPELLWARDEN_API_KEY" in error["message"]
    assert all("detail" not in n for n in report["notices"])
    _, markdown, _ = run_cli(["scan", str(repo), "--format", "markdown", "--no-telemetry"], env=env)
    unescaped = markdown.replace("\\", "")
    assert "connected_required" in unescaped and "SPELLWARDEN_API_KEY" in unescaped  # the comment says what to fix
    # outside CI the setting asks for nothing (6.2): the run is local
    assert run_cli(["scan", str(repo), "--format", "json", "--no-telemetry"])[0] == 0


def test_required_false_falls_back_with_the_notice_and_first_text_line(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = repo_of(make_repo, tmp_path, {"skills/deploy/SKILL.md": SKILL})
    env = connected_github(tmp_path, SPELLWARDEN_ORG="acme")
    code, out, _ = run_cli(["scan", str(repo), "--no-telemetry"], env=env)
    assert code == 0 and fake.requests == []
    first, *_rest = out.splitlines()
    assert first == "Connected mode unavailable (connected_no_credential): baseline rules only, nothing uploaded."
    assert "notice connected_fallback : Connected mode was not available (connected_no_credential); this run applied the " \
           "baseline rules only and uploaded nothing." in out
    code, markdown, _ = run_cli(["scan", str(repo), "--format", "markdown", "--no-telemetry"], env=env)
    assert "**Connected mode**" in markdown and "Connected mode unavailable (connected\\_no\\_credential)" in markdown


def test_a_local_run_without_a_credential_prints_nothing_about_connected_mode(make_repo, run_cli, tmp_path):
    repo = repo_of(make_repo, tmp_path, {".spellwarden/config.yml": REQUIRED})
    code, out, _ = run_cli(["scan", str(repo), "--no-telemetry"])
    assert code == 0 and "onnected" not in out.replace("notice", "")


def test_fork_pull_request_with_an_empty_key_secret_follows_required(make_repo, run_cli, tmp_path, api_double):
    """GitHub withholds secrets from a fork's pull request: the key is empty, no OIDC token exists."""
    fake, _ = api_double
    for required, expected_code in ((False, 0), (True, 2)):
        repo = make_repo(tmp_path / f"repo{required}", {"README.md": "x\n", ".spellwarden/config.yml": REQUIRED if required else NOT_REQUIRED})
        base = git(repo, "rev-parse", "HEAD").strip()
        commit(repo, {"README.md": "fork\n"})
        env = request_env(tmp_path, base, head_repo="mallory/tools", SPELLWARDEN_API_KEY="", GITHUB_ACTOR="mallory")
        code, report, _, _ = scan_json(run_cli, repo, env)
        assert code == expected_code and fake.requests == []
        if required:
            assert report["errors"][0]["code"] == "connected_required" and "connected_no_credential" in report["errors"][0]["message"]
        else:  # an empty secret and no `required`: connected mode was never asked for, so it is silent
            assert not [n for n in report["notices"] if n["code"].startswith(("connected", "fork_free", "dependabot_free"))]


@pytest.mark.parametrize("required", [False, True])
def test_fork_pull_request_with_a_key_is_fork_free_mode_then_required_decides(make_repo, run_cli, tmp_path, api_double,
                                                                              required):
    fake, _ = api_double
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", ".spellwarden/config.yml": REQUIRED if required else NOT_REQUIRED})
    base = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, {"README.md": "fork\n"})
    env = request_env(tmp_path, base, head_repo="mallory/tools", SPELLWARDEN_API_KEY=credential("swk"))
    code, report, out, err = scan_json(run_cli, repo, env)
    assert fake.requests == [] and credential("swk") not in out + err  # the key is ignored: nothing is sent
    if required:
        assert code == 2 and report["errors"][0]["code"] == "connected_required"
        assert "fork_free_mode" in report["errors"][0]["message"]
    else:
        assert code == 0 and "fork_free_mode" in codes(report["notices"])
        assert "(fork_free_mode)" in notice(report, "fork_free_mode")["message"]


def test_fork_free_mode_applies_to_no_other_event(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    fake.script("GET", KEY_PATH, 200, orgs_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    payload = {"pull_request": {"number": 3, "head": {"repo": {"full_name": "mallory/tools"}}}, "repository": {}}
    env = connected_github(tmp_path, "pull_request_target", payload, SPELLWARDEN_API_KEY=credential("swk"))
    code, report, _, _ = scan_json(run_cli, repo_of(make_repo, tmp_path), env)
    assert code == 0 and "fork_free_mode" not in codes(report["notices"]) and report["connected"]["credential"] == "key"


def dependabot_repo(make_repo, tmp_path: Path, head: dict, base_files: dict | None = None) -> tuple[Path, str]:
    """A repository whose base commit requires connected mode, and a head commit that changes `head`."""
    repo = make_repo(tmp_path / "repo", {"README.md": "x\n", "package.json": "{}\n", ".spellwarden/config.yml": REQUIRED,
                                         **(base_files or {})})
    base = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, head)
    return repo, base


def test_dependabot_with_no_candidate_in_scope_is_dependabot_free_mode_even_when_required(make_repo, run_cli, tmp_path,
                                                                                         api_double):
    fake, _ = api_double
    repo, base = dependabot_repo(make_repo, tmp_path, {"package.json": '{"name": "bumped"}\n'})
    env = request_env(tmp_path, base, GITHUB_ACTOR="dependabot[bot]")
    code, report, _, _ = scan_json(run_cli, repo, env)
    assert code == 0 and report["errors"] == [] and fake.requests == []
    assert "(connected_no_credential)" in notice(report, "dependabot_free_mode")["message"]
    assert "connected_fallback" not in codes(report["notices"])


@pytest.mark.parametrize(("base_files", "head"), [
    ({}, {"skills/deploy/SKILL.md": SKILL}),
    ({"skills/deploy/SKILL.md": SKILL}, {"skills/deploy/run.sh": "echo\n"}),
    ({}, {".mcp.json": '{"mcpServers": {"s": {"url": "https://m.example/mcp"}}}'}),
], ids=["a new skill", "a file of a skill", "a server entry"])
@pytest.mark.usefixtures("api_double")
def test_dependabot_with_a_candidate_in_scope_exits_2(make_repo, run_cli, tmp_path, base_files, head):
    repo, base = dependabot_repo(make_repo, tmp_path, head, base_files)
    code, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base, GITHUB_ACTOR="dependabot[bot]"))
    assert code == 2 and report["errors"][0]["code"] == "connected_required"
    assert "dependabot_free_mode" not in codes(report["notices"])


def test_a_missing_base_puts_every_dependabot_candidate_in_scope(make_repo, tmp_path):
    from spellwarden_cli import ci

    found = _found(make_repo, tmp_path, {"README.md": "x\n"})
    dependabot = ci.detect({"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_ACTOR": "dependabot[bot]",
                            "GITHUB_REPOSITORY": "acme/tools"}, read_text=lambda _p: '{"pull_request": {"number": 1}}')
    assert dependabot.dependabot and dependabot.is_request
    stop = connected.ConnectedStop("connected_no_credential", "No credential.")
    required = Settings(connected=Connected(required=True))
    error, free = connected.decide_stop(stop, required, dependabot, found, None)  # the base is unavailable
    assert error is not None and error.code == "connected_required" and free is None
    error, free = connected.decide_stop(stop, required, dependabot, found, [])  # a diff that holds nothing in scope
    assert error is None and free.code == "dependabot_free_mode"
    other = ci.detect({"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REPOSITORY": "acme/tools"},
                      read_text=lambda _p: '{"pull_request": {"number": 1}}')
    error, free = connected.decide_stop(stop, required, other, found, [])  # only Dependabot is exempt
    assert error is not None and free is None


@pytest.mark.usefixtures("api_double")
def test_required_added_by_the_request_itself_is_ignored(make_repo, run_cli, tmp_path):
    repo = repo_of(make_repo, tmp_path)
    base = git(repo, "rev-parse", "HEAD").strip()
    commit(repo, {".spellwarden/config.yml": REQUIRED})  # the request asks for connected mode it cannot be held to
    code, report, _, _ = scan_json(run_cli, repo, request_env(tmp_path, base))
    assert code == 0 and report["errors"] == [] and "connected_fallback" not in codes(report["notices"])
    assert "settings_from_base" in codes(report["notices"])
    # and the other way: a request cannot drop the requirement the base set
    repo2 = make_repo(tmp_path / "repo2", {"README.md": "x\n", ".spellwarden/config.yml": REQUIRED})
    base2 = git(repo2, "rev-parse", "HEAD").strip()
    commit(repo2, {".spellwarden/config.yml": NOT_REQUIRED})
    code, report, _, _ = scan_json(run_cli, repo2, request_env(tmp_path, base2))
    assert code == 2 and report["errors"][0]["code"] == "connected_required"


# --- after the session --------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("status", "body", "expected", "times"), [
    (503, {"error": "internal"}, "connected_unavailable", 2), (429, {"error": "rate_limited", "message": "Slow down"},
                                                             "connected_rate_limited", 2),
    (404, {"error": "not_found"}, "connected_unavailable", 1), (404, {"error": "pack_not_allowed", "message": "no"},
                                                               "policy_not_found", 1),
    (401, {"error": "api_key_expired"}, "connected_auth", 1), (402, {"error": "subscription_required"},
                                                              "connected_subscription", 1),
    (403, {"error": "ci_key_required"}, "connected_ci_key_required", 1),
])
@pytest.mark.parametrize("required", [False, True])
def test_post_session_failures_exit_2_whatever_required_says(make_repo, run_cli, tmp_path, api_double, status, body, expected,
                                                            times, required):
    fake, _ = api_double
    fake.script("POST", EXCHANGE_PATH, 201, session_answer())
    fake.script("GET", POLICY_PATH, status, body, times=times)
    repo = repo_of(make_repo, tmp_path, {".spellwarden/config.yml": REQUIRED if required else NOT_REQUIRED})
    code, report, _, _ = scan_json(run_cli, repo, connected_gitlab(SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN))
    assert code == 2 and codes(report["errors"]) == [expected] and "connected" not in report
    assert "connected_required" not in codes(report["errors"]) and "connected_fallback" not in codes(report["notices"])
    assert report["findings"] == [] and report["items"] == []  # an incomplete scan is never a pass


def test_connected_unavailable_message_for_a_missing_route(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    fake.script("POST", EXCHANGE_PATH, 201, session_answer())
    fake.script("GET", POLICY_PATH, 404, {"error": "not_found", "message": "no such route"})
    code, report, _, _ = scan_json(run_cli, repo_of(make_repo, tmp_path), connected_gitlab(SPELLWARDEN_ORG="acme",
                                                                                              SPELLWARDEN_ID_TOKEN=ID_TOKEN))
    assert code == 2 and report["errors"] == [{"code": "connected_unavailable", "path": "",
                                               "message": "Connected mode is not available yet on this server"}]


@pytest.mark.parametrize(("status", "body", "code_name", "text"), [
    (401, {"error": "api_key_invalid", "message": "Key revoked"}, "connected_auth",
     "The organisation did not accept this pipeline's identity: Key revoked. Check the CI connection under Settings, CI "
     "connections, or the SPELLWARDEN_API_KEY secret."),
    (402, {"error": "subscription_required"}, "connected_subscription",
     "The organisation's subscription is not active. Machine access is paused until billing is restored; people can still "
     "sign in."),
    (403, {"error": "ci_key_required"}, "connected_ci_key_required",
     "Connected mode needs a CI key. Create one under Settings, API keys, with access CI."),
    (404, {"error": "pack_not_allowed", "message": "Pack not in the list"}, "policy_not_found",
     "The pack named in .spellwarden/config.yml is not one this organisation allows for CI: Pack not in the list."),
    (429, {"error": "rate_limited", "message": "Too many runs"}, "connected_rate_limited",
     "A Spellwarden limit, not an outage, stopped this call: Too many runs."),
])
def test_the_error_texts_are_the_spec_texts(make_repo, run_cli, tmp_path, api_double, status, body, code_name, text):
    fake, _ = api_double
    fake.script("POST", EXCHANGE_PATH, 201, session_answer())
    fake.script("GET", POLICY_PATH, status, body, times=2)
    _, report, _, _ = scan_json(run_cli, repo_of(make_repo, tmp_path), connected_gitlab(SPELLWARDEN_ORG="acme",
                                                                                          SPELLWARDEN_ID_TOKEN=ID_TOKEN))
    assert report["errors"] == [{"code": code_name, "path": "", "message": text}]


def test_a_malformed_policy_answer_is_connected_unavailable_exit_2(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    fake.script("POST", EXCHANGE_PATH, 201, session_answer())
    broken = policy_answer([])
    del broken["limits"]
    fake.script("GET", POLICY_PATH, 200, broken)
    code, report, _, _ = scan_json(run_cli, repo_of(make_repo, tmp_path), connected_gitlab(SPELLWARDEN_ORG="acme",
                                                                                              SPELLWARDEN_ID_TOKEN=ID_TOKEN))
    assert code == 2 and codes(report["errors"]) == ["connected_unavailable"] and "connected" not in report


# --- the configuration errors of 6.2 -------------------------------------------------------------------------------

def test_a_scan_root_outside_the_scope_grammar_is_connected_config_before_any_request(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    repo = make_repo(tmp_path / "repo", {"a b/README.md": "x\n"})
    code, report, _, _ = scan_json(run_cli, repo / "a b", connected_gitlab(SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN))
    assert code == 2 and report["errors"] == [{"code": "connected_config", "path": "", "message":
                                              "the scan root's path cannot be a scan root in connected mode: a b"}]
    assert fake.requests == []
    # free mode scans the same directory as before
    assert run_cli(["scan", str(repo / "a b"), "--no-telemetry"])[0] == 0


def test_the_scan_scope_below_the_work_tree_is_the_exchange_scope(make_repo, run_cli, tmp_path, api_double):
    fake, _ = api_double
    fake.script("POST", EXCHANGE_PATH, 201, session_answer())
    fake.script("GET", POLICY_PATH, 200, policy_answer([]))
    repo = make_repo(tmp_path / "repo", {"services/agent/README.md": "x\n"})
    code, report, _, _ = scan_json(run_cli, repo / "services" / "agent", connected_gitlab(
        SPELLWARDEN_ORG="acme", SPELLWARDEN_ID_TOKEN=ID_TOKEN))
    assert code == 0 and fake.requests[0][3]["client"]["scope"] == "services/agent"
    assert report["connected"]["run"]["scope"] == "services/agent"


@pytest.mark.parametrize("org", ["Acme", "a", "acme corp", "acme/evil", "a" * 65])
def test_an_org_that_is_not_a_slug_is_connected_config(make_repo, run_cli, tmp_path, api_double, org):
    fake, _ = api_double
    code, report, _, _ = scan_json(run_cli, repo_of(make_repo, tmp_path), connected_gitlab(SPELLWARDEN_ORG=org,
                                                                                              SPELLWARDEN_ID_TOKEN=ID_TOKEN))
    assert code == 2 and codes(report["errors"]) == ["connected_config"] and fake.requests == []


# --- the pure parts ------------------------------------------------------------------------------------------------

def test_activation_is_the_one_owner_of_the_decision():
    from spellwarden_cli import ci

    github = ci.detect({"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push"}, read_text=lambda _p: "{}")
    required = Settings(connected=Connected(required=True))
    empty = Credentials(None, None, None, None, None)
    assert connected.activation(Settings(), github, empty) is None
    assert connected.activation(Settings(), ci.LOCAL, Credentials("acme", None, None, None, None)) == "org"
    assert connected.activation(Settings(), github, Credentials(None, Secret("k"), None, None, None)) == "key"
    assert connected.activation(required, github, empty) == "required"
    assert connected.activation(required, ci.LOCAL, empty) is None  # `required` asks for nothing outside CI
    assert connected.activation(required, github, Credentials("acme", None, None, None, None)) == "org"


def test_the_resolver_names_are_the_engines():
    from spellwarden_scan import identity

    assert connected.RESOLVER_NAMES == frozenset(identity._RESOLVER_FILES)


def _found(make_repo, tmp_path, files: dict, links: dict | None = None):
    repo = make_repo(tmp_path / "repo", files)
    for link, target in (links or {}).items():
        os.makedirs(os.path.dirname(repo / link), exist_ok=True)
        os.symlink(target, repo / link)
    return discover(list_files(str(repo), Settings()))


MCP_HTTP = '{"mcpServers": {"s": {"url": "https://m.example/mcp"}}}'
MCP_STDIO = '{"mcpServers": {"s": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}}'


def test_dependabot_candidates_in_scope(make_repo, tmp_path):
    found = _found(make_repo, tmp_path, {"skills/a/SKILL.md": SKILL, "shared/run.sh": "echo\n", "src/app.py": "x\n", ".mcp.json": MCP_HTTP,
                                         "package.json": "{}\n", "plain/README.md": "x\n"},
                   links={"skills/a/tool.sh": "../../shared/run.sh"})
    scope = connected.dependabot_candidates_in_scope
    assert scope(found, None) is True  # the base is unavailable: everything is in scope
    assert scope(found, []) is False and scope(found, ["package.json", "src/app.py", "plain/README.md"]) is False
    assert scope(found, ["skills/a/SKILL.md"]) is True and scope(found, ["skills/a/new.md"]) is True
    assert scope(found, ["skills/a2/x.md"]) is False  # a sibling directory is not under the skill
    assert scope(found, ["shared/run.sh"]) is True  # a file a followed link of the skill points at
    assert scope(found, [".mcp.json"]) is True  # a document holding a server
    assert scope(found, ["package.json", ".npmrc"]) is False  # a resolver file matters only where a stdio entry exists
    stdio = _found(make_repo, tmp_path / "stdio", {".mcp.json": MCP_STDIO, "README.md": "x\n"})
    assert scope(stdio, [".npmrc"]) is True and scope(stdio, ["pip.conf"]) is True and scope(stdio, ["README.md"]) is False


def test_the_root_skill_puts_every_change_in_scope(make_repo, tmp_path):
    found = _found(make_repo, tmp_path, {"SKILL.md": SKILL, "run.sh": "echo\n"})
    assert connected.dependabot_candidates_in_scope(found, ["anything.txt"]) is True


def test_run_scan_defaults_leave_free_mode_alone(make_repo, tmp_path, monkeypatch):
    """Without a credential and without `required` the connected module is never asked to establish anything."""
    monkeypatch.setattr(connected, "establish", lambda *_a, **_k: pytest.fail("establish called in free mode"))
    from datetime import date

    repo = repo_of(make_repo, tmp_path)
    report = run.scan(run.ScanOptions(root=str(repo), settings=Settings(), as_of=date(2026, 12, 1)))
    assert report.connected is None and report.exit_code() == 0
