"""Spec 6.11 and claim C17: `spellwarden ci comment` against recorded GitHub and GitLab APIs. One marked comment,
created or updated; a refused permission or any failure is a notice, never a failed check."""
from __future__ import annotations

import os

import pytest
from fake_http import RecordedOpener, load

from spellwarden_cli import ci, forge
from spellwarden_cli.report import Notice

BODY = forge.MARKER + "\n**Spellwarden**: passed."
GITHUB_ENV = {"GITHUB_TOKEN": "ghs-test-token", "GITHUB_API_URL": "https://api.github.com", "GITHUB_REPOSITORY": "acme/agents"}
GITLAB_ENV = {"SPELLWARDEN_GITLAB_TOKEN": "glpat-test-token", "CI_API_V4_URL": "https://gitlab.example/api/v4",
              "CI_PROJECT_ID": "42"}
PR = ci.CiContext(provider="github", event="pull_request", is_request=True, request_number=7, fork=False,
                  dependabot=False, protected_ref=False, identity=None)
MR = ci.CiContext(provider="gitlab", event="merge_request_event", is_request=True, request_number=5, fork=False,
                  dependabot=False, protected_ref=False, identity=None)


def github(scenario: str, env: dict | None = None):
    opener = RecordedOpener(load("forge_github", scenario))
    return forge.post_comment("github", BODY, env=env or GITHUB_ENV, ctx=PR, opener=opener), opener


def gitlab(scenario: str, env: dict | None = None):
    opener = RecordedOpener(load("forge_gitlab", scenario))
    return forge.post_comment("gitlab", BODY, env=env or GITLAB_ENV, ctx=MR, opener=opener), opener


def writes(opener) -> list[tuple[str, str, dict | None]]:
    return [(r["method"], r["url"], r["body"]) for r in opener.requests if r["method"] in ("POST", "PATCH", "PUT")]


def test_github_creates_a_comment_when_none_of_its_own_is_marked():
    notice, opener = github("create")
    assert notice is None
    assert writes(opener) == [("POST", "https://api.github.com/repos/acme/agents/issues/7/comments", {"body": BODY})]
    sent = opener.requests[-1]["headers"]
    assert sent["authorization"] == "Bearer ghs-test-token" and sent["accept"] == "application/vnd.github+json"
    assert all(r["url"].startswith("https://api.github.com/") for r in opener.requests)


def test_github_updates_the_first_marked_comment_of_the_token_user():
    notice, opener = github("update")
    assert notice is None
    assert writes(opener) == [("PATCH", "https://api.github.com/repos/acme/agents/issues/comments/11", {"body": BODY})]
    notice, opener = github("personal_token", {**GITHUB_ENV, "SPELLWARDEN_GITHUB_TOKEN": "ghp-personal"})
    assert notice is None and writes(opener)[0][1].endswith("/issues/comments/22")
    assert opener.requests[0]["headers"]["authorization"] == "Bearer ghp-personal"


@pytest.mark.parametrize("scenario", ["forbidden", "not_found"])
def test_github_403_and_404_are_a_permission_notice(scenario):
    notice, _ = github(scenario)
    assert notice.code == "comment_permission" and "pull-requests: write" in notice.message


def test_github_other_failures_are_comment_failed():
    notice, _ = github("server_error")
    assert notice == Notice("comment_failed", "", "the comment was not posted (status 500)")
    notice = forge.post_comment("github", BODY, env=GITHUB_ENV, ctx=PR, opener=RecordedOpener([]))
    assert notice.code == "comment_failed"  # the API cannot be reached at all


def test_github_reads_at_most_ten_pages_of_one_hundred():
    base = "https://api.github.com/repos/acme/agents/issues/7/comments?per_page=100&page="
    page = [{"id": n, "user": {"login": "octo"}, "body": "chatter"} for n in range(100)]
    exchanges = [{"method": "GET", "url": "https://api.github.com/user", "status": 403, "body": {}}]
    exchanges += [{"method": "GET", "url": f"{base}{n}", "status": 200, "body": page} for n in range(1, 12)]
    exchanges += [{"method": "POST", "url": "https://api.github.com/repos/acme/agents/issues/7/comments", "status": 201, "body": {}}]
    opener = RecordedOpener(exchanges)
    assert forge.post_comment("github", BODY, env=GITHUB_ENV, ctx=PR, opener=opener) is None
    assert [r["url"][len(base):] for r in opener.requests if r["url"].startswith(base)] == [str(n) for n in range(1, 11)]
    marked = page[:-1] + [{"id": 777, "user": {"login": "github-actions[bot]"}, "body": forge.MARKER}]
    opener = RecordedOpener(exchanges[:1] + [{"method": "GET", "url": f"{base}1", "status": 200, "body": page},
                                             {"method": "GET", "url": f"{base}2", "status": 200, "body": marked},
                                             {"method": "PATCH", "url": "https://api.github.com/repos/acme/agents/issues/comments/777",
                                              "status": 200, "body": {}}])
    assert forge.post_comment("github", BODY, env=GITHUB_ENV, ctx=PR, opener=opener) is None
    assert writes(opener)[0][0] == "PATCH"


def test_gitlab_creates_and_updates_merge_request_notes():
    notice, opener = gitlab("create")
    assert notice is None
    assert writes(opener) == [("POST", "https://gitlab.example/api/v4/projects/42/merge_requests/5/notes", {"body": BODY})]
    assert opener.requests[-1]["headers"]["private-token"] == "glpat-test-token"
    notice, opener = gitlab("update")
    assert notice is None
    assert writes(opener) == [("PUT", "https://gitlab.example/api/v4/projects/42/merge_requests/5/notes/9", {"body": BODY})]


def test_gitlab_refusal_failure_and_missing_token():
    assert gitlab("forbidden")[0].code == "comment_permission"
    assert gitlab("server_error")[0] == Notice("comment_failed", "", "the comment was not posted (status 502)")
    notice, opener = gitlab("create", {**GITLAB_ENV, "SPELLWARDEN_GITLAB_TOKEN": "", "CI_JOB_TOKEN": "job"})
    assert notice.code == "comment_token_missing" and opener.requests == []


def test_no_request_no_comment_and_no_token_no_call():
    push = ci.CiContext(provider="github", event="push", is_request=False, request_number=None, fork=False,
                        dependabot=False, protected_ref=True, identity=None)
    opener = RecordedOpener([])
    assert forge.post_comment("github", BODY, env=GITHUB_ENV, ctx=push, opener=opener).code == "comment_no_request"
    assert forge.post_comment("github", BODY, env={}, ctx=PR, opener=opener).code == "comment_token_missing"
    assert opener.requests == []


def test_the_command_always_exits_zero(tmp_path, monkeypatch, capsys):
    body = tmp_path / "report.md"
    body.write_text(BODY, encoding="utf-8")
    event = tmp_path / "event.json"
    event.write_text('{"pull_request": {"number": 7, "head": {"repo": {"full_name": "acme/agents"}}}}', encoding="utf-8")
    for name, value in {**GITHUB_ENV, "CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
                        "GITHUB_EVENT_PATH": str(event)}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(forge, "_urlopen", RecordedOpener(load("forge_github", "forbidden")))
    parser_args = type("Args", (), {"provider": "github", "body": str(body)})()
    assert ci.cmd_comment(parser_args) == 0
    assert "::notice title=Spellwarden::comment_permission:" in capsys.readouterr().err
    missing = type("Args", (), {"provider": "github", "body": str(tmp_path / "absent.md")})()
    assert ci.cmd_comment(missing) == 0
    assert "comment_failed" in capsys.readouterr().err


def _comment_args(path) -> object:
    return type("Args", (), {"provider": "github", "body": str(path)})()


def test_the_command_never_reads_the_body_through_a_symlink_or_from_a_non_file(tmp_path, monkeypatch, capsys):
    posted: list[str] = []
    monkeypatch.setattr(forge, "post_comment", lambda _provider, body, **_kwargs: posted.append(body))
    secret = tmp_path / "environ"
    secret.write_bytes((BODY + "\nGITHUB_TOKEN=secret\n").encode("utf-8"))
    link = tmp_path / "report.md"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("symbolic links cannot be created here")
    assert ci.cmd_comment(_comment_args(link)) == 0
    assert posted == [] and "comment_failed" in capsys.readouterr().err
    assert ci.cmd_comment(_comment_args(tmp_path)) == 0  # a directory
    assert posted == [] and "comment_failed" in capsys.readouterr().err
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo.md"
        os.mkfifo(fifo)
        assert ci.cmd_comment(_comment_args(fifo)) == 0  # neither blocks nor reads
        assert posted == [] and "comment_failed" in capsys.readouterr().err
    big = tmp_path / "big.md"
    big.write_bytes(b"x" * (ci.BODY_MAX + 1))
    assert ci.cmd_comment(_comment_args(big)) == 0
    assert posted == []
    regular = tmp_path / "ok.md"
    regular.write_bytes(BODY.encode("utf-8"))  # no `\r\n` on Windows
    assert ci.cmd_comment(_comment_args(regular)) == 0
    assert posted == [BODY]
