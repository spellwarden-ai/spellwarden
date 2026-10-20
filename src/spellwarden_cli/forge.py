"""The pull and merge request comment (spec 6.11): one comment per request, found by its marker and updated in
place, posted with the token the pipeline gave, to the API URL the CI gives, and nowhere else.

A comment never fails the check: every outcome other than success is a `Notice`, `comment_permission` when the
forge refused for want of a permission (403, 404: fork and Dependabot tokens are read-only, or `pull-requests:
write` was not granted), `comment_failed` for anything else, `comment_token_missing` without a token.

One of the three modules of `spellwarden_cli` that may reach the network (`tests/test_network_boundary.py`)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from urllib.parse import quote, urlsplit

from spellwarden_scan.version import __version__

from spellwarden_cli.output.markdown import MARKER  # one marker: the report's first line is what this module finds
from spellwarden_cli.report import Notice

MAX_PAGES = 10
PER_PAGE = 100
TIMEOUT_SECONDS = 10
GITHUB_ACTIONS_BOT = "github-actions[bot]"
_urlopen = urllib.request.urlopen  # tests replace it (tests/cli/test_forge.py)


class _NoToken(Exception):
    pass


class _Refused(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


def _call(opener: Callable[..., object], method: str, url: str, headers: dict[str, str], body: object = None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        **headers, "User-Agent": f"Spellwarden/{__version__} (+https://spellwarden.ai)",
        **({"Content-Type": "application/json"} if data is not None else {})})
    try:
        with opener(request, timeout=TIMEOUT_SECONDS) as response:
            payload = response.read(8 * 2**20)
    except urllib.error.HTTPError as exc:
        raise _Refused(exc.code) from None
    return json.loads(payload.decode("utf-8")) if payload else None


def _api(url: str | None) -> str | None:
    """The API base URL the CI gave, without a trailing slash; None when it is not an absolute HTTP(S) URL."""
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return None
    if parts.scheme not in ("https", "http") or not parts.hostname:
        return None
    return (url or "").rstrip("/")


def _permission(provider: str) -> Notice:
    if provider == "github":
        return Notice("comment_permission", "", "the token cannot comment on this pull request: grant `pull-requests: "
                      "write` to the workflow (fork and Dependabot pull requests always get a read-only token)")
    return Notice("comment_permission", "", "SPELLWARDEN_GITLAB_TOKEN cannot write merge request notes: use a project "
                  "access token with the `api` scope and at least the Reporter role")


def _failed(status: object) -> Notice:
    return Notice("comment_failed", "", f"the comment was not posted ({status})")


def _github(body: str, env: Mapping[str, str], number: int, opener) -> None:
    token = env.get("SPELLWARDEN_GITHUB_TOKEN") or env.get("GITHUB_TOKEN")
    if not token:
        raise _NoToken("GITHUB_TOKEN")
    api = _api(env.get("GITHUB_API_URL") or "https://api.github.com")
    repository = env.get("GITHUB_REPOSITORY") or ""
    if api is None or repository.count("/") != 1:
        raise ValueError("GITHUB_API_URL or GITHUB_REPOSITORY")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    base = f"{api}/repos/{repository}"
    try:  # a personal token names its user; the workflow's GITHUB_TOKEN cannot read /user and comments as the bot
        user = _call(opener, "GET", f"{api}/user", headers)
        login = user.get("login") if isinstance(user, dict) else None
    except _Refused:
        login = None
    login = login or GITHUB_ACTIONS_BOT
    existing = None
    for page in range(1, MAX_PAGES + 1):
        comments = _call(opener, "GET", f"{base}/issues/{number}/comments?per_page={PER_PAGE}&page={page}", headers)
        comments = comments if isinstance(comments, list) else []
        for comment in comments:
            author = comment.get("user") if isinstance(comment, dict) else None
            if (isinstance(comment.get("body"), str) and comment["body"].startswith(MARKER) and isinstance(author, dict)
                    and author.get("login") == login and isinstance(comment.get("id"), int)):
                existing = comment["id"]
                break
        if existing is not None or len(comments) < PER_PAGE:
            break
    if existing is not None:
        _call(opener, "PATCH", f"{base}/issues/comments/{existing}", headers, {"body": body})
    else:
        _call(opener, "POST", f"{base}/issues/{number}/comments", headers, {"body": body})


def _gitlab(body: str, env: Mapping[str, str], number: int, opener) -> None:
    token = env.get("SPELLWARDEN_GITLAB_TOKEN")
    if not token:  # CI_JOB_TOKEN cannot write notes
        raise _NoToken("SPELLWARDEN_GITLAB_TOKEN")
    api = _api(env.get("CI_API_V4_URL"))
    project = env.get("CI_PROJECT_ID") or ""
    if api is None or not project:
        raise ValueError("CI_API_V4_URL or CI_PROJECT_ID")
    headers = {"PRIVATE-TOKEN": token}
    base = f"{api}/projects/{quote(project, safe='')}/merge_requests/{number}/notes"
    user = _call(opener, "GET", f"{api}/user", headers)
    username = user.get("username") if isinstance(user, dict) else None
    existing = None
    for page in range(1, MAX_PAGES + 1):
        notes = _call(opener, "GET", f"{base}?per_page={PER_PAGE}&page={page}&sort=asc&order_by=created_at", headers)
        notes = notes if isinstance(notes, list) else []
        for note in notes:
            author = note.get("author") if isinstance(note, dict) else None
            if (isinstance(note.get("body"), str) and note["body"].startswith(MARKER) and isinstance(author, dict)
                    and author.get("username") == username and not note.get("system") and isinstance(note.get("id"), int)):
                existing = note["id"]
                break
        if existing is not None or len(notes) < PER_PAGE:
            break
    if existing is not None:
        _call(opener, "PUT", f"{base}/{existing}", headers, {"body": body})
    else:
        _call(opener, "POST", base, headers, {"body": body})


def post_comment(provider: str, body: str, *, env: Mapping[str, str], ctx, opener: Callable[..., object] | None = None
                 ) -> Notice | None:
    """Finds the comment of the token's user that starts with `MARKER` (at most 10 pages of 100) and updates it, or
    creates one. None on success; a `Notice` otherwise. Never raises."""
    if not (ctx.is_request and ctx.request_number is not None):
        return Notice("comment_no_request", "", "this run has no pull or merge request to comment on")
    try:
        if provider == "github":
            _github(body, env, ctx.request_number, opener or _urlopen)
        elif provider == "gitlab":
            _gitlab(body, env, ctx.request_number, opener or _urlopen)
        else:
            return _failed(f"unknown provider {provider!r}")
    except _NoToken as exc:
        return Notice("comment_token_missing", "", f"no {exc.args[0]}: the comment was skipped")
    except _Refused as exc:
        return _permission(provider) if exc.status in (403, 404) else _failed(f"status {exc.status}")
    except Exception as exc:  # noqa: BLE001 -- a comment never fails the check (spec 6.11)
        return _failed(type(exc).__name__)
    return None


__all__ = ["MARKER", "MAX_PAGES", "PER_PAGE", "post_comment"]
