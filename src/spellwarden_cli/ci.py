"""CI detection (spec 6.11), the trust rule for private probing (6.8), the installation identity of the usage ping
(6.10), and the two CI commands: `spellwarden ci comment` and `spellwarden ci-run gitlab` (10.2a).

Detection reads environment variables and, on GitHub, the event file; nothing else. Where it cannot tell, it gives
the restrictive answer: an unknown event or an unreadable event file is a pull request, and a pull request whose
head repository cannot be read is a fork; a CI system's own marker makes a run CI even without `CI=true`."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from spellwarden_cli import escape
from spellwarden_cli.report import Notice
from spellwarden_cli.settings import FAIL_ON

GITHUB_REQUEST_EVENTS = ("pull_request", "pull_request_target", "merge_group")
GITLAB_REQUEST_SOURCES = ("merge_request_event", "external_pull_request_event")
# Spec 6.8: the only events whose run, on a protected ref, may probe private addresses. An allowlist: any other
# event (a comment, a review, a workflow_run, a dispatch, one added later) is untrusted.
GITHUB_TRUSTED_EVENTS = ("push", "schedule", "workflow_dispatch")
GITLAB_TRUSTED_SOURCES = ("push", "schedule", "web")
DEPENDABOT = "dependabot[bot]"
IDENTITY_PREFIX = "spellwarden-ping-v1:"
EVENT_FILE_MAX = 25 * 2**20
BODY_MAX = 2**20
_TRUE = ("1", "true", "yes", "on")
# The outputs of `ci-run gitlab`, in the job's working directory, as templates/scan.yml lists them (spec 10.2).
# Spec 6.11: variables a CI system sets whether or not it sets `CI=true`. Any of them, non-empty, makes the run CI
# (`other` unless it is GitHub or GitLab): detection fails closed, so a CI job is never mistaken for a trusted
# local run. A generic name such as `BUILD_ID` is not one: local tools set it too, and Jenkins always sets
# `JENKINS_URL`.
CI_MARKERS = ("JENKINS_URL", "TF_BUILD", "TEAMCITY_VERSION", "BUILDKITE", "CIRCLECI",
              "BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "DRONE", "TRAVIS")
GITLAB_OUTPUTS = (("gitlab-codequality", "gl-code-quality-report.json"), ("sarif", "spellwarden.sarif"),
                  ("markdown", "spellwarden.md"), ("json", "spellwarden.json"))
GITLAB_MARKDOWN = dict(GITLAB_OUTPUTS)["markdown"]
_SCP_REMOTE = re.compile(r"^[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):/?([^/]+)/")


@dataclass(frozen=True)
class CiContext:
    provider: str | None          # "github" | "gitlab" | "other"; None for a local run (no CI variable or marker)
    event: str | None             # GITHUB_EVENT_NAME or CI_PIPELINE_SOURCE
    is_request: bool              # a pull or merge request, or unknown (treated as one)
    request_number: int | None    # the pull request number or the merge request IID
    fork: bool
    dependabot: bool
    protected_ref: bool           # GITHUB_REF_PROTECTED / CI_COMMIT_REF_PROTECTED is true
    identity: str | None          # the installation identity of 6.10, before hashing


LOCAL = CiContext(provider=None, event=None, is_request=False, request_number=None, fork=False, dependabot=False,
                  protected_ref=False, identity=None)


def _true(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUE


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read(EVENT_FILE_MAX)


def git_remote_of(root: str) -> str | None:
    """`git remote get-url origin` of the work tree holding `root`, with `safe.directory` set to that one work tree
    (spec 6.4), or None."""
    from spellwarden_cli.files import work_tree_top

    top = work_tree_top(root)
    if top is None:
        return None
    try:
        done = subprocess.run(["git", "-c", f"safe.directory={top}", "-C", root, "remote", "get-url", "origin"],
                              capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    url = done.stdout.strip()
    return url if done.returncode == 0 and url else None


def _git_remote() -> str | None:
    return git_remote_of(os.getcwd())


def _host_of(url: str | None) -> str | None:
    try:
        host = urlsplit(url or "").hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _github(env: Mapping[str, str], read_text: Callable[[str], str]) -> CiContext:
    event = env.get("GITHUB_EVENT_NAME") or None
    payload: object = None
    path = env.get("GITHUB_EVENT_PATH")
    if path:
        try:
            payload = json.loads(read_text(path))
        except (OSError, ValueError):
            payload = None
    readable = isinstance(payload, dict)
    pull = payload.get("pull_request") if readable else None
    run = payload.get("workflow_run") if readable and event == "workflow_run" else None
    issue = payload.get("issue") if readable and event == "issue_comment" else None
    run_of_request = isinstance(run, dict) and run.get("event") in GITHUB_REQUEST_EVENTS
    comment_on_request = isinstance(issue, dict) and issue.get("pull_request") is not None
    # Every `pull_request*` event (pull_request_review, pull_request_review_comment, ...) is a request too.
    is_request = (event is None or not readable or event in GITHUB_REQUEST_EVENTS or event.startswith("pull_request")
                  or run_of_request or comment_on_request)
    number = _int(pull.get("number")) if isinstance(pull, dict) else None
    fork = False
    if run_of_request:  # the run's head repository; missing means a fork
        head_repo = run.get("head_repository")
        full_name = head_repo.get("full_name") if isinstance(head_repo, dict) else None
        fork = not isinstance(full_name, str) or full_name != env.get("GITHUB_REPOSITORY")
    elif comment_on_request:  # the payload names no head repository: assume a fork
        fork = True
    elif is_request:
        head = pull.get("head") if isinstance(pull, dict) else None
        repo = head.get("repo") if isinstance(head, dict) else None
        full_name = repo.get("full_name") if isinstance(repo, dict) else None
        fork = not isinstance(full_name, str) or full_name != env.get("GITHUB_REPOSITORY")
    host = _host_of(env.get("GITHUB_SERVER_URL"))
    owner_id = env.get("GITHUB_REPOSITORY_OWNER_ID") or ""
    identity = f"github:{host}:{owner_id}" if host and owner_id.isdigit() else None
    return CiContext(provider="github", event=event, is_request=is_request, request_number=number, fork=fork,
                     dependabot=env.get("GITHUB_ACTOR") == DEPENDABOT, protected_ref=_true(env.get("GITHUB_REF_PROTECTED")),
                     identity=identity)


def _gitlab(env: Mapping[str, str]) -> CiContext:
    source = env.get("CI_PIPELINE_SOURCE") or None
    is_request = source is None or source in GITLAB_REQUEST_SOURCES
    number = _int(env.get("CI_MERGE_REQUEST_IID"))
    fork = False
    if is_request:
        origin = env.get("CI_MERGE_REQUEST_SOURCE_PROJECT_ID")
        fork = not origin or origin != env.get("CI_PROJECT_ID")
    host = (env.get("CI_SERVER_HOST") or "").strip().lower()
    namespace = (env.get("CI_PROJECT_ROOT_NAMESPACE") or "").strip()
    identity = f"gitlab:{host}:{namespace}" if host and namespace else None
    return CiContext(provider="gitlab", event=source, is_request=is_request, request_number=number, fork=fork,
                     dependabot=False, protected_ref=_true(env.get("CI_COMMIT_REF_PROTECTED")), identity=identity)


def _remote_identity(url: str | None) -> str | None:
    """`other:<host>/<owner>` from an origin URL: `https://host/owner/repo`, `ssh://git@host:22/owner/repo` or
    `git@host:owner/repo.git`; credentials and ports are dropped, the host is lower-cased."""
    if not url:
        return None
    match = _SCP_REMOTE.match(url)
    if match and "://" not in url:
        host, owner = match.group(1).lower(), match.group(2)
    else:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
        except ValueError:
            return None
        segments = [segment for segment in parts.path.split("/") if segment]
        owner = segments[0] if len(segments) >= 2 else ""
    if not host or not owner:
        return None
    return f"other:{host}/{owner}"


def detect(env: Mapping[str, str], *, read_text: Callable[[str], str] = _read_text,
           git_remote: Callable[[], str | None] = _git_remote) -> CiContext:
    """Spec 6.11: the provider, the event, whether the run is a pull or merge request, its number, fork and
    Dependabot, ref protection and the installation identity. A local run (neither `CI` true nor one of
    `CI_MARKERS` set) is `LOCAL`."""
    if _true(env.get("GITHUB_ACTIONS")):
        return _github(env, read_text)
    if _true(env.get("GITLAB_CI")):
        return _gitlab(env)
    if _true(env.get("CI")) or any(env.get(name) for name in CI_MARKERS):
        try:
            identity = _remote_identity(git_remote())
        except Exception:  # noqa: BLE001 -- an identity is optional; the ping then carries null
            identity = None
        return CiContext(provider="other", event=None, is_request=False, request_number=None, fork=False,
                         dependabot=False, protected_ref=False, identity=identity)
    return LOCAL


def private_probe_trusted(ctx: CiContext) -> bool:
    """Spec 6.8: a local run, or a CI run on a protected ref whose event is on the allowlist (GitHub `push`,
    `schedule`, `workflow_dispatch`; GitLab `push`, `schedule`, `web`) and is not a pull or merge request. Trust
    never comes from the absence of a pull request alone; every other or unknown event, and `other` CI, is
    untrusted."""
    if ctx.provider is None:
        return True
    if ctx.provider == "github":
        return ctx.protected_ref and not ctx.is_request and ctx.event in GITHUB_TRUSTED_EVENTS
    if ctx.provider == "gitlab":
        return ctx.protected_ref and not ctx.is_request and ctx.event in GITLAB_TRUSTED_SOURCES
    return False


def org_hash(identity: str | None) -> str | None:
    """Spec 6.10: the SHA-256 hex of `spellwarden-ping-v1:` and the installation identity; pseudonymous, not
    anonymous (anyone who knows an identity can compute its hash)."""
    if not identity:
        return None
    return hashlib.sha256((IDENTITY_PREFIX + identity).encode("utf-8")).hexdigest()


def emit(ctx: CiContext, notice: Notice, *, stream=None) -> None:
    """One notice line on stderr: a workflow command on GitHub (`::notice::`), plain text elsewhere."""
    text = escape.terminal(f"{notice.code}: {notice.message}")
    line = f"::notice title=Spellwarden::{text}" if ctx.provider == "github" else f"spellwarden: notice {text}"
    print(line, file=stream or sys.stderr)


# --- `spellwarden ci comment` -----------------------------------------------------------------------------------

def read_body(path: str) -> str:
    """The comment body (spec 6.13): a regular file opened without following a symbolic link in its last component
    (`O_NOFOLLOW`; where the platform lacks it, a link is refused before opening), never a FIFO or device (opened
    non-blocking, then `fstat`), at most `BODY_MAX` bytes of UTF-8. Raises `OSError` or `ValueError`."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow and os.path.islink(path):
        raise ValueError("the comment body is a symbolic link")
    fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("the comment body is not a regular file")
        chunks: list[bytes] = []
        size = 0
        while size <= BODY_MAX:
            chunk = os.read(fd, BODY_MAX + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    if size > BODY_MAX:
        raise ValueError("the comment body is over 1 MiB")
    return b"".join(chunks).decode("utf-8")


def cmd_comment(args: argparse.Namespace) -> int:
    """Spec 6.11: posts or updates the one marked comment; always exits 0 (a comment never fails the check)."""
    from spellwarden_cli import forge

    ctx = detect(os.environ)
    try:
        text = read_body(args.body)
    except (OSError, ValueError) as exc:
        emit(ctx, Notice("comment_failed", "", f"cannot read the comment body: {type(exc).__name__}"))
        return 0
    notice = forge.post_comment(args.provider, text, env=os.environ, ctx=ctx)
    if notice is not None:
        emit(ctx, notice)
    return 0


# --- `spellwarden ci-run gitlab` (spec 10.2a) -------------------------------------------------------------------

def _choice(env: Mapping[str, str], name: str, label: str, allowed: tuple[str, ...], problems: list[str]) -> str:
    value = env.get(name, "")
    if value not in allowed:
        problems.append(f"input {label}: {escape.terminal(value)!r} is not one of {', '.join(allowed)}")
    return value


def gitlab_argv(env: Mapping[str, str]) -> tuple[list[str], list[str], bool]:
    """The `spellwarden scan` arguments of the component's job from its `SW_*` variables, the problems found (the
    same checks as step 1 of the Action, spec 9.2), and whether a comment is wanted. Every boolean is passed as an
    explicit positive or negative flag, so the scanned settings file cannot change what an input chose (6.3)."""
    problems: list[str] = []
    path = env.get("SW_PATH") or "."
    fail_on = _choice(env, "SW_FAIL_ON", "fail-on", FAIL_ON, problems)
    locked = _choice(env, "SW_LOCKED", "locked", ("auto", "true", "false"), problems)
    probe = _choice(env, "SW_PROBE", "probe", ("true", "false"), problems)
    private = _choice(env, "SW_PROBE_PRIVATE", "probe-private", ("true", "false"), problems)
    comment = _choice(env, "SW_COMMENT", "comment", ("true", "false"), problems)
    telemetry = _choice(env, "SW_TELEMETRY", "telemetry", ("true", "false"), problems)
    argv = ["scan", path, "--fail-on", fail_on]
    if locked == "true" or (locked == "auto" and os.path.isfile(os.path.join(path, ".spellwarden", "lock.json"))):
        argv.append("--locked")
    argv.append("--probe" if probe == "true" else "--no-probe")
    argv.append("--probe-private" if private == "true" else "--no-probe-private")
    if telemetry == "false":
        argv.append("--no-telemetry")
    for fmt, output in GITLAB_OUTPUTS:
        argv += ["--format", fmt, "--output", output]
    argv += ["--format", "text"]
    return argv, problems, comment == "true"


def run_gitlab(env: Mapping[str, str]) -> int:
    """The component job's whole script (spec 10.2a): validate, scan, comment on a merge request when asked, and
    exit with the scan's code."""
    argv, problems, comment = gitlab_argv(env)
    if problems:
        for problem in problems:
            print(f"spellwarden: error: {problem}", file=sys.stderr)
        return 2
    # The output names are reserved: a file, or a symbolic link, of that name in the checkout is the revision's,
    # never this job's report, so it is removed before the scan and only what the scan writes is uploaded or posted.
    for _, output in GITLAB_OUTPUTS:
        try:
            if os.path.lexists(output):
                os.unlink(output)
        except OSError as exc:
            print(f"spellwarden: error: cannot remove {output} from the job directory, a name the job's reports "
                  f"use: {type(exc).__name__}", file=sys.stderr)
            return 2
    from spellwarden_cli import forge, main as cli

    code = cli.main(argv)
    if comment:
        ctx = detect(env)
        if not (ctx.is_request and ctx.request_number is not None):
            emit(ctx, Notice("comment_no_request", "", "comment is true but this pipeline has no merge request"))
        elif code == 2:
            emit(ctx, Notice("comment_failed", "", "the scan did not complete (exit 2): no comment was posted"))
        else:
            try:
                body = read_body(GITLAB_MARKDOWN)
            except (OSError, ValueError) as exc:
                emit(ctx, Notice("comment_failed", "", f"cannot read the Markdown report: {type(exc).__name__}"))
            else:
                notice = forge.post_comment("gitlab", body, env=env, ctx=ctx)
                if notice is not None:
                    emit(ctx, notice)
    return code


def cmd_ci_run(_args: argparse.Namespace) -> int:  # one provider today: `gitlab`, checked by argparse
    return run_gitlab(os.environ)


def add_parser(commands) -> None:
    """`spellwarden ci comment --provider github|gitlab --body FILE` and `spellwarden ci-run gitlab` (spec 6.2)."""
    ci = commands.add_parser("ci", help="CI helpers: the pull or merge request comment")
    sub = ci.add_subparsers(dest="ci_command", required=True)
    comment = sub.add_parser("comment", help="post or update the one Spellwarden comment on the pull or merge request")
    comment.add_argument("--provider", choices=("github", "gitlab"), required=True)
    comment.add_argument("--body", required=True, metavar="FILE")
    comment.set_defaults(handler=cmd_comment)
    run = commands.add_parser("ci-run", help="the GitLab component's job: validate SW_* variables, scan, comment")
    run.add_argument("provider", choices=("gitlab",))
    run.set_defaults(handler=cmd_ci_run)
