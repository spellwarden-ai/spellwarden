"""CI detection (spec 6.11), the trust rule for private probing (6.8), the installation identity of the usage ping
(6.10), the base revision a pull or merge request's settings file and baseline are read from (6.3, 6.7, D35), and
the two CI commands: `spellwarden ci comment` and `spellwarden ci-run gitlab` (10.2a).

Detection reads environment variables and, on GitHub, the event file; nothing else. Where it cannot tell, it gives
the restrictive answer: an unknown GitHub event, a GitLab pipeline with no source or with a merge request IID, a GitLab
child pipeline on an unprotected ref, or an unreadable event file is a pull request, and a pull request whose head
repository cannot be read is a fork; any `CI` value but an empty or false one (`CI=woodpecker`) and a CI system's
own marker make a run CI even without `CI=true`."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from spellwarden_scan.evidence import mask_credentials

from spellwarden_cli import escape, paths
from spellwarden_cli.report import Notice
from spellwarden_cli.settings import FAIL_ON

GITHUB_REQUEST_EVENTS = ("pull_request", "pull_request_target", "merge_group")
GITLAB_REQUEST_SOURCES = ("merge_request_event", "external_pull_request_event")
GITLAB_CHILD_SOURCE = "parent_pipeline"  # a request unless its ref is protected (spec 6.11)
# Spec 6.8: the only events whose run, on a protected ref, may probe private addresses. An allowlist: any other
# event (a comment, a review, a workflow_run, a dispatch, one added later) is untrusted.
GITHUB_TRUSTED_EVENTS = ("push", "schedule", "workflow_dispatch")
GITLAB_TRUSTED_SOURCES = ("push", "schedule", "web")
DEPENDABOT = "dependabot[bot]"
IDENTITY_PREFIX = "spellwarden-ping-v1:"
EVENT_FILE_MAX = 25 * 2**20
BODY_MAX = 2**20
_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")
# The outputs of `ci-run gitlab`, in the job's working directory, as templates/scan.yml lists them (spec 10.2).
# Spec 6.11: variables a CI system sets whether or not it sets `CI=true`. Any of them, non-empty, makes the run CI
# (`other` unless it is GitHub or GitLab): detection fails closed, so a CI job is never mistaken for a trusted
# local run. A generic name such as `BUILD_ID` is not one: local tools set it too, and Jenkins always sets
# `JENKINS_URL`. Woodpecker sets `CI=woodpecker` and `CI_SYSTEM_NAME=woodpecker` (its documented variables).
CI_MARKERS = ("JENKINS_URL", "TF_BUILD", "TEAMCITY_VERSION", "BUILDKITE", "CIRCLECI",
              "BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "DRONE", "TRAVIS", "CI_SYSTEM_NAME")
GITLAB_OUTPUTS = (("gitlab-codequality", "gl-code-quality-report.json"), ("sarif", "spellwarden.sarif"),
                  ("markdown", "spellwarden.md"), ("json", "spellwarden.json"))
GITLAB_MARKDOWN = dict(GITLAB_OUTPUTS)["markdown"]
_SCP_REMOTE = re.compile(r"^[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):/?([^/]+)/")
_OBJECT_ID = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
ORG_RE = re.compile(r"[a-z0-9-]{2,64}")  # an organisation slug (O3 spec 6.2)
# GitLab: the merge request's merge base first (an ancestor of the source branch, so a deep enough clone holds it),
# then the target branch's tip; an external pull request names only its target branch's tip.
GITLAB_BASE_VARIABLES = {"merge_request_event": ("CI_MERGE_REQUEST_DIFF_BASE_SHA", "CI_MERGE_REQUEST_TARGET_BRANCH_SHA"),
                         "external_pull_request_event": ("CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_SHA",)}


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
    base_sha: str | None = None   # the request's base commit (40 or 64 lower-case hex), or None (D35)
    # O3 spec 6.8: what the connected calls and the upload say about the run. None where the CI does not tell.
    repository_url: str | None = None       # the forge URL of the repository, userinfo, query and fragment removed
    repository_identity: str | None = None  # github:<host>/<owner>/<name>, gitlab:<host>[/<url>]/<path>, other:<host>/<path>
    sha: str | None = None                  # the commit scanned (GITHUB_SHA, CI_COMMIT_SHA, else git rev-parse HEAD)
    ref_name: str | None = None             # the branch: the request's source branch on a request
    head_sha: str | None = None             # on a request, the head commit
    head_ref: str | None = None             # on a request, the head branch
    default_branch: str | None = None       # SPELLWARDEN_DEFAULT_BRANCH, else the payload / CI variable
    visibility: str | None = None           # "public" or "private" (`internal` is private); None for a local run
    run_url: str | None = None
    job: str | None = None
    attempt: int = 1

    def run_kind(self) -> str:
        """O3 spec 6.8: `request` when `is_request`; `default_branch` when not a request, the event is a trusted one
        (any run of `other` CI) and `ref_name == default_branch`; `branch` otherwise."""
        if self.is_request:
            return "request"
        trusted = (self.provider == "other"
                   or (self.provider == "github" and self.event in GITHUB_TRUSTED_EVENTS)
                   or (self.provider == "gitlab" and self.event in GITLAB_TRUSTED_SOURCES))
        if trusted and self.default_branch is not None and self.ref_name == self.default_branch:
            return "default_branch"
        return "branch"


LOCAL = CiContext(provider=None, event=None, is_request=False, request_number=None, fork=False, dependabot=False,
                  protected_ref=False, identity=None)


def _true(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUE


def _ci_set(value: str | None) -> bool:
    """`CI` names a CI unless it is empty or a false value: CI systems set `true`, but also their own name
    (`CI=woodpecker`), and detection fails closed."""
    folded = (value or "").strip().lower()
    return bool(folded) and folded not in _FALSE


def _object_id(value: object) -> str | None:
    """A commit id as the CI gave it: exactly 40 (SHA-1) or 64 (SHA-256) hexadecimal characters, lower-cased;
    anything else is None, so a value never reaches git as an option or a revision expression."""
    if not isinstance(value, str) or not _OBJECT_ID.fullmatch(value):
        return None
    return value.lower()


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read(EVENT_FILE_MAX)


def git_remote_of(root: str, *, env: Mapping[str, str] | None = None) -> str | None:
    """`git remote get-url origin` of the work tree holding `root`, with `safe.directory` set to that one work tree
    (spec 6.4), or None. The subprocess gets an explicit environment (`env`, else a copy of ours; O3 invariant 2)."""
    from spellwarden_cli.files import work_tree_top

    top = work_tree_top(root)
    if top is None:
        return None
    try:
        done = subprocess.run(["git", "-c", f"safe.directory={top}", "-C", root, "remote", "get-url", "origin"],
                              capture_output=True, text=True, timeout=10, check=False,
                              env=dict(os.environ) if env is None else dict(env))
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


_REPOSITORY = re.compile(r"[^/\s]+/[^/\s]+")
_SCP_FULL = re.compile(r"^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):/?(.+)$")
_SEGMENT = re.compile(r"[^/\s]+")
_SSH_SCHEMES = ("ssh", "git", "git+ssh", "ssh+git")
BRANCH_MAX = 255


def _branch(value: object) -> str | None:
    """A branch name as the CI gave it: a non-empty string of printable characters, at most 255 of them."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text if 0 < len(text) <= BRANCH_MAX and text.isprintable() else None


def _authority(parts) -> str | None:
    """`host` or `host:port`, lower-cased, the port only when it is not the scheme's default (an IPv6 literal keeps its
    brackets); None for a URL without a host or with a bad port."""
    try:
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    default = {"https": 443, "http": 80}.get(parts.scheme)
    return host if port is None or port == default else f"{host}:{port}"


def _forge_url(url: str | None, *, cased_host: bool = False) -> tuple[str, str, str] | None:
    """`(scheme, authority, path)` of an http(s) URL, userinfo, query and fragment dropped and the path without a
    trailing slash; None when it is not one. `cased_host` keeps the host as written (a URL is not an identity)."""
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None
    authority = _authority(parts)
    if authority is None:
        return None
    if cased_host:
        netloc = parts.netloc.rsplit("@", 1)[-1]
        authority = netloc
    return parts.scheme, authority, parts.path.rstrip("/")


def _normalise_remote(remote: str | None) -> tuple[str, str] | None:
    """`(https URL, "host[:port]/path")` of an `origin` remote (O3 spec 6.8, P19): `git@host:owner/repo.git` and
    `ssh://` forms become `https://host/path` with userinfo and the SSH port dropped (it names no HTTPS port); an
    `https://` remote keeps a non-443 port; query, fragment and a trailing `.git` are dropped. At least an owner and a
    repository are needed; a local path or anything else is None."""
    text = (remote or "").strip()
    if not text:
        return None
    if "://" not in text and "\\" not in text:
        scp = _SCP_FULL.match(text)
        if scp is None or ("@" not in text.split(":", 1)[0] and "." not in scp.group(1)):
            return None
        authority, path = scp.group(1).lower(), scp.group(2)
    else:
        try:
            parts = urlsplit(text)
            authority = _authority(parts) if parts.scheme in ("http", "https") else (parts.hostname or "").lower()
        except ValueError:
            return None
        if parts.scheme not in ("http", "https", *_SSH_SCHEMES) or not authority:
            return None
        path = parts.path
    segments = [segment for segment in path.split("/") if segment]
    if segments:
        segments[-1] = segments[-1].removesuffix(".git")
    if len(segments) < 2 or not all(_SEGMENT.fullmatch(segment) and segment not in (".", "..") for segment in segments):
        return None
    joined = "/".join(segments)
    return f"https://{authority}/{joined}", f"{authority}/{joined}"


def _github(env: Mapping[str, str], read_text: Callable[[str], str], git_head: Callable[[], str | None] | None) -> CiContext:
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
    server = _forge_url(env.get("GITHUB_SERVER_URL"), cased_host=True)
    repository = env.get("GITHUB_REPOSITORY") or ""
    named = server is not None and _REPOSITORY.fullmatch(repository) is not None
    repository_url = f"{server[0]}://{server[1]}{server[2]}/{repository}" if named else None
    forge = _forge_url(env.get("GITHUB_SERVER_URL"))
    repository_identity = f"github:{forge[1]}{forge[2]}/{repository}".lower() if named and forge is not None else None
    head_sha = head_ref = None
    if readable and event is not None and event.startswith("pull_request") and isinstance(pull, dict):
        head = pull.get("head")
        if isinstance(head, dict):
            head_sha, head_ref = _object_id(head.get("sha")), _branch(head.get("ref"))
    repo_payload = payload.get("repository") if readable else None
    if not isinstance(repo_payload, dict):
        repo_payload = {}
    default_branch = _branch(env.get("SPELLWARDEN_DEFAULT_BRANCH")) or _branch(repo_payload.get("default_branch"))
    run_id = env.get("GITHUB_RUN_ID") or ""
    attempt = _int(env.get("GITHUB_RUN_ATTEMPT"))
    return CiContext(provider="github", event=event, is_request=is_request, request_number=number, fork=fork,
                     dependabot=env.get("GITHUB_ACTOR") == DEPENDABOT, protected_ref=_true(env.get("GITHUB_REF_PROTECTED")),
                     identity=identity, base_sha=_github_base(event, payload if readable else None),
                     repository_url=repository_url, repository_identity=repository_identity,
                     sha=_object_id(env.get("GITHUB_SHA")) or _object_id(git_head() if git_head else None),
                     ref_name=_branch((env.get("GITHUB_HEAD_REF") if is_request else None) or env.get("GITHUB_REF_NAME")),
                     head_sha=head_sha, head_ref=head_ref, default_branch=default_branch,
                     visibility="public" if repo_payload.get("visibility") == "public" else "private",
                     run_url=f"{repository_url}/actions/runs/{run_id}" if repository_url and run_id.isdigit() else None,
                     job=_branch(env.get("GITHUB_JOB")), attempt=attempt if attempt is not None and attempt >= 1 else 1)


def _github_base(event: str | None, payload: dict | None) -> str | None:
    """Every `pull_request*` event: `pull_request.base.sha`; `merge_group`: `merge_group.base_sha`; any other event
    (`workflow_run`, `issue_comment`, ...) names no base the scanner can trust: None."""
    if payload is None or event is None:
        return None
    if event == "merge_group":
        group = payload.get("merge_group")
        return _object_id(group.get("base_sha")) if isinstance(group, dict) else None
    if event.startswith("pull_request"):
        pull = payload.get("pull_request")
        base = pull.get("base") if isinstance(pull, dict) else None
        return _object_id(base.get("sha")) if isinstance(base, dict) else None
    return None


def _gitlab(env: Mapping[str, str], git_head: Callable[[], str | None] | None) -> CiContext:
    source = env.get("CI_PIPELINE_SOURCE") or None
    protected = _true(env.get("CI_COMMIT_REF_PROTECTED"))
    merge_request = bool(env.get("CI_MERGE_REQUEST_IID"))
    # A child pipeline (`parent_pipeline`) started by a merge request pipeline runs the request's code: a request,
    # unless its ref is protected; any pipeline that carries a merge request IID is one.
    is_request = (source is None or source in GITLAB_REQUEST_SOURCES or merge_request
                  or (source == GITLAB_CHILD_SOURCE and not protected))
    number = _int(env.get("CI_MERGE_REQUEST_IID"))
    fork = False
    if is_request:
        origin = env.get("CI_MERGE_REQUEST_SOURCE_PROJECT_ID")
        fork = not origin or origin != env.get("CI_PROJECT_ID")
    host = (env.get("CI_SERVER_HOST") or "").strip().lower()
    namespace = (env.get("CI_PROJECT_ROOT_NAMESPACE") or "").strip()
    identity = f"gitlab:{host}:{namespace}" if host and namespace else None
    names = GITLAB_BASE_VARIABLES.get(source or "", ())
    if not names and is_request and (source == GITLAB_CHILD_SOURCE or merge_request):
        names = GITLAB_BASE_VARIABLES["merge_request_event"]  # none set: the defaults and `base_unavailable`
    candidates = (_object_id(env.get(name)) for name in names)
    project = env.get("CI_PROJECT_URL")
    if not project and env.get("CI_SERVER_URL") and env.get("CI_PROJECT_PATH"):
        project = f"{env['CI_SERVER_URL'].rstrip('/')}/{env['CI_PROJECT_PATH'].strip('/')}"
    forge = _forge_url(project)
    url = _forge_url(project, cased_host=True)
    commit = _object_id(env.get("CI_COMMIT_SHA")) or _object_id(git_head() if git_head else None)
    source_branch = _branch(env.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")) if is_request else None
    return CiContext(provider="gitlab", event=source, is_request=is_request, request_number=number, fork=fork,
                     dependabot=False, protected_ref=protected, identity=identity,
                     base_sha=next((sha for sha in candidates if sha is not None), None),
                     repository_url=f"{url[0]}://{url[1]}{url[2]}" if url is not None and url[2] else None,
                     repository_identity=f"gitlab:{forge[1]}{forge[2]}".lower() if forge is not None and forge[2] else None,
                     sha=commit, ref_name=source_branch or _branch(env.get("CI_COMMIT_REF_NAME")),
                     head_sha=(_object_id(env.get("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA")) or commit) if is_request else None,
                     head_ref=source_branch, default_branch=_branch(env.get("SPELLWARDEN_DEFAULT_BRANCH"))
                     or _branch(env.get("CI_DEFAULT_BRANCH")),
                     visibility="public" if env.get("CI_PROJECT_VISIBILITY") == "public" else "private",
                     run_url=env.get("CI_JOB_URL") or None, job=_branch(env.get("CI_JOB_NAME")))


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
           git_remote: Callable[[], str | None] = _git_remote, git_head: Callable[[], str | None] | None = None,
           git_branch: Callable[[], str | None] | None = None) -> CiContext:
    """Spec 6.11: the provider, the event, whether the run is a pull or merge request, its number, fork and
    Dependabot, ref protection and the installation identity; O3 spec 6.8: the run context. A local run (`CI` unset,
    empty or false, and none of `CI_MARKERS` set) is `LOCAL`. `git_head` and `git_branch` are the lookups of the
    commit and of the current branch for a CI that names neither (`other`); without them there is none."""
    if _true(env.get("GITHUB_ACTIONS")):
        return _github(env, read_text, git_head)
    if _true(env.get("GITLAB_CI")):
        return _gitlab(env, git_head)
    if _ci_set(env.get("CI")) or any(env.get(name) for name in CI_MARKERS):
        try:
            remote = git_remote()
            identity = _remote_identity(remote)
            normalised = _normalise_remote(remote)
        except Exception:  # noqa: BLE001 -- an identity is optional; the ping then carries null
            identity, normalised = None, None
        return CiContext(provider="other", event=None, is_request=False, request_number=None, fork=False,
                         dependabot=False, protected_ref=False, identity=identity,
                         repository_url=normalised[0] if normalised else None,
                         repository_identity=f"other:{normalised[1]}".lower() if normalised else None,
                         sha=_lookup(git_head, _object_id), ref_name=_lookup(git_branch, _branch),
                         default_branch=_branch(env.get("SPELLWARDEN_DEFAULT_BRANCH")), visibility="private")
    return LOCAL


def _lookup(source: Callable[[], str | None] | None, clean: Callable[[object], str | None]) -> str | None:
    if source is None:
        return None
    try:
        return clean(source())
    except Exception:  # noqa: BLE001 -- a lookup that fails is a value the CI did not give
        return None


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


# --- the base revision of a pull or merge request (spec 6.3, 6.7, D35) ---------------------------------------------
#
# A request controls its own `.spellwarden/config.yml` and `.spellwarden/baseline.yml`, so it could exclude its own
# malicious file or accept its own finding. On a request in CI both are read from the base revision with git (the
# blob at `<base sha>:<repository prefix of the scan root><path>`), never from the working tree; everywhere else the
# working tree is read as before. The base is fetched once from `origin` when a shallow clone lacks it.

GIT_TIMEOUT = 30
FETCH_TIMEOUT = 120
KILL_TIMEOUT = 10
GIT_STDERR_MAX = 64 * 2**10
GIT_MESSAGE_MAX = 300
_WINDOWS = os.name == "nt"
_REGULAR_MODES = ("100644", "100755")


class RevisionUnavailable(Exception):
    """The base revision cannot be read: no git, not a work tree, or the commit is missing. The message says why."""


@dataclass(frozen=True)
class RevisionSource:
    """Where a scan reads the settings file and the baseline. `read` is None for the working tree; otherwise
    `read(relative, max_bytes) -> bytes` with the contract of `paths.read_contained`: `FileNotFoundError` when the file
    is absent, `paths.TooLarge` past `max_bytes`, `paths.UnsafePath` for a link or anything but a regular file."""
    read: Callable[[str, int], bytes] | None = None
    notices: tuple[Notice, ...] = ()


WORKING_TREE = RevisionSource()


def _which_git() -> str | None:
    return shutil.which("git")


class _TemporaryUnusable(OSError):
    """No temporary file can be made for git's output: no git call can run (r3 nit)."""


def _run_git(executable: str, top: str, root: str, *args: str, timeout: float = GIT_TIMEOUT,
             env: Mapping[str, str] | None = None) -> bytes:
    """`git -c safe.directory=<top> -c core.fsmonitor=false -C <root> <args>` (the form of `files._git`, spec 6.4), with
    a timeout per call and no prompt; raises `OSError` naming the failure."""
    command = [executable, "-c", f"safe.directory={top.replace(os.sep, '/')}", "-c", "core.fsmonitor=false",
               "-C", root, *args]
    environment = {**(env if env is not None else os.environ), "GIT_TERMINAL_PROMPT": "0"}
    # The timeout is hard on every OS: git's output goes to temporary files, so nothing waits on a pipe that a helper
    # such as `git-remote-https` still holds, and git runs in its own process group, which is killed whole.
    group = ({"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)} if _WINDOWS
             else {"start_new_session": True})
    try:
        out, err = tempfile.TemporaryFile(), tempfile.TemporaryFile()
    except OSError as exc:
        raise _TemporaryUnusable(f"the temporary directory is unusable ({type(exc).__name__}), so git's output cannot be "
                                 "captured") from exc
    with out, err:
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=environment,
                                       **group)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise OSError(f"git could not run ({type(exc).__name__})") from exc
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            _kill_tree(process)
            raise OSError(f"git {args[0] if args else ''} took longer than {timeout} s") from exc
        except BaseException:
            _kill_tree(process)
            raise
        out.seek(0)
        stdout = out.read()
        err.seek(0)
        stderr = err.read(GIT_STDERR_MAX)
    if returncode != 0:
        first = stderr.decode("utf-8", "replace").strip().splitlines()
        raise OSError(_git_message(first[0]) if first else f"git exited {returncode}")
    return stdout


def _git_message(line: str) -> str:
    """git's first stderr line as it reaches the `base_unavailable` notice and the comment: credentials masked
    (`evidence.mask_credentials`), then at most `GIT_MESSAGE_MAX` characters."""
    masked = mask_credentials(line)
    return masked if len(masked) <= GIT_MESSAGE_MAX else masked[:GIT_MESSAGE_MAX - 3] + "..."


def _kill_tree(process: subprocess.Popen) -> None:
    """Kills `process` and every process it started: on Windows with `taskkill /T /F`, elsewhere by signalling its
    process group (it was started in a session of its own). Never raises."""
    if _WINDOWS:
        taskkill = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows", "System32", "taskkill.exe")
        try:
            subprocess.run([taskkill, "/T", "/F", "/PID", str(process.pid)], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=KILL_TIMEOUT, check=False)
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=KILL_TIMEOUT)
    except subprocess.TimeoutExpired:
        pass


class _Repository:
    """The work tree holding a scan root, as git sees it."""

    def __init__(self, root: str, git: str | None = None, env: Mapping[str, str] | None = None) -> None:
        from spellwarden_cli.files import work_tree_top

        self.env = dict(os.environ) if env is None else dict(env)  # every git call below gets this environment
        self.root = os.path.abspath(root)
        self.executable = _which_git() if git is None else git
        if not self.executable:
            raise RevisionUnavailable("git is not available")
        top = work_tree_top(self.root)
        if top is None:
            raise RevisionUnavailable("the scan root is not inside a git work tree")
        self.top = top
        try:
            self.prefix = self._git("rev-parse", "--show-prefix").decode("utf-8").strip()
        except _TemporaryUnusable as exc:
            raise RevisionUnavailable(str(exc)) from exc
        except (OSError, UnicodeDecodeError) as exc:
            raise RevisionUnavailable(f"git cannot read the work tree ({exc})") from exc

    def _git(self, *args: str, timeout: float = GIT_TIMEOUT, env: Mapping[str, str] | None = None) -> bytes:
        return _run_git(self.executable, self.top, self.root, *args, timeout=timeout,
                        env=self.env if env is None else env)

    def has_commit(self, sha: str) -> bool:
        try:
            self._git("cat-file", "-e", f"{sha}^{{commit}}")
        except OSError:
            return False
        return True

    def ensure(self, sha: str, *, fetch: bool) -> None:
        """The commit `sha` is present, after at most one shallow fetch of exactly that commit from `origin` (hooks
        off, no tags, no submodules, bounded by `FETCH_TIMEOUT`); else `RevisionUnavailable`."""
        if self.has_commit(sha):
            return
        if not fetch:
            raise RevisionUnavailable(f"the base commit {sha[:12]} is not in the clone")
        try:
            hooks = tempfile.TemporaryDirectory(prefix="spellwarden-hooks-", ignore_cleanup_errors=True)
        except OSError as exc:  # spec 6.2: never a crash; the base is then unavailable
            raise RevisionUnavailable(f"the base commit {sha[:12]} is not in the clone and the empty hooks directory "
                                      f"for fetching it cannot be created ({type(exc).__name__})") from exc
        with hooks as no_hooks:
            try:
                self._git("-c", "protocol.version=2", "-c", f"core.hooksPath={no_hooks}", "fetch", "--no-tags",
                          "--no-recurse-submodules", "--depth=1", "origin", sha, timeout=FETCH_TIMEOUT)
            except OSError as exc:
                raise RevisionUnavailable(f"the base commit {sha[:12]} is not in the clone and fetching it from "
                                          f"origin failed ({exc})") from exc
        if not self.has_commit(sha):
            raise RevisionUnavailable(f"the base commit {sha[:12]} is not in the clone, even after a fetch")

    def _entry(self, sha: str, path: str) -> tuple[str, str] | None:
        """`(mode, object id)` of the tree entry `path` (repository-relative) at `sha`, or None when there is none."""
        listing = self._git("--literal-pathspecs", "ls-tree", "-z", "--full-tree", sha, "--", path)
        for record in listing.split(b"\0"):
            meta, _, name = record.partition(b"\t")
            fields = meta.decode("ascii", "replace").split(" ")
            if name.decode("utf-8", "replace") == path and len(fields) == 3 and _OBJECT_ID.fullmatch(fields[2]):
                return fields[0], fields[2]
        return None

    def read(self, sha: str, relative: str, max_bytes: int) -> bytes | None:
        """The blob at `sha` for the scan-root-relative `relative`, refused as the working-tree read refuses: a link
        or anything but a regular file at the path or at a directory above it within the scan root."""
        contained = paths.contain("", relative)
        parts = contained.split("/")
        for depth in range(1, len(parts) + 1):
            entry = self._entry(sha, self.prefix + "/".join(parts[:depth]))
            if entry is None:
                return None
            mode, oid = entry
            if mode == "120000":
                raise paths.UnsafePath(f"{contained}: symlink at the base revision {sha[:12]}")
            if depth < len(parts) and mode != "40000" and mode != "040000":
                raise paths.UnsafePath(f"{contained}: not a regular file at the base revision {sha[:12]}")
        if mode not in _REGULAR_MODES:
            raise paths.UnsafePath(f"{contained}: not a regular file at the base revision {sha[:12]}")
        size = self._git("cat-file", "-s", oid).strip()
        if not size.isdigit() or int(size) > max_bytes:
            raise paths.TooLarge(f"{contained}: more than {max_bytes} bytes")
        data = self._git("cat-file", "blob", oid)
        if len(data) > max_bytes:
            raise paths.TooLarge(f"{contained}: more than {max_bytes} bytes")
        return data


def read_at_revision(root: str, sha: str, relative: str, *, max_bytes: int, fetch: bool = False,
                     git: str | None = None, env: Mapping[str, str] | None = None) -> bytes | None:
    """The content of the scan-root-relative file `relative` at commit `sha`, or None when that revision holds no
    such file. Raises `RevisionUnavailable` (no git, no work tree, `sha` not a commit id or not present after the
    one fetch `fetch` allows), `paths.UnsafePath` (a link, a directory, a submodule), `paths.TooLarge` and `OSError`.
    `git=None` looks git up on `PATH`; `git=""` disables it."""
    commit = _object_id(sha)
    if commit is None:
        raise RevisionUnavailable("the base commit is not a commit id")
    repository = _Repository(root, git, env)
    repository.ensure(commit, fetch=fetch)
    return repository.read(commit, relative, max_bytes)


SCOPE_GRAMMAR = re.compile(r"([A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*)?")


def scope_path(root: str) -> str:
    """The scan root's path below its work tree, POSIX, no trailing slash; `""` at the top and outside any work tree."""
    from spellwarden_cli.files import work_tree_top

    absolute = os.path.abspath(root)
    top = work_tree_top(absolute)
    if top is None:
        return ""
    relative = os.path.relpath(absolute, top).replace(os.sep, "/")
    return "" if relative == "." else relative.strip("/")


def scan_scope(root: str, *, git: str | None, env: Mapping[str, str]) -> str | None:  # noqa: ARG001 -- the registry's shape; no git is needed
    """O3 spec 6.8, P41: `scope_path` when it is inside the grammar `^([A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*)?$`, else
    None: the server binds a CI token to one such scope."""
    scope = scope_path(root)
    return scope if SCOPE_GRAMMAR.fullmatch(scope) else None


def git_head_of(root: str, *, git: str | None = None, env: Mapping[str, str] | None = None) -> str | None:
    """`git rev-parse HEAD` of the work tree holding `root`, or None (the scan of an `other` CI names no commit)."""
    try:
        return _object_id(_Repository(root, git, env)._git("rev-parse", "HEAD").decode("ascii", "replace").strip())
    except (RevisionUnavailable, OSError):
        return None


def git_branch_of(root: str, *, git: str | None = None, env: Mapping[str, str] | None = None) -> str | None:
    """The checked-out branch of the work tree holding `root`, or None (detached, or no git)."""
    try:
        return _branch(_Repository(root, git, env)._git("symbolic-ref", "--short", "-q", "HEAD").decode("utf-8").strip())
    except (RevisionUnavailable, OSError, UnicodeDecodeError):
        return None


def _parents(commit: bytes) -> list[str]:
    """The `parent` lines of the header of `git cat-file -p` output (the header ends at the first empty line)."""
    parents = []
    for line in commit.decode("utf-8", "replace").split("\n"):
        if not line:
            break
        key, _, value = line.partition(" ")
        if key == "parent":
            parents.append(value)
    return parents


def changed_paths(root: str, ctx: CiContext, *, git: str | None = None, env: Mapping[str, str]) -> list[str] | None:
    """O3 spec 6.6 "Scope", P15: the paths a request changes, relative to the scan root, sorted (a rename is both
    names). On a GitHub `pull_request` whose checkout is the test merge commit (`git rev-parse HEAD` equals
    `ctx.sha` and `git cat-file -p HEAD` holds exactly two `parent` lines) the first parent is read from that output
    (a shallow clone has no `HEAD^1` and an empty `%P`), fetched by id, and the diff is `<parent> HEAD`. In every other
    case the diff is the two-dot `<base_sha> HEAD`, which can only widen the set. None when the run is no request, the
    base is unknown or cannot be fetched, or there is no work tree."""
    if not ctx.is_request or ctx.base_sha is None:
        return None
    try:
        repository = _Repository(root, git, env)
        baseline = ctx.base_sha
        if ctx.provider == "github" and ctx.event == "pull_request" and ctx.sha is not None:
            head = repository._git("rev-parse", "HEAD").decode("ascii", "replace").strip()
            if _object_id(head) == ctx.sha:
                parents = _parents(repository._git("cat-file", "-p", "HEAD"))
                first = _object_id(parents[0]) if len(parents) == 2 else None
                if first is not None:
                    baseline = first
        repository.ensure(baseline, fetch=True)
        listing = repository._git("diff", "--name-only", "--no-renames", "--no-ext-diff", "--relative", "-z", baseline, "HEAD")
    except (RevisionUnavailable, OSError):
        return None
    return sorted({name.decode("utf-8", "surrogateescape") for name in listing.split(b"\0") if name})


def read_at_base(root: str, ctx: CiContext, path: str, *, git: str | None = None, env: Mapping[str, str]) -> bytes | None:
    """The scan-root-relative file `path` at the request's base revision, or None when the base holds no such file, the
    base is unknown or cannot be fetched, or the path is not a readable regular file there."""
    from spellwarden_cli.files import FILE_MAX

    if ctx.base_sha is None:
        return None
    try:
        return read_at_revision(root, ctx.base_sha, path, max_bytes=FILE_MAX, fetch=True, git=git, env=env)
    except (RevisionUnavailable, paths.UnsafePath, paths.TooLarge, OSError):
        return None


def _quoted(names: tuple[str, ...]) -> str:
    return " and ".join(names)


def _base_hint(ctx: CiContext) -> str:
    if ctx.base_sha is None:
        if ctx.provider == "github":
            return "Run the scan on the pull_request event, whose payload names the base commit."
        return "Run the scan in a merge request pipeline, which names the base commit."
    if ctx.provider == "github":
        return ("Check out with actions/checkout `fetch-depth: 0`, or keep its default `persist-credentials: true` so "
                "the scanner can fetch the base commit.")
    return ("Set `GIT_DEPTH: 0` (or a depth that reaches the merge base) in the job's variables so the clone holds "
            "the base commit.")


def revision_source(root: str, ctx: CiContext, *, config: bool, baseline: bool, git: str | None = None,
                    env: Mapping[str, str] | None = None) -> RevisionSource:
    """Spec 6.3, 6.7 and D35. On a pull or merge request in CI, the files the operator did not name (`config`: the
    settings file, `baseline`: the baseline) are read from the base revision, with the notice `settings_from_base`;
    when that revision cannot be read, from nowhere (the defaults and no baseline), with the notice
    `base_unavailable`. Everywhere else, and for files named by `--config` or `--baseline`: the working tree."""
    from spellwarden_cli import baseline as baseline_file
    from spellwarden_cli import settings

    names = tuple(name for name, wanted in ((settings.CONFIG_PATH, config), (baseline_file.BASELINE_PATH, baseline))
                  if wanted)
    if ctx.provider is None or not ctx.is_request or not names:
        return WORKING_TREE
    verb = "is" if len(names) == 1 else "are"
    try:
        if ctx.base_sha is None:
            raise RevisionUnavailable(f"the {ctx.event or 'unknown'} event names no base commit")
        repository = _Repository(root, git, env)
        repository.ensure(ctx.base_sha, fetch=True)
    except RevisionUnavailable as exc:
        used = [text for text, wanted in (("the default settings", config), ("no baseline", baseline)) if wanted]
        hint = ("Point TMPDIR (TEMP on Windows) at a writable directory." if isinstance(exc.__cause__, _TemporaryUnusable)
                else _base_hint(ctx))
        message = (f"On a pull or merge request, {_quoted(names)} {verb} read from the base revision, never from the "
                   f"request, but {exc}; the scan used {_quoted(tuple(used))}. {hint}")
        return RevisionSource(read=_absent, notices=(Notice("base_unavailable", "", message),))
    sha = ctx.base_sha

    def read(relative: str, max_bytes: int) -> bytes:
        data = repository.read(sha, relative, max_bytes)
        if data is None:
            raise FileNotFoundError(relative)
        return data

    message = (f"On a pull or merge request, {_quoted(names)} {verb} read from the base revision {sha[:12]}, never "
               f"from the request: a change the request makes to {'it' if len(names) == 1 else 'them'} applies once "
               f"it is merged.")
    return RevisionSource(read=read, notices=(Notice("settings_from_base", "", message),))


def _absent(relative: str, _max_bytes: int) -> bytes:
    raise FileNotFoundError(relative)


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


def gitlab_argv(env: Mapping[str, str]) -> tuple[list[str], list[str], bool, dict[str, str]]:
    """The `spellwarden scan` arguments of the component's job from its `SW_*` variables, the problems found (the
    same checks as step 1 of the Action, spec 9.2), whether a comment is wanted, and the environment variables the
    job sets for the scan (O3 spec 11, P12: `SW_ORG` becomes `SPELLWARDEN_ORG`; the component only passes
    variables). Every boolean is passed as an explicit positive or negative flag, so the scanned settings file cannot
    change what an input chose (6.3)."""
    problems: list[str] = []
    path = env.get("SW_PATH") or "."
    fail_on = _choice(env, "SW_FAIL_ON", "fail-on", FAIL_ON, problems)
    locked = _choice(env, "SW_LOCKED", "locked", ("auto", "true", "false"), problems)
    probe = _choice(env, "SW_PROBE", "probe", ("true", "false"), problems)
    private = _choice(env, "SW_PROBE_PRIVATE", "probe-private", ("true", "false"), problems)
    comment = _choice(env, "SW_COMMENT", "comment", ("true", "false"), problems)
    telemetry = _choice(env, "SW_TELEMETRY", "telemetry", ("true", "false"), problems)
    upload = env.get("SW_UPLOAD", "")
    if upload:
        _choice(env, "SW_UPLOAD", "upload", ("true", "false"), problems)
    org = env.get("SW_ORG", "").strip()
    updates: dict[str, str] = {}
    if org:
        if ORG_RE.fullmatch(org):
            updates["SPELLWARDEN_ORG"] = org
        else:
            problems.append(f"input org: {escape.terminal(org)!r} is not an organisation slug (2 to 64 lower-case letters, "
                            "digits and hyphens)")
    argv = ["scan", path, "--fail-on", fail_on]
    if locked == "true" or (locked == "auto" and os.path.isfile(os.path.join(path, ".spellwarden", "lock.json"))):
        argv.append("--locked")
    argv.append("--probe" if probe == "true" else "--no-probe")
    argv.append("--probe-private" if private == "true" else "--no-probe-private")
    if telemetry == "false":
        argv.append("--no-telemetry")
    if upload in ("true", "false"):
        argv.append("--upload" if upload == "true" else "--no-upload")
    for fmt, output in GITLAB_OUTPUTS:
        argv += ["--format", fmt, "--output", output]
    argv += ["--format", "text"]
    return argv, problems, comment == "true", updates if not problems else {}


def run_gitlab(env: Mapping[str, str]) -> int:
    """The component job's whole script (spec 10.2a): validate, scan, comment on a merge request when asked, and
    exit with the scan's code."""
    argv, problems, comment, updates = gitlab_argv(env)
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

    os.environ.update(updates)  # SPELLWARDEN_ORG for the scan, which reads os.environ (O3 P12)
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
