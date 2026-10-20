"""CI detection (spec 6.11), the trust rule for private probing (6.8), the installation identity of the usage ping
(6.10), the base revision a pull or merge request's settings file and baseline are read from (6.3, 6.7, D35), and
the two CI commands: `spellwarden ci comment` and `spellwarden ci-run gitlab` (10.2a).

Detection reads environment variables and, on GitHub, the event file; nothing else. Where it cannot tell, it gives
the restrictive answer: an unknown event or an unreadable event file is a pull request, and a pull request whose
head repository cannot be read is a fork; any `CI` value but an empty or false one (`CI=woodpecker`) and a CI system's
own marker make a run CI even without `CI=true`."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from spellwarden_cli import escape, paths
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
                     identity=identity, base_sha=_github_base(event, payload if readable else None))


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
    candidates = (_object_id(env.get(name)) for name in GITLAB_BASE_VARIABLES.get(source or "", ()))
    return CiContext(provider="gitlab", event=source, is_request=is_request, request_number=number, fork=fork,
                     dependabot=False, protected_ref=_true(env.get("CI_COMMIT_REF_PROTECTED")), identity=identity,
                     base_sha=next((sha for sha in candidates if sha is not None), None))


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
    Dependabot, ref protection and the installation identity. A local run (`CI` unset, empty or false, and none of
    `CI_MARKERS` set) is `LOCAL`."""
    if _true(env.get("GITHUB_ACTIONS")):
        return _github(env, read_text)
    if _true(env.get("GITLAB_CI")):
        return _gitlab(env)
    if _ci_set(env.get("CI")) or any(env.get(name) for name in CI_MARKERS):
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


# --- the base revision of a pull or merge request (spec 6.3, 6.7, D35) ---------------------------------------------
#
# A request controls its own `.spellwarden/config.yml` and `.spellwarden/baseline.yml`, so it could exclude its own
# malicious file or accept its own finding. On a request in CI both are read from the base revision with git (the
# blob at `<base sha>:<repository prefix of the scan root><path>`), never from the working tree; everywhere else the
# working tree is read as before. The base is fetched once from `origin` when a shallow clone lacks it.

GIT_TIMEOUT = 30
FETCH_TIMEOUT = 120
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


def _run_git(executable: str, top: str, root: str, *args: str, timeout: float = GIT_TIMEOUT,
             env: Mapping[str, str] | None = None) -> bytes:
    """`git -c safe.directory=<top> -c core.fsmonitor=false -C <root> <args>` (the form of `files._git`, spec 6.4), with
    a timeout per call and no prompt; raises `OSError` naming the failure."""
    command = [executable, "-c", f"safe.directory={top.replace(os.sep, '/')}", "-c", "core.fsmonitor=false",
               "-C", root, *args]
    try:
        done = subprocess.run(command, capture_output=True, check=False, timeout=timeout, stdin=subprocess.DEVNULL,
                              env={**(env if env is not None else os.environ), "GIT_TERMINAL_PROMPT": "0"})
    except subprocess.TimeoutExpired as exc:
        raise OSError(f"git {args[0] if args else ''} took longer than {timeout} s") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError(f"git could not run ({type(exc).__name__})") from exc
    if done.returncode != 0:
        first = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise OSError(first[0] if first else f"git exited {done.returncode}")
    return done.stdout


class _Repository:
    """The work tree holding a scan root, as git sees it."""

    def __init__(self, root: str, git: str | None = None) -> None:
        from spellwarden_cli.files import work_tree_top

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
        except (OSError, UnicodeDecodeError) as exc:
            raise RevisionUnavailable(f"git cannot read the work tree ({exc})") from exc

    def _git(self, *args: str, timeout: float = GIT_TIMEOUT, env: Mapping[str, str] | None = None) -> bytes:
        return _run_git(self.executable, self.top, self.root, *args, timeout=timeout, env=env)

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
        with tempfile.TemporaryDirectory(prefix="spellwarden-hooks-") as no_hooks:
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
                     git: str | None = None) -> bytes | None:
    """The content of the scan-root-relative file `relative` at commit `sha`, or None when that revision holds no
    such file. Raises `RevisionUnavailable` (no git, no work tree, `sha` not a commit id or not present after the
    one fetch `fetch` allows), `paths.UnsafePath` (a link, a directory, a submodule), `paths.TooLarge` and `OSError`.
    `git=None` looks git up on `PATH`; `git=""` disables it."""
    commit = _object_id(sha)
    if commit is None:
        raise RevisionUnavailable("the base commit is not a commit id")
    repository = _Repository(root, git)
    repository.ensure(commit, fetch=fetch)
    return repository.read(commit, relative, max_bytes)


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


def revision_source(root: str, ctx: CiContext, *, config: bool, baseline: bool, git: str | None = None) -> RevisionSource:
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
        repository = _Repository(root, git)
        repository.ensure(ctx.base_sha, fetch=True)
    except RevisionUnavailable as exc:
        used = [text for text, wanted in (("the default settings", config), ("no baseline", baseline)) if wanted]
        message = (f"On a pull or merge request, {_quoted(names)} {verb} read from the base revision, never from the "
                   f"request, but {exc}; the scan used {_quoted(tuple(used))}. {_base_hint(ctx)}")
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
