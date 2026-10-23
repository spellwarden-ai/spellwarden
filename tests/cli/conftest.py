"""Helpers of the command's tests (`tests/cli`). pytest imports every
`conftest.py` of a directory without `__init__.py` under the one module name
`conftest`, so this file re-exports the names of `tests/conftest.py`: the
engine's tests keep `from conftest import credential, ...` working whichever
conftest was imported last. Test files under `tests/cli` must not share a
basename with a file under `tests/` (prepend import mode)."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("_spellwarden_tests_root_conftest",
                                               Path(__file__).resolve().parents[1] / "conftest.py")
_root = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_root)
for _name in dir(_root):
    if not _name.startswith("__") and _name not in globals():
        globals()[_name] = getattr(_root, _name)

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main",
       "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"]
# Variables that would make the command think it runs in CI (and ping) or change its settings.
_SCRUBBED_PREFIXES = ("GITHUB_", "GITLAB_", "CI_", "SPELLWARDEN_", "RUNNER_")
_SCRUBBED = ("CI", "DO_NOT_TRACK", "GITLAB_CI", "GITHUB_ACTIONS", "JENKINS_URL", "TF_BUILD",
             "TEAMCITY_VERSION", "BUILDKITE", "CIRCLECI", "BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "DRONE",
             "TRAVIS")


# The developer's global and system git configuration (a global excludes file, a signing setting) must not change
# what a test lists; the command's own git calls read the same variables.
HERMETIC_GIT = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.excludesFile", "GIT_CONFIG_VALUE_0": os.devnull}  # also the XDG ignore file


@pytest.fixture(autouse=True)
def _hermetic_git(monkeypatch):
    for key, value in HERMETIC_GIT.items():
        monkeypatch.setenv(key, value)


def git(repo: Path, *args: str) -> str:
    done = subprocess.run([*GIT, "-C", str(repo), *args], capture_output=True, text=True, check=True)
    return done.stdout


def write_tree(root: Path, files: dict[str, str | bytes]) -> Path:
    """`files` maps POSIX paths to text (written as UTF-8 bytes, no newline translation) or bytes."""
    for path, content in files.items():
        target = root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    return root


def _make_repo(base: Path, files: dict[str, str | bytes], modes: dict[str, str] | None = None) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    git(base, "init", "-q")
    write_tree(base, files)
    git(base, "add", "-A")
    for path, mode in (modes or {}).items():
        git(base, "update-index", "--chmod=+x" if mode == "100755" else "--chmod=-x", path)
    git(base, "commit", "-q", "--allow-empty", "-m", "fixture")
    return base


@pytest.fixture
def make_repo():
    """`make_repo(base, files, modes=None) -> base`: a committed git repository at `base` (created when missing)
    holding `files`; `modes` maps a path to its index mode (`"100755"` is set with `git update-index --chmod=+x`,
    so the bit is in the index on every OS)."""
    return _make_repo


def clean_env(extra: dict | None = None) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items()
           if key not in _SCRUBBED and not key.startswith(_SCRUBBED_PREFIXES)}
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(HERMETIC_GIT)
    env.update(extra or {})
    return env


def _run_cli(args: list[str], cwd: Path | None = None, env: dict | None = None) -> tuple[int, str, str]:
    from spellwarden_cli import main as cli

    saved_env, saved_cwd = dict(os.environ), os.getcwd()
    saved_out, saved_err = sys.stdout, sys.stderr
    out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    environment = clean_env(env)  # read before the clear: an empty `os.environ` would leave the command no PATH
    os.environ.clear()
    os.environ.update(environment)
    try:
        if cwd is not None:
            os.chdir(cwd)
        sys.stdout, sys.stderr = out, err
        code = cli.main(list(args))
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err
        os.chdir(saved_cwd)
        os.environ.clear()
        os.environ.update(saved_env)
    out.flush()
    err.flush()
    return code, out.buffer.getvalue().decode("utf-8"), err.buffer.getvalue().decode("utf-8")


@pytest.fixture
def run_cli():
    """`run_cli(args, cwd=None, env=None) -> (exit code, stdout, stderr)`: `spellwarden_cli.main.main(args)` in this
    process with stdout and stderr captured, the working directory set to `cwd`, and an environment without CI or
    Spellwarden variables (so no test pings) plus `env`; everything is restored afterwards."""
    return _run_cli


# --- connected mode (O3 Task 8): the API double, the CI environments and the answers it gives --------------------------

SHA = "1" * 40
HEAD = "2" * 40
KEY_PATH = "/api/v1/orgs"
POLICY_PATH = "/api/v1/orgs/acme/ci/policy"
EXCHANGE_PATH = "/api/public/ci/token"
CHECK_PATH = "/api/v1/orgs/acme/ci/registry-check"
SCANS_PATH = "/api/v1/orgs/acme/ci/scans"


@pytest.fixture
def api_double(monkeypatch):
    """A `FakeApi` behind the transport seams of `connected.py`, with its clock: no test of connected mode opens a
    socket or waits. Returns `(fake, clock)`."""
    from fake_api import FakeApi, FakeClock

    from spellwarden_cli import connected

    clock = FakeClock()
    fake = FakeApi(clock)
    monkeypatch.setitem(connected.TRANSPORT, "opener", fake.opener)
    monkeypatch.setitem(connected.TRANSPORT, "resolver", fake.resolver)
    monkeypatch.setitem(connected.TRANSPORT, "clock", clock)
    return fake, clock


def pack_document(org_rules=(), *, pack_id: str = "a" * 32, name: str = "Organisation rules", version: str = "1.3") -> dict:
    from spellwarden_scan import baseline_pack

    document = baseline_pack().to_dict()
    document["pack"] = {**document["pack"], "id": pack_id, "name": name, "version": version}
    document["org_rules"] = sorted(org_rules, key=lambda spec: spec["id"])
    return document


def org_rule(rule_id: str = "SW-ORG-010", pattern: str = "bastion\\.staging", *, area: str = "skill") -> dict:
    return {"id": rule_id, "title": "Mentions the staging bastion", "severity": "high", "area": area,
            "detection": {"kind": "pattern", "pattern": pattern}}


def probe_rule(rule_id: str = "SW-ORG-020") -> dict:
    return {"id": rule_id, "title": "Server on a legacy transport", "severity": "medium", "area": "mcp",
            "detection": {"kind": "probe", "predicate": "transport_in", "values": ["sse"]}}


def policy_answer(org_rules=(), *, skipped=(), source: str = "org_rules", chosen_by: str = "organisation",
                  registry: str | None = "acme", gate: dict | None = None, pack_name: str = "Organisation rules",
                  version: str = "1.3", rules_version: str | None = None) -> dict:
    from spellwarden_scan import pack_sha256

    document = pack_document(org_rules, name=pack_name, version=version)
    if rules_version is not None:
        document["engine"] = {**document["engine"], "rules_version": rules_version}
    return {
        "org": {"slug": "acme", "name": "Acme", "plan": "enterprise"}, "dashboard_url": "https://dash.spellwarden.ai/acme",
        "ci_policy": {"gate": {"enabled": True, "scope": "changed", "stdio": True, "plugins": True, **(gate or {})}},
        "policy": {"source": source, "chosen_by": chosen_by, "pack_id": document["pack"]["id"], "version": version,
                   "sha256": pack_sha256(document), "document": document, "skipped": list(skipped)},
        "registry": {"name": registry} if registry else None,
        "limits": {"upload_max_bytes": 1048576, "upload_max_findings": 500, "upload_max_items": 2000,
                   "upload_max_probes": 200,
                   "check_max": {"skills": 2000, "servers": 500, "stdio": 500, "plugins": 500, "marketplaces": 100}},
    }


def session_answer(token: str | None = None, run: dict | None = None) -> dict:
    return {"token": token or _root.credential("swt"), "expires_at": "2026-10-23T10:15:00Z",
            "org": {"slug": "acme", "name": "Acme", "plan": "enterprise"},
            "run": run if run is not None else {"identity": "github:github.com/acme/tools", "event": "push", "sha": SHA}}


def orgs_answer(*, access: str = "ci", orgs=None) -> dict:
    listing = [{"slug": "acme", "name": "Acme", "plan": "enterprise", "billing_state": "active", "reachable": True}]
    return {"orgs": listing if orgs is None else orgs, "caller": {"kind": "api_key", "access": access}}


@pytest.fixture
def fixture_tools(monkeypatch):
    """`make_repo` and `check` of `fixtures/repos` (check.py imports make_repo, so the directory joins the path); the
    modules leave `sys.modules` afterwards, `scripts/e2e.py` imports another `make_repo`."""
    import importlib
    import sys

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "fixtures" / "repos"))
    for name in ("make_repo", "check"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    yield importlib.import_module("make_repo"), importlib.import_module("check")
    for name in ("make_repo", "check"):
        sys.modules.pop(name, None)


def admit_all(body: dict, *, refuse_server: bool = False, dashboard: str = "https://dash.spellwarden.ai/acme") -> dict:
    """A registry-check answer computed from the request body (`FakeApi.script` takes it as the answer): every item
    admitted, the first server not with `refuse_server`."""
    answer: dict = {"schema": 1}
    for name in ("skills", "servers", "stdio", "plugins", "marketplaces"):
        answer[name] = [{"path": item["path"], "admitted": True, "exported_name": None, "request_url": None}
                        for item in body.get(name, [])]
    if refuse_server and answer["servers"]:
        answer["servers"][0] = {"path": body["servers"][0]["path"], "admitted": False, "exported_name": None,
                                "request_url_template": f"{dashboard}/mcp-servers?add=1&url="}
    return answer


def connected_github(tmp_path: Path, event: str = "push", payload: dict | None = None, **more: str) -> dict[str, str]:
    path = tmp_path / f"event-{event}.json"
    path.write_text(json.dumps(payload if payload is not None else {"repository": {"default_branch": "main"}}),
                    encoding="utf-8")
    return {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": event, "GITHUB_EVENT_PATH": str(path),
            "GITHUB_REPOSITORY": "acme/tools", "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REF_NAME": "main",
            "GITHUB_REPOSITORY_OWNER_ID": "1", "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "9", "GITHUB_REF_PROTECTED": "true", **more}


def connected_gitlab(**more: str) -> dict[str, str]:
    return {"CI": "true", "GITLAB_CI": "true", "CI_PIPELINE_SOURCE": "push", "CI_COMMIT_REF_PROTECTED": "true",
            "CI_PROJECT_ID": "42", "CI_PROJECT_URL": "https://gitlab.com/acme/tools", "CI_COMMIT_SHA": SHA,
            "CI_COMMIT_REF_NAME": "main", "CI_DEFAULT_BRANCH": "main", "CI_SERVER_HOST": "gitlab.com",
            "CI_PROJECT_ROOT_NAMESPACE": "acme", "CI_JOB_URL": "https://gitlab.com/acme/tools/-/jobs/7", **more}


def scan_json(run_cli, repo, env=None, *args: str):
    """`(exit code, report, stdout, stderr)` of `spellwarden scan` in JSON, with no usage ping."""
    code, out, err = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", *args], env=env)
    return code, (json.loads(out) if out.startswith("{") else None), out, err
