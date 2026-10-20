"""Helpers of the command's tests (`tests/cli`). pytest imports every
`conftest.py` of a directory without `__init__.py` under the one module name
`conftest`, so this file re-exports the names of `tests/conftest.py`: the
engine's tests keep `from conftest import credential, ...` working whichever
conftest was imported last. Test files under `tests/cli` must not share a
basename with a file under `tests/` (prepend import mode)."""
from __future__ import annotations

import importlib.util
import io
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
_SCRUBBED = ("CI", "DO_NOT_TRACK", "GITLAB_CI", "GITHUB_ACTIONS")


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
    os.environ.clear()
    os.environ.update(clean_env(env))
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
