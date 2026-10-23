"""Builds one fixture repository (plan P10): python fixtures/make_repo.py <case> <dest> [--github-output] [--shell-env FILE].

<case> is <name> or <name>@<variant>. The repository is `fixtures/<name>/repo/` (or the `repo/` of the
fixture named by `repo_from`), plus `files`, plus the `generated_files` of this OS (names that cannot be
committed, such as a `|`, which Windows forbids), then `git init`, every file added, `modes` applied to the
index with `git update-index --chmod=+x`, and one commit. With `--github-output` the Action inputs of the case
go to $GITHUB_OUTPUT and its `env` to $GITHUB_ENV; with `--shell-env FILE` both are written as `export` lines
for the GitLab job (sourced with `.`). Standard library only, Python 3.11."""
from __future__ import annotations

import datetime
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULTS: dict = {
    "repo_from": None, "files": {}, "generated_files": {}, "modes": {}, "baseline_dates": False, "inputs": {},
    "env": {}, "exit_code": 0, "findings": 0, "accepted": 0, "report": "any", "notices": [], "errors": [],
    "sarif_prefix": None, "lock": None, "probes": None, "ping": False, "absent_files": [], "variants": {},
    "on_request": {}, "on_gitlab_request": {}, "on_fork_request": {}, "annotations": [], "connected": None,
}
INPUT_DEFAULTS = {
    "path": ".", "fail-on": "high", "locked": "auto", "probe": "false", "probe-private": "false",
    "requirements-file": "", "comment": "false", "sarif-upload": "false", "telemetry": "false", "token": "",
    # connected mode (O3 spec 11): empty means off; `api-key` is a secret the workflow supplies, never a case value
    "org": "", "api-key": "", "upload": "", "default-branch": "",
}
# The variables `spellwarden ci-run gitlab` reads (spec 10.2a), by Action input name.
GITLAB_VARIABLES = {
    "path": "SW_PATH", "fail-on": "SW_FAIL_ON", "locked": "SW_LOCKED", "probe": "SW_PROBE",
    "probe-private": "SW_PROBE_PRIVATE", "comment": "SW_COMMENT", "telemetry": "SW_TELEMETRY", "org": "SW_ORG",
    "upload": "SW_UPLOAD",
}
MERGED_KEYS = ("files", "inputs", "env", "generated_files", "modes")
BASELINE = ".spellwarden/baseline.yml"


def load_case(case: str) -> dict:
    """The expectation of `<name>[@<variant>]`: defaults, then expect.json, then the variant's keys
    (dictionaries in MERGED_KEYS are merged key by key, everything else replaced)."""
    name, _, variant = case.partition("@")
    document = json.loads((HERE / name / "expect.json").read_text(encoding="utf-8"))
    unknown = set(document) - set(DEFAULTS)
    if unknown:
        raise SystemExit(f"{name}/expect.json has unknown keys {sorted(unknown)}")
    expect = {**DEFAULTS, **document, "name": name}
    if variant:
        if variant not in expect["variants"]:
            raise SystemExit(f"{name} has no variant {variant!r}")
        for key, value in expect["variants"][variant].items():
            if key in MERGED_KEYS:
                expect[key] = {**expect[key], **value}
            else:
                expect[key] = value
    expect["inputs"] = {**INPUT_DEFAULTS, **expect["inputs"]}
    return expect


def _write(root: Path, relative: str, content: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content.encode("utf-8"))


def _git(dest: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.safecrlf=false", "-C", str(dest), *args],
                   check=True, stdout=subprocess.DEVNULL)


def build(case: str, dest: Path) -> dict:
    expect = load_case(case)
    source = HERE / (expect["repo_from"] or expect["name"]) / "repo"
    if dest.exists():
        shutil.rmtree(dest)
    if source.is_dir():
        shutil.copytree(source, dest)
    else:
        dest.mkdir(parents=True)
    for relative, content in sorted(expect["files"].items()):
        _write(dest, relative, content)
    platform = "windows" if os.name == "nt" else "posix"
    for relative, content in sorted(expect["generated_files"].get(platform, {}).items()):
        _write(dest, relative, content)
    if expect["baseline_dates"]:
        today = datetime.datetime.now(datetime.timezone.utc).date()
        baseline = dest / BASELINE
        text = baseline.read_text(encoding="utf-8")
        text = text.replace("__ADDED__", today.isoformat()).replace("__EXPIRES__", (today + datetime.timedelta(days=90)).isoformat())
        baseline.write_bytes(text.encode("utf-8"))
    _git(dest, "init", "-q", "-b", "main")
    _git(dest, "add", "-A")
    for relative, mode in sorted(expect["modes"].items()):
        if mode != "100755":
            raise SystemExit(f"{case}: only 100755 is supported in modes, not {mode}")
        _git(dest, "update-index", "--chmod=+x", "--", relative)
    _git(dest, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
         "commit", "-q", "--allow-empty", "-m", f"fixture {case}")
    return expect


def inputs_of(expect: dict, dest: Path) -> dict[str, str]:
    """The Action inputs of the case: `path` made absolute under dest (POSIX separators, which Git Bash and
    Windows Python both read), `@fixture/<file>` resolved to the fixture's own directory."""
    values = dict(expect["inputs"])
    values["path"] = (dest / values["path"]).as_posix() if values["path"] != "." else dest.as_posix()
    requirements = values["requirements-file"]
    if requirements.startswith("@fixture/"):
        values["requirements-file"] = (HERE / expect["name"] / requirements.removeprefix("@fixture/")).as_posix()
    for key, value in values.items():
        if "\n" in value or "\r" in value:
            raise SystemExit(f"input {key} holds a line break")
    return values


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    case, dest = argv[1], Path(argv[2]).resolve()
    options = argv[3:]
    expect = build(case, dest)
    values = inputs_of(expect, dest)
    if "--github-output" in options:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
            for key, value in values.items():
                handle.write(f"{key}={value}\n")
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as handle:
            for key, value in sorted(expect["env"].items()):
                handle.write(f"{key}={value}\n")
    if "--shell-env" in options:
        target = Path(options[options.index("--shell-env") + 1])
        lines = [f"export {GITLAB_VARIABLES[key]}={shlex.quote(value)}" for key, value in values.items() if key in GITLAB_VARIABLES]
        lines += [f"export {key}={shlex.quote(value)}" for key, value in sorted(expect["env"].items())]
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
