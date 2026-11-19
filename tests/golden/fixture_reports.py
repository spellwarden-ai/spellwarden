"""Fixture reports for the golden tests of 1.18.0: a fixture directory copied into a fresh git repository (`build_repo`, so
executable bits come from the index and match on every OS), scanned in this process with a clean environment (`render`), and a
report's scanner version set to a given one (`as_version`), so a golden file holds the same bytes whatever version the tree
carries. tests/golden/record_1_17_0.py, tests/golden/record_1_18_0.py and their tests use it."""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AS_OF = "2026-11-17"
SIX_FORMATS = (("json", "report.json"), ("sarif", "report.sarif"), ("markdown", "report.md"),
               ("gitlab-codequality", "gl-code-quality-report.json"), ("text", "report.txt"), ("cyclonedx", "report.cdx.json"))
ALL_FORMATS = (*SIX_FORMATS, ("html", "report.html"))
# Variables that would make the command think it runs in CI (and ping) or change its settings, as tests/cli/conftest.py.
SCRUBBED_PREFIXES = ("GITHUB_", "GITLAB_", "CI_", "SPELLWARDEN_", "RUNNER_")
SCRUBBED = ("CI", "DO_NOT_TRACK", "GITLAB_CI", "GITHUB_ACTIONS", "JENKINS_URL", "TF_BUILD", "TEAMCITY_VERSION", "BUILDKITE",
            "CIRCLECI", "BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID", "DRONE", "TRAVIS")
HERMETIC_GIT = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.excludesFile", "GIT_CONFIG_VALUE_0": os.devnull}
# Where a report prints the scanner's version: the JSON report, the SARIF driver, the Markdown footer and the HTML report's
# first line. The CycloneDX document is rewritten instead; the text and Code Quality reports print none.
VERSION_TEMPLATES = ('"scanner_version": "{}"', '"semanticVersion": "{}"', "Spellwarden {}, rules")


def clean_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items()
                   if key not in SCRUBBED and not key.startswith(SCRUBBED_PREFIXES)}
    environment.update(HERMETIC_GIT)
    environment.update(extra or {})
    return environment


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.safecrlf=false", "-c", "user.name=golden",
                    "-c", "user.email=golden@example.invalid", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main",
                    *args], cwd=repo, env=clean_environment(), check=True, capture_output=True)


def build_repo(source: str, dest: Path) -> Path:
    """A git repository at `dest` holding a copy of the repository-relative directory `source`, every file committed."""
    shutil.copytree(ROOT / source, dest)
    _git(dest, "init", "-q")
    _git(dest, "add", "-A")
    _git(dest, "commit", "-q", "--allow-empty", "-m", "fixture")
    return dest


def scan_argv(repo: Path, out: Path, formats: Sequence[tuple[str, str]], extra: Sequence[str] = ()) -> list[str]:
    argv = ["scan", str(repo), "--as-of", AS_OF, "--no-telemetry", "--no-probe", "--quiet", *extra]
    for fmt, name in formats:
        argv += ["--format", fmt, "--output", str(out / name)]
    return argv


@contextlib.contextmanager
def _environment(extra: Mapping[str, str] | None) -> Iterator[None]:
    saved = dict(os.environ)
    environment = clean_environment(extra)
    os.environ.clear()
    os.environ.update(environment)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def render(repo: Path, out: Path, *, formats: Sequence[tuple[str, str]] = SIX_FORMATS, extra: Sequence[str] = (),
           env: Mapping[str, str] | None = None) -> tuple[int, dict[str, bytes]]:
    """`spellwarden scan` of `repo` in this process, each format to its file under `out`: the exit code and the bytes."""
    from spellwarden_cli.main import main

    out.mkdir(parents=True, exist_ok=True)
    with _environment(env):
        code = main(scan_argv(repo, out, formats, extra))
    return code, {fmt: (out / name).read_bytes() for fmt, name in formats}


def as_version(fmt: str, data: bytes, current: str, target: str) -> bytes:
    """`data` with the scanner's version `current` set to `target` wherever the report prints it. A CycloneDX document also loses
    its `serialNumber`, a digest of the whole document that changes with the version."""
    text = data.decode("utf-8")
    if fmt == "cyclonedx":
        document = json.loads(text)
        document.pop("serialNumber", None)
        for tool in document.get("metadata", {}).get("tools", {}).get("components", []):
            if tool.get("name") == "Spellwarden" and tool.get("version") == current:
                tool["version"] = target
        return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    for template in VERSION_TEMPLATES:
        text = text.replace(template.format(current), template.format(target))
    return text.encode("utf-8")
