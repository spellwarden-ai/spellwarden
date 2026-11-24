"""Fixture reports for the golden tests of 1.18.0: a fixture directory copied into a fresh git repository (`build_repo`, so
executable bits come from the index and match on every OS), scanned in this process with a clean environment (`render`), and a
report's scanner version, and since 1.20.0 its rules version, set to a given release's (`as_version`), so a golden file holds
the same bytes whatever version the tree carries. tests/golden/record_1_17_0.py, tests/golden/record_1_18_0.py and their tests use it."""
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
# Where a report prints the rules version (Engine 1.20.0: scan selection, D45): the JSON report, the Markdown footer and the HTML
# report's first line. The CycloneDX document's `spellwarden:rules_version` property is rewritten instead; SARIF, text and Code
# Quality reports print none.
RULES_TEMPLATES = ('"rules_version": "{}"', ", rules {}")
# The rules version each recorded release printed. 1.20.0 moved it to 2026.11.8 (SW-CFG-012 and SW-CFG-013 read settings
# documents) and 1.22.0 to 2026.11.9 (P6-4: skill rules also read a normalised copy of the text), so a golden test of an older
# release sets it back as it sets the scanner's version back.
RECORDED_RULES = {"1.17.0": "2026.11.7", "1.18.0": "2026.11.7", "1.19.0": "2026.11.7", "1.20.0": "2026.11.8", "1.21.0": "2026.11.8"}
# The fixture roots whose files 1.20.0 changes (Engine 1.20.0: scan selection, C40a): a file planted there for a new row of the
# client table is read by the repository scan of every version (a `SKILL.md`, an `AGENTS.md`), so the digests that 1.17.0 and
# 1.18.0 took from the fixture trees of their day no longer hold there. Their records keep the roots; their tests skip them.
FIXTURES_CHANGED_IN_1_20_0 = ("tests/fixtures/homes/common", "tests/fixtures/homes/windows")
# The fixture roots whose reports 1.22.0 changes (P6-4 spec 6.9): the normalised reading of the skill rules adds SW-SKL-007 to the
# positive fixture of SW-SKL-032, whose line 26 decodes a download piped to a shell. The records of 1.17.0 to 1.20.0 keep the root;
# their tests skip it, and tests/golden/1.22.0 records its reports.
FIXTURES_CHANGED_IN_1_22_0 = ("fixtures/skills/SW-SKL-032/positive",)


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


def as_version(fmt: str, data: bytes, current: str, target: str, *, current_rules: str | None = None) -> bytes:
    """`data` with the scanner's version `current` set to `target` wherever the report prints it and, when `target` is a release
    of `RECORDED_RULES` that printed another rules version, the rules version `current_rules` (default: this tree's
    `RULES_VERSION`) set to that one. A CycloneDX document also loses its `serialNumber`, a digest of the whole document that
    changes with either version."""
    from spellwarden_scan import RULES_VERSION

    rules_now = RULES_VERSION if current_rules is None else current_rules
    rules_then = RECORDED_RULES.get(target, rules_now)
    text = data.decode("utf-8")
    if fmt == "cyclonedx":
        document = json.loads(text)
        document.pop("serialNumber", None)
        metadata = document.get("metadata", {})
        for tool in metadata.get("tools", {}).get("components", []):
            if tool.get("name") == "Spellwarden" and tool.get("version") == current:
                tool["version"] = target
        for prop in metadata.get("properties", []):
            if prop.get("name") == "spellwarden:rules_version" and prop.get("value") == rules_now:
                prop["value"] = rules_then
        return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    for template in VERSION_TEMPLATES:
        text = text.replace(template.format(current), template.format(target))
    if rules_then != rules_now:
        for template in RULES_TEMPLATES:
            text = text.replace(template.format(rules_now), template.format(rules_then))
    return text.encode("utf-8")
