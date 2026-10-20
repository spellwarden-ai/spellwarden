#!/usr/bin/env python3
"""Spec 7.5, run by the owner after release.yml succeeded for vX.Y.Z.

  release-wrappers.py X.Y.Z         check the draft release manifest against PyPI and the registry, write
                                    ../scan-action/requirements.txt and the image default of
                                    ../scan-gitlab/templates/scan.yml, commit each on a branch release/X.Y.Z
  release-wrappers.py X.Y.Z --tag   after both branches are merged and green: check that each main HEAD is the
                                    merged release commit and that its pipeline passed, then create SSH-signed tags
                                    (vX.Y.Z and the moved vX in scan-action, X.Y.Z in scan-gitlab) and verify them

It pushes nothing: it prints the push commands for the owner. Standard library only; git, gh and docker run as
subprocesses, GitLab's public API is read with urllib."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_manifest  # noqa: E402

ENGINE_REPO = "spellwarden-ai/spellwarden"
ACTION_REPO = "spellwarden-ai/scan"
GITLAB_PROJECT = "spellwarden-ai/scan"
IMAGE = "ghcr.io/spellwarden-ai/spellwarden"
# Task 18's contract: exactly one line of templates/scan.yml matches this; it holds the default image.
_IMAGE_DEFAULT = re.compile(r'^    image: +\{default: "[^"]*"\}$', re.M)

Runner = Callable[..., tuple[int, str]]


class ReleaseError(Exception):
    pass


def run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str]:
    done = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    return done.returncode, done.stdout if done.returncode == 0 else done.stdout + done.stderr


def http_json(url: str) -> object:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 (fixed https URLs)
        return json.load(response)


@dataclass
class Context:
    version: str
    engine: Path
    action: Path
    gitlab: Path
    runner: Runner = run
    http: Callable[[str], object] = http_json

    def out(self, cmd: list[str], cwd: Path | None = None) -> str:
        code, text = self.runner(cmd, cwd)
        if code != 0:
            raise ReleaseError(f"`{' '.join(cmd)}` failed ({code}): {text.strip()}")
        return text

    @property
    def major(self) -> str:
        return "v" + self.version.split(".")[0]


def fetch_manifest(ctx: Context) -> dict:
    text = ctx.out(["gh", "release", "download", f"v{ctx.version}", "--repo", ENGINE_REPO,
                    "--pattern", "release-manifest.json", "--output", "-"])
    manifest = json.loads(text)
    problems = release_manifest.validate(manifest)
    if problems or manifest["version"] != ctx.version:
        raise ReleaseError("release manifest invalid: " + "; ".join(problems or [f"version {manifest['version']}"]))
    return manifest


def check_pypi(ctx: Context, manifest: dict) -> None:
    problems = release_manifest.pypi_problems(manifest, ctx.http(f"https://pypi.org/pypi/spellwarden/{ctx.version}/json"))
    if problems:
        raise ReleaseError("PyPI disagrees with the manifest: " + "; ".join(problems))


def check_image(ctx: Context, manifest: dict) -> None:
    text = ctx.out(["docker", "buildx", "imagetools", "inspect", f"{IMAGE}:{ctx.version}", "--format", "{{json .Manifest}}"])
    digest = json.loads(text)["digest"]
    if digest != manifest["image_digest"]:
        raise ReleaseError(f"the image {IMAGE}:{ctx.version} is {digest}, the manifest says {manifest['image_digest']}")


def deps_lines(text: str) -> str:
    return "".join(line for line in text.splitlines(keepends=True) if not line.startswith("#"))


def action_requirements(version: str, wheel_sha256: str, deps: str) -> str:
    return (f"# Written by spellwarden-ai/spellwarden scripts/release-wrappers.py for {version}. Do not edit by hand.\n"
            f"spellwarden=={version} \\\n    --hash=sha256:{wheel_sha256}\n" + deps)


def set_component_image(text: str, image_ref: str) -> str:
    matches = _IMAGE_DEFAULT.findall(text)
    if len(matches) != 1:
        raise ReleaseError(f"templates/scan.yml must hold exactly one `image:` input default, found {len(matches)}")
    return _IMAGE_DEFAULT.sub(lambda _m: f'    image:          {{default: "{image_ref}"}}', text)


def _cache(path: Path) -> bool:
    """Python's byte-code cache, which the fixture scripts leave behind and no repository tracks."""
    return "__pycache__" in path.parts or path.suffix == ".pyc"


def _tree(root: Path) -> dict[str, bytes]:
    if not root.is_dir():
        return {}
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and not _cache(p.relative_to(root))}


def sync_fixtures(source: Path, target: Path) -> bool:
    """Makes `target` a byte-equal copy of `source` (plan P10); True when anything changed."""
    if not source.is_dir():
        raise ReleaseError(f"{source} does not exist; scan-action holds the fixture cases")
    if _tree(source) == _tree(target):
        return False
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return True


def _require_clean(ctx: Context, repo: Path) -> None:
    if ctx.out(["git", "status", "--porcelain"], repo).strip():
        raise ReleaseError(f"{repo} has uncommitted changes")


def _branch(ctx: Context, repo: Path, edit: Callable[[], list[str]]) -> None:
    """Creates release/X.Y.Z from origin/main, applies `edit` (which returns the paths to stage), commits."""
    _require_clean(ctx, repo)
    branch = f"release/{ctx.version}"
    ctx.out(["git", "fetch", "origin"], repo)
    code, _ = ctx.runner(["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], repo)
    if code == 0:
        raise ReleaseError(f"{repo} already has a branch {branch}")
    ctx.out(["git", "switch", "-c", branch, "origin/main"], repo)
    paths = edit()
    ctx.out(["git", "add", "-A", "--", *paths], repo)
    ctx.out(["git", "commit", "-m", f"Release {ctx.version}: pin spellwarden {ctx.version} (spec 7.5)"], repo)


def prepare(ctx: Context) -> list[str]:
    manifest = fetch_manifest(ctx)
    check_pypi(ctx, manifest)
    check_image(ctx, manifest)
    deps = deps_lines((ctx.engine / "docker" / "requirements.deps.txt").read_text(encoding="utf-8"))

    def edit_action() -> list[str]:
        (ctx.action / "requirements.txt").write_text(
            action_requirements(ctx.version, manifest["wheel_sha256"], deps), encoding="utf-8")
        return ["requirements.txt"]

    def edit_gitlab() -> list[str]:
        template = ctx.gitlab / "templates" / "scan.yml"
        template.write_text(set_component_image(template.read_text(encoding="utf-8"),
                                                f"{IMAGE}:{ctx.version}@{manifest['image_digest']}"), encoding="utf-8")
        paths = ["templates/scan.yml"]
        if (ctx.gitlab / "ci" / "test-image").is_dir():  # the first release retires the pre-1.0 test image
            ctx.out(["git", "rm", "-r", "-q", "ci/test-image"], ctx.gitlab)
            pipeline = ctx.gitlab / "ci" / "fixture-pipeline.yml"
            text = pipeline.read_text(encoding="utf-8") if pipeline.is_file() else ""
            kept = "".join(line for line in text.splitlines(keepends=True) if "1.0.0 removes this line" not in line)
            if kept != text:  # and the fixture pipelines' input that named that image
                pipeline.write_text(kept, encoding="utf-8")
                paths.append("ci/fixture-pipeline.yml")
        if sync_fixtures(ctx.action / "fixtures", ctx.gitlab / "fixtures"):
            paths.append("fixtures")
        return paths

    _branch(ctx, ctx.action, edit_action)
    _branch(ctx, ctx.gitlab, edit_gitlab)
    branch = f"release/{ctx.version}"
    notes = []
    if sync_fixtures(ctx.action / "fixtures", ctx.engine / "fixtures" / "repos"):
        notes.append(f"# {ctx.engine}/fixtures/repos was re-copied from scan-action: commit it on a branch of "
                     "spellwarden-oss and merge it through a pull request")
    return notes + [
        f"git -C {ctx.action} push -u origin {branch}",
        f"gh pr create --repo {ACTION_REPO} --head {branch} --base main --title 'Release {ctx.version}' "
        f"--body 'Pins spellwarden {ctx.version}.'",
        f"git -C {ctx.gitlab} push -u origin {branch}",
        f"glab mr create --repo {GITLAB_PROJECT} --source-branch {branch} --target-branch main "
        f"--title 'Release {ctx.version}'",
    ]


TAG_KEY_SETTING = "spellwarden.tagSigningKey"


def _tag_key(ctx: Context, repo: Path) -> str:
    """The SSH key the release tags are signed with (spec 11.2 point 2): its own setting, so that the repository's
    commits keep whatever signing the owner chose for them, and only `git tag -s` here uses SSH."""
    code, value = ctx.runner(["git", "config", "--get", TAG_KEY_SETTING], repo)
    if code != 0 or not value.strip():
        raise ReleaseError(f"git config {TAG_KEY_SETTING} is not set in {repo}: "
                           f"git -C {repo} config {TAG_KEY_SETTING} ~/.ssh/spellwarden_tags.pub (spec 11.2 point 2)")
    return os.path.expanduser(value.strip())


def _main_head(ctx: Context, repo: Path, path: str, needle: str) -> str:
    ctx.out(["git", "fetch", "origin", "--tags"], repo)
    sha = ctx.out(["git", "rev-parse", "origin/main"], repo).strip()
    if needle not in ctx.out(["git", "show", f"origin/main:{path}"], repo):
        raise ReleaseError(f"main of {repo} does not pin the release in {path}; merge the release branch first")
    return sha


def _require_absent(ctx: Context, repo: Path, tag: str) -> None:
    code, _ = ctx.runner(["git", "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}"], repo)
    if code == 0:
        raise ReleaseError(f"the tag {tag} already exists in {repo}")


def _check_runs_passed(ctx: Context, sha: str) -> None:
    text = ctx.out(["gh", "api", "--paginate", f"repos/{ACTION_REPO}/commits/{sha}/check-runs",
                    "--jq", ".check_runs[] | [.name, .status, .conclusion] | @tsv"])
    runs = [line.split("\t") for line in text.splitlines() if line.strip()]
    # A job whose `if:` is false on a push (the pull-request-only cases of test.yml) concludes `skipped`; `neutral`
    # is no failure either. Every run must be completed, none may have failed, and at least one must have passed.
    bad = [r for r in runs if r[1:2] != ["completed"] or r[2:] not in (["success"], ["skipped"], ["neutral"])]
    if bad:
        raise ReleaseError(f"check run not successful on {ACTION_REPO}@{sha}: {bad}")
    if not any(r[2:] == ["success"] for r in runs):
        raise ReleaseError(f"no check run passed on {ACTION_REPO}@{sha}")


def _pipeline_passed(ctx: Context, sha: str) -> None:
    project = urllib.parse.quote(GITLAB_PROJECT, safe="")
    pipelines = ctx.http(f"https://gitlab.com/api/v4/projects/{project}/pipelines?sha={sha}&ref=main&order_by=id&sort=desc")
    if not pipelines or pipelines[0].get("status") != "success":
        status = pipelines[0].get("status") if pipelines else "none"
        raise ReleaseError(f"the latest main pipeline of {GITLAB_PROJECT}@{sha} is {status}, not success")


def _sign(ctx: Context, repo: Path, key: str, args: list[str], name: str) -> None:
    ctx.out(["git", "-c", "gpg.format=ssh", "-c", f"user.signingkey={key}", "tag", *args], repo)
    signers = ctx.engine / "allowed_signers"
    # Only a key of allowed_signers is trusted fully; minTrustLevel refuses any other valid signature (D59).
    ctx.out(["git", "-c", f"gpg.ssh.allowedSignersFile={signers}", "-c", "gpg.minTrustLevel=fully", "tag", "-v", name],
            repo)


def tag(ctx: Context) -> list[str]:
    manifest = fetch_manifest(ctx)
    version = ctx.version
    action_key, gitlab_key = _tag_key(ctx, ctx.action), _tag_key(ctx, ctx.gitlab)
    action_sha = _main_head(ctx, ctx.action, "requirements.txt", f"--hash=sha256:{manifest['wheel_sha256']}")
    gitlab_sha = _main_head(ctx, ctx.gitlab, "templates/scan.yml", f"{IMAGE}:{version}@{manifest['image_digest']}")
    _require_absent(ctx, ctx.action, f"v{version}")
    _require_absent(ctx, ctx.gitlab, version)
    _check_runs_passed(ctx, action_sha)
    _pipeline_passed(ctx, gitlab_sha)
    _sign(ctx, ctx.action, action_key, ["-s", f"v{version}", "-m", f"spellwarden {version}", action_sha], f"v{version}")
    _sign(ctx, ctx.action, action_key,
          ["-f", "-s", ctx.major, "-m", f"spellwarden {ctx.major}, currently {version}", action_sha], ctx.major)
    _sign(ctx, ctx.gitlab, gitlab_key, ["-s", version, "-m", f"spellwarden {version}", gitlab_sha], version)
    return [
        f"git -C {ctx.action} push origin v{version}",
        f"git -C {ctx.action} push --force origin {ctx.major}",
        f"git -C {ctx.gitlab} push origin {version}",
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="release-wrappers.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version")
    parser.add_argument("--tag", action="store_true")
    parser.add_argument("--action-dir", default="../scan-action")
    parser.add_argument("--gitlab-dir", default="../scan-gitlab")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        print("version must be X.Y.Z", file=sys.stderr)
        return 2
    engine = Path(__file__).resolve().parents[1]
    ctx = Context(version=args.version, engine=engine, action=Path(args.action_dir).resolve(),
                  gitlab=Path(args.gitlab_dir).resolve())
    try:
        commands = tag(ctx) if args.tag else prepare(ctx)
    except ReleaseError as exc:
        print(f"release-wrappers: {exc}", file=sys.stderr)
        return 1
    print("Nothing was pushed. Run these yourself:")
    for command in commands:
        print(f"  {command}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
