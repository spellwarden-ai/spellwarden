#!/usr/bin/env python3
"""The release manifest of spec 7.5: one JSON file that ties together the PyPI files, the container image and the
two wrapper tags of one version. release.yml drafts it (`draft`, `notes`), manifest.yml checks and fills it
(`check-pypi`, `get`, `fill`), and scripts/release-wrappers.py reads it. Standard library only."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

FIELDS = ("version", "wheel_sha256", "sdist_sha256", "image_digest", "action_commit", "component_commit")
_SHAPES = {
    "version": re.compile(r"^\d+\.\d+\.\d+$"),
    "wheel_sha256": re.compile(r"^[0-9a-f]{64}$"),
    "sdist_sha256": re.compile(r"^[0-9a-f]{64}$"),
    "image_digest": re.compile(r"^sha256:[0-9a-f]{64}$"),
    "action_commit": re.compile(r"^[0-9a-f]{40}$"),
    "component_commit": re.compile(r"^[0-9a-f]{40}$"),
}
_NULLABLE = frozenset({"action_commit", "component_commit"})


def draft(version: str, wheel_sha256: str, sdist_sha256: str, image_digest: str) -> dict:
    return {"version": version, "wheel_sha256": wheel_sha256, "sdist_sha256": sdist_sha256,
            "image_digest": image_digest, "action_commit": None, "component_commit": None}


def validate(manifest: dict) -> list[str]:
    problems = [f"{key}: unknown key" for key in sorted(set(manifest) - set(FIELDS))]
    for key in FIELDS:
        if key not in manifest:
            problems.append(f"{key}: missing")
            continue
        value = manifest[key]
        if value is None and key in _NULLABLE:
            continue
        if not isinstance(value, str) or not _SHAPES[key].match(value):
            problems.append(f"{key}: malformed value {value!r}")
    return problems


def render(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"


def fill(manifest: dict, *, action_commit: str, component_commit: str) -> dict:
    return {**manifest, "action_commit": action_commit, "component_commit": component_commit}


def pypi_problems(manifest: dict, pypi: dict) -> list[str]:
    """Compares the manifest's hashes with PyPI's JSON API answer for the version."""
    version = manifest["version"]
    expected = {f"spellwarden-{version}-py3-none-any.whl": manifest["wheel_sha256"],
                f"spellwarden-{version}.tar.gz": manifest["sdist_sha256"]}
    found = {entry.get("filename"): entry.get("digests", {}).get("sha256") for entry in pypi.get("urls", [])}
    problems = []
    for filename, digest in expected.items():
        if filename not in found:
            problems.append(f"{filename}: not on PyPI")
        elif found[filename] != digest:
            problems.append(f"{filename}: PyPI has sha256 {found[filename]}, the manifest {digest}")
    return problems


def changelog_section(text: str, version: str) -> str:
    """The body under `## <version>` (any date suffix) up to the next `## ` heading."""
    match = re.search(rf"^## {re.escape(version)}\b.*?\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    if match is None:
        raise ValueError(f"CHANGELOG.md has no section for {version}")
    return match.group(1).strip("\n") + "\n"


def _load(path: str) -> dict:
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    problems = validate(manifest)
    if problems:
        raise SystemExit("release manifest invalid: " + "; ".join(problems))
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="release_manifest.py")
    commands = parser.add_subparsers(dest="command", required=True)
    d = commands.add_parser("draft")
    for flag in ("--version", "--wheel-sha256", "--sdist-sha256", "--image-digest"):
        d.add_argument(flag, required=True)
    n = commands.add_parser("notes")
    n.add_argument("version")
    f = commands.add_parser("fill")
    f.add_argument("manifest")
    f.add_argument("--action-commit", required=True)
    f.add_argument("--component-commit", required=True)
    c = commands.add_parser("check-pypi")
    c.add_argument("manifest")
    c.add_argument("pypi_json")
    g = commands.add_parser("get")
    g.add_argument("manifest")
    g.add_argument("field", choices=FIELDS)
    args = parser.parse_args(argv)

    if args.command == "draft":
        manifest = draft(args.version, args.wheel_sha256, args.sdist_sha256, args.image_digest)
    elif args.command == "notes":
        sys.stdout.write(changelog_section(Path("CHANGELOG.md").read_text(encoding="utf-8"), args.version))
        return 0
    elif args.command == "fill":
        manifest = fill(_load(args.manifest), action_commit=args.action_commit, component_commit=args.component_commit)
    elif args.command == "check-pypi":
        problems = pypi_problems(_load(args.manifest), json.loads(Path(args.pypi_json).read_text(encoding="utf-8")))
        for problem in problems:
            print(f"::error::{problem}")
        return 1 if problems else 0
    else:
        print(_load(args.manifest)[args.field])
        return 0
    problems = validate(manifest)
    if problems:
        print("release manifest invalid: " + "; ".join(problems), file=sys.stderr)
        return 1
    sys.stdout.write(render(manifest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
