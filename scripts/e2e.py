#!/usr/bin/env python3
"""Helpers of the pre-release wrapper test (spec 7.4), used by release.yml's e2e jobs and the e2e-setup action.
The fixture cases themselves are built and checked by fixtures/repos/make_repo.py and check.py (Task 17's tools).

  requirements   the hash-pinned requirements file that installs this run's wheel with --no-index
  expected-exit  a fixture case's expected exit code, read through the fixtures' own loader
  event          a synthetic pull_request event file (the comment check of e2e-permissions)
  sarif          a SARIF file validates against the vendored full SARIF 2.1.0 schema (run under `uv run`)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _requirements(args) -> int:
    wheels = sorted(Path(args.dist).glob("spellwarden-*-py3-none-any.whl"))
    if len(wheels) != 1:
        print(f"expected one wheel in {args.dist}, found {len(wheels)}", file=sys.stderr)
        return 2
    wheel = wheels[0]
    version = wheel.name.split("-")[1]
    house = Path(args.wheelhouse)
    house.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(wheel, house / wheel.name)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    deps = [line for line in Path(args.deps).read_text(encoding="utf-8").splitlines(keepends=True)
            if not line.startswith("#")]
    Path(args.out).write_text(
        "--no-index\n"
        f"--find-links {house.resolve().as_uri()}\n"
        f"spellwarden=={version} --hash=sha256:{digest}\n" + "".join(deps),
        encoding="utf-8")
    return 0


def _expected_exit(args) -> int:
    sys.path.insert(0, str(Path(args.fixtures).resolve()))
    from make_repo import load_case  # the fixtures' own loader: defaults, expect.json, then the variant

    print(load_case(args.case)["exit_code"])
    return 0


def _event(args) -> int:
    event = {"pull_request": {"number": 1, "head": {"repo": {"full_name": args.repository}}}}
    Path(args.path).write_text(json.dumps(event), encoding="utf-8")
    return 0


def _sarif(args) -> int:
    import jsonschema  # dev group; run through `uv run --locked`

    schema = json.loads((ROOT / "tests" / "schemas" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    document = json.loads(Path(args.file).read_text(encoding="utf-8"))
    validator = jsonschema.validators.validator_for(schema)(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    for error in errors[:20]:
        print(f"{list(error.absolute_path)}: {error.message}", file=sys.stderr)
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="e2e.py")
    commands = parser.add_subparsers(dest="command", required=True)
    r = commands.add_parser("requirements")
    for flag in ("--dist", "--wheelhouse", "--deps", "--out"):
        r.add_argument(flag, required=True)
    x = commands.add_parser("expected-exit")
    x.add_argument("case")
    x.add_argument("--fixtures", default=str(ROOT / "fixtures" / "repos"))
    e = commands.add_parser("event")
    e.add_argument("path")
    e.add_argument("--repository", required=True)
    s = commands.add_parser("sarif")
    s.add_argument("file")
    args = parser.parse_args(argv)
    handlers = {"requirements": _requirements, "expected-exit": _expected_exit, "event": _event, "sarif": _sarif}
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
