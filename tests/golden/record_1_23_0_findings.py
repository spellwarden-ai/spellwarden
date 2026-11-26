"""Records what 1.23.0 finds (engine 1.24.0, speed and deadline spec 11.1): for every case below, the number of findings,
`truncated` and the SHA-256 of the findings as `benchmarks/speed_profile.digest` writes them, in `tests/golden/1.23.0/findings.json`.
It must be run on the tree of 1.23.0, before any change to `src/`: a pin recorded after a change would prove nothing, so it
refuses any other scanner version. Run it from the repository root and commit the file on its own:

    uv run --locked python tests/golden/record_1_23_0_findings.py

The reduced cases (128 KiB of agent text, 64 KiB lines) take seconds; the `full/` cases are the full-size inputs of spec 5.2 and
take about four minutes: `tests/test_golden_1_23_0_findings.py` checks the reduced ones in `make check`, and
`benchmarks/speed_profile.py check` the full ones. The inputs are built in memory and written nowhere. `benchmarks/` is not in the
sdist, so nothing here works without it."""
from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).resolve().parent / "1.23.0" / "findings.json"
RECORDED_VERSION = "1.23.0"
REDUCED = 128 * 1024  # bytes of agent text of a reduced generated case
LINE = 64 * 1024  # characters of a reduced adversarial line
FIXTURES = ROOT / "fixtures" / "skills"


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


speed = _module("speed_profile_recorder", ROOT / "benchmarks" / "speed_profile.py")
disguise = _module("disguise_recorder", ROOT / "benchmarks" / "disguise.py")
# the tests' own reader of the fixtures: three packages (SW-SKL-002 positive and negative, SW-SKL-011 positive) are built in code
# by `conftest.GENERATED`, and their directories hold only `expected.json`
conftest = _module("conftest_recorder", ROOT / "tests" / "conftest.py")

from spellwarden_scan import RuleSet, normalise, scan_skill_package  # noqa: E402

# `normalise=` of every case of the fixtures: on, off and each candidate step alone
VARIANTS = (("true", True), ("false", False), *((f"step-{step}", [step]) for step in normalise.CANDIDATE_STEPS))
ON_OFF = VARIANTS[:2]


def fixture_packages() -> Iterator[tuple[str, dict[str, bytes]]]:
    """`(rule/kind, files)` of every directory `fixtures/skills/<rule>/positive` and `.../negative`, as the tests read them
    (`conftest.load_skill_fixture`, generated packages included)."""
    for rule in sorted(FIXTURES.iterdir()):
        for kind in ("positive", "negative"):
            files, _expected = conftest.load_skill_fixture(rule.name, kind)
            yield f"{rule.name}/{kind}", files


def cases() -> Iterator[tuple[str, dict[str, bytes], object]]:
    """`(case id, files, normalise)` of every reduced case, in a fixed order."""
    packages = list(fixture_packages())
    for name, files in packages:
        for label, option in VARIANTS:
            yield f"fixture/{name}/{label}", files, option
    for technique in disguise.TECHNIQUE_IDS:
        for name, files in packages:
            variant = disguise.variant(files, technique, key=name)
            for label, option in ON_OFF:
                yield f"disguise/{technique}/{name}/{label}", variant, option
    for name, files in speed.generated_cases(REDUCED).items():
        for label, option in ON_OFF:
            yield f"generated/{name}/{label}", files, option
    for name, line in speed.normalise_lines(LINE).items():
        files = {"SKILL.md": speed.SKILL_MD, "scripts/run.sh": line.encode("utf-8")}
        for label, option in ON_OFF:
            yield f"lines/{name}/{label}", files, option


def full_cases() -> Iterator[tuple[str, dict[str, bytes], object]]:
    """The full-size inputs of spec 5.2, scanned with `normalise=True`: (a), (b), (b1), (b2) and (c)."""
    for name in speed.FULL_IDS:
        yield f"full/{name}", speed.full_input(name), True


def digest_of(files: dict[str, bytes], option: object) -> dict:
    return speed.digest(scan_skill_package(files, RuleSet.baseline(), normalise=option))


def record(full: bool = True) -> dict:
    from spellwarden_scan import RULES_VERSION, __version__

    if __version__ != RECORDED_VERSION:
        raise SystemExit(f"this records {RECORDED_VERSION}, and the tree is {__version__}: run it on the unchanged tree")
    found = {case: digest_of(files, option) for case, files, option in cases()}
    if full:
        found.update({case: digest_of(files, option) for case, files, option in full_cases()})
    return {"scanner_version": __version__, "rules_version": RULES_VERSION, "generator": speed.SEED_PREFIX, "cases": found}


def main(argv: list[str]) -> int:
    document = record(full="--reduced" not in argv)
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
