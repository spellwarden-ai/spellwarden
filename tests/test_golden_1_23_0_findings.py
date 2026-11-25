"""Engine 1.24.0 (speed and deadline spec 11.1, claim T1): the findings of the engine, for every reduced case that
tests/golden/record_1_23_0_findings.py lists, are those 1.23.0 recorded on the unchanged tree, down to the order of the findings
and the count of what is truncated: the speed changes and the deadline must not change a finding. The full-size cases are checked
by `benchmarks/speed_profile.py check`. `benchmarks/` is not in an sdist, so this file skips there, as tests/test_disguise.py does."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RECORDER = ROOT / "tests" / "golden" / "record_1_23_0_findings.py"
if not (ROOT / "benchmarks" / "speed_profile.py").exists():
    pytest.skip("benchmarks/ is not in an sdist", allow_module_level=True)

_spec = importlib.util.spec_from_file_location("record_1_23_0_findings", RECORDER)
record = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record)

RECORDED = json.loads(record.GOLDEN.read_text(encoding="utf-8"))
GROUPS = ("fixture/", "disguise/", "generated/", "lines/")


def _differences(prefix: str) -> list[str]:
    wrong = []
    for case, files, option in record.cases():
        if case.startswith(prefix) and record.digest_of(files, option) != RECORDED["cases"][case]:
            wrong.append(case)
    return wrong


def test_the_pin_is_the_one_1_23_0_recorded():
    assert (RECORDED["scanner_version"], RECORDED["rules_version"]) == ("1.23.0", "2026.11.9")
    assert RECORDED["generator"] == record.speed.SEED_PREFIX


def test_every_reduced_case_has_a_recorded_digest_and_the_full_cases_are_recorded_too():
    produced = [case for case, _files, _option in record.cases()]
    assert len(produced) == len(set(produced))
    assert set(produced) <= set(RECORDED["cases"]) and len(produced) == 984
    assert sorted(case for case in RECORDED["cases"] if case.startswith("full/")) == [
        "full/a-ordinary", "full/b-worst", "full/b1-base64-line", "full/b2-lookalike-line", "full/c-big-skill"]
    assert set(RECORDED["cases"]) == set(produced) | {case for case in RECORDED["cases"] if case.startswith("full/")}


@pytest.mark.parametrize("prefix", GROUPS)
def test_the_findings_equal_those_of_1_23_0(prefix):
    wrong = _differences(prefix)
    assert not wrong, f"{len(wrong)} cases differ from 1.23.0, the first: {wrong[:5]}"


def test_the_pin_is_not_trivial():
    """Cases that find something are in it: the pin would hold for a scanner that found nothing otherwise."""
    cases = RECORDED["cases"]
    assert sum(1 for value in cases.values() if value["count"]) > 300
    assert any(value["truncated"] for value in cases.values())
    assert any(case.startswith("generated/worst/") and value["count"] for case, value in cases.items())
