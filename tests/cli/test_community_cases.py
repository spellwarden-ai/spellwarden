"""Community reports spec 11, claims S-1 to S-3: every case of `fixtures/community/` is a test of the command. `spellwarden scan`
over a copy of the case's files must read it (exit 0 or 1, never 2), and for a fixed case a miss has a finding of its rule and a
false positive has none; an open case is a strict expected failure on that finding check only, so the build fails on the day it
starts to pass (6.5). While the corpus holds no case, the parametrised tests below are skipped by pytest for an empty parameter
set; the oracle test (S-3) runs on a synthetic corpus and proves the check can fail both ways."""
from __future__ import annotations

import pytest

from community_cases import ROOT, SCRIPTS, load_script, write_case
from community_scan import finding_problems, scan_rules

if not SCRIPTS.is_dir():
    pytest.skip("scripts/ is not in an sdist", allow_module_level=True)

from conftest import load_skill_fixture

corpus = load_script("community_corpus.py", "spellwarden_community_corpus_cases_test")


def _real_cases() -> list:
    try:
        return corpus.load_cases(ROOT / "fixtures" / "community")
    except corpus.CorpusError:
        return []  # tests/test_community_corpus.py reports the layout problem


CASES = _real_cases()
FIXED = [pytest.param(case, id=case.id) for case in CASES if case.record["outcome"] == "fixed"]
OPEN = [pytest.param(case, id=case.id, marks=pytest.mark.xfail(strict=True, reason="an open case: the rule change is not released"))
        for case in CASES if case.record["outcome"] == "open"]


@pytest.mark.parametrize("case", [pytest.param(case, id=case.id) for case in CASES])
def test_the_command_reads_every_case_whole(case, tmp_path, run_cli):
    code, _found = scan_rules(case.files, tmp_path, run_cli)
    assert code in (0, 1), f"{case.id}: exit {code}"


@pytest.mark.parametrize("case", FIXED)
def test_a_fixed_case_gives_the_corrected_behaviour(case, tmp_path, run_cli):
    assert finding_problems(case, tmp_path, run_cli) == []


@pytest.mark.parametrize("case", OPEN)
def test_an_open_case_is_an_expected_failure_until_the_rule_changes(case, tmp_path, run_cli):
    assert finding_problems(case, tmp_path, run_cli) == []


# --- S-3: the oracle proves itself on a synthetic corpus ------------------------------------------------------------------------

def _synthetic(tmp_path, kind: str):
    files, _expected = load_skill_fixture("SW-SKL-001", "positive")
    write_case(tmp_path / "corpus", "COM-0001", files=files, kind=kind, rule="SW-SKL-001", outcome="fixed", fixed_in="1.23.0")
    return corpus.load_cases(tmp_path / "corpus")[0]


def test_a_known_positive_skill_passes_as_a_miss_and_fails_as_a_false_positive(tmp_path, run_cli):
    assert finding_problems(_synthetic(tmp_path / "a", "miss"), tmp_path / "work-a", run_cli) == []
    problems = finding_problems(_synthetic(tmp_path / "b", "false_positive"), tmp_path / "work-b", run_cli)
    assert problems == ["COM-0001: the scan still has a finding of SW-SKL-001, which a false positive must not have"]


def test_a_known_negative_skill_fails_as_a_miss(tmp_path, run_cli):
    files, _expected = load_skill_fixture("SW-SKL-001", "negative")
    write_case(tmp_path / "corpus", "COM-0001", files=files, kind="miss", rule="SW-SKL-001", outcome="fixed", fixed_in="1.23.0")
    case = corpus.load_cases(tmp_path / "corpus")[0]
    assert finding_problems(case, tmp_path / "work", run_cli) == ["COM-0001: the scan has no finding of SW-SKL-001, which a miss needs"]


def test_a_sample_the_command_cannot_read_is_a_failing_case_never_a_pass(tmp_path):
    case = _synthetic(tmp_path, "false_positive")

    def unreadable(*_args, **_kwargs):
        return 2, "", "scan: unreadable"

    assert scan_rules(case.files, tmp_path / "work", unreadable) == (2, set())
    assert finding_problems(case, tmp_path / "work", unreadable) == ["COM-0001: the command could not read the sample (exit 2)"]
