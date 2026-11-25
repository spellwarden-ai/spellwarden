"""Community reports spec 11, claim B-6: for a case that is one skill package, the rule benchmark's result (`read_root`, in memory)
agrees with the command's (`spellwarden scan`), so a count of the benchmark and the test of the same case say the same thing."""
from __future__ import annotations

import importlib.util
import sys

import pytest

from community_cases import CLEAN_SKILL, PIP_SKILL, ROOT, SCRIPTS, write_case
from community_scan import finding_problems

BENCHMARK = ROOT / "benchmarks" / "rule_benchmark.py"
if not SCRIPTS.is_dir() or not BENCHMARK.exists():
    pytest.skip("benchmarks/ and scripts/ are not in an sdist", allow_module_level=True)

_spec = importlib.util.spec_from_file_location("rule_benchmark_agreement_test", BENCHMARK)
rb = importlib.util.module_from_spec(_spec)
sys.modules["rule_benchmark_agreement_test"] = rb
_spec.loader.exec_module(rb)

CASES = [  # (id, files, kind, rule, the benchmark's result)
    ("COM-0001", {"SKILL.md": PIP_SKILL}, "miss", "SW-SKL-009", "holds"),
    ("COM-0002", {"SKILL.md": CLEAN_SKILL}, "miss", "SW-SKL-009", "fails"),
    ("COM-0003", {"SKILL.md": CLEAN_SKILL}, "false_positive", "SW-SKL-009", "holds"),
    ("COM-0004", {"SKILL.md": PIP_SKILL}, "false_positive", "SW-SKL-009", "fails"),
    ("COM-0005", {"SKILL.md": PIP_SKILL, "scripts/run.sh": "pip install requests\n"}, "miss", "SW-SKL-009", "holds"),
]


def test_the_benchmark_and_the_command_agree_on_every_skill_case(tmp_path, run_cli):
    corpus = tmp_path / "corpus"
    for case_id, files, kind, rule, _result in CASES:
        write_case(corpus, case_id, files=files, kind=kind, rule=rule, outcome="fixed", fixed_in="1.24.0")
    block = rb.measure_community(rb.RuleSet.baseline(), corpus)
    for case in rb.COMMUNITY.load_cases(corpus):
        expected = next(row[4] for row in CASES if row[0] == case.id)
        assert block["cases"][case.id]["result"] == expected
        command_agrees = finding_problems(case, tmp_path / f"work-{case.id}", run_cli) == []
        assert command_agrees == (expected == "holds"), case.id
