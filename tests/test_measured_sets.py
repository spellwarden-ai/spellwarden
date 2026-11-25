"""The record of a rule's own measurement (P6-9 spec 8.6, claims 26 to 30): `benchmarks/measured_sets.py`, its JSON file and the
release gate `rule_benchmark.py check-measured`. `benchmarks/` is not in an sdist, so this file skips there."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

from spellwarden_scan import RuleSet

ROOT = Path(__file__).resolve().parents[1]
MEASURED = ROOT / "benchmarks" / "measured_sets.py"
if not (ROOT / "benchmarks" / "rule_benchmark.py").exists():
    pytest.skip("benchmarks/ is not in an sdist", allow_module_level=True)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ms = _load("measured_sets", MEASURED)
rb = _load("rule_benchmark_for_measured_sets", ROOT / "benchmarks" / "rule_benchmark.py")


def measured(positive: int = 30, benign: int = 10, **more) -> dict:
    """A valid `measured` record whose holdout has `positive` and `benign` units, everything else consistent."""
    labelled = positive + benign
    value, (low, high) = positive / labelled, ms.wilson(positive, labelled)
    record = {
        "status": "measured", "set": "sw-mcp-013-v1", "frozen_sha256": "a" * 64, "frozen_at": "2026-12-01",
        "frame": {"units": 35000, "kind": "tool signatures", "collected": "2026-11-28", "components": 900},
        "split": {"tuning_units": 17000, "holdout_units": 18000},
        "g0": {"flagged_units": 80, "components": 30, "passed": True},
        "tuning": {"rounds": 2, "flagged": 40, "positive": 30, "benign": 10},
        "holdout": {"flagged": labelled + 2, "positive": positive, "benign": benign, "ambiguous": 1, "error": 1},
        "precision": {"value": round(value, 3), "low": round(low, 3), "high": round(high, 3)},
        "recall": {"value": 0.1, "low": 0.0, "high": 0.2, "method": "posterior of the sampled strata"},
        "planted_catch": {"caught": 90, "planted": 100}, "owner_audit": {"items": 150, "agreement": 0.9},
        "severity": ms.severity_for(positive, benign), "measured_on": "2026-12-02", "candidate_commit": "b" * 40,
        "kinds": ["tool"], "limits": ["It does not see local servers."],
    }
    record.update(more)
    return record


def pending(rule_id: str) -> dict:
    return {"status": "pending", "set": rule_id.lower() + "-v1", "limits": ["It does not see everything."]}


def document(**records: dict) -> dict:
    return {"measured_sets": 1, "rules": {rule_id.replace("_", "-"): record for rule_id, record in records.items()}}


# --- severity_for (claim 27) --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("positive, benign, expected", [
    (14, 6, "medium"), (13, 7, None), (18, 2, "high"), (17, 3, "medium"), (25, 5, "high"), (24, 6, "medium"), (36, 24, "medium"),
    (35, 25, None), (19, 0, None), (0, 0, None), (10, 9, None), (10, 10, None)])
def test_severity_for_at_each_edge(positive, benign, expected):
    assert ms.severity_for(positive, benign) == expected


def test_the_table_of_the_spec_is_the_least_number_of_positives():
    needed = {20: (14, 18), 25: (17, 21), 30: (19, 25), 40: (25, 32), 60: (36, 48), 100: (60, 80)}
    for labelled, (for_medium, for_high) in needed.items():
        least_medium = next(p for p in range(labelled + 1) if ms.severity_for(p, labelled - p) is not None)
        least_high = next(p for p in range(labelled + 1) if ms.severity_for(p, labelled - p) == "high")
        assert (least_medium, least_high) == (for_medium, for_high), labelled


def test_below_twenty_labelled_units_is_never_assessable():
    assert all(ms.severity_for(positive, 19 - positive) is None for positive in range(20))


def test_the_interval_is_the_one_of_the_benchmark():
    for found, total in ((0, 0), (1, 1), (14, 20), (36, 60), (100, 100), (3, 1000)):
        assert ms.wilson(found, total) == rb.wilson(found, total)


# --- check_record (claim 26) --------------------------------------------------------------------------------------------------

def test_a_consistent_measured_record_is_valid():
    assert ms.check_record("SW-MCP-013", measured()) == []
    assert ms.check_record("SW-MCP-013", measured(recall=None, planted_catch=None)) == []


def test_a_precision_that_does_not_match_its_counts_is_refused():
    record = measured()
    record["precision"] = {**record["precision"], "value": record["precision"]["value"] + 0.002}
    assert any("precision.value" in problem for problem in ms.check_record("SW-MCP-013", record))
    record = measured()
    record["precision"] = {**record["precision"], "low": record["precision"]["low"] - 0.01}
    assert any("precision.low" in problem for problem in ms.check_record("SW-MCP-013", record))
    record = measured()
    record["precision"] = {**record["precision"], "high": 1.0}
    assert any("precision.high" in problem for problem in ms.check_record("SW-MCP-013", record))


def test_a_severity_other_than_the_one_the_counts_give_is_refused():
    assert any("severity" in problem for problem in ms.check_record("SW-MCP-013", measured(30, 10, severity="high")))  # 0.75: medium
    assert any("severity" in problem for problem in ms.check_record("SW-MCP-013", measured(36, 4, severity="medium")))  # 0.90: high
    assert ms.check_record("SW-MCP-013", measured(36, 4)) == [] and measured(36, 4)["severity"] == "high"


def test_a_measured_record_that_misses_the_bar_is_refused():
    record = measured(10, 10, severity="medium")
    assert any("does not meet the bar" in problem for problem in ms.check_record("SW-MCP-013", record))
    record = measured(10, 5, severity="medium")  # fewer than 20 labelled
    assert any("does not meet the bar" in problem for problem in ms.check_record("SW-MCP-013", record))


def test_flagged_must_be_the_sum_of_its_parts():
    record = measured()
    record["holdout"]["flagged"] += 1
    assert any("holdout.flagged" in problem for problem in ms.check_record("SW-MCP-013", record))


def test_the_count_gate_must_have_passed():
    record = measured()
    record["g0"] = {"flagged_units": 59, "components": 30, "passed": False}
    assert any("count gate" in problem for problem in ms.check_record("SW-MCP-013", record))
    record["g0"] = {"flagged_units": 59, "components": 30, "passed": True}
    assert any("count gate" in problem for problem in ms.check_record("SW-MCP-013", record))
    record["g0"] = {"flagged_units": 80, "components": 19, "passed": True}
    assert any("count gate" in problem for problem in ms.check_record("SW-MCP-013", record))


def test_a_long_string_and_an_unknown_key_are_refused():
    assert any("longer than 300" in p for p in ms.check_record("SW-MCP-013", measured(limits=["x" * 301])))
    assert any("unknown member" in p for p in ms.check_record("SW-MCP-013", measured(sample="a tool name")))
    record = measured()
    record["frame"]["host"] = "example.org"
    assert any("frame" in p for p in ms.check_record("SW-MCP-013", record))


def test_the_shape_of_each_status():
    assert ms.check_record("SW-MCP-013", pending("SW-MCP-013")) == []
    assert any("pending" in p for p in ms.check_record("SW-MCP-013", {**pending("SW-MCP-013"), "frozen_at": "2026-12-01"}))
    withdrawn = {**pending("SW-MCP-013"), "status": "withdrawn", "reason": "g0_failed",
                 "g0": {"flagged_units": 12, "components": 5, "passed": False}}
    assert ms.check_record("SW-MCP-013", withdrawn) == []
    assert ms.check_record("SW-MCP-013", {**withdrawn, "reason": "because"}) != []
    assert ms.check_record("SW-MCP-013", {**pending("SW-MCP-013"), "status": "withdrawn", "reason": "g0_failed"}) != []
    assert ms.check_record("SW-MCP-013", {"status": "done", "set": "x", "limits": ["a"]}) != []
    assert ms.check_record("SW-MCP-013", "text") != []
    assert ms.check_record("SW-XXX-001", pending("SW-MCP-013")) != []


def test_dates_and_hashes_are_checked():
    assert any("not a date" in p for p in ms.check_record("SW-MCP-013", measured(measured_on="yesterday")))
    assert any("not a hash" in p for p in ms.check_record("SW-MCP-013", measured(frozen_sha256="abc")))
    assert any("not a hash" in p for p in ms.check_record("SW-MCP-013", measured(candidate_commit="b" * 39)))


# --- the file and the gate (claim 28) -------------------------------------------------------------------------------------------

REGISTERED = {"SW-SKL-038": "medium", "SW-MCP-013": "medium", "SW-CFG-015": "medium"}


def all_pending() -> dict:
    return document(**{rule_id: pending(rule_id) for rule_id in ms.PENDING_RULES})


def test_the_committed_file_is_valid_pins_the_three_rules_and_is_written_in_the_file_form():
    path = ROOT / "benchmarks" / "measured_sets.json"
    text = path.read_text(encoding="utf-8")
    loaded = json.loads(text)
    assert ms.check_document(loaded) == [] and text == ms.dump(loaded) and text.isascii()
    assert set(loaded["rules"]) == set(ms.PENDING_RULES)


def test_the_development_gate_accepts_pending_records_and_needs_a_record_for_each_registered_rule():
    assert ms.release_problems(all_pending(), REGISTERED, release=False) == []
    missing = all_pending()
    del missing["rules"]["SW-MCP-013"]
    assert ms.release_problems(missing, REGISTERED, release=False) == ["SW-MCP-013: registered, with no record in measured_sets.json"]
    assert ms.release_problems(missing, {k: v for k, v in REGISTERED.items() if k != "SW-MCP-013"}, release=False) == []


def test_the_release_gate_refuses_a_pending_record_a_different_severity_and_a_withdrawn_rule_still_registered():
    assert ms.release_problems(all_pending(), REGISTERED, release=True) == [
        f"{rule_id}: not measured yet, so it cannot be released" for rule_id in ms.PENDING_RULES]
    ready = document(SW_SKL_038=measured(set="sw-skl-038-v1"), SW_MCP_013=measured(36, 4),
                     SW_CFG_015=measured(set="sw-cfg-015-v1"))
    assert ms.release_problems(ready, REGISTERED, release=True) == ["SW-MCP-013: registered at medium and measured at high"]
    ready["rules"]["SW-MCP-013"] = measured()
    assert ms.release_problems(ready, REGISTERED, release=True) == []
    withdrawn = {**pending("SW-CFG-015"), "status": "withdrawn", "reason": "precision_below_bar",
                 "holdout": {"flagged": 40, "positive": 10, "benign": 30, "ambiguous": 0, "error": 0}}
    ready["rules"]["SW-CFG-015"] = withdrawn
    assert ms.release_problems(ready, REGISTERED, release=True) == ["SW-CFG-015: its record says withdrawn and the rule is still registered"]
    assert ms.release_problems(ready, {k: v for k, v in REGISTERED.items() if k != "SW-CFG-015"}, release=True) == []
    ready["rules"]["SW-CFG-015"] = measured(set="sw-cfg-015-v1")
    assert ms.release_problems(ready, {k: v for k, v in REGISTERED.items() if k != "SW-MCP-013"}, release=True) == [
        "SW-MCP-013: has a measured record and is not registered"]


def _run(tmp_path, document_or_text, *args) -> tuple[int, str, str]:
    import contextlib
    import io

    path = tmp_path / "measured_sets.json"
    if document_or_text is not None:
        path.write_text(document_or_text if isinstance(document_or_text, str) else ms.dump(document_or_text), encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = rb.main(["check-measured", "--records", str(path), *args])
    return code, out.getvalue(), err.getvalue()


def test_check_measured_exits_0_in_development_with_pending_records(tmp_path):
    assert _run(tmp_path, all_pending())[0] == 0


def test_check_measured_release_exits_1_for_a_pending_record(tmp_path):
    code, out, _err = _run(tmp_path, all_pending(), "--release")
    assert code == 1 and "SW-SKL-038: not measured yet" in out


def test_check_measured_exits_1_for_an_invalid_record(tmp_path):
    broken = all_pending()
    broken["rules"]["SW-SKL-038"]["extra"] = "x"
    code, out, _err = _run(tmp_path, broken)
    assert code == 1 and "unknown member" in out


def test_check_measured_exits_2_for_a_missing_or_unreadable_file(tmp_path):
    code, _out, err = _run(tmp_path, None)
    assert code == 2 and err.startswith("measured_sets: ")
    assert _run(tmp_path, "{not json")[0] == 2


def test_check_measured_reads_the_registered_rules_of_this_checkout():
    assert rb.main(["check-measured"]) == 0
    registered = {rule.id for rule in RuleSet.baseline()}
    assert set(ms.PENDING_RULES) <= registered


# --- the README block (claim 29) ----------------------------------------------------------------------------------------------------

def test_the_block_of_pending_rules_says_that_no_rule_is_measured():
    assert ms.block(all_pending()) == "No rule is measured on a set of its own in this version.\n"


def test_the_block_has_a_row_for_a_measured_rule_and_a_line_for_a_withdrawn_one_and_no_sample_text():
    withdrawn = {**pending("SW-CFG-015"), "status": "withdrawn", "reason": "g0_failed",
                 "g0": {"flagged_units": 12, "components": 5, "passed": False}}
    text = ms.block(document(SW_SKL_038=pending("SW-SKL-038"), SW_MCP_013=measured(), SW_CFG_015=withdrawn))
    lines = text.splitlines()
    assert lines[0].startswith("| Rule | Set |") and lines[2].startswith("| SW-MCP-013 | 35,000 units of public tool lists of remote MCP servers | 42 |")
    assert "75.0% (59.8% to 85.8%)" in lines[2] and "10.0% (0.0% to 20.0%) " in lines[2] and "| medium | 2026-12-02 |" in lines[2]
    assert "SW-SKL-038" not in text.split("\n\n")[0] and lines[-1] == "SW-CFG-015 was measured and withdrawn before release (g0 failed); its id stays reserved."
    assert "It does not see local servers." in lines[2]


def test_the_readme_block_equals_the_record_and_a_wrong_block_is_found(tmp_path):
    readme = (ROOT / "README.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert readme.count(ms.README_START) == 1 and readme.count(ms.README_END) == 1
    current = readme[readme.index(ms.README_START) + len(ms.README_START) + 1:readme.index(ms.README_END)]
    assert current == ms.block(json.loads((ROOT / "benchmarks" / "measured_sets.json").read_text(encoding="utf-8")))
    copy_of = tmp_path / "README.md"
    copy_of.write_text(readme.replace(current, "stale\n"), encoding="utf-8")
    assert ms.main(["render", "--check", "--readme", str(copy_of)]) == 1
    assert ms.main(["render", "--readme", str(copy_of)]) == 0
    assert ms.main(["render", "--check", "--readme", str(copy_of)]) == 0
    assert copy_of.read_text(encoding="utf-8") == readme
    with pytest.raises(ValueError):
        ms.with_block("no markers", "x")


# --- the release workflow runs the gate (claim 30) --------------------------------------------------------------------------------------

def test_the_release_workflow_runs_the_gate_in_the_build_job_before_the_checks():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    runs = [step.get("run", "") for step in workflow["jobs"]["build"]["steps"]]
    gate = "uv run --locked python benchmarks/rule_benchmark.py check-measured --release"
    assert runs.count(gate) == 1 and runs.index(gate) < runs.index("make check")
    step = next(step for step in workflow["jobs"]["build"]["steps"] if step.get("run") == gate)
    assert re.fullmatch(r"[A-Za-z][^`$]*", step["name"])
