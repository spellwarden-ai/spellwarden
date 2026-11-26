"""The record of a rule's own measurement (P6-9 spec 8.6, claims 26 to 35): `benchmarks/measured_sets.py`, its JSON file and the
release gate `rule_benchmark.py check-measured`. `benchmarks/` is not in an sdist, so this file skips there."""
from __future__ import annotations

import importlib.util
import json
import os
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
    assert code == 1 and "SW-MCP-013: not measured yet" in out and "SW-CFG-015: not measured yet" in out


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
    assert set(ms.PENDING_RULES) - {"SW-SKL-038"} <= registered and "SW-SKL-038" not in registered


# --- the README block (claim 29) ----------------------------------------------------------------------------------------------------

def test_the_block_of_pending_rules_says_that_no_rule_is_measured():
    assert ms.block(all_pending()) == "No rule is measured on a set of its own in this version.\n"


def test_the_block_has_a_row_for_a_measured_rule_and_a_line_for_a_withdrawn_one_and_no_sample_text():
    withdrawn = {**pending("SW-CFG-015"), "status": "withdrawn", "reason": "g0_failed",
                 "g0": {"flagged_units": 12, "components": 5, "passed": False}}
    text = ms.block(document(SW_SKL_038=pending("SW-SKL-038"), SW_MCP_013=measured(), SW_CFG_015=withdrawn))
    lines = text.splitlines()
    assert lines[0].startswith("| Rule | Set |") and lines[2].startswith("| SW-MCP-013 | 35,000 units of public tool lists of remote MCP servers | 42 (holdout half) |")
    assert "75.0% (59.8% to 85.8%)" in lines[2] and "10.0% (0.0% to 20.0%) " in lines[2] and "| medium | 2026-12-02 |" in lines[2]
    assert "SW-SKL-038" not in text.split("\n\n")[0] and lines[-1] == ("SW-CFG-015 was withdrawn by the count gate before release: 12 flagged units from 5 components, "
                                                                                           "where 60 and 20 were needed; its id stays reserved.")
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


# --- a measured record with a missing, null or out-of-range member is a problem line, never a traceback (r0:F5) ---------------------

def _without(record: dict, *names: str) -> dict:
    return {key: value for key, value in record.items() if key not in names}


def _holdout_without(name: str) -> dict:
    record = measured()
    record["holdout"] = _without(record["holdout"], name)
    return record


@pytest.mark.parametrize("record", [
    _holdout_without("flagged"), _holdout_without("positive"),
    measured(g0=None), measured(g0={}), measured(g0={"flagged_units": 80}),
    measured(precision=None), measured(precision={"value": 0.75}),
    measured(frame=None), measured(frame={}), measured(split=None), measured(tuning=None), measured(owner_audit={}),
    measured(holdout=None), measured(holdout={}),
    measured(kinds=7), measured(kinds=[]), measured(kinds=["nonsense"]), measured(kinds=[3]),
    measured(tuning={"rounds": 99, "flagged": 40, "positive": 30, "benign": 10}),
    measured(tuning={"rounds": 0, "flagged": 40, "positive": 30, "benign": 10}),
])
def test_a_measured_record_with_a_missing_null_or_out_of_range_member_is_a_problem_not_a_traceback(record):
    problems = ms.check_record("SW-MCP-013", record)
    assert problems and all(isinstance(line, str) and "\n" not in line for line in problems)
    assert ms.check_document(document(SW_MCP_013=record)) == problems


def test_a_null_frame_makes_the_release_check_exit_1_and_nothing_renders(tmp_path):
    code, _, _ = _run(tmp_path, document(SW_MCP_013=measured(frame=None)), "--release")
    assert code == 1


def test_the_rounds_of_tuning_may_be_one_to_three():
    for rounds in (1, 2, 3):
        assert ms.check_record("SW-MCP-013", measured(tuning={"rounds": rounds, "flagged": 40, "positive": 30, "benign": 10})) == []


# --- whole-frame records and version 2 (spec 8.6 and 8.1a, claims 31 to 35) --------------------------------------------------------

LIMIT_WHOLE = "The set was scored whole: no part of it was held out, and the rule was not tuned on it."
SETS = Path(__file__).resolve().parents[2] / "code-p6-9-sets" / "data" / "rule-sets"  # the `code` tooling's records, beside this checkout
SETS = Path(os.environ.get("SPELLWARDEN_RULE_SETS", SETS))


def whole_frame(positive: int = 22, benign: int = 0, **more) -> dict:
    """A valid whole-frame `measured` record (spec 8.6): no split, tuning or holdout; `scored` holds the flagged units of the frame."""
    record = measured(positive, benign, set="sw-cfg-015-v2", design="whole_frame")
    for name in ("split", "tuning", "holdout"):
        del record[name]
    record["g0"] = {"flagged_units": positive + benign, "components": 16, "passed": True}
    record["scored"] = {"flagged": positive + benign, "positive": positive, "benign": benign, "ambiguous": 0, "error": 0}
    record["limits"] = ["It does not see local servers.", LIMIT_WHOLE]
    record.update(more)
    return record


def whole_withdrawn(reason: str, positive: int, benign: int, **more) -> dict:
    record = whole_frame(positive, benign, status="withdrawn", reason=reason)
    del record["severity"]
    record.update(more)
    return record


def not_assessable(**more) -> dict:
    """22 flagged units of which only 10 are labelled positive or benign: fewer than 20, so the set cannot be assessed."""
    low, high = ms.wilson(5, 10)
    return whole_withdrawn("not_assessable", 5, 5, g0={"flagged_units": 22, "components": 16, "passed": True},
                           scored={"flagged": 22, "positive": 5, "benign": 5, "ambiguous": 10, "error": 2},
                           precision={"value": 0.5, "low": round(low, 3), "high": round(high, 3)}, **more)


def document2(rules: dict, superseded: dict) -> dict:
    return {"measured_sets": 2, "rules": rules, "superseded": superseded}


def real_record(name: str) -> dict:
    path = SETS / name / "record.json"
    if not path.is_file():
        pytest.skip(f"the `code` tooling's record {name} is not at {SETS}; set SPELLWARDEN_RULE_SETS to the rule-sets directory")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert set(loaded) == {"rule", "record"}
    return loaded["record"]


def test_the_designs_and_the_band_of_a_whole_frame_set_are_the_specs():  # claim 32
    assert ms.DESIGNS == ("split", "whole_frame") and ms.WHOLE_FRAME_G0 == (20, 10)


def test_a_whole_frame_record_measured_or_withdrawn_is_valid():  # claim 31
    assert ms.check_record("SW-CFG-015", whole_frame()) == []
    assert ms.check_record("SW-CFG-015", whole_frame(recall=None, planted_catch=None)) == []
    assert ms.check_record("SW-MCP-013", whole_frame(36, 18, set="sw-mcp-013-v2")) == []  # 0.667: medium
    assert whole_frame(36, 18)["severity"] == "medium" and whole_frame()["severity"] == "high"
    below = whole_withdrawn("precision_below_bar", 10, 15)
    assert ms.check_record("SW-CFG-015", below) == []
    short = not_assessable()
    assert ms.check_record("SW-CFG-015", short) == []
    assert ms.check_record("SW-CFG-015", {k: v for k, v in short.items() if k != "precision"}) == []


def test_a_whole_frame_record_holds_no_split_tuning_or_holdout():  # claim 31
    for name, block in (("split", {"tuning_units": 1, "holdout_units": 1}), ("tuning", {"rounds": 1, "flagged": 1, "positive": 1, "benign": 0}),
                        ("holdout", {"flagged": 1, "positive": 1, "benign": 0, "ambiguous": 0, "error": 0})):
        assert any(name in p for p in ms.check_record("SW-CFG-015", whole_frame(**{name: block}))), name
    assert any("scored" in p for p in ms.check_record("SW-CFG-015", _without(whole_frame(), "scored")))
    assert any("scored" in p for p in ms.check_record("SW-CFG-015", whole_frame(scored={"flagged": 22})))


def test_a_whole_frame_g0_must_have_passed_and_lie_in_the_band():  # claim 31
    def problems(**g0):
        return ms.check_record("SW-CFG-015", whole_frame(g0={"flagged_units": 22, "components": 16, "passed": True, **g0}))
    assert problems() == []
    assert problems(flagged_units=20, components=10) == []
    for g0 in ({"passed": False}, {"flagged_units": 19}, {"components": 9}, {"flagged_units": 60, "components": 20}):
        assert any("count gate" in p for p in problems(**g0)), g0
    assert problems(flagged_units=60, components=19) == [] and problems(flagged_units=59, components=20) == []
    assert any("count gate" in p for p in ms.check_record("SW-CFG-015", whole_withdrawn(
        "precision_below_bar", 10, 15, g0={"flagged_units": 25, "components": 16, "passed": False})))


def test_a_whole_frame_record_is_never_withdrawn_by_g0_and_a_withdrawal_agrees_with_its_counts():  # claim 31
    assert any("reason" in p for p in ms.check_record("SW-CFG-015", whole_withdrawn("g0_failed", 10, 15)))
    assert any("reason" in p for p in ms.check_record("SW-CFG-015", whole_withdrawn("because", 10, 15)))
    assert any("scored" in p or "g0" in p for p in ms.check_record("SW-CFG-015", _without(whole_withdrawn("precision_below_bar", 10, 15), "scored")))
    assert any("precision_below_bar" in p for p in ms.check_record("SW-CFG-015", whole_withdrawn("precision_below_bar", 20, 2)))  # meets the bar
    assert any("not_assessable" in p for p in ms.check_record("SW-CFG-015", whole_withdrawn("not_assessable", 10, 15)))  # 25 are enough
    assert any("precision_below_bar" in p for p in ms.check_record("SW-CFG-015", whole_withdrawn("precision_below_bar", 5, 5)))  # too few
    assert any("precision" in p for p in ms.check_record("SW-CFG-015", whole_withdrawn(
        "precision_below_bar", 10, 15, precision={"value": 0.9, "low": 0.8, "high": 0.95})))


def test_a_whole_frame_precision_and_severity_are_recomputed_from_scored():  # claim 31
    record = whole_frame(36, 18, set="sw-mcp-013-v2")
    assert any("precision.value" in p for p in ms.check_record("SW-MCP-013", {**record, "precision": {**record["precision"], "value": 0.7}}))
    assert any("severity" in p for p in ms.check_record("SW-MCP-013", {**record, "severity": "high"}))
    assert any("scored.flagged" in p for p in ms.check_record("SW-MCP-013", {**record, "scored": {**record["scored"], "flagged": 55}}))
    assert any("does not meet the bar" in p for p in ms.check_record("SW-MCP-013", whole_frame(10, 10, severity="medium")))
    assert any("planted_catch" in p for p in ms.check_record("SW-MCP-013", {**record, "planted_catch": {"caught": 101, "planted": 100}}))


def test_a_design_that_is_unknown_and_a_split_record_with_scored_are_refused_and_a_record_without_design_is_a_split_record():  # claim 31
    assert any("design" in p for p in ms.check_record("SW-CFG-015", whole_frame(design="halves")))
    assert any("design" in p for p in ms.check_record("SW-CFG-015", whole_frame(design=None)))
    split = measured()
    assert "design" not in split and ms.check_record("SW-MCP-013", split) == []
    assert ms.check_record("SW-MCP-013", {**split, "design": "split"}) == []
    assert any("scored" in p for p in ms.check_record("SW-MCP-013", {**split, "scored": split["holdout"]}))
    assert any("split" in p for p in ms.check_record("SW-CFG-015", _without(whole_frame(design="split"), "scored")))


def test_a_version_2_document_checks_each_superseded_record_by_its_own_design():  # claim 33
    split_withdrawn = {**pending("SW-CFG-015"), "status": "withdrawn", "reason": "g0_failed",
                       "g0": {"flagged_units": 22, "components": 16, "passed": False}}
    rules = {"SW-CFG-015": whole_frame(), "SW-MCP-013": measured(set="sw-mcp-013-v2")}
    assert ms.check_document(document2(rules, {"SW-CFG-015": [split_withdrawn]})) == []
    assert ms.check_document(document2(rules, {})) == []
    second = whole_withdrawn("precision_below_bar", 10, 15, set="sw-cfg-015-v3")
    assert ms.check_document(document2({**rules, "SW-CFG-015": second}, {"SW-CFG-015": [split_withdrawn, whole_frame()]})) == []


@pytest.mark.parametrize("document_, needle", [
    (lambda _w, r: {"measured_sets": 2, "rules": r}, "the file is not"),
    (lambda _w, r: {**document2(r, {}), "extra": 1}, "the file is not"),
    (lambda _w, _r: {**document(**{"SW_CFG_015": whole_frame()}), "superseded": {}}, "the file is not"),
    (lambda _w, r: {"measured_sets": 3, "rules": r, "superseded": {}}, "the file is not"),
    (lambda _w, r: document2(r, []), "superseded is not an object"),
    (lambda w, r: document2(r, {"SW-CFG-015": w}), "list of records"),
    (lambda w, r: document2(r, {"SW-SKL-038": [w]}), "not in rules"),
    (lambda w, r: document2(r, {"SW-CFG-015": [{**w, "set": "sw-cfg-015-v2"}]}), "same set"),
    (lambda w, r: document2(r, {"SW-CFG-015": [w, w]}), "same set"),
    (lambda _w, r: document2(r, {"SW-CFG-015": [pending("SW-CFG-015")]}), "superseded"),
    (lambda w, r: document2(r, {"SW-CFG-015": [{**w, "reason": "g0_failed"}]}), "reason"),
    (lambda w, r: document2(r, {"SW-CFG-015": [{**w, "g0": {"flagged_units": 22, "components": 16}}]}), "superseded"),
])
def test_a_version_2_document_with_a_bad_superseded_member_is_refused(document_, needle):  # claim 33
    withdrawn = whole_withdrawn("precision_below_bar", 10, 15, set="sw-cfg-015-v1")
    rules = {"SW-CFG-015": whole_frame(), "SW-MCP-013": measured(set="sw-mcp-013-v2")}
    problems = ms.check_document(document_(withdrawn, rules))
    assert problems and any(needle in p for p in problems), problems


def test_the_superseded_records_are_in_set_order():  # claim 33
    older = whole_withdrawn("precision_below_bar", 10, 15, set="sw-cfg-015-v1")
    newer = whole_withdrawn("precision_below_bar", 10, 15, set="sw-cfg-015-v2")
    rules = {"SW-CFG-015": whole_frame(set="sw-cfg-015-v3")}
    assert ms.check_document(document2(rules, {"SW-CFG-015": [older, newer]})) == []
    assert any("set order" in p for p in ms.check_document(document2(rules, {"SW-CFG-015": [newer, older]})))


def test_the_gate_reads_a_version_2_document(tmp_path):  # claim 33
    rules = {rule_id: pending(rule_id) for rule_id in ms.PENDING_RULES}
    code, _out, _err = _run(tmp_path, document2(rules, {}))
    assert code == 0


def test_the_block_says_flagged_units_scored_with_the_design_in_words():  # claim 34
    text = ms.block(document2({"SW-CFG-015": whole_frame(), "SW-MCP-013": measured(set="sw-mcp-013-v2")}, {}))
    lines = text.splitlines()
    assert "| Flagged units scored |" in lines[0] and "Holdout flagged" not in text
    assert "| 22 (whole frame) |" in lines[2] and "| 42 (holdout half) |" in lines[3]


def test_the_block_shows_a_withdrawn_precision_or_counts_and_one_line_for_each_superseded_record():  # claim 34
    below = whole_withdrawn("precision_below_bar", 10, 15)
    short = not_assessable()
    split_withdrawn = {**pending("SW-MCP-013"), "status": "withdrawn", "reason": "g0_failed",
                       "g0": {"flagged_units": 54, "components": 47, "passed": False}}
    text = ms.block(document2({"SW-CFG-015": below, "SW-MCP-013": short}, {"SW-MCP-013": [split_withdrawn]}))
    lines = text.splitlines()
    assert lines[0] == "No rule is measured on a set of its own in this version." and lines[1] == ""
    assert lines[2] == "SW-CFG-015 was measured and withdrawn before release (precision below bar): precision 40.0% (23.4% to 59.3%) "\
        "over 25 flagged units scored on the whole frame; its id stays reserved."
    assert lines[4] == "SW-MCP-013 was measured and withdrawn before release (not assessable): 5 positive, 5 benign, 10 ambiguous and "\
        "2 error among 22 flagged units scored on the whole frame; its id stays reserved."
    assert lines[6] == "SW-MCP-013 was first measured on a split design and withdrawn by the count gate: 54 flagged units from 47 "\
        "components, where 60 and 20 were needed."
    assert len(lines) == 7 and not any(line.startswith("|") for line in lines)
    only = ms.block(document2({"SW-MCP-013": whole_frame(36, 18, set="sw-mcp-013-v2")}, {"SW-MCP-013": [split_withdrawn]}))
    assert only.splitlines()[-1] == lines[6] and only.splitlines()[-2] == ""


def test_the_block_of_a_version_2_document_without_superseded_records_is_the_one_of_version_1():  # claim 34
    assert ms.block(document2({rule_id: pending(rule_id) for rule_id in ms.PENDING_RULES}, {})) == ms.block(all_pending())


def test_a_whole_frame_record_of_the_code_tooling_passes_unchanged():  # claim 35
    for rule_id, name in (("SW-CFG-015", "sw-cfg-015-v2"), ("SW-MCP-013", "sw-mcp-013-v2")):
        record = real_record(name)
        assert record["design"] == "whole_frame" and record["set"] == name
        assert ms.check_record(rule_id, record) == [], name


def test_the_five_records_of_the_code_tooling_make_a_valid_version_2_document():  # claims 33 and 35
    records = {name: real_record(name) for name in ("sw-cfg-015-v1", "sw-cfg-015-v2", "sw-mcp-013-v1", "sw-mcp-013-v2", "sw-skl-038-v1")}
    for rule_id, name in (("SW-CFG-015", "sw-cfg-015-v1"), ("SW-MCP-013", "sw-mcp-013-v1"), ("SW-SKL-038", "sw-skl-038-v1")):
        assert ms.check_record(rule_id, records[name]) == [], name  # the v1 records pass unchanged, each by its own design
    built = document2({"SW-CFG-015": records["sw-cfg-015-v2"], "SW-MCP-013": records["sw-mcp-013-v2"], "SW-SKL-038": records["sw-skl-038-v1"]},
                      {"SW-CFG-015": [records["sw-cfg-015-v1"]], "SW-MCP-013": [records["sw-mcp-013-v1"]]})
    assert ms.check_document(built) == []
    assert text_is_file_form(built)
    text = ms.block(built)
    assert "SW-CFG-015 was first measured on a split design and withdrawn by the count gate: 22 flagged units from 16 components" in text
    assert "SW-MCP-013 was first measured on a split design and withdrawn by the count gate: 54 flagged units from 47 components" in text
    assert "SW-SKL-038 was withdrawn by the count gate before release: 2 flagged units from 2 components, where 60 and 20 were needed; its id stays reserved." in text
    assert "| 22 (whole frame) |" in text and "| 54 (whole frame) |" in text


def text_is_file_form(built: dict) -> bool:
    text = ms.dump(built)
    return json.loads(text) == built and text.isascii() and text.endswith("\n")


# --- the records of the rules that are measured (1.25.0) ----------------------------------------------------------------------------

# rule: (severity, precision value, precision low, precision high, recall value, scored flagged, scored positive, scored benign).
MEASURED_1_25_0 = {
    "SW-CFG-015": ("high", 1.0, 0.851345, 1.0, 0.661271, 22, 22, 0),
    "SW-MCP-013": ("medium", 0.666667, 0.53361, 0.777586, 0.131091, 54, 36, 18),
}


def committed() -> dict:
    return json.loads((ROOT / "benchmarks" / "measured_sets.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("rule_id", sorted(MEASURED_1_25_0))
def test_a_measured_rule_holds_its_whole_frame_record_and_keeps_the_withdrawn_split_record(rule_id):
    severity, value, low, high, recall, flagged, positive, benign = MEASURED_1_25_0[rule_id]
    loaded = committed()
    record = loaded["rules"][rule_id]
    assert loaded["measured_sets"] == 2 and record["status"] == "measured" and record["design"] == "whole_frame"
    assert record["severity"] == severity == ms.severity_for(positive, benign)
    assert record["precision"] == {"value": value, "low": low, "high": high} and record["recall"]["value"] == recall
    assert record["scored"] == {"flagged": flagged, "positive": positive, "benign": benign, "ambiguous": 0, "error": 0}
    assert record["frame"]["collected"] == "2026-11-25" and record["measured_on"] == "2026-11-26"
    assert [(old["status"], old["reason"], old["set"]) for old in loaded["superseded"][rule_id]] == [
        ("withdrawn", "g0_failed", rule_id.lower() + "-v1")]
    assert "whole frame" in ms.block(loaded)
    registered = {rule.id: rule.severity_default for rule in RuleSet.baseline()}
    assert registered[rule_id] == record["severity"]


def test_the_memory_rule_is_withdrawn_by_the_count_gate_its_id_stays_reserved_and_the_release_gate_passes():
    loaded = committed()
    record = loaded["rules"]["SW-SKL-038"]
    assert record["status"] == "withdrawn" and record["reason"] == "g0_failed" and record["set"] == "sw-skl-038-v1"
    assert record["g0"] == {"flagged_units": 2, "components": 2, "passed": False} and record["frame"]["units"] == 18789
    assert "SW-SKL-038" not in loaded["superseded"] and ms.check_record("SW-SKL-038", record) == []
    assert "SW-SKL-038" not in {rule.id for rule in RuleSet.baseline()}
    assert "SW-SKL-038 was withdrawn by the count gate before release: 2 flagged units from 2 components, where 60 and 20 were needed; its id stays reserved." in ms.block(loaded)
    assert rb.main(["check-measured", "--release"]) == 0
