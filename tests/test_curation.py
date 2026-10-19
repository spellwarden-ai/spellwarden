"""Spec 5.9 and claim P6."""
from __future__ import annotations

import json

from spellwarden_scan.curation import CURATED_THRESHOLD, curation_score, is_curated, is_quarantined, severities_of, severity_weights
from spellwarden_scan.model import CurationInputs, Finding, Location


def finding(rule_id: str, severity: str, malicious: bool = False) -> Finding:
    return Finding(rule_id, severity, "t", Location("SKILL.md", 1), "e", "f" * 64, malicious)


def test_the_worked_example_scores_10_1_and_is_curated():
    """Spec 5.9's worked example: one open low, two accepted mediums, full metadata, the Phase B eval
    component: `12 * (0.6 * (1 - 1.25 / 12) + 0.2 * 1 + 0.2 * 0.5)` = 10.05, which rounds to 10.1
    (the spec's prose says 9.9; its own formula says 10.05, and the formula wins)."""
    inputs = CurationInputs(
        open_findings=(finding("SW-SKL-031", "low"),),
        accepted_findings=(finding("SW-SKL-012", "medium"), finding("SW-SKL-019", "medium")),
        metadata_present=5, eval_component=0.5,
    )
    assert severity_weights(inputs.open_findings) == 0.25
    score = curation_score(inputs)
    assert score == round(12 * (0.6 * (1 - 1.25 / 12) + 0.2 * 1 + 0.2 * 0.5), 1) == 10.1
    assert is_curated(inputs, score)


def test_the_formula_components():
    clean = CurationInputs((), (), 5)
    assert curation_score(clean) == 10.8  # 12 * (0.6 + 0.2 + 0.1)
    assert curation_score(CurationInputs((), (), 0)) == 8.4
    assert curation_score(CurationInputs((), (), 5, eval_component=1.0)) == 12.0
    critical = CurationInputs((finding("SW-SKL-011", "critical"),), (), 5)
    assert curation_score(critical) == 7.2  # S = 0.5
    two_critical = CurationInputs((finding("SW-SKL-011", "critical"), finding("SW-SKL-011", "critical")), (), 5)
    assert curation_score(two_critical) == 3.6  # S clamps at 0
    assert curation_score(CurationInputs((), (finding("SW-SKL-011", "critical"),), 5)) == 9.0  # accepted counts half


def test_curated_needs_the_threshold_no_open_critical_or_high_a_matching_hash_and_no_quarantine():
    base = CurationInputs((), (), 5, eval_component=1.0)
    assert is_curated(base, 12.0) and CURATED_THRESHOLD == 8.0
    assert not is_curated(base, 7.9)
    high = CurationInputs((finding("SW-SKL-001", "high"),), (), 5, eval_component=1.0)
    assert curation_score(high) >= 8.0 and not is_curated(high, curation_score(high))
    assert not is_curated(CurationInputs((), (), 5, eval_component=1.0, sha256_matches=False), 12.0)
    assert not is_curated(CurationInputs((), (), 5, eval_component=1.0, quarantined=True), 12.0)


def test_inputs_accept_findings_or_severity_strings_and_serialise():
    """Spec 5.2: `open_findings` and `accepted_findings` are sequences of `Finding` or severities."""
    assert severities_of((finding("SW-SKL-001", "high"), "low", "critical")) == ["high", "low", "critical"]
    mixed = CurationInputs((finding("SW-SKL-031", "low"), "medium"), ("medium",), 5)
    only_strings = CurationInputs(("low", "medium"), ("medium",), 5)
    assert curation_score(mixed) == curation_score(only_strings) == round(12 * (0.6 * (1 - 1.75 / 12) + 0.2 + 0.1), 1)
    assert is_curated(only_strings, curation_score(only_strings))
    assert not is_curated(CurationInputs(("high",), (), 5), 12.0)
    back = CurationInputs.from_dict(json.loads(json.dumps(mixed.to_dict())))
    assert back == mixed and back.open_findings[1] == "medium"
    try:
        severities_of(("severe",))
    except ValueError as exc:
        assert "severe" in str(exc)
    else:
        raise AssertionError("an unknown severity string must be refused")


def test_the_readme_rule_table_equals_the_baseline():
    from pathlib import Path

    from spellwarden_scan.rules import RuleSet

    text = Path(__file__).resolve().parents[1].joinpath("README.md").read_text()
    for rule in RuleSet.baseline():
        owasp = ", ".join(rule.owasp_agentic + rule.owasp_mcp)
        assert f"| {rule.id} | " in text, rule.id
        row = next(line for line in text.splitlines() if line.startswith(f"| {rule.id} | "))
        assert f"| {rule.severity_default} | {owasp} | {', '.join(rule.nist)} |" in row, rule.id


def test_quarantine_reads_open_malicious_findings_only():
    malicious = finding("SW-SKL-008", "critical", malicious=True)
    assert is_quarantined([malicious])
    assert is_quarantined([finding("SW-SKL-004", "critical", malicious=True), finding("SW-SKL-031", "low")])
    assert not is_quarantined([finding("SW-SKL-011", "critical")])
    # Accepting the finding moves it out of the open list, which lifts the quarantine (spec 5.9; hosted B9 guards who may do that).
    inputs = CurationInputs(open_findings=(), accepted_findings=(malicious,), metadata_present=5)
    assert not is_quarantined(inputs.open_findings)
    assert is_curated(CurationInputs((), (), 5, eval_component=1.0, quarantined=is_quarantined(inputs.open_findings)), 12.0)
