"""Claim P5: the 14 servers of product spec 9.3 classify to the published counts."""
from __future__ import annotations

from collections import Counter

from conftest import load_probe_fixture

from spellwarden_scan.probe import evaluate_probe
from spellwarden_scan.rules import RuleSet

RULES = RuleSet.baseline()
SAMPLES = ["deploy-orchestrator", "k8s-readonly", "terraform-runner", "incident-notes", "billing-lookup", "grafana-query",
           "jira-bridge", "s3-docs", "vault-reader", "crm-search", "ci-logs", "legacy-reports", "warehouse-sql", "ticket-triage"]


def results():
    for name in SAMPLES:
        probe, expected = load_probe_fixture(f"samples/{name}")
        yield name, evaluate_probe(probe, RULES), expected


def test_every_sample_matches_its_expected_classification():
    for name, result, expected in results():
        for key in ("transport", "auth_mode", "spec_version", "migration_status"):
            assert getattr(result, key) == expected[key], f"{name}: {key}"
        assert [item.key for item in result.checklist] == expected["checklist"], name


def test_the_derived_counts_of_product_spec_9_3():
    rows = [r for _, r, _ in results()]
    assert Counter(r.transport for r in rows) == {"streamable-http": 11, "sse": 3}
    assert Counter(r.auth_mode for r in rows) == {"none": 5, "static-key": 3, "oauth-dcr": 2, "oauth-cimd": 3, "xaa": 1}
    assert Counter(r.migration_status for r in rows) == {"ready": 4, "to_migrate": 10}


def test_ci_logs_checklist_equals_screen_3_in_order():
    probe, _ = load_probe_fixture("samples/ci-logs")
    assert [i.key for i in evaluate_probe(probe, RULES).checklist] == ["server_discover", "meta_version", "sampling_to_mrtr", "oauth_cimd", "validate_iss", "list_ttl", "traceparent", "rescan"]


def test_a_newer_compatible_version_is_ready():
    probe, expected = load_probe_fixture("samples/future-ready")
    result = evaluate_probe(probe, RULES)
    assert result.spec_version == "2027-03-26" and result.migration_status == "ready" == expected["migration_status"]
