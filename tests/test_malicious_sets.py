"""The two hand-kept sets of malicious-indicator rules (the CLI's baseline-expiry cap and the curation quarantine) follow
the registry: a rule added with `malicious=True` must join them."""
from __future__ import annotations

from spellwarden_cli.baseline import MALICIOUS_RULES as CLI_MALICIOUS_RULES
from spellwarden_scan import RuleSet
from spellwarden_scan.curation import MALICIOUS_RULES as CURATION_MALICIOUS_RULES

BASELINE = RuleSet.baseline()


def test_the_cli_set_is_the_baseline_ids_flagged_malicious():
    assert CLI_MALICIOUS_RULES == {rule.id for rule in BASELINE if rule.malicious_indicator}


def test_the_curation_set_is_the_malicious_skill_rules():
    assert CURATION_MALICIOUS_RULES == {rule.id for rule in BASELINE.by_area("skill") if rule.malicious_indicator}


def test_the_password_protected_download_lure_is_malicious_in_both_sets():
    assert "SW-SKL-032" in CLI_MALICIOUS_RULES and "SW-SKL-032" in CURATION_MALICIOUS_RULES
