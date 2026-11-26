"""An organisation rule may map to the tags of 1.2.x only (a pack using a newer tag is refused by every older scanner), so
the tags the baseline gained since stay out of the organisation lists. The lists are pinned literally."""
from __future__ import annotations

import pytest

from spellwarden_scan.orgrules import OrgRuleError, compile_org_rule
from spellwarden_scan.rules import ALLOWED_NIST, ALLOWED_OWASP, BASELINE_ONLY_TAGS, ORG_ALLOWED_NIST, ORG_ALLOWED_OWASP


def test_the_organisation_owasp_list_is_the_one_of_1_2_x():
    assert ORG_ALLOWED_OWASP == ("ASI01", "ASI04", "ASI10", "MCP01", "MCP10")


def test_the_organisation_nist_list_is_the_one_of_1_2_x():
    assert ORG_ALLOWED_NIST == ("AC-3", "AC-6", "AU-2", "IA-5", "SC-7", "SI-10", "SR-3")


def test_the_baseline_only_tags_are_exactly_the_tags_added_since_1_2_x():
    assert BASELINE_ONLY_TAGS == {"ASI02", "ASI03", "ASI05", "ASI07", "ASI09", "MCP02", "MCP03", "MCP04", "MCP05", "MCP06",
                                  "MCP07", "MCP08", "MCP09", "SC-8", "SI-3", "SI-7", "CM-7"}
    assert BASELINE_ONLY_TAGS <= set(ALLOWED_OWASP) | set(ALLOWED_NIST)


def test_the_new_batch_tags_are_allowed_in_the_baseline():
    assert {"ASI02", "ASI05", "ASI09", "MCP02"} <= set(ALLOWED_OWASP)
    assert {"CM-7", "SI-3"} <= set(ALLOWED_NIST)


def test_mcp05_is_allowed_in_the_baseline_only_and_asi06_and_asi08_in_neither_list():
    """1.25.0 (P6-9 spec 8.5): the command-line rule needs MCP05; ASI06 and ASI08 stay out because no rule carries them (the memory
    rule was withdrawn), and MCP10 is a tag of 1.2.x, so it stays an organisation tag."""
    assert "MCP05" in ALLOWED_OWASP and "MCP05" in BASELINE_ONLY_TAGS
    assert "MCP05" not in ORG_ALLOWED_OWASP
    for tag in ("ASI06", "ASI08"):
        assert tag not in ALLOWED_OWASP and tag not in BASELINE_ONLY_TAGS
    assert "MCP10" in ORG_ALLOWED_OWASP


@pytest.mark.parametrize("tag", ("MCP05",))
def test_an_organisation_rule_that_uses_a_tag_of_1_25_0_is_refused_as_bad_mapping(tag):
    spec = {"id": "SW-ORG-001", "title": "Org pattern", "severity": "high", "area": "skill", "owasp": [tag], "nist": ["SI-10"],
            "detection": {"kind": "pattern", "pattern": "needle"}}
    with pytest.raises(OrgRuleError) as caught:
        compile_org_rule(spec)
    assert caught.value.code == "bad_mapping"
    assert compile_org_rule({**spec, "owasp": ["MCP10"]}).id == "SW-ORG-001"  # a tag of 1.2.x still compiles
