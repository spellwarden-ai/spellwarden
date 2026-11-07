"""An organisation rule may map to the tags of 1.2.x only (a pack using a newer tag is refused by every older scanner), so
the tags the baseline gained since stay out of the organisation lists. The lists are pinned literally."""
from __future__ import annotations

from spellwarden_scan.rules import ALLOWED_NIST, ALLOWED_OWASP, BASELINE_ONLY_TAGS, ORG_ALLOWED_NIST, ORG_ALLOWED_OWASP


def test_the_organisation_owasp_list_is_the_one_of_1_2_x():
    assert ORG_ALLOWED_OWASP == ("ASI01", "ASI04", "ASI10", "MCP01", "MCP10")


def test_the_organisation_nist_list_is_the_one_of_1_2_x():
    assert ORG_ALLOWED_NIST == ("AC-3", "AC-6", "AU-2", "IA-5", "SC-7", "SI-10", "SR-3")


def test_the_baseline_only_tags_are_exactly_the_tags_added_since_1_2_x():
    assert BASELINE_ONLY_TAGS == {"ASI02", "ASI03", "ASI05", "ASI07", "ASI09", "MCP02", "MCP03", "MCP04", "MCP06", "MCP07", "MCP08",
                                  "MCP09", "SC-8", "SI-3", "SI-7", "CM-7"}
    assert BASELINE_ONLY_TAGS <= set(ALLOWED_OWASP) | set(ALLOWED_NIST)


def test_the_new_batch_tags_are_allowed_in_the_baseline():
    assert {"ASI02", "ASI05", "ASI09", "MCP02"} <= set(ALLOWED_OWASP)
    assert {"CM-7", "SI-3"} <= set(ALLOWED_NIST)
