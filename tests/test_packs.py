"""Phase C spec 5.3, 5.4 and claim E6: the enforcement rules, the baseline
pack (the JSON file and the constant are one document), the pack document's
validator, its canonical form and its size bound."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from spellwarden_scan.packs import (
    BASELINE_JSON, ENFORCEMENT_IDS, ENFORCEMENT_RULES, MAX_DOCUMENT_BYTES, PACK_ERROR_CODES, TARGET_IDS, PackDocument,
    PackError, baseline_pack, canonical_json, make_pack_document, pack_sha256, validate_pack,
)
from spellwarden_scan.rules import ALLOWED_NIST, ALLOWED_OWASP, ORG_ALLOWED_NIST, ORG_ALLOWED_OWASP
from spellwarden_scan.version import RULES_VERSION, __version__

ROOT = Path(__file__).resolve().parents[1]
PACKS = ROOT / "fixtures" / "packs"
BASELINE_FILE = ROOT / "src" / "spellwarden_scan" / "packs" / "baseline.json"
PID = "3b1e8c2a9d7f4e605a1b2c3d4e5f6071"
# The OrgRuleError code each bad_org_rule fixture carries, where the spec fixes it (5.2.1).
RULE_ERRORS = {"unknown-key": "unknown_key", "id-000": "bad_id", "baseline-id": "bad_id", "title-with-lf": "bad_title",
               "hooks-target-on-lines": "bad_target", "pattern-too-long": "pattern_too_long"}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_files() -> list[Path]:
    return sorted((PACKS / "valid").glob("*.json"))


def invalid_files() -> list[tuple[str, Path]]:
    return [(path.parent.name, path) for path in sorted((PACKS / "invalid").glob("*/*.json"))]


def org_rule(number: int, **fields) -> dict:
    spec = {"id": f"SW-ORG-{number:03d}", "title": "Asks the agent to reveal its system prompt", "severity": "medium",
            "area": "skill", "owasp": ["ASI01"], "nist": ["SI-10"], "targets": ["kong"], "malicious": False,
            "detection": {"kind": "pattern", "files": "**", "in": "lines", "pattern": "reveal (your|the) prompt",
                          "case_sensitive": False}}
    spec.update(fields)
    return spec


def document(org_rules=(), **pack) -> dict:
    return make_pack_document(pack_id=pack.get("pack_id", PID), name=pack.get("name", "Platform team"),
                              version=pack.get("version", "1.0"), description=pack.get("description", ""),
                              rules={rule_id: True for rule_id in ENFORCEMENT_IDS}, org_rules=list(org_rules))


# --- the enforcement rules (5.3) ---------------------------------------------------------------------------------

def test_the_eight_enforcement_rules_of_the_spec_table():
    table = {rule.id: (rule.severity, rule.owasp_agentic + rule.owasp_mcp, rule.nist, rule.targets, rule.enforced_by)
             for rule in ENFORCEMENT_RULES}
    assert table == {
        "SW-HK-001": ("high", ("ASI04",), ("SR-3",), ("claude-code-hooks",), ("claude-code-hooks",)),
        "SW-HK-002": ("high", ("MCP01",), ("IA-5",), ("claude-code-hooks", "cloudflare-egress"), ("claude-code-hooks",)),
        "SW-GW-003": ("high", ("MCP01",), ("AC-3",), ("kong", "zuplo", "agentcore-policy"), ()),
        "SW-GW-004": ("medium", ("ASI01", "MCP10"), ("SI-10",), ("kong", "zuplo"), ("kong",)),
        "SW-EG-005": ("medium", ("ASI10",), ("SC-7",), ("cloudflare-egress",), ()),
        "SW-GW-006": ("high", ("ASI10",), ("AC-6",), ("agentcore-policy", "claude-code-hooks"), ("claude-code-hooks",)),
        "SW-RG-007": ("medium", ("ASI04",), ("SR-3",), ("registry",), ("registry",)),
        "SW-OB-008": ("low", (), ("AU-2",), ("claude-code-hooks", "kong", "zuplo", "agentcore-policy", "cloudflare-egress"), ()),
    }
    assert ENFORCEMENT_IDS == ("SW-HK-001", "SW-HK-002", "SW-GW-003", "SW-GW-004", "SW-EG-005", "SW-GW-006",
                               "SW-RG-007", "SW-OB-008")
    assert TARGET_IDS == ("claude-code-hooks", "kong", "zuplo", "agentcore-policy", "cloudflare-egress", "registry")


def test_enforcement_rules_use_only_allowed_mappings_and_serialise_like_rules():
    for rule in ENFORCEMENT_RULES:
        assert set(rule.owasp_agentic + rule.owasp_mcp) <= set(ALLOWED_OWASP)
        assert set(rule.nist) <= set(ALLOWED_NIST)
        assert set(rule.enforced_by) <= set(rule.targets) <= set(TARGET_IDS)
        assert rule.to_dict() == {"id": rule.id, "title": rule.title, "severity": rule.severity,
                                  "owasp_agentic": list(rule.owasp_agentic), "owasp_mcp": list(rule.owasp_mcp),
                                  "nist": list(rule.nist), "targets": list(rule.targets),
                                  "enforced_by": list(rule.enforced_by)}


def test_enforcement_rules_are_not_detection_rules():
    from spellwarden_scan.rules import RuleSet

    assert not {rule.id for rule in RuleSet.baseline()} & set(ENFORCEMENT_IDS)
    assert len(RuleSet.baseline()) == 59


# --- the baseline pack (5.3) -------------------------------------------------------------------------------------

def test_the_baseline_file_and_the_constant_are_byte_equal():
    assert BASELINE_FILE.read_bytes() == BASELINE_JSON.encode("utf-8")
    assert (PACKS / "valid" / "baseline.json").read_bytes() == BASELINE_JSON.encode("utf-8")


def test_the_baseline_pack():
    pack = baseline_pack()
    assert (pack.pack_id, pack.name, pack.version) == ("baseline", "Spellwarden Baseline for Agents", "1.0")
    assert pack.enabled() == ENFORCEMENT_IDS
    assert pack.org_rules == ()
    assert (pack.engine_version, pack.rules_version) == ("1.2.0", RULES_VERSION)
    assert pack.to_dict() == json.loads(BASELINE_JSON)
    assert BASELINE_JSON == json.dumps(pack.to_dict(), indent=2, ensure_ascii=False) + "\n"


# --- validation (5.4) --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", valid_files(), ids=lambda p: p.stem)
def test_valid_fixtures_validate_and_round_trip(path):
    doc = load(path)
    pack = validate_pack(doc)
    assert isinstance(pack, PackDocument)
    assert pack.to_dict() == doc


@pytest.mark.parametrize(("code", "path"), invalid_files(), ids=lambda v: v if isinstance(v, str) else v.stem)
def test_each_invalid_fixture_fails_with_its_code(code, path):
    assert code in PACK_ERROR_CODES
    with pytest.raises(PackError) as caught:
        validate_pack(load(path))
    assert caught.value.code == code
    assert caught.value.message and str(caught.value) == caught.value.message
    if path.stem in RULE_ERRORS:
        assert caught.value.rule_error == RULE_ERRORS[path.stem]
        assert caught.value.rule_id in caught.value.message


def test_every_pack_error_code_has_a_fixture_directory():
    assert {path.name for path in (PACKS / "invalid").iterdir()} == set(PACK_ERROR_CODES)


def test_the_fixture_set_is_the_one_the_generator_wrote():
    names = sorted(path.relative_to(PACKS).as_posix() for path in PACKS.rglob("*.json"))
    assert len(names) == 39
    assert names[:5] == ["invalid/bad_org_rule/baseline-id.json", "invalid/bad_org_rule/hooks-target-on-lines.json",
                         "invalid/bad_org_rule/id-000.json", "invalid/bad_org_rule/malicious-not-critical.json",
                         "invalid/bad_org_rule/pattern-too-long.json"]


@pytest.mark.parametrize("name", ['Ops "prod" pack # main', "x: y", "- z", "Équipe sécurité",
                                  "安全チーム", "Deploy \U0001f680", "&anchor *alias !tag"])
def test_names_with_quotes_yaml_looking_text_and_non_ascii_letters_are_accepted(name):
    assert validate_pack(document(name=name)).name == name


@pytest.mark.parametrize("name", ["a\rb", "a\nb", "a\u2028b", "a\u2029b", "a\u202eb", "a\u2066b", "a\u0000b", "a\u007fb",
                                  "a\u0085b", "a\u200db", "a\ufeffb", "a\U000e0041b", "", "   "])
def test_names_with_control_format_or_line_separator_characters_are_refused(name):
    with pytest.raises(PackError) as caught:
        validate_pack(document(name=name))
    assert caught.value.code == "bad_pack"


def test_a_description_may_hold_line_feeds_but_no_carriage_return():
    assert validate_pack(document(description="first\nsecond")).description == "first\nsecond"
    with pytest.raises(PackError):
        validate_pack(document(description="first\r\nsecond"))


def test_org_rules_must_be_distinct_and_in_id_order():
    with pytest.raises(PackError) as caught:
        doc = document()
        doc["org_rules"] = [org_rule(2), org_rule(1)]
        validate_pack(doc)
    assert caught.value.code == "bad_org_rule"
    with pytest.raises(PackError):
        doc = document()
        doc["org_rules"] = [org_rule(1), org_rule(1, title="Another title")]
        validate_pack(doc)


def test_schema_and_enabled_must_be_exact_types():
    doc = document()
    doc["schema"] = True
    with pytest.raises(PackError) as caught:
        validate_pack(doc)
    assert caught.value.code == "bad_schema"
    doc = document()
    doc["rules"][0]["enabled"] = 1
    with pytest.raises(PackError) as caught:
        validate_pack(doc)
    assert caught.value.code == "bad_rules"


def test_text_that_is_not_valid_unicode_is_refused():
    with pytest.raises(PackError) as caught:
        validate_pack(document(description="half a pair \ud800"))
    assert caught.value.code in ("bad_pack", "bad_schema")


def test_a_published_document_keeps_full_copies_of_its_org_rules():
    spec = org_rule(1)
    pack = validate_pack(document(org_rules=[spec]))
    spec["title"] = "Changed after publishing"
    assert pack.org_rules[0]["title"] == "Asks the agent to reveal its system prompt"
    pack.to_dict()["org_rules"][0]["title"] = "Changed in a copy"
    assert pack.org_rules[0]["title"] == "Asks the agent to reveal its system prompt"


# --- make_pack_document, canonical JSON and the size bound -------------------------------------------------------

def test_make_pack_document_fills_the_engine_block_orders_and_copies():
    doc = make_pack_document(pack_id=PID, name="Platform team", version="1.3", description="",
                             rules={rule_id: rule_id != "SW-OB-008" for rule_id in reversed(ENFORCEMENT_IDS)},
                             org_rules=[org_rule(7), org_rule(3)])
    assert doc["engine"] == {"version": __version__, "rules_version": RULES_VERSION}
    assert [rule["id"] for rule in doc["rules"]] == list(ENFORCEMENT_IDS)
    assert doc["rules"][-1] == {"id": "SW-OB-008", "enabled": False}
    assert [spec["id"] for spec in doc["org_rules"]] == ["SW-ORG-003", "SW-ORG-007"]
    assert validate_pack(doc).enabled() == ENFORCEMENT_IDS[:-1]
    with pytest.raises(ValueError):
        make_pack_document(pack_id=PID, name="x", version="1.0", description="", rules={"SW-XX-009": True}, org_rules=[])


def test_canonical_json_is_the_same_for_two_key_orders():
    doc = load(PACKS / "valid" / "with-org-rules.json")
    reordered = json.loads(json.dumps(doc, sort_keys=True))
    reordered["pack"] = dict(reversed(list(reordered["pack"].items())))
    reordered["org_rules"] = [dict(reversed(list(spec.items()))) for spec in reordered["org_rules"]]
    assert canonical_json(doc) == canonical_json(reordered) == canonical_json(validate_pack(reordered))
    assert pack_sha256(doc) == pack_sha256(validate_pack(doc))
    text = canonical_json(doc).decode("utf-8")
    assert text == json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert json.loads(text) == doc


def test_canonical_json_keeps_non_ascii_as_utf_8():
    pack = validate_pack(load(PACKS / "valid" / "names-unicode.json"))
    assert "Équipe".encode() in canonical_json(pack)


def _largest_ascii_rule(number: int) -> dict:
    """One org rule at the largest size of every field, in ASCII (spec 5.2.1, 5.2.2)."""
    return {"id": f"SW-ORG-{number:03d}", "title": "T" * 120, "severity": "critical", "area": "skill",
            "owasp": list(ORG_ALLOWED_OWASP), "nist": list(ORG_ALLOWED_NIST[:5]), "targets": ["claude-code-hooks", "kong"],
            "malicious": True,
            "detection": {"kind": "pattern", "files": "f" * 200, "in": "commands", "pattern": "\\." * 150,
                          "case_sensitive": False}}


def test_the_largest_valid_pack_is_below_300_000_bytes():
    doc = document(org_rules=[_largest_ascii_rule(n) for n in range(1, 201)], name="N" * 80, description="D" * 500)
    pack = validate_pack(doc)
    assert len(pack.org_rules) == 200
    assert len(canonical_json(pack)) < MAX_DOCUMENT_BYTES


def test_a_pack_whose_text_passes_300_000_bytes_is_refused():
    rules = [_largest_ascii_rule(n) for n in range(1, 201)]
    for spec in rules:
        spec["title"] = "\U0001f680" * 120
        spec["detection"]["pattern"] = "一" * 300
    with pytest.raises(PackError) as caught:
        validate_pack(document(org_rules=rules))
    assert caught.value.code == "too_many_org_rules"


def test_long_host_lists_reach_the_byte_bound_before_the_rule_count():
    # review of 2026-10-21 (r0:F5): the largest rules are host lists, and the message names what to shorten
    hosts = [f"h{n:02d}." + ".".join(["a" * 62] * 3 + ["a" * 52]) + ".example" for n in range(50)]
    assert all(len(host) == 253 for host in hosts)

    def host_rule(number: int) -> dict:
        return {"id": f"SW-ORG-{number:03d}", "title": "T" * 120, "severity": "high", "area": "mcp", "owasp": [],
                "nist": [], "targets": [], "malicious": False,
                "detection": {"kind": "probe", "predicate": "endpoint_host_not_in", "values": hosts}}

    assert len(validate_pack(document(org_rules=[host_rule(n) for n in range(1, 21)])).org_rules) == 20
    with pytest.raises(PackError) as caught:
        validate_pack(document(org_rules=[host_rule(n) for n in range(1, 25)]))
    assert caught.value.code == "too_many_org_rules" and "host lists" in caught.value.message


def test_201_org_rules_are_refused_before_any_is_read():
    doc = copy.deepcopy(load(PACKS / "invalid" / "too_many_org_rules" / "201-org-rules.json"))
    doc["org_rules"][0] = {"not": "a rule"}
    with pytest.raises(PackError) as caught:
        validate_pack(doc)
    assert caught.value.code == "too_many_org_rules"
