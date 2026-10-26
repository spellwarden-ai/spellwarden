"""O4 spec 6.3, 6.4, 6.6, 6.7, 6.9, 7 and claims D1, S4, S5, S10, S11, E2, C1, W1 (repository part): a whole scan of a repository
with agent cards, through the command: the `agents` list, the notices, the findings through the baseline, the exit codes and
the report schema. Nothing here opens a connection."""
from __future__ import annotations

import base64
import json
import os
from datetime import date
from pathlib import Path

import jsonschema
import pytest
from a2a_cards import card_bytes, clean_card
from a2a_wire import Wire
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from spellwarden_scan.jcs import jcs_canonicalize

from spellwarden_cli import run
from spellwarden_cli.ci import LOCAL
from spellwarden_cli.settings import Settings

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "a2a" / "signed"
SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "schemas" / "report.schema.json").read_text(encoding="utf-8"))
WELL_KNOWN = "public/.well-known/agent-card.json"
CONFIG = ".spellwarden/config.yml"


def scan(run_cli, make_repo, tmp_path, files: dict, *args: str, env: dict | None = None):
    repo = make_repo(tmp_path / "repo", files)
    code, out, err = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", *args], env=env or {})
    report = json.loads(out)
    jsonschema.validate(report, SCHEMA)
    return code, report, err


def signed(name: str) -> bytes:
    return (FIXTURES / f"{name}.json").read_bytes()


def by_rule(report: dict) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for finding in report["findings"]:
        found.setdefault(finding["rule_id"], []).append(finding)
    return found


KEYS_CONFIG = "version: 1\na2a:\n  keys: .well-known/jwks.json\n"


def test_a_signed_card_with_a_trusted_key_is_ready_and_passes(run_cli, make_repo, tmp_path):
    code, report, _ = scan(run_cli, make_repo, tmp_path, {WELL_KNOWN: signed("es256"), CONFIG: KEYS_CONFIG,
                                                         ".well-known/jwks.json": signed("jwks")})
    assert code == 0 and report["findings"] == [] and report["errors"] == []
    [agent] = report["agents"]
    assert (agent["item"], agent["source"], agent["path_form"], agent["status"]) == (f"a2a-card:{WELL_KNOWN}", "repository", "well_known", "checked")
    assert (agent["card_format"], agent["protocol_versions"], agent["migration_status"], agent["signature_status"]) == (
        "1.0", ["1.0"], "ready", "verified")
    assert agent["signatures"][0]["key_source"] == "keys_file" and agent["signatures"][0]["payload_form"] == "as_served"
    assert agent["counts_toward_exit"] is True and agent["fetch"] is None and agent["checklist"][0]["key"] == "rescan"
    assert [(n["code"]) for n in report["notices"] if n["code"].startswith("a2a_")] == []


def test_a_repository_without_cards_has_no_agents_key_and_is_otherwise_as_before(run_cli, make_repo, tmp_path):
    code, report, _ = scan(run_cli, make_repo, tmp_path, {"README.md": "x"})
    assert "agents" not in report and code == 0 and [n["code"] for n in report["notices"]] == ["no_agent_content"]


def test_s4_a_card_signed_by_a_key_outside_the_trusted_file_fails_the_default_check(run_cli, make_repo, tmp_path):
    code, report, _ = scan(run_cli, make_repo, tmp_path, {WELL_KNOWN: signed("es256-stranger"), CONFIG: KEYS_CONFIG,
                                                         ".well-known/jwks.json": signed("jwks")})
    assert code == 1 and [(f["rule_id"], f["severity"]) for f in report["findings"]] == [("SW-A2A-010", "high")]
    assert report["agents"][0]["signature_status"] == "invalid" and report["agents"][0]["signatures"][0]["outcome"] == "untrusted_key"


def test_without_a_keys_file_a_signed_card_is_unverified_with_one_notice_and_no_finding_beyond_the_note(run_cli, make_repo, tmp_path):
    code, report, _ = scan(run_cli, make_repo, tmp_path, {WELL_KNOWN: signed("es256")})
    assert code == 0 and list(by_rule(report)) == []
    assert report["agents"][0]["signature_status"] == "unverified"
    notices = [n for n in report["notices"] if n["code"] == "a2a_signature_unverified"]
    assert len(notices) == 1 and notices[0]["path"] == f"a2a-card:{WELL_KNOWN}" and "a2a.keys" in notices[0]["message"]
    assert "--probe" in notices[0]["message"]


def test_s10_a_keys_file_that_is_named_but_absent_is_a_notice_and_one_that_does_not_parse_is_exit_2(run_cli, make_repo, tmp_path):
    code, report, _ = scan(run_cli, make_repo, tmp_path / "a", {WELL_KNOWN: signed("es256"), CONFIG: KEYS_CONFIG})
    assert code == 0 and [n["code"] for n in report["notices"] if n["code"].startswith("a2a_")] == ["a2a_keys_missing"]
    assert report["agents"][0]["signatures"][0]["detail"] == "keys_file_missing" and report["findings"] == []
    code, report, _ = scan(run_cli, make_repo, tmp_path / "b", {WELL_KNOWN: signed("es256"), CONFIG: KEYS_CONFIG,
                                                               ".well-known/jwks.json": b'{"keys": [,]}'})
    assert code == 2 and [e["code"] for e in report["errors"]] == ["settings_invalid"]
    assert report["errors"][0]["path"] == ".well-known/jwks.json" and "a2a.keys" in report["errors"][0]["message"]
    code, report, _ = scan(run_cli, make_repo, tmp_path / "c", {WELL_KNOWN: signed("es256"), CONFIG: KEYS_CONFIG,
                                                               ".well-known/jwks.json": b'{"not": "a key set"}'})
    assert code == 2 and report["errors"][0]["code"] == "settings_invalid"


def test_s11_a_key_without_a_kid_and_a_private_key_are_notices_and_the_card_is_not_verified_by_them(run_cli, make_repo, tmp_path):
    jwks = json.loads(signed("jwks"))
    es256 = next(key for key in jwks["keys"] if key["kid"] == "es256")
    without_kid = {"keys": [{key: value for key, value in es256.items() if key != "kid"}, {**es256, "kid": "es256", "d": "AAAA"}]}
    code, report, _ = scan(run_cli, make_repo, tmp_path, {WELL_KNOWN: signed("es256"), CONFIG: KEYS_CONFIG,
                                                         ".well-known/jwks.json": json.dumps(without_kid).encode()})
    assert sorted(n["code"] for n in report["notices"] if n["code"].startswith("a2a_")) == ["a2a_key_without_kid", "a2a_private_key_in_jwks"]
    assert report["agents"][0]["signatures"][0]["outcome"] == "untrusted_key" and code == 1


def test_d1_look_alike_files_are_notices_and_the_same_bytes_at_a_well_known_path_are_findings(run_cli, make_repo, tmp_path):
    commented = b'// c\n{"name": "x"}'
    code, report, _ = scan(run_cli, make_repo, tmp_path / "a", {".well-known/agent.json": commented, "samples/agent-card.json": b" " * (2**20 + 1),
                                                               "tools/agent-card.json": b'{"hello": "world"}'})
    assert code == 0 and "agents" not in report and report["findings"] == []
    notes = {n["path"]: n["message"] for n in report["notices"] if n["code"] == "a2a_not_card"}
    assert notes == {".well-known/agent.json": "not checked as an agent card: not_json",
                     "samples/agent-card.json": "not checked as an agent card: over 1 MiB",
                     "tools/agent-card.json": "not checked as an agent card: not an agent card"}
    code, report, _ = scan(run_cli, make_repo, tmp_path / "b", {WELL_KNOWN: commented})
    assert code == 1 and [(f["rule_id"], f["severity"], f["location"]) for f in report["findings"]] == [
        ("SW-A2A-018", "high", {"path": WELL_KNOWN, "line": None})]
    assert report["errors"] == []
    code, report, _ = scan(run_cli, make_repo, tmp_path / "c", {WELL_KNOWN: b'{"hello": "world"}'})
    assert code == 0 and [(f["rule_id"], f["severity"]) for f in report["findings"]] == [("SW-A2A-001", "medium")]  # `not_a_card`
    code, report, _ = scan(run_cli, make_repo, tmp_path / "d", {WELL_KNOWN: b"\xef\xbb\xbf" + card_bytes(clean_card())})
    assert code == 1 and by_rule(report)["SW-A2A-018"][0]["evidence"].startswith("bom: a byte-order mark")


def test_r0_f2_look_alike_links_that_cannot_be_followed_do_not_make_a_run_exit_2(run_cli, make_repo, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    repo = make_repo(tmp_path / "repo", {"README.md": "x"})
    (repo / ".well-known").mkdir()
    (repo / ".well-known" / "agent.json").symlink_to(outside)
    (repo / "docs").mkdir()
    (repo / "docs" / "agent-card.json").symlink_to("../missing.json")
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry"])
    report = json.loads(out)
    assert code == 0 and report["errors"] == [] and "agents" not in report
    assert sorted(n["path"] for n in report["notices"] if n["code"] == "symlink_skipped") == [".well-known/agent.json", "docs/agent-card.json"]


def test_d1_a_baseline_entry_accepts_an_unreadable_card(run_cli, make_repo, tmp_path):
    files = {WELL_KNOWN: b'{"name": "x",}'}
    repo = make_repo(tmp_path / "repo", files)
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry"])
    fingerprint = json.loads(out)["findings"][0]["fingerprint"]
    assert code == 1
    baseline = f'version: 1\naccepted:\n  - fingerprint: "{fingerprint}"\n    reason: "a negative fixture"\n    added: "2026-10-26"\n    expires: "2026-12-01"\n'
    (repo / ".spellwarden" / "baseline.yml").parent.mkdir(exist_ok=True)
    (repo / ".spellwarden" / "baseline.yml").write_text(baseline)
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--as-of", "2026-10-27"])
    report = json.loads(out)
    assert code == 0 and report["findings"][0]["suppressed"] is True and report["errors"] == []


def test_d2_201_cards_give_200_reports_and_the_notice(run_cli, make_repo, tmp_path):
    files = {f"a/a{number:03d}/.well-known/agent-card.json": card_bytes(clean_card()) for number in range(201)}
    code, report, _ = scan(run_cli, make_repo, tmp_path, files)
    assert len(report["agents"]) == 200 and code == 0
    assert [n["code"] for n in report["notices"] if n["code"] == "a2a_cards_limit"] == ["a2a_cards_limit"]


def test_listed_cards_and_the_exclude_setting(run_cli, make_repo, tmp_path):
    config = "version: 1\na2a:\n  cards: ['deploy/card.json', 'nowhere.json']\nexclude: ['samples/**']\n"
    code, report, _ = scan(run_cli, make_repo, tmp_path, {"deploy/card.json": b'{"x":', "samples/agent-card.json": b"{",
                                                         CONFIG: config})
    assert [(f["rule_id"], f["location"]["path"]) for f in report["findings"]] == [("SW-A2A-018", "deploy/card.json")] and code == 1
    assert [(n["code"], n["path"]) for n in report["notices"] if n["code"] == "file_missing"] == [("file_missing", "nowhere.json")]
    assert [a["path_form"] for a in report["agents"]] == ["listed"]


def test_a_card_with_findings_is_reported_with_its_checklist_and_the_findings_point_at_its_lines(run_cli, make_repo, tmp_path):
    card = clean_card()
    card["supportedInterfaces"][0]["url"] = "http://agent.example.com/a2a"
    code, report, _ = scan(run_cli, make_repo, tmp_path, {WELL_KNOWN: card_bytes(card)})
    assert code == 1 and [f["rule_id"] for f in report["findings"]] == ["SW-A2A-004", "SW-A2A-012"]
    first = report["findings"][0]
    assert first["item"] == f"a2a-card:{WELL_KNOWN}" and first["location"]["path"] == WELL_KNOWN and first["location"]["line"] == 7
    assert report["agents"][0]["migration_status"] == "ready"  # HTTP is a finding, not a migration step


def test_e2_the_report_of_a_card_free_repository_equals_the_one_of_a_repository_with_only_a_look_alike_but_for_the_notice(run_cli, make_repo, tmp_path):
    files = {".mcp.json": json.dumps({"mcpServers": {"docs": {"url": "https://docs.example.com/mcp"}}})}
    _, plain, _ = scan(run_cli, make_repo, tmp_path / "a", files)
    _, alike, _ = scan(run_cli, make_repo, tmp_path / "b", {**files, "agent.json": b"{}", "tools/.well-known/agent.json": b"{"})
    assert [n["code"] for n in alike["notices"] if n["code"] == "a2a_not_card"] == ["a2a_not_card"]
    alike["notices"] = [n for n in alike["notices"] if n["code"] != "a2a_not_card"]
    assert plain == alike


def test_the_agent_card_findings_are_in_the_markdown_text_and_sarif_outputs(run_cli, make_repo, tmp_path):
    card = clean_card()
    card["supportedInterfaces"][0]["url"] = "http://agent.example.com/a2a"
    repo = make_repo(tmp_path / "repo", {WELL_KNOWN: card_bytes(card)})
    for fmt, needle in (("text", "SW-A2A-004"), ("markdown", "SW-A2A-004"), ("sarif", "SW-A2A-004"), ("gitlab-codequality", "SW-A2A-004")):
        code, out, _ = run_cli(["scan", str(repo), "--format", fmt, "--no-telemetry"])
        assert code == 1 and needle in out, fmt


# --- the leftovers of the O4 build (items 5, 6 and 8) ---------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def throwaway_signed(card: dict) -> tuple[dict, bytes]:
    """`card` with an ES256 signature over its RFC 8785 form (the `as_served` payload) by a key made for this test, and the public
    key set that holds it as `k`. Nothing private leaves this function."""
    key = ec.generate_private_key(ec.SECP256R1())
    protected = _b64(json.dumps({"alg": "ES256", "kid": "k", "typ": "JOSE"}, separators=(",", ":")).encode())
    body = {name: value for name, value in card.items() if name != "signatures"}
    signing_input = protected.encode() + b"." + _b64(jcs_canonicalize(body)).encode()
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    numbers = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": "k", "use": "sig", "alg": "ES256",
           "x": _b64(numbers.x.to_bytes(32, "big")), "y": _b64(numbers.y.to_bytes(32, "big"))}
    signature = {"protected": protected, "signature": _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}
    return {**card, "signatures": [signature]}, json.dumps({"keys": [jwk]}).encode()


def test_d_l1_an_empty_alternative_added_to_the_security_requirements_after_signing_makes_the_signature_invalid(run_cli, make_repo, tmp_path):
    """(D-L1) The `sdk` form verifies a card whose `securityRequirements` gained `{}` (it removes it), but `{}` is the alternative
    "no authentication": a whole requirement entry left unsigned is `unsigned_legacy`, SW-A2A-010."""
    card, jwks = throwaway_signed(clean_card())
    card["securityRequirements"].append({})
    code, report, _ = scan(run_cli, make_repo, tmp_path, {WELL_KNOWN: card_bytes(card), CONFIG: KEYS_CONFIG, ".well-known/jwks.json": jwks})
    [signature] = report["agents"][0]["signatures"]
    assert (signature["outcome"], signature["payload_form"]) == ("unsigned_legacy", "sdk")
    assert signature["unsigned_members"] == ["/securityRequirements/1"] and "/securityRequirements/1" in signature["detail"]
    assert code == 1 and ("SW-A2A-010", "high") in [(f["rule_id"], f["severity"]) for f in report["findings"]]


def test_d_l1_a_scope_less_scheme_entry_the_sdk_cannot_sign_is_listed_and_the_signature_stays_verified(run_cli, make_repo, tmp_path):
    """(D-L1 revised, r1:F3) `a2a-sdk` removes `schemes: {bearer: {}}` before signing, as it does for every requirement without
    scopes; failing that would fail every SDK-signed card with bearer, API key or mTLS auth. It is listed, not invalid."""
    card = clean_card()
    card["securitySchemes"] = {"bearer": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}}
    card["securityRequirements"] = [{"schemes": {"bearer": {}}}]
    signed_card, jwks = throwaway_signed({key: value for key, value in card.items() if key != "securityRequirements"})
    signed_card["securityRequirements"] = card["securityRequirements"]
    code, report, _ = scan(run_cli, make_repo, tmp_path, {WELL_KNOWN: card_bytes(signed_card), CONFIG: KEYS_CONFIG,
                                                         ".well-known/jwks.json": jwks})
    [signature] = report["agents"][0]["signatures"]
    assert (signature["outcome"], signature["payload_form"]) == ("verified", "sdk")
    assert signature["unsigned_members"] == ["/securityRequirements/0/schemes/bearer"]
    assert "SW-A2A-010" not in [f["rule_id"] for f in report["findings"]] and report["agents"][0]["signature_status"] == "verified"


@pytest.mark.parametrize("alias", ["security_requirements", "supported_interfaces", "security_schemes"])
def test_r1_f2_a_proto_field_name_alias_added_after_signing_makes_the_signature_invalid(run_cli, make_repo, tmp_path, alias):
    """protobuf's JSON reader takes `security_requirements` for `securityRequirements` and the later spelling wins, so an alias
    appended after signing replaces the signed member for a proto-based client: `unsigned_legacy`, SW-A2A-010, exit 1 (r1:F2)."""
    card, jwks = throwaway_signed(clean_card())
    card[alias] = [{}] if alias != "security_schemes" else {"evil": {"apiKeySecurityScheme": {"location": "header", "name": "k"}}}
    code, report, _ = scan(run_cli, make_repo, tmp_path, {WELL_KNOWN: card_bytes(card), CONFIG: KEYS_CONFIG, ".well-known/jwks.json": jwks})
    [signature] = report["agents"][0]["signatures"]
    assert signature["outcome"] == "unsigned_legacy" and f"/{alias}" in signature["detail"]
    assert code == 1 and ("SW-A2A-010", "high") in [(f["rule_id"], f["severity"]) for f in report["findings"]]
    assert report["agents"][0]["signature_status"] == "invalid"


def test_d_l1_a_plain_vendor_member_added_after_signing_is_still_verified_with_the_member_listed(run_cli, make_repo, tmp_path):
    card, jwks = throwaway_signed(clean_card())
    card["x-vendor"] = {"note": "added later"}
    code, report, _ = scan(run_cli, make_repo, tmp_path, {WELL_KNOWN: card_bytes(card), CONFIG: KEYS_CONFIG, ".well-known/jwks.json": jwks})
    [signature] = report["agents"][0]["signatures"]
    assert (signature["outcome"], signature["unsigned_members"]) == ("verified", ["/x-vendor"])
    assert code == 0 and report["findings"] == []


def unsafe_repo(tmp_path) -> None:
    """A card file next to the repository, which a link of the repository may name but never follow."""
    (tmp_path / "outside.json").write_bytes(card_bytes(clean_card()))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links")
@pytest.mark.parametrize(("target", "reason"), [("../../../outside.json", "unsafe_path"), ("../missing.json", "unsafe_path"),
                                                ("..", "unsafe_path")])
def test_r1_f2_a_well_known_link_that_cannot_be_followed_is_a_high_finding_and_exit_1_never_exit_2(run_cli, make_repo, tmp_path, target, reason):
    unsafe_repo(tmp_path)
    repo = make_repo(tmp_path / "repo", {"README.md": "x"})
    (repo / "public" / ".well-known").mkdir(parents=True)
    (repo / "public" / ".well-known" / "agent-card.json").symlink_to(target)
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry"])
    report = json.loads(out)
    jsonschema.validate(report, SCHEMA)
    assert report["errors"] == [] and code == 1
    [finding] = report["findings"]
    assert (finding["rule_id"], finding["severity"], finding["location"]) == ("SW-A2A-018", "high", {"path": WELL_KNOWN, "line": None})
    assert finding["evidence"].startswith(f"{reason}: ") and "symbolic link" in finding["evidence"]
    assert not [n for n in report["notices"] if n["code"] == "symlink_skipped"]
    [agent] = report["agents"]
    assert (agent["item"], agent["path_form"], agent["status"]) == (f"a2a-card:{WELL_KNOWN}", "well_known", "checked")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links")
def test_r1_f2_a_listed_link_that_escapes_the_scan_root_is_a_finding_and_the_baseline_accepts_it(run_cli, make_repo, tmp_path):
    unsafe_repo(tmp_path)
    repo = make_repo(tmp_path / "repo", {CONFIG: "version: 1\na2a:\n  cards:\n    - docs/card.json\n"})
    (repo / "docs").mkdir()
    (repo / "docs" / "card.json").symlink_to("../../outside.json")
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry"])
    report = json.loads(out)
    jsonschema.validate(report, SCHEMA)
    assert report["errors"] == [] and code == 1
    [finding] = report["findings"]
    assert (finding["rule_id"], finding["location"]["path"], finding["evidence"].split(":")[0]) == ("SW-A2A-018", "docs/card.json", "unsafe_path")
    assert [a["path_form"] for a in report["agents"]] == ["listed"]
    baseline = ("version: 1\naccepted:\n  - fingerprint: \"" + finding["fingerprint"] + "\"\n    reason: \"a negative fixture\"\n"
                "    added: \"2026-10-26\"\n    expires: \"2026-12-01\"\n")
    (repo / ".spellwarden" / "baseline.yml").write_text(baseline)
    code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry", "--as-of", "2026-10-27"])
    report = json.loads(out)
    assert code == 0 and report["findings"][0]["suppressed"] is True and report["errors"] == []


@pytest.mark.skipif(not hasattr(os, "chmod") or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs a non-root user")
def test_r1_f2_a_well_known_card_the_os_refuses_to_read_is_an_unreadable_finding_and_exit_1(run_cli, make_repo, tmp_path):
    repo = make_repo(tmp_path / "repo", {WELL_KNOWN: card_bytes(clean_card())})
    path = repo / WELL_KNOWN
    path.chmod(0)
    try:
        code, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry"])
    finally:
        path.chmod(0o644)
    report = json.loads(out)
    jsonschema.validate(report, SCHEMA)
    assert report["errors"] == [] and code == 1
    [finding] = report["findings"]
    assert (finding["rule_id"], finding["location"]["path"], finding["evidence"].split(":")[0]) == ("SW-A2A-018", WELL_KNOWN, "unreadable")


def test_r0_f3_a_repository_whose_only_card_named_file_is_a_look_alike_that_is_not_a_card_is_told_it_has_no_agent_content(run_cli, make_repo, tmp_path):
    code, report, _ = scan(run_cli, make_repo, tmp_path, {"README.md": "x", "tools/.well-known/agent.json": "// not a card\n{}"})
    assert code == 0 and "agents" not in report
    assert sorted(n["code"] for n in report["notices"]) == ["a2a_not_card", "no_agent_content"]


def card_with_jku(jku: str) -> bytes:
    protected = _b64(json.dumps({"alg": "ES256", "kid": "k", "jku": jku}, separators=(",", ":")).encode())
    return card_bytes({**clean_card(), "signatures": [{"protected": protected, "signature": "AQ" * 42 + "AQ"}]})


def test_r0_f5_a_non_https_jku_under_probe_is_key_unavailable_with_its_reason_and_no_advice_to_probe(run_cli, make_repo, tmp_path):
    """(r0:F5) The key set of an `http://` jku is never fetched; with --probe on, the outcome must say the key could not be had
    (`network`, the reason the remote path gives the same URL), not that no source was tried, and must not tell the user to
    run with --probe."""
    files = {WELL_KNOWN: card_with_jku("http://keys.example.com/jwks.json")}
    code, report, _ = scan(run_cli, make_repo, tmp_path / "on", files, "--probe")
    [signature] = report["agents"][0]["signatures"]
    assert (signature["outcome"], signature["detail"]) == ("key_unavailable", "network")
    assert [n["code"] for n in report["notices"] if n["code"].startswith("a2a_")] == ["a2a_keys_unavailable"]
    assert not [n for n in report["notices"] if "--probe" in n["message"]]
    code, report, _ = scan(run_cli, make_repo, tmp_path / "off", files)
    [signature] = report["agents"][0]["signatures"]
    assert (signature["outcome"], signature["detail"]) == ("key_unavailable", "no_key_source")
    assert [n["code"] for n in report["notices"] if n["code"].startswith("a2a_")] == ["a2a_signature_unverified"]
    assert [n for n in report["notices"] if "--probe" in n["message"]]


@pytest.mark.parametrize("jku", ["http://[bad/keys.json", "https://[bad/keys.json", "https://keys.example.com:notaport/k.json",
                                 "https://[::1/k.json"])
def test_r0_f1_a_jku_that_does_not_parse_is_key_unavailable_never_a_crash(run_cli, make_repo, tmp_path, jku):
    """(r0:F1, invariant 10) A card's `jku` is untrusted text: `urlsplit` raises ValueError on a bracketed host or a bad port.
    Under --probe that must be the outcome `key_unavailable` (`network`), never an internal error and exit 2."""
    code, report, _ = scan(run_cli, make_repo, tmp_path, {WELL_KNOWN: card_with_jku(jku)}, "--probe")
    assert report["errors"] == [] and code in (0, 1)
    [signature] = report["agents"][0]["signatures"]
    assert (signature["outcome"], signature["detail"]) == ("key_unavailable", "network")


def test_r1_f3_an_upper_case_https_jku_of_a_repository_card_is_requested_under_probe(monkeypatch, tmp_path):
    wire = Wire(monkeypatch, {"HTTPS://keys.example.com/jwks.json": (200, {"Content-Type": "application/json"}, b'{"keys": []}'),
                              "https://keys.example.com/jwks.json": (200, {"Content-Type": "application/json"}, b'{"keys": []}')})
    root = tmp_path / "repo"
    (root / "public/.well-known").mkdir(parents=True)
    (root / WELL_KNOWN).write_bytes(card_with_jku("HTTPS://keys.example.com/jwks.json"))
    run.scan(run.ScanOptions(root=str(root), settings=Settings(probe=True), as_of=date(2026, 10, 26), env={}, context=LOCAL))
    assert [url.lower() for url in wire.urls] == ["https://keys.example.com/jwks.json"]
