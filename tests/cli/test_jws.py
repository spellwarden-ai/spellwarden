"""O4 spec 6.6 and claims S1, S2, S3, S7, S9, S11 (verification part), B1: key sets and signature verification over the signed
fixture cards (`scripts/make_fixture_cards.py`, `scripts/record_sdk_card.py`): every verified algorithm, the refused ones,
the key rules, and the one module that imports `cryptography`."""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from spellwarden_scan import parse_agent_card, signature_inputs
from spellwarden_scan.a2a_signing import b64url_encode

from spellwarden_cli import jws
from spellwarden_cli.agents import KeyFetch, Trust, outcome_of, outcomes_of

SIGNED = Path(__file__).resolve().parents[1] / "fixtures" / "a2a" / "signed"
SRC = Path(__file__).resolve().parents[2] / "src"
VERIFIED = {"es256": "ES256", "es384": "ES384", "es512": "ES512", "rs256": "RS256", "rs384": "RS384", "rs512": "RS512",
            "ps256": "PS256", "ps384": "PS384", "ps512": "PS512", "ed25519": "Ed25519", "eddsa": "EdDSA"}


def card(name: str):
    return parse_agent_card(f"{name}.json", (SIGNED / f"{name}.json").read_bytes())


def keyset(name: str = "jwks") -> jws.KeySet:
    return jws.load_jwks((SIGNED / f"{name}.json").read_bytes())


def trusted(name: str = "jwks") -> Trust:
    return Trust("keys.json", "loaded", keyset(name))


def outcomes(name: str, trust: Trust | None = None, fetched=None):
    return outcomes_of(card(name), trust if trust is not None else trusted(), fetched or {})


@pytest.mark.parametrize(("name", "alg"), sorted(VERIFIED.items()))
def test_s1_a_card_signed_with_each_verified_algorithm_verifies_against_the_trusted_key_file(name, alg):
    [outcome] = outcomes(name)
    assert (outcome.outcome, outcome.alg, outcome.key_source, outcome.payload_form) == ("verified", alg, "keys_file", "as_served")
    assert outcome.unsigned_members == () and outcome.kid == alg.lower()


def test_s1_ed25519_and_eddsa_verify_with_the_same_kind_of_key():
    assert outcomes("ed25519")[0].outcome == outcomes("eddsa")[0].outcome == "verified"
    [entry] = signature_inputs(card("eddsa"))
    eddsa_key = next(key for key in keyset().keys if key.kid == "eddsa")
    assert jws.verify("Ed25519", eddsa_key, entry.inputs[0][1], entry.signature)  # the alg name does not change the check


def test_s1_none_and_an_unknown_algorithm_are_refused_and_shared_secret_and_ed448_cannot_be_verified():
    assert [(o.outcome, o.detail) for o in outcomes("none")] == [("refused_alg", None)]
    assert [o.outcome for o in outcomes("unknown-alg")] == ["refused_alg"]
    hs = outcomes("hs256")[0]
    assert (hs.outcome, hs.detail) == ("unverifiable_alg", "a shared-secret signature can only be checked by the agent that holds the secret")
    ed448 = outcomes("ed448")[0]
    assert (ed448.outcome, ed448.detail) == ("unverifiable_alg", "Ed448 is not verified by this release")
    assert not [key for key in keyset().keys if key.public is None and key.crv != "Ed448"]  # the Ed448 key is kept, unused


def test_s1_a_der_encoded_ecdsa_signature_is_malformed_with_that_cause():
    [outcome] = outcomes("es256-der")
    assert (outcome.outcome, outcome.detail) == ("malformed", jws.DER_DETAIL)
    [entry] = signature_inputs(card("es256-der"))
    assert jws.ecdsa_problem("ES256", entry.signature) == jws.DER_DETAIL
    assert jws.ecdsa_problem("ES256", b"x" * 10).startswith("ECDSA signature of 10 bytes; ES256 needs 64 bytes")
    assert jws.ecdsa_problem("ES256", b"x" * 64) is None and jws.ecdsa_problem("RS256", b"x") is None


def test_s2_one_changed_character_is_a_bad_signature_and_a_reformatted_copy_still_verifies():
    assert outcomes("es256-tampered")[0].outcome == "bad_signature"
    assert outcomes("es256-reformatted")[0].outcome == "verified"
    assert outcomes("es256-tampered")[0].key_source == "keys_file"


def test_s3_the_card_signed_by_the_sdk_verifies_over_the_sdk_payload_form():
    [outcome] = outcomes("sdk-es256", trusted("jwks-sdk"))
    assert (outcome.outcome, outcome.payload_form, outcome.alg, outcome.kid) == ("verified", "sdk", "ES256", "sdk-key")
    assert outcome.unsigned_members == ()
    assert outcomes("sdk-es256")[0].outcome == "untrusted_key"  # not in the other key file


def test_s4_a_key_that_is_not_in_the_trusted_file_is_untrusted_even_when_a_jku_would_verify_it():
    [outcome] = outcomes("es256-stranger")
    assert (outcome.outcome, outcome.kid) == ("untrusted_key", "stranger")
    stranger = KeyFetch(keyset("jwks-stranger"))
    card_with_jku = card("es256-jku")
    [entry] = signature_inputs(card_with_jku)
    served = {entry.jku: KeyFetch(keyset())}
    with_keys_file = outcome_of(entry, trusted("jwks-stranger"), served)  # the keys file does not hold es256: no fetch is used
    assert with_keys_file.outcome == "untrusted_key" and with_keys_file.key_source == "keys_file"
    assert stranger.reason is None


def test_without_a_keys_file_the_fetched_key_set_of_the_jku_verifies_and_the_source_says_so():
    [entry] = signature_inputs(card("es256-jku"))
    assert entry.jku == "https://agent.example.com/.well-known/jwks.json"
    none = Trust()
    verified = outcome_of(entry, none, {entry.jku: KeyFetch(keyset())})
    assert (verified.outcome, verified.key_source, verified.payload_form) == ("verified", "jku", "as_served")
    assert verified.jku == entry.jku
    assert outcome_of(entry, none, {entry.jku: KeyFetch(keyset("jwks-stranger"))}).outcome == "no_key"
    failed = outcome_of(entry, none, {entry.jku: KeyFetch(None, "timeout")})
    assert (failed.outcome, failed.detail) == ("key_unavailable", "timeout")
    unfetched = outcome_of(entry, none, {})
    assert (unfetched.outcome, unfetched.detail) == ("key_unavailable", "no_key_source")


def test_a_header_that_carries_its_own_key_is_embedded_key_only_unless_a_keys_file_is_in_force():
    [entry] = signature_inputs(card("es256-embedded"))
    assert outcome_of(entry, Trust(), {}).outcome == "embedded_key_only"
    assert outcome_of(entry, trusted(), {}).outcome == "untrusted_key"  # kid `inline` is not in the trusted file


def test_the_keys_file_states_missing_and_invalid_make_every_signature_unavailable():
    [entry] = signature_inputs(card("es256"))
    assert outcome_of(entry, Trust("keys.json", "missing"), {}).detail == "keys_file_missing"
    assert outcome_of(entry, Trust("keys.json", "invalid"), {}).detail == "keys_file_invalid"


def test_s9_a_vendor_member_added_after_signing_verifies_with_the_member_listed_and_a_legacy_member_does_not():
    [vendor] = outcomes("es256-vendor")
    assert (vendor.outcome, vendor.payload_form, vendor.unsigned_members) == ("verified", "spec", ("/x-vendor",))
    [legacy] = outcomes("es256-legacy")
    assert legacy.outcome == "unsigned_legacy" and legacy.payload_form == "spec"
    assert legacy.unsigned_members == ("/supportsAuthenticatedExtendedCard",)
    assert legacy.detail == "signed without members clients read: /supportsAuthenticatedExtendedCard"


def test_two_signatures_one_good_one_bad_are_reported_each_and_the_card_is_verified():
    first, second = outcomes("two-signatures")
    assert (first.outcome, second.outcome) == ("bad_signature", "verified") and (first.index, second.index) == (0, 1)


def test_malformed_headers_and_numbers_are_malformed_outcomes_with_their_detail():
    assert outcomes("no-kid")[0].outcome == "malformed" and outcomes("no-kid")[0].detail == "the protected header has no kid"
    assert outcomes("crit")[0].outcome == "malformed"
    big = outcomes("es256-big-number")[0]
    assert (big.outcome, big.alg) == ("malformed", "ES256") and "number outside the range" in big.detail


# --- key sets ----------------------------------------------------------------------------------------------------------

def test_load_jwks_reads_the_fixture_key_set_and_counts_what_it_leaves_out():
    loaded = keyset()
    assert len(loaded.keys) == 12 and (loaded.without_kid, loaded.private, loaded.unusable) == (0, 0, 0)
    assert {key.kty for key in loaded.keys} == {"EC", "RSA", "OKP"}


def test_s7_a_key_with_a_private_member_is_dropped_and_counted_and_a_key_without_a_kid_is_never_used():
    entries = json.loads((SIGNED / "jwks.json").read_text())["keys"]
    es256 = next(entry for entry in entries if entry["kid"] == "es256")
    dirty = {"keys": [{**es256, "d": "AAAA"}, {k: v for k, v in es256.items() if k != "kid"}, dict(es256, kid="ok"),
                      {"kty": "oct", "kid": "s", "k": "AAAA"}, {"kty": "EC", "crv": "P-999", "kid": "z", "x": "AA", "y": "AA"},
                      {"kty": "EC", "crv": "P-256", "kid": "off", "x": "AAAA", "y": "AAAA"}, "x"]}
    loaded = jws.load_jwks(json.dumps(dirty).encode())
    assert [key.kid for key in loaded.keys] == ["ok"]
    assert (loaded.private, loaded.without_kid, loaded.unusable) == (2, 1, 3)  # `oct` holds a private `k`; a point off the curve; "x"
    for private in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"):
        assert jws.load_jwks(json.dumps({"keys": [{**es256, private: "AA"}]}).encode()).keys == ()


@pytest.mark.parametrize(("content", "code"), [
    (b"", "not_json"), (b'{"keys": [],}', "not_json"), (b'[1]', "not_a_key_set"), (b'{"keys": 3}', "not_a_key_set"),
    (b'{"nope": []}', "not_a_key_set"), (b'\xef\xbb\xbf{"keys": []}', "bom"), (b" " * (64 * 1024 + 1), "too_large"),
    (json.dumps({"keys": [{}] * 21}).encode(), "too_many_keys"),
])
def test_a_file_that_is_not_a_key_set_is_refused_with_its_reason(content, code):
    with pytest.raises(jws.JwksError) as caught:
        jws.load_jwks(content)
    assert caught.value.args == (code,)


def test_twenty_keys_are_the_most_a_key_set_may_list():
    assert jws.load_jwks(json.dumps({"keys": [{}] * 20}).encode()).without_kid == 20
    assert jws.load_jwks(json.dumps({"keys": [{}] * 3}).encode(), max_keys=2 + 1).without_kid == 3
    with pytest.raises(jws.JwksError):
        jws.load_jwks(json.dumps({"keys": [{}] * 3}).encode(), max_keys=2)


def test_candidate_keys_follow_6_6_step_2():
    base = json.loads((SIGNED / "jwks.json").read_text())["keys"]
    es256 = next(entry for entry in base if entry["kid"] == "es256")
    rsa = next(entry for entry in base if entry["kid"] == "rs256")

    def pick(entry: dict, alg: str, kid: str = "k") -> int:
        return len(jws.candidates(jws.load_jwks(json.dumps({"keys": [{**entry, "kid": "k"}]}).encode()), alg, kid))

    assert pick(es256, "ES256") == 1 and pick(es256, "ES384") == 0 and pick(es256, "RS256") == 0
    assert pick(es256, "ES256", "other") == 0
    assert pick({**es256, "use": "enc"}, "ES256") == 0 and pick({**es256, "use": "sig"}, "ES256") == 1
    assert pick({**es256, "key_ops": ["sign"]}, "ES256") == 0 and pick({**es256, "key_ops": ["verify"]}, "ES256") == 1
    assert pick({**es256, "alg": "ES384"}, "ES256") == 0 and pick({**es256, "alg": "ES256"}, "ES256") == 1
    unbound = {key: value for key, value in rsa.items() if key != "alg"}  # a key `alg` must equal the header's
    assert pick(rsa, "RS256") == 1 and pick(rsa, "PS384") == 0 and pick(unbound, "PS384") == 1 and pick(unbound, "ES256") == 0
    ed448 = {key: value for key, value in next(entry for entry in base if entry["kid"] == "ed448").items() if key != "alg"}
    assert pick(ed448, "EdDSA") == 1 and pick(ed448, "Ed25519") == 0 and pick(ed448, "Ed448") == 0


def test_an_rsa_key_under_2048_bits_is_never_a_candidate():
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa

    numbers = crypto_rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_numbers()
    entry = {"kty": "RSA", "kid": "weak", "n": b64url_encode(numbers.n.to_bytes(128, "big")), "e": "AQAB"}
    loaded = jws.load_jwks(json.dumps({"keys": [entry]}).encode())
    assert len(loaded.keys) == 1 and loaded.keys[0].bits == 1024
    assert jws.candidates(loaded, "RS256", "weak") == ()


def test_verify_never_raises_and_refuses_the_wrong_key_type_or_a_bad_signature():
    [entry] = signature_inputs(card("es256"))
    keys = {key.kid: key for key in keyset().keys}
    signing_input = entry.inputs[0][1]
    assert jws.verify("ES256", keys["es256"], signing_input, entry.signature)
    assert not jws.verify("ES256", keys["es256"], signing_input + b"x", entry.signature)
    assert not jws.verify("ES256", keys["rs256"], signing_input, entry.signature)
    assert not jws.verify("ES384", keys["es256"], signing_input, entry.signature)
    assert not jws.verify("ES256", keys["es256"], signing_input, b"")
    assert not jws.verify("HS256", keys["es256"], signing_input, entry.signature)
    assert not jws.verify("none", keys["es256"], signing_input, b"")
    assert not jws.verify("RS256", keys["ed25519"], signing_input, entry.signature)
    assert not jws.verify("EdDSA", keys["ed448"], signing_input, entry.signature)  # Ed448 is never verified here


def test_b1_only_jws_imports_cryptography_and_nothing_in_it_signs():
    importers = set()
    for package in ("spellwarden_scan", "spellwarden_cli"):
        for path in sorted((SRC / package).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else (
                    [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else [])
                if any(name == "cryptography" or name.startswith("cryptography.") for name in names):
                    importers.add(path.relative_to(SRC).as_posix())
    assert importers == {"spellwarden_cli/jws.py"}
    source = (SRC / "spellwarden_cli" / "jws.py").read_text(encoding="utf-8")
    assert ".sign(" not in source and "generate_private_key" not in source and "private_bytes" not in source
    defined = [name for name, value in vars(jws).items() if callable(value) and getattr(value, "__module__", "") == jws.__name__]
    assert [name for name in defined if "sign" in name.lower()] == [] and "verify" in defined
