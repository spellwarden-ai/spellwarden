"""O4 spec 5.6 and claims S2 (inputs part), S3 (inputs part), S8, S9 (inputs part), J1: the byte strings a verifier must check
a card's signatures over, in up to three payload forms; the `_PRESENCE` table against the committed proto excerpt. The
engine never verifies; `tests/cli/test_jws.py` does, with `cryptography`, over these inputs."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from a2a_cards import card_bytes, clean_card

from spellwarden_scan._json import Refused, load_json
from spellwarden_scan.a2a import is_legacy_pointer, parse_agent_card
from spellwarden_scan.a2a_signing import (
    _PRESENCE, HEADER_MAX_BYTES, NUMBER_DETAIL, _clean_empty, b64url_decode, b64url_encode, must_be_signed, signature_inputs,
)
from spellwarden_scan.jcs import jcs_canonicalize

SIGNED = Path(__file__).resolve().parent / "fixtures" / "a2a" / "signed"
PROTO = Path(__file__).resolve().parent / "fixtures" / "a2a" / "proto" / "a2a-v1.0.1-card.proto"


def inputs_of(content: bytes | dict):
    document = parse_agent_card("card.json", content if isinstance(content, bytes) else card_bytes(content))
    return signature_inputs(document)


def fixture(name: str) -> bytes:
    return (SIGNED / f"{name}.json").read_bytes()


def header_of(protected: dict | bytes) -> str:
    return b64url_encode(protected if isinstance(protected, bytes) else json.dumps(protected).encode())


def signed(card: dict, protected: str, signature: str = "c2ln") -> dict:
    return {**card, "signatures": [{"protected": protected, "signature": signature}]}


GOOD_HEADER = header_of({"alg": "ES256", "kid": "k1", "typ": "JOSE", "jku": "https://agent.example.com/jwks.json"})


# --- S8: _PRESENCE is what the proto excerpt says -----------------------------------------------------------------------

_MESSAGE = re.compile(r"^message (\w+) \{\n(.*?)^\}", re.M | re.S)
_FIELD = re.compile(r"^\s*(optional |repeated )?(map<\w+, ?[\w.]+>|[\w.]+) (\w+) = [0-9]+(?: \[(.*)\])?;$")


def _json_name(proto_name: str) -> str:
    head, *rest = proto_name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _kind(prefix: str | None, proto_type: str) -> str:
    if proto_type.startswith("map<"):
        value = proto_type[proto_type.index(",") + 1:-1].strip()
        return "map:string" if value == "string" else f"map:message:{value}"
    if proto_type == "google.protobuf.Struct":
        return "struct"
    if proto_type in ("string", "bool", "int32", "int64"):
        return "repeated:string" if prefix == "repeated " else "scalar"
    return f"repeated:message:{proto_type}" if prefix == "repeated " else f"message:{proto_type}"


def proto_table() -> dict[str, dict[str, tuple[str, str]]]:
    """The presence table the proto excerpt states: REQUIRED by the `field_behavior` option, `optional` by the keyword,
    `oneof` for the members of a `oneof`, `plain` for the rest."""
    table: dict[str, dict[str, tuple[str, str]]] = {}
    for message in _MESSAGE.finditer(PROTO.read_text(encoding="utf-8")):
        fields, in_oneof = {}, False
        for line in message.group(2).splitlines():
            if line.strip().startswith("oneof "):
                in_oneof = True
                continue
            if line.strip() == "}":
                in_oneof = False
                continue
            field = _FIELD.match(line)
            assert field is not None, f"the excerpt has a line this test cannot read: {line!r}"
            prefix, proto_type, name, options = field.group(1), field.group(2), field.group(3), field.group(4) or ""
            rule = ("required" if "field_behavior) = REQUIRED" in options else "optional" if prefix == "optional "
                    else "oneof" if in_oneof else "plain")
            fields[_json_name(name)] = (rule, _kind(prefix, proto_type))
        table[message.group(1)] = fields
    return table


def test_s8_the_presence_table_equals_the_committed_proto_excerpt():
    assert PROTO.read_text(encoding="utf-8").startswith("// Excerpt of specification/a2a.proto, github.com/a2aproject/A2A tag v1.0.1, commit 3303592")
    assert _PRESENCE == proto_table()
    assert len(_PRESENCE) == 21
    assert _PRESENCE["AgentCard"]["capabilities"] == ("required", "message:AgentCapabilities")
    assert _PRESENCE["AgentCapabilities"]["streaming"] == ("optional", "scalar")
    assert _PRESENCE["AuthorizationCodeOAuthFlow"]["pkceRequired"] == ("plain", "scalar")
    assert _PRESENCE["SecurityScheme"]["mtlsSecurityScheme"] == ("oneof", "message:MutualTlsSecurityScheme")


# --- the header and the signature -------------------------------------------------------------------------------------

def test_the_protected_header_is_decoded_and_its_members_are_reported():
    [entry] = inputs_of(signed(clean_card(), GOOD_HEADER))
    assert (entry.error, entry.alg, entry.kid, entry.typ, entry.jku) == (None, "ES256", "k1", "JOSE", "https://agent.example.com/jwks.json")
    assert (entry.has_jwk, entry.has_x5c, entry.has_x5u, entry.has_crit) == (False, False, False, False)
    assert entry.signature == b"sig" and entry.protected == GOOD_HEADER and entry.index == 0
    header = header_of({"alg": "ES256", "kid": "k", "jwk": {"kty": "EC"}, "x5c": [], "x5u": "https://x"})
    [embedded] = inputs_of(signed(clean_card(), header))
    assert (embedded.has_jwk, embedded.has_x5c, embedded.has_x5u, embedded.error) == (True, True, True, None)


@pytest.mark.parametrize(("protected", "detail"), [
    (header_of({"kid": "k"}), "the protected header has no alg"),
    (header_of({"alg": 5, "kid": "k"}), "the protected header has no alg"),
    (header_of({"alg": "ES256"}), "the protected header has no kid"),
    (header_of({"alg": "ES256", "kid": ["k"]}), "the protected header has no kid"),
    (header_of({"alg": "ES256", "kid": "k", "crit": ["exp"]}), "the protected header has crit and the scanner understands no extension"),
    (header_of({"alg": "ES256", "kid": "k", "b64": False}), "the protected header has b64 false"),
    (header_of(b"[1]"), "the protected header is not a JSON object"),
    (header_of(b'{"alg": "ES256",}'), "the protected header is not a JSON object"),
    (header_of(b"{" + b" " * HEADER_MAX_BYTES + b"}"), "the protected header is over 4 KiB"),
    ("eyJhbGciOiJFUzI1NiJ9=", "the protected header is not base64url without padding"),
    ("a+b/", "the protected header is not base64url without padding"),
    ("abcde", "the protected header is not base64url without padding"),
])
def test_a_malformed_header_is_an_error_with_its_detail_and_no_inputs(protected, detail):
    [entry] = inputs_of(signed(clean_card(), protected))
    assert (entry.error, entry.inputs) == (detail, ())


def test_a_header_member_that_is_not_a_string_is_none_and_b64_true_is_accepted():
    [entry] = inputs_of(signed(clean_card(), header_of({"alg": "ES256", "kid": "k", "typ": 3, "jku": 4, "b64": True})))
    assert (entry.error, entry.typ, entry.jku) == (None, None, None)


def test_a_signature_that_is_not_base64url_without_padding_is_malformed_and_a_bad_entry_does_not_stop_the_others():
    for bad in ("c2ln=", "a b", "+/+/", "abcde"):
        [entry] = inputs_of(signed(clean_card(), GOOD_HEADER, bad))
        assert entry.error == "the signature is not base64url without padding", bad
    card = {**clean_card(), "signatures": ["x", {"protected": 1, "signature": "s"}, {"protected": GOOD_HEADER, "signature": "c2ln"}]}
    errors = [entry.error for entry in inputs_of(card)]
    assert errors == ["the entry is not an object", "protected and signature must be strings", None]


def test_at_most_five_entries_are_read_and_an_unsigned_or_unreadable_card_has_none():
    card = {**clean_card(), "signatures": [{"protected": GOOD_HEADER, "signature": "c2ln"}] * 7}
    assert [entry.index for entry in inputs_of(card)] == [0, 1, 2, 3, 4]
    assert inputs_of(clean_card()) == () and inputs_of(b"{") == () and inputs_of({**clean_card(), "signatures": []}) == ()


# --- the payload forms ---------------------------------------------------------------------------------------------------

def payload_of(entry, form: str) -> bytes:
    """The payload of one input: its signing input is `protected . BASE64URL(payload)`."""
    for name, signing_input, _ in entry.inputs:
        if name == form:
            head, _, body = signing_input.decode("ascii").partition(".")
            assert head == entry.protected
            return b64url_decode(body) or b""
    raise AssertionError(f"no {form} form")


def test_s2_the_as_served_form_is_the_rfc_8785_form_of_the_card_without_signatures():
    card = clean_card()
    [entry] = inputs_of(signed(card, GOOD_HEADER))
    assert [form for form, _, _ in entry.inputs] == ["as_served"]  # the clean card is its own spec and sdk form
    assert payload_of(entry, "as_served") == jcs_canonicalize(card)
    assert entry.inputs[0][2] == ()


def test_s2_a_reordered_and_reindented_copy_has_the_same_inputs():
    original, reformatted = inputs_of(fixture("es256"))[0], inputs_of(fixture("es256-reformatted"))[0]
    assert original.error is None and original.inputs == reformatted.inputs
    assert json.loads(fixture("es256-reformatted")) != json.loads(fixture("es256-tampered"))
    tampered = inputs_of(fixture("es256-tampered"))[0]
    assert tampered.inputs != original.inputs  # one character changed after signing: other bytes, same signature


def test_the_spec_form_drops_defaults_and_unknown_members_and_keeps_required_optional_and_oneof_members():
    card = clean_card()
    card.update({"x-vendor": {"a": 1}, "documentationUrl": "", "provider": {"organization": "O", "url": "", "x": 1}})
    card["capabilities"] = {"streaming": False, "pushNotifications": True, "extensions": [{"uri": "u", "required": False,
                                                                                         "params": {"k": []}, "x-e": 1}]}
    card["securitySchemes"] = {"m": {"mtlsSecurityScheme": {}}, "k": {"apiKeySecurityScheme": {
        "location": "header", "name": "n", "description": "", "in": "header"}}}
    card["skills"][0].update(examples=[], inputModes=[], securityRequirements=[])
    [entry] = inputs_of(signed(card, GOOD_HEADER))
    spec = json.loads(payload_of(entry, "spec"))
    assert "x-vendor" not in spec and spec["documentationUrl"] == ""                  # optional: kept as served
    assert spec["provider"] == {"organization": "O", "url": ""}                         # required kept, unknown dropped
    assert spec["capabilities"] == {"streaming": False, "pushNotifications": True,      # optional booleans kept
                                    "extensions": [{"uri": "u", "params": {"k": []}}]}  # `required: false` is a default
    assert spec["securitySchemes"] == {"m": {"mtlsSecurityScheme": {}}, "k": {"apiKeySecurityScheme": {"location": "header", "name": "n"}}}
    assert "examples" not in spec["skills"][0] and "inputModes" not in spec["skills"][0] and "securityRequirements" not in spec["skills"][0]
    assert sorted(entry.inputs[1][2]) == sorted(["/x-vendor", "/provider/x", "/capabilities/extensions/0/x-e",
                                                 "/securitySchemes/k/apiKeySecurityScheme/in"])


def test_the_sdk_form_also_removes_empty_required_and_optional_members_and_what_that_empties():
    card = clean_card()
    card["capabilities"] = {}
    card["documentationUrl"] = ""
    [entry] = inputs_of(signed(card, GOOD_HEADER))
    assert [form for form, _, _ in entry.inputs] == ["as_served", "sdk"]  # the spec form keeps both, so it equals as_served
    sdk, served = json.loads(payload_of(entry, "sdk")), json.loads(payload_of(entry, "as_served"))
    assert "capabilities" not in sdk and "documentationUrl" not in sdk
    assert served["capabilities"] == {} and served["documentationUrl"] == ""


def test_clean_empty_is_the_sdk_s():
    assert _clean_empty({"a": "", "b": [], "c": {"d": ""}, "e": False, "f": 0, "g": [{"h": []}]}) == {"e": False, "f": 0}
    assert _clean_empty({"a": ""}) is None and _clean_empty([]) is None and _clean_empty("x") == "x"


def test_s9_a_vendor_member_added_after_signing_is_in_unsigned_members_of_the_spec_and_sdk_forms():
    original, vendor = inputs_of(fixture("es256"))[0], inputs_of(fixture("es256-vendor"))[0]
    assert [form for form, _, _ in vendor.inputs] == ["as_served", "spec"]  # sdk equals spec: one form
    assert payload_of(vendor, "spec") == payload_of(original, "as_served")
    assert vendor.inputs[1][2] == ("/x-vendor",) and vendor.inputs[0][2] == ()


def unsigned_of(card: dict) -> dict[str, tuple[str, ...]]:
    """`form -> unsigned members` of the one signature of `card` (a form equal to an earlier one is not listed)."""
    [entry] = inputs_of(signed(card, GOOD_HEADER))
    return {form: members for form, _, members in entry.inputs}


def test_s3_a_legacy_member_that_holds_a_default_is_still_unsigned_in_the_spec_and_sdk_forms():  # (item 3)
    card = clean_card()
    card["skills"][0]["security"] = []  # to a 0.x client an empty skill-level list overrides the card's requirements to none
    card["security"] = []
    card["supportsAuthenticatedExtendedCard"] = False
    card["capabilities"] = {}  # makes the sdk form differ from the spec form, so both are listed
    forms = unsigned_of(card)
    assert list(forms) == ["as_served", "spec", "sdk"] and forms["as_served"] == ()
    expected = ["/security", "/skills/0/security", "/supportsAuthenticatedExtendedCard"]
    assert sorted(forms["spec"]) == expected and sorted(forms["sdk"]) == expected
    assert all(is_legacy_pointer(pointer) for pointer in forms["spec"])


def test_s3_a_vendor_member_that_holds_a_default_stays_unreported():
    card = clean_card()
    card.update({"x-vendor": [], "x-flag": False})
    assert all(members == () for members in unsigned_of(card).values())  # a default the protocol treats as absent


def test_s3_the_sdk_form_reports_the_list_elements_it_removes():  # (item 4)
    card = clean_card()
    card["securityRequirements"] = [{"schemes": {"a": {"list": ["x"]}}}, {}]  # `{}`: "anonymous allowed"
    forms = unsigned_of(card)
    assert list(forms) == ["as_served", "sdk"]  # the spec form keeps `{}` and so equals as_served
    assert forms["sdk"] == ("/securityRequirements/1",) and forms["as_served"] == ()
    card["skills"][0]["securityRequirements"] = [{}]
    assert "/skills/0/securityRequirements/0" in unsigned_of(card)["sdk"]


def test_s3_the_sdk_form_reports_the_map_entries_it_removes_and_what_a_nested_removal_emptied():
    card = clean_card()
    card["securitySchemes"] = {"a": {}, "m": {"mtlsSecurityScheme": {}}}
    card["securityRequirements"] = [{"schemes": {"a": {"list": []}}}]
    forms = unsigned_of(card)
    # the deepest removal, not its parents; `m` held only an empty oneof member, which the sdk removes with its scheme
    assert forms["sdk"] == ("/securityRequirements/0/schemes/a", "/securitySchemes/a", "/securitySchemes/m")
    assert "sdk" in forms and forms["as_served"] == ()


def test_s3_the_sdk_form_leaves_empty_message_fields_unreported():
    card = clean_card()
    card["capabilities"] = {}
    card["documentationUrl"] = ""
    card["skills"][0]["examples"] = []
    assert unsigned_of(card)["sdk"] == ()
    [entry] = inputs_of(fixture("sdk-es256"))
    assert all(members == () for _, _, members in entry.inputs)


def test_clean_empty_reports_the_pointers_it_removes_by_kind():
    removed: list[str] = []
    value = {"a": "", "b": [{}, "k", ""], "c": {"d": ""}, "scopes": {"x": ""}}
    assert _clean_empty(value, "", removed, "struct") == {"b": ["k"]}
    assert removed == ["/a", "/b/0", "/b/2", "/c/d", "/scopes/x"]


def test_s9_a_legacy_member_added_after_signing_is_listed_and_is_a_legacy_pointer():
    entry = inputs_of(fixture("es256-legacy"))[0]
    unsigned = [pointer for _, _, members in entry.inputs for pointer in members]
    assert unsigned == ["/supportsAuthenticatedExtendedCard"] and all(is_legacy_pointer(pointer) for pointer in unsigned)


def test_s3_the_sdk_card_has_three_forms_and_the_sdk_one_leaves_out_the_empty_capabilities():
    [entry] = inputs_of(fixture("sdk-es256"))
    assert (entry.error, entry.alg, entry.kid) == (None, "ES256", "sdk-key")
    assert [form for form, _, _ in entry.inputs] == ["as_served", "spec", "sdk"]
    served = json.loads(fixture("sdk-es256"))
    assert served["skills"][0]["examples"] == [] and served["capabilities"] == {}
    sdk = json.loads(payload_of(entry, "sdk"))
    assert "capabilities" not in sdk and "examples" not in sdk["skills"][0]
    assert "pkceRequired" not in sdk["securitySchemes"]["oauth"]["oauth2SecurityScheme"]["flows"]["authorizationCode"]
    assert json.loads(payload_of(entry, "spec"))["capabilities"] == {}


def test_a_number_past_2_to_the_53_is_malformed_with_its_detail_not_guessed():
    for entry in inputs_of(fixture("es256-big-number")):
        assert (entry.error, entry.inputs) == (NUMBER_DETAIL, ())
    assert inputs_of(fixture("es256-big-number"))[0].alg == "ES256"  # the header is still read, so the report names the algorithm


def test_the_generated_fixtures_have_the_headers_the_claims_need():
    expected = {"es256": "ES256", "es384": "ES384", "es512": "ES512", "rs256": "RS256", "rs384": "RS384", "rs512": "RS512",
                "ps256": "PS256", "ps384": "PS384", "ps512": "PS512", "ed25519": "Ed25519", "eddsa": "EdDSA", "ed448": "Ed448",
                "hs256": "HS256", "none": "none", "unknown-alg": "XX999", "es256-der": "ES256"}
    for name, alg in expected.items():
        [entry] = inputs_of(fixture(name))
        assert (entry.error, entry.alg, entry.kid) == (None, alg, "shared" if name == "hs256" else entry.kid), name
    assert inputs_of(fixture("no-kid"))[0].error == "the protected header has no kid"
    assert "crit" in inputs_of(fixture("crit"))[0].error
    assert inputs_of(fixture("es256-embedded"))[0].has_jwk and inputs_of(fixture("es256-jku"))[0].jku.endswith("/.well-known/jwks.json")
    assert [entry.error for entry in inputs_of(fixture("two-signatures"))] == [None, None]


def test_s6_no_file_under_fixtures_or_tests_holds_a_jwk_private_member():
    root = Path(__file__).resolve().parents[1]
    private = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
    scanned = 0

    def walk(node, where: str) -> None:
        if isinstance(node, dict):
            assert not ("kty" in node and private & set(node)), f"{where} holds a private JWK member"
            for key, value in node.items():
                walk(value, f"{where}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{where}[{index}]")

    for directory in ("fixtures", "tests"):
        for path in sorted((root / directory).rglob("*.json")):
            try:
                document = load_json(path.read_bytes())  # lenient: some fixtures are JSONC
            except Refused:
                continue
            walk(document, str(path.relative_to(root)))
            scanned += 1
    assert scanned > 40
    for path in sorted(list((root / "tests").rglob("*.py")) + list((root / "scripts").rglob("*.py"))):
        if path.name != "test_a2a_signing.py":
            assert "BEGIN PRIVATE KEY" not in path.read_text(encoding="utf-8"), path


@pytest.mark.parametrize(("pointer", "expected"), [
    # legacy members, in their JSON and their proto spelling
    ("/security", True), ("/url", True), ("/skills/0/security", True), ("/securitySchemes/k/type", True),
    ("/supportedInterfaces/0/transport", True), ("/preferred_transport", True), ("/supports_authenticated_extended_card", True),
    ("/capabilities/state_transition_history", True), ("/securitySchemes/my_key/in", True),
    # proto field-name aliases of 1.0 members (r1:F2): protobuf's JSON reader takes them for the member
    ("/security_requirements", True), ("/skills/0/security_requirements", True), ("/security_schemes", True),
    ("/supported_interfaces", True), ("/supported_interfaces/0/url", True), ("/supportedInterfaces/0/protocol_binding", True),
    ("/default_input_modes", True), ("/securitySchemes/k/api_key_security_scheme", True),
    # the JSON spelling of security members is listed, not required (D-L1 revised), and vendor members never are
    # a whole requirement entry (the sdk form drops only `{}`, "no authentication") must be signed; below it, only listed
    ("/securityRequirements/1", True), ("/skills/2/securityRequirements/0", True),
    ("/securityRequirements", False), ("/securityRequirements/0/schemes", False), ("/securitySchemes/oauth", False),
    ("/skills/0/securityRequirements/0/schemes/bearer", False), ("/securitySchemes/my_key", False),
    ("/name", False), ("/x-vendor", False), ("/x_vendor", False), ("/skills/0/x_note", False), ("", False),
])
def test_must_be_signed_names_legacy_members_and_proto_field_name_aliases(pointer, expected):
    assert must_be_signed(pointer) is expected, pointer
    if is_legacy_pointer(pointer):
        assert must_be_signed(pointer)


def test_a_proto_field_name_alias_holding_a_default_is_still_reported_unsigned():
    card = clean_card()
    card["security_requirements"] = []
    [si] = inputs_of(signed(card, header_of({"alg": "ES256", "kid": "k"})))
    assert [name for name, _, members in si.inputs if "/security_requirements" not in members] == ["as_served"]
