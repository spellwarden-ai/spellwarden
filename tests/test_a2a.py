"""O4 spec 5.1 and 5.3 and claims J2, V1, V2, V3, F1 (parse part): the strict read of an agent card, its shape, format and
protocol versions, and the validator of the A2A 1.0 field rules. Every row and reason of 5.3 has a positive and a negative
case; the specification's own sample cards are read as the claims say."""
from __future__ import annotations

import pytest
from a2a_cards import card_bytes, clean_card, spec_card

from spellwarden_scan.a2a import (
    CAPS, AgentCardDocument, capped, is_legacy_pointer, legacy_members, parse_agent_card, pointer_of, validate_1_0,
    legacy_version_issues,
)

# V2: the required members of an AgentCard that the TCK checks (`tests/compatibility/agent_card/test_agent_card.py`,
# `_REQUIRED_FIELDS`, a2a-tck commit d4d6fae), which are the proto's REQUIRED annotations at v1.0.1.
TCK_REQUIRED = {"name", "description", "version", "capabilities", "skills", "supportedInterfaces", "defaultInputModes",
                "defaultOutputModes"}


def parsed(card: dict, path: str = "public/.well-known/agent-card.json") -> AgentCardDocument:
    return parse_agent_card(path, card_bytes(card))


def reasons(card: dict) -> list[tuple[str, str]]:
    """`(pointer, reason)` of every issue the validator finds, in the order found."""
    return [(issue.pointer, issue.reason) for issue in validate_1_0(parsed(card))]


def test_a_clean_card_has_no_issue_and_the_shape_format_and_versions_of_a_1_0_card():
    document = parsed(clean_card())
    assert (document.error, document.card_shape, document.card_format, document.protocol_versions) == (None, True, "1.0", ("1.0",))
    assert validate_1_0(document) == () and document.truncated is False
    assert len(document.raw_sha256) == 64


@pytest.mark.parametrize(("content", "error"), [
    (b"", "not_json"), (b"[1]", "not_an_object"), (b'{"a": 1,}', "not_json"), (b"// c\n{}", "not_json"),
    (b'\xef\xbb\xbf{"name": "x"}', "bom"), (b'{"a": 1, "a": 2}', "duplicate_key"), (b"\xff", "not_utf8"),
    (b" " * (2**20 + 1), "too_large"),
])
def test_a_card_that_cannot_be_read_is_a_document_with_an_error_and_no_root(content, error):
    document = parse_agent_card("agent-card.json", content)
    assert (document.error, document.root, document.card_format, document.protocol_versions) == (error, None, "unknown", ())
    assert validate_1_0(document) == ()


def test_j2_a_card_nested_128_levels_parses_and_129_is_too_deep():
    def deep(levels: int) -> bytes:
        inner = '{"a":' * (levels - 1) + "{}" + "}" * (levels - 1)
        return ('{"capabilities":{"extensions":[{"uri":"x","params":' + inner + "}]}}").encode()

    assert parse_agent_card("c.json", deep(124)).error is None
    assert parse_agent_card("c.json", deep(125)).error == "too_deep"


def test_card_shape_needs_a_name_and_interfaces_or_a_url():
    assert not parsed({"name": "x"}).card_shape and parsed({"name": "x"}).card_format == "unknown"
    assert parsed({"name": "x", "url": "https://a.example/"}).card_shape
    assert parsed({"name": "x", "supportedInterfaces": []}).card_shape
    assert not parsed({"url": "https://a.example/"}).card_shape and not parsed({"name": 3, "url": "u"}).card_shape


@pytest.mark.parametrize(("card", "expected"), [
    ({"name": "x", "supportedInterfaces": [], "url": "https://a.example/"}, "1.0"),   # leftovers do not make it older
    ({"name": "x", "url": "https://a.example/", "signatures": []}, "0.3"),
    ({"name": "x", "url": "https://a.example/", "protocolVersion": "0.3.0"}, "0.3"),
    ({"name": "x", "url": "https://a.example/", "protocolVersion": "0.3"}, "0.3"),
    ({"name": "x", "url": "https://a.example/", "protocolVersion": "0.2.5"}, "0.2"),
    ({"name": "x", "url": "https://a.example/", "preferredTransport": "JSONRPC", "supportsAuthenticatedExtendedCard": True}, "0.2"),
    ({"name": "x", "url": "https://a.example/", "protocolVersion": 3}, "0.2"),
])
def test_card_format_is_decided_on_the_root_keys_alone(card, expected):
    assert parsed(card).card_format == expected


def test_protocol_versions_are_reduced_to_major_minor_sorted_numerically_and_unreadable_ones_left_out():
    card = clean_card()
    card["supportedInterfaces"] = [{"protocolVersion": version} for version in ("1.0.1", "1.10", "1.2", "1.0", "x", 3, "2.0.0")]
    assert parsed(card).protocol_versions == ("1.0", "1.2", "1.10", "2.0")
    assert parsed({"name": "x", "url": "https://a.example/", "protocolVersion": "0.3.0"}).protocol_versions == ("0.3",)
    assert parsed({"name": "x", "url": "https://a.example/"}).protocol_versions == ()  # the SDK's 0.3.0 default is not assumed
    assert parsed({"name": "x", "url": "https://a.example/", "protocolVersion": "later"}).protocol_versions == ()


def test_f1_the_specification_sample_cards():
    one, three, two = (parse_agent_card("agent-card.json", spec_card(name)) for name in ("v1.0.1", "v0.3.0", "v0.2.6"))
    assert (one.card_format, one.protocol_versions, validate_1_0(one)) == ("1.0", ("1.0",), ())
    assert [member for _, member, _ in legacy_members(one)] == ["security"]
    assert (three.card_format, three.protocol_versions) == ("0.3", ("0.2",))  # it has `signatures`, and declares "0.2.9"
    assert (two.card_format, two.protocol_versions) == ("0.2", ("0.2",))
    assert validate_1_0(three) == () == validate_1_0(two)  # an older card is reported by SW-A2A-002, not validated


def test_a_0_x_card_with_an_unreadable_version_has_one_version_format_issue_and_a_1_0_card_none():
    document = parsed({"name": "x", "url": "https://a.example/", "protocolVersion": "later"})
    assert [(issue.pointer, issue.reason) for issue in legacy_version_issues(document)] == [("/protocolVersion", "version_format")]
    assert legacy_version_issues(parsed({"name": "x", "url": "https://a.example/", "protocolVersion": "0.2.9"})) == ()
    assert legacy_version_issues(parsed(clean_card())) == ()


def test_the_caps_mark_the_document_truncated_and_the_validator_reads_only_what_is_within_them():
    card = clean_card()
    card["skills"] = [{"id": f"s{n}", "name": "n", "description": "d", "tags": ["t"]} for n in range(CAPS["skills"] + 1)]
    document = parsed(card)
    assert document.truncated is True and validate_1_0(document) == ()
    assert len(capped(document.root["skills"], "skills")) == CAPS["skills"] and capped("no", "skills") == []
    for name, value in (("supportedInterfaces", [card["supportedInterfaces"][0]] * 51), ("signatures", [{}] * 6),
                        ("defaultInputModes", ["text/plain"] * 201), ("securityRequirements", [{"schemes": {}}] * 51)):
        more = clean_card()
        more[name] = value
        assert parsed(more).truncated is True, name
    assert parsed(clean_card()).truncated is False


# --- V1: every row and reason of 5.3 -----------------------------------------------------------------------------------

SHAPE_MEMBERS = {"name", "supportedInterfaces"}  # without one of these the file is not recognised as a 1.0 card at all


def test_v2_the_required_set_of_the_agent_card_is_the_tck_s():
    """A member is required when removing it from a clean card is reported as missing, or (for the two members that make
    a file a card: `name` and `supportedInterfaces`) takes away the card shape, which SW-A2A-001 reports as `not_a_card`."""
    required = set()
    for key in sorted(clean_card()):
        card = clean_card()
        del card[key]
        if not parsed(card).card_shape or (f"/{key}", "missing") in reasons(card):
            required.add(key)
    assert required == TCK_REQUIRED
    assert {key for key in TCK_REQUIRED if not parsed({k: v for k, v in clean_card().items() if k != key}).card_shape} == SHAPE_MEMBERS


@pytest.mark.parametrize("key", sorted(TCK_REQUIRED - SHAPE_MEMBERS))
def test_a_missing_required_member_is_missing_with_the_line_of_the_card(key):
    card = clean_card()
    del card[key]
    document = parsed(card)
    issues = [issue for issue in validate_1_0(document) if issue.pointer == f"/{key}"]
    assert [(issue.reason, issue.member, issue.identity) for issue in issues] == [("missing", key, "card")]
    assert issues[0].line == 1  # a missing member is reported at the line of its object


def test_a_required_array_must_not_be_empty_and_a_member_of_the_wrong_type_is_wrong_type():
    for key in ("supportedInterfaces", "skills", "defaultInputModes", "defaultOutputModes"):
        card = clean_card()
        card[key] = []
        assert (f"/{key}", "empty") in reasons(card), key
    card = clean_card()
    card.update(version=3, capabilities=[], skills="no", description=None)
    assert {("/version", "wrong_type"), ("/capabilities", "wrong_type"), ("/skills", "wrong_type"), ("/description", "wrong_type")} <= set(reasons(card))


def test_optional_members_are_checked_for_type_only_when_present():
    card = clean_card()
    card.update(provider="x", securitySchemes=[], securityRequirements={}, signatures="x", documentationUrl=1, iconUrl=2)
    assert set(reasons(card)) == {("/provider", "wrong_type"), ("/securitySchemes", "wrong_type"),
                                  ("/securityRequirements", "wrong_type"), ("/signatures", "wrong_type"),
                                  ("/documentationUrl", "wrong_type"), ("/iconUrl", "wrong_type")}
    assert reasons(clean_card()) == []


def test_agent_interface_rows():
    def with_interface(**changes) -> list[tuple[str, str]]:
        card = clean_card()
        card["supportedInterfaces"][0].update(changes)
        return reasons(card)

    assert with_interface(protocolVersion="1.0.1") == [] and with_interface(protocolBinding="https://example.com/b") == []
    assert with_interface(protocolBinding="urn:example:binding") == []
    assert ("/supportedInterfaces/0/protocolVersion", "version_format") in with_interface(protocolVersion="v1")
    assert ("/supportedInterfaces/0/protocolBinding", "binding_unknown") in with_interface(protocolBinding="SOAP")
    assert ("/supportedInterfaces/0/url", "not_absolute_uri") in with_interface(url="agent.example.com/a2a")
    assert with_interface(protocolBinding="GRPC", url="agent.example.com:443") == []          # host:port is accepted for GRPC
    assert with_interface(protocolBinding="GRPC", url="[2001:db8::1]:50051") == []
    assert ("/supportedInterfaces/0/url", "not_absolute_uri") in with_interface(url="agent.example.com:443")  # only for GRPC
    assert ("/supportedInterfaces/0/tenant", "wrong_type") in with_interface(tenant=3)
    for key in ("url", "protocolBinding", "protocolVersion"):
        card = clean_card()
        del card["supportedInterfaces"][0][key]
        assert (f"/supportedInterfaces/0/{key}", "missing") in reasons(card), key
    card = clean_card()
    card["supportedInterfaces"] = ["x"]
    assert reasons(card) == [("/supportedInterfaces/0", "wrong_type")]


def test_agent_provider_capabilities_and_extension_rows():
    card = clean_card()
    card["provider"] = {}
    assert set(reasons(card)) == {("/provider/url", "missing"), ("/provider/organization", "missing")}
    card = clean_card()
    card["capabilities"] = {"streaming": "yes", "pushNotifications": 1, "extendedAgentCard": None,
                            "extensions": [{"uri": 1, "description": 2, "required": "x"}, "y"]}
    assert set(reasons(card)) == {
        ("/capabilities/streaming", "wrong_type"), ("/capabilities/pushNotifications", "wrong_type"),
        ("/capabilities/extendedAgentCard", "wrong_type"), ("/capabilities/extensions/0/uri", "wrong_type"),
        ("/capabilities/extensions/0/description", "wrong_type"), ("/capabilities/extensions/0/required", "wrong_type"),
        ("/capabilities/extensions/1", "wrong_type")}
    card = clean_card()
    card["capabilities"] = {"extensions": [{"uri": "https://example.com/ext", "description": "d", "required": True, "params": {}}]}
    assert reasons(card) == []


def test_agent_skill_rows_and_the_duplicate_skill_id():
    card = clean_card()
    card["skills"] = [{"name": 1, "tags": [], "examples": "x", "inputModes": [1], "securityRequirements": {}}, "x"]
    assert set(reasons(card)) == {
        ("/skills/0/id", "missing"), ("/skills/0/name", "wrong_type"), ("/skills/0/description", "missing"),
        ("/skills/0/tags", "empty"), ("/skills/0/examples", "wrong_type"), ("/skills/0/inputModes", "wrong_type"),
        ("/skills/0/securityRequirements", "wrong_type"), ("/skills/1", "wrong_type")}
    card = clean_card()
    card["skills"].append(dict(card["skills"][0]))
    document = parsed(card)
    issues = validate_1_0(document)
    assert [(issue.pointer, issue.reason, issue.identity) for issue in issues] == [("/skills/1/id", "duplicate_skill_id", "skill-at:1")]
    assert validate_1_0(parsed(clean_card())) == ()


def test_security_scheme_rows():
    def with_scheme(scheme) -> list[tuple[str, str]]:
        card = clean_card()
        card["securitySchemes"] = {"s": scheme}
        card["securityRequirements"] = []
        return reasons(card)

    assert with_scheme({"apiKeySecurityScheme": {"location": "header", "name": "X-Key"}}) == []
    assert with_scheme({"httpAuthSecurityScheme": {"scheme": "Bearer", "bearerFormat": "JWT"}}) == []
    assert with_scheme({"openIdConnectSecurityScheme": {"openIdConnectUrl": "https://i.example/.well-known/openid-configuration"}}) == []
    assert with_scheme({"mtlsSecurityScheme": {}}) == []
    assert with_scheme({}) == [("/securitySchemes/s", "scheme_type")]
    assert with_scheme({"mtlsSecurityScheme": {}, "httpAuthSecurityScheme": {"scheme": "x"}}) == [("/securitySchemes/s", "scheme_type")]
    assert with_scheme({"type": "http"}) == [("/securitySchemes/s", "scheme_type")]  # a 0.x scheme is not a 1.0 scheme
    assert with_scheme("x") == [("/securitySchemes/s", "wrong_type")]
    assert with_scheme({"apiKeySecurityScheme": {"location": "body", "name": 3}}) == [
        ("/securitySchemes/s/apiKeySecurityScheme/name", "wrong_type"), ("/securitySchemes/s/apiKeySecurityScheme/location", "wrong_type")]
    assert with_scheme({"apiKeySecurityScheme": {}}) == [("/securitySchemes/s/apiKeySecurityScheme/name", "missing"),
                                                         ("/securitySchemes/s/apiKeySecurityScheme/location", "missing")]
    assert with_scheme({"httpAuthSecurityScheme": {}}) == [("/securitySchemes/s/httpAuthSecurityScheme/scheme", "missing")]
    assert with_scheme({"openIdConnectSecurityScheme": {}}) == [("/securitySchemes/s/openIdConnectSecurityScheme/openIdConnectUrl", "missing")]


def test_oauth_flow_rows_and_the_deprecated_flows_need_nothing():
    def with_flows(flows) -> list[tuple[str, str]]:
        card = clean_card()
        card["securitySchemes"] = {"o": {"oauth2SecurityScheme": {"flows": flows}}}
        card["securityRequirements"] = []
        return reasons(card)

    base = "/securitySchemes/o/oauth2SecurityScheme/flows"
    assert with_flows({"authorizationCode": {"authorizationUrl": "https://a/", "tokenUrl": "https://t/", "scopes": {}}}) == []
    assert with_flows({"clientCredentials": {"tokenUrl": "https://t/", "scopes": {"a": "b"}}}) == []
    assert with_flows({"deviceCode": {"deviceAuthorizationUrl": "https://d/", "tokenUrl": "https://t/", "scopes": {}}}) == []
    assert with_flows({"implicit": {}}) == [] and with_flows({"password": {}}) == []  # V1: no required member, empty scopes
    assert with_flows({"implicit": {"authorizationUrl": "https://a/", "scopes": {}}}) == []
    assert with_flows({"password": {"tokenUrl": 3, "refreshUrl": 4, "scopes": {"a": 1}}}) == [
        (f"{base}/password/tokenUrl", "wrong_type"), (f"{base}/password/refreshUrl", "wrong_type"), (f"{base}/password/scopes", "wrong_type")]
    assert with_flows({}) == [("/securitySchemes/o/oauth2SecurityScheme/flows", "flow_count")]
    assert with_flows({"implicit": {}, "password": {}}) == [("/securitySchemes/o/oauth2SecurityScheme/flows", "flow_count")]
    assert with_flows({"authorizationCode": {}}) == [(f"{base}/authorizationCode/authorizationUrl", "missing"),
                                                     (f"{base}/authorizationCode/tokenUrl", "missing"), (f"{base}/authorizationCode/scopes", "missing")]
    assert with_flows({"clientCredentials": {"tokenUrl": "https://t/"}}) == [(f"{base}/clientCredentials/scopes", "missing")]
    assert with_flows({"deviceCode": {"scopes": {}}}) == [(f"{base}/deviceCode/deviceAuthorizationUrl", "missing"), (f"{base}/deviceCode/tokenUrl", "missing")]
    assert with_flows({"authorizationCode": {"authorizationUrl": "a", "tokenUrl": "t", "scopes": {}, "pkceRequired": "yes"}}) == [
        (f"{base}/authorizationCode/pkceRequired", "wrong_type")]
    card = clean_card()
    card["securitySchemes"] = {"o": {"oauth2SecurityScheme": {}}}
    card["securityRequirements"] = []
    assert reasons(card) == [("/securitySchemes/o/oauth2SecurityScheme/flows", "missing")]


def test_security_requirement_rows():
    def with_requirements(requirements, schemes=None) -> list[tuple[str, str]]:
        card = clean_card()
        card["securityRequirements"] = requirements
        if schemes is not None:
            card["securitySchemes"] = schemes
        return reasons(card)

    assert with_requirements([{"schemes": {"oauth": {"list": []}}}]) == []
    assert with_requirements([{"schemes": {"oauth": {}}}]) == []   # protojson leaves an empty `list` out
    assert with_requirements([{}]) == [("/securityRequirements/0/schemes", "missing")]
    assert with_requirements([{"schemes": {"nope": {"list": []}}}]) == [("/securityRequirements/0/schemes/nope", "undefined_scheme")]
    assert with_requirements([{"schemes": {"oauth": {"list": [1]}}}]) == [("/securityRequirements/0/schemes/oauth/list", "wrong_type")]
    assert with_requirements([{"schemes": {"oauth": []}}]) == [("/securityRequirements/0/schemes/oauth", "wrong_type")]
    assert with_requirements(["x"]) == [("/securityRequirements/0", "wrong_type")]
    card = clean_card()
    card["skills"][0]["securityRequirements"] = [{"schemes": {"missing": {"list": []}}}]
    assert reasons(card) == [("/skills/0/securityRequirements/0/schemes/missing", "undefined_scheme")]


def test_signature_entry_rows():
    card = clean_card()
    card["signatures"] = [{"protected": 1, "header": []}, "x", {}]
    assert set(reasons(card)) == {("/signatures/0/protected", "wrong_type"), ("/signatures/0/signature", "missing"),
                                  ("/signatures/0/header", "wrong_type"), ("/signatures/1", "wrong_type"),
                                  ("/signatures/2/protected", "missing"), ("/signatures/2/signature", "missing")}
    card["signatures"] = [{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "c2ln", "header": {}}]
    assert reasons(card) == []


def test_v3_unknown_fields_are_ignored():
    card = clean_card()
    for number in range(10):
        card[f"x-vendor-{number}"] = {"anything": [number]}
    card["skills"][0]["x-rank"] = 3
    card["supportedInterfaces"][0]["x-note"] = "n"
    assert reasons(card) == []


def test_pointers_are_rfc_6901_escaped_and_issues_carry_stable_identities_and_lines():
    card = clean_card()
    card["securitySchemes"] = {"a/b~c": "x"}
    card["securityRequirements"] = []
    issue = validate_1_0(parsed(card))[0]
    assert (issue.pointer, issue.identity, issue.reason) == ("/securitySchemes/a~1b~0c", "scheme:a/b~c", "wrong_type")
    assert pointer_of("a/b", 3, "~") == "/a~1b/3/~0"
    card = clean_card()
    card["skills"][0]["tags"] = []
    issue = validate_1_0(parsed(card))[0]
    text = card_bytes(card).decode().splitlines()
    assert (issue.identity, issue.member, issue.line) == ("skill:summarise", "tags", text.index('      "tags": [],') + 1)


def test_legacy_members_and_pointers():
    card = clean_card()
    card.update(url="https://a.example/", preferredTransport="JSONRPC", security=[], supportsAuthenticatedExtendedCard=True)
    card["capabilities"]["stateTransitionHistory"] = False
    card["skills"][0]["security"] = []
    card["supportedInterfaces"][0]["transport"] = "JSONRPC"
    card["securitySchemes"]["legacy"] = {"type": "apiKey", "in": "query"}
    card["securitySchemes"]["wrapped"] = {"apiKeySecurityScheme": {"location": "query", "name": "k", "in": "query"}}
    found = {pointer for pointer, _, _ in legacy_members(parsed(card))}
    assert found == {"/url", "/preferredTransport", "/security", "/supportsAuthenticatedExtendedCard",
                     "/capabilities/stateTransitionHistory", "/skills/0/security", "/supportedInterfaces/0/transport",
                     "/securitySchemes/legacy/type", "/securitySchemes/legacy/in",
                     "/securitySchemes/wrapped/apiKeySecurityScheme/in"}
    assert all(is_legacy_pointer(pointer) for pointer in found)
    for pointer in ("/name", "/skills/0/id", "/securitySchemes/oauth/oauth2SecurityScheme", "/capabilities/streaming",
                    "/x-url", "/supportedInterfaces/0/url"):
        assert not is_legacy_pointer(pointer), pointer
    assert list(legacy_members(parsed(clean_card()))) == []
