"""SW-A2A-019 (1.4.0): the card as a protobuf client reads it. `PROTO_NAMES` against the committed proto excerpt, and
`client_view`: a member spelled with its proto field name is read as the member it names, the later of two spellings is
kept, and every such spelling is a `ProtoAlias`. The outcomes were taken from a2a-sdk 1.2.3 over protobuf 7.36
(`json_format.ParseDict` into `AgentCard`): for a repeated, map or plain member the later spelling wins and a later
`null` clears it; both spellings of an `optional` or `oneof` member raise `ParseError` ("multiple ... oneof fields")."""
from __future__ import annotations

import json
import re
from pathlib import Path

from a2a_cards import card_bytes, clean_card

from spellwarden_scan.a2a import client_view, parse_agent_card
from spellwarden_scan.a2a_proto import PRESENCE, PROTO_NAMES, json_name, proto_name

PROTO = Path(__file__).resolve().parent / "fixtures" / "a2a" / "proto" / "a2a-v1.0.1-card.proto"
_MESSAGE = re.compile(r"^message (\w+) \{\n(.*?)^\}", re.M | re.S)
_FIELD = re.compile(r"^\s*(?:optional |repeated )?(?:map<\w+, ?[\w.]+>|[\w.]+) (\w+) = [0-9]+")


def parsed(card: dict):
    return parse_agent_card("card.json", card_bytes(card))


def renamed(card: dict, name: str, to: str) -> dict:
    return {to if key == name else key: value for key, value in card.items()}


def test_proto_names_are_the_field_names_of_the_excerpt_whose_json_name_differs():
    expected: dict[str, dict[str, str]] = {}
    for message in _MESSAGE.finditer(PROTO.read_text(encoding="utf-8")):
        fields = [match.group(1) for match in map(_FIELD.match, message.group(2).splitlines()) if match]
        expected[message.group(1)] = {field: json_name(field) for field in fields if json_name(field) != field}
    assert PROTO_NAMES == expected
    assert PROTO_NAMES["AgentCard"]["security_requirements"] == "securityRequirements"
    assert PROTO_NAMES["SecurityScheme"]["open_id_connect_security_scheme"] == "openIdConnectSecurityScheme"
    assert all(proto_name(name) in PROTO_NAMES[message] or proto_name(name) == name
               for message, fields in PRESENCE.items() for name in fields)


def test_a_card_without_proto_names_is_its_own_view():
    document = parsed(clean_card())
    assert document.view is document.root and document.aliases == ()


def test_a_member_spelled_only_with_its_proto_field_name_is_read_as_that_member_on_its_own_line():
    card = clean_card()
    card["supportedInterfaces"][0] = renamed(card["supportedInterfaces"][0], "protocolBinding", "protocol_binding")
    card = renamed(card, "supportedInterfaces", "supported_interfaces")
    document = parsed(card)
    assert (document.card_shape, document.card_format, document.protocol_versions) == (True, "1.0", ("1.0",))
    interface = document.view["supportedInterfaces"][0]
    assert interface["protocolBinding"] == "JSONRPC" and "protocol_binding" not in interface
    assert interface.lines["protocolBinding"] == document.root["supported_interfaces"][0].lines["protocol_binding"]
    assert [(a.pointer, a.view_pointer, a.alias, a.name, a.outcome) for a in document.aliases] == [
        ("/supported_interfaces", "/supportedInterfaces", "supported_interfaces", "supportedInterfaces", "alias_only"),
        ("/supported_interfaces/0/protocol_binding", "/supportedInterfaces/0/protocolBinding", "protocol_binding",
         "protocolBinding", "alias_only"),
    ]
    assert document.aliases[0].line == document.root.lines["supported_interfaces"]


def test_of_two_spellings_the_later_is_kept_and_a_later_null_clears():
    alias_later = parsed({**clean_card(), "security_requirements": [{"schemes": {}}]})
    assert alias_later.view["securityRequirements"] == [{"schemes": {}}]
    assert [a.outcome for a in alias_later.aliases] == ["alias_wins"]
    name_later = parsed({"security_requirements": [{"schemes": {}}], **clean_card()})
    assert name_later.view["securityRequirements"] == clean_card()["securityRequirements"]
    assert [a.outcome for a in name_later.aliases] == ["name_wins"]
    cleared = parsed({**clean_card(), "security_requirements": None})
    assert cleared.view["securityRequirements"] is None and [a.outcome for a in cleared.aliases] == ["alias_wins"]


def test_both_spellings_of_an_optional_or_oneof_member_are_refused():
    card = {**clean_card(), "iconUrl": "https://example.com/a.png", "icon_url": "https://example.com/b.png"}
    scheme = card["securitySchemes"]["oauth"]
    scheme["oauth2_security_scheme"] = json.loads(json.dumps(scheme["oauth2SecurityScheme"]))
    document = parsed(card)
    assert sorted((a.pointer, a.outcome) for a in document.aliases) == [
        ("/icon_url", "refused"), ("/securitySchemes/oauth/oauth2_security_scheme", "refused")]
    assert document.view["iconUrl"] == "https://example.com/b.png"


def test_nothing_below_a_dropped_spelling_is_read_and_free_form_keys_stay_as_served():
    card = {"security_schemes": {"x": {"http_auth_security_scheme": {"scheme": "basic"}}}, **clean_card()}
    card["capabilities"] = {"extensions": [{"uri": "urn:x", "params": {"security_requirements": [{}]}}]}
    card["securitySchemes"]["oauth"]["oauth2SecurityScheme"]["flows"]["authorizationCode"]["scopes"] = {"token_url": "x"}
    card["securitySchemes"]["api_key_security_scheme"] = {"mtlsSecurityScheme": {}}
    document = parsed(card)
    assert [(a.pointer, a.outcome) for a in document.aliases] == [("/security_schemes", "name_wins")]
    assert document.view["capabilities"]["extensions"][0]["params"] == {"security_requirements": [{}]}
    assert "api_key_security_scheme" in document.view["securitySchemes"]
    flows = document.view["securitySchemes"]["oauth"]["oauth2SecurityScheme"]["flows"]
    assert flows["authorizationCode"]["scopes"] == {"token_url": "x"}


def test_unknown_members_and_near_spellings_are_not_aliases():
    view, aliases = client_view(parsed({**clean_card(), "Security_requirements": [{}], "security__requirements": [{}],
                                        "x_vendor": 1}).root)
    assert aliases == () and {"Security_requirements", "security__requirements", "x_vendor"} <= set(view)


# --- 1.5.0: the snake_case spellings of 0.x members, read as a2a-sdk 0.3 reads them -------------------------------------
# Outcomes taken on 2026-10-27 from a2a-sdk 0.3.26 (pydantic 2.14.1, `validate_by_name=True, validate_by_alias=True`:
# the snake_case name alone is the member, and with both spellings the camelCase one is kept whatever the order), a2a-sdk
# 1.2.3 (`card_resolver.parse_agent_card` pops only the camelCase legacy members and ignores their snake_case spelling) and
# @a2a-js/sdk 0.3.14 (camelCase only).

LEGACY_CARD = {
    "protocol_version": "0.3.0", "name": "Legacy router", "description": "Routes orders.",
    "url": "https://agent.example.com/a2a", "preferred_transport": "GRPC",
    "additional_interfaces": [{"url": "https://agent.example.com/grpc", "transport": "GRPC"}],
    "version": "1.0.0", "capabilities": {"state_transition_history": True},
    "securitySchemes": {"oidc": {"type": "openIdConnect", "open_id_connect_url": "https://id.example.com/.well-known/x"}},
    "security": [{"oidc": ["openid"]}], "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "route", "name": "Route", "description": "Routes an order.", "tags": ["orders"]}],
}


def test_a_0x_member_spelled_only_in_snake_case_is_read_as_that_member():
    document = parsed(LEGACY_CARD)
    assert (document.card_shape, document.card_format, document.protocol_versions) == (True, "0.3", ("0.3",))
    view = document.view
    assert view["protocolVersion"] == "0.3.0" and view["preferredTransport"] == "GRPC"
    assert view["additionalInterfaces"][0]["transport"] == "GRPC" and view["capabilities"]["stateTransitionHistory"] is True
    assert view["securitySchemes"]["oidc"]["openIdConnectUrl"] == "https://id.example.com/.well-known/x"
    assert view.lines["preferredTransport"] == document.root.lines["preferred_transport"]
    assert sorted((a.pointer, a.view_pointer, a.outcome, a.legacy) for a in document.aliases) == [
        ("/additional_interfaces", "/additionalInterfaces", "alias_only", True),
        ("/capabilities/state_transition_history", "/capabilities/stateTransitionHistory", "alias_only", True),
        ("/preferred_transport", "/preferredTransport", "alias_only", True),
        ("/protocol_version", "/protocolVersion", "alias_only", True),
        ("/securitySchemes/oidc/open_id_connect_url", "/securitySchemes/oidc/openIdConnectUrl", "alias_only", True),
    ]


def test_of_two_spellings_of_a_0x_member_the_camel_case_one_is_kept_whatever_the_order():
    later = parsed({**clean_card(), "preferredTransport": "JSONRPC", "preferred_transport": "GRPC"})
    earlier = parsed({"preferred_transport": "GRPC", **clean_card(), "preferredTransport": "JSONRPC"})
    nulled = parsed({**clean_card(), "preferredTransport": None, "preferred_transport": "GRPC"})
    for document, kept in ((later, "JSONRPC"), (earlier, "JSONRPC"), (nulled, None)):
        assert document.view["preferredTransport"] == kept and "preferred_transport" not in document.view
        assert [(a.pointer, a.outcome, a.legacy) for a in document.aliases] == [("/preferred_transport", "name_kept", True)]


def test_the_0x_scheme_members_are_read_only_in_a_scheme_of_the_0x_type_form():
    card = {**clean_card(), "securitySchemes": {
        "legacy": {"type": "oauth2", "oauth2_metadata_url": "https://auth.example.com/.well-known/oauth",
                   "flows": {"authorization_code": {"authorization_url": "https://auth.example.com/authorize",
                                                    "token_url": "https://auth.example.com/token",
                                                    "refresh_url": "https://auth.example.com/refresh",
                                                    "scopes": {"read_all": "x"}}}},
        "bearer": {"type": "http", "scheme": "bearer", "bearer_format": "JWT"},
        "wrapped": {"httpAuthSecurityScheme": {"scheme": "bearer"}, "bearer_format": "JWT"}}}
    document = parsed(card)
    schemes = document.view["securitySchemes"]
    flow = schemes["legacy"]["flows"]["authorizationCode"]
    assert (flow["authorizationUrl"], flow["tokenUrl"], flow["refreshUrl"]) == (
        "https://auth.example.com/authorize", "https://auth.example.com/token", "https://auth.example.com/refresh")
    assert flow["scopes"] == {"read_all": "x"}  # scope names are map keys, read as served
    assert schemes["legacy"]["oauth2MetadataUrl"] == "https://auth.example.com/.well-known/oauth"
    assert schemes["bearer"]["bearerFormat"] == "JWT"
    assert "bearer_format" in schemes["wrapped"] and "bearerFormat" not in schemes["wrapped"]  # a 1.0 scheme: unknown member
    assert sorted(a.view_pointer for a in document.aliases) == [
        "/securitySchemes/bearer/bearerFormat", "/securitySchemes/legacy/flows/authorizationCode",
        "/securitySchemes/legacy/flows/authorizationCode/authorizationUrl",
        "/securitySchemes/legacy/flows/authorizationCode/refreshUrl",
        "/securitySchemes/legacy/flows/authorizationCode/tokenUrl", "/securitySchemes/legacy/oauth2MetadataUrl"]
    assert all(a.legacy and a.outcome == "alias_only" for a in document.aliases)


def test_a_1_0_alias_is_not_a_legacy_one():
    document = parsed(renamed(clean_card(), "supportedInterfaces", "supported_interfaces"))
    assert [(a.alias, a.legacy) for a in document.aliases] == [("supported_interfaces", False)]
