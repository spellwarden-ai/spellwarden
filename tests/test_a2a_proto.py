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
