"""The messages an A2A 1.0 agent card is made of, from the normative proto at `v1.0.1`: every field's JSON name, presence
rule and kind (`PRESENCE`), and the proto field name a protobuf JSON reader also accepts for it (`PROTO_NAMES`). Shared by
the signature inputs (`a2a_signing`) and the client's reading of a card (`a2a.client_view`). No imports from the rest of
the engine, so both can use it."""
from __future__ import annotations

# Every field of the messages an agent card is made of at `v1.0.1`: `message -> JSON name -> (rule, kind)`. `rule` is
# `required` (REQUIRED), `optional` (the `optional` keyword), `oneof` (a member of a `oneof`, which tracks presence) or
# `plain`. `kind` is `scalar`, `struct`, `message:<M>`, `repeated:string`, `repeated:message:<M>`, `map:string` or
# `map:message:<M>`. Generated from `tests/fixtures/a2a/proto/a2a-v1.0.1-card.proto` and compared with it by
# `tests/test_a2a_signing.py` (claim S8).
PRESENCE: dict[str, dict[str, tuple[str, str]]] = {
    "AgentInterface": {
        "url": ("required", "scalar"),
        "protocolBinding": ("required", "scalar"),
        "tenant": ("plain", "scalar"),
        "protocolVersion": ("required", "scalar"),
    },
    "AgentCard": {
        "name": ("required", "scalar"),
        "description": ("required", "scalar"),
        "supportedInterfaces": ("required", "repeated:message:AgentInterface"),
        "provider": ("plain", "message:AgentProvider"),
        "version": ("required", "scalar"),
        "documentationUrl": ("optional", "scalar"),
        "capabilities": ("required", "message:AgentCapabilities"),
        "securitySchemes": ("plain", "map:message:SecurityScheme"),
        "securityRequirements": ("plain", "repeated:message:SecurityRequirement"),
        "defaultInputModes": ("required", "repeated:string"),
        "defaultOutputModes": ("required", "repeated:string"),
        "skills": ("required", "repeated:message:AgentSkill"),
        "signatures": ("plain", "repeated:message:AgentCardSignature"),
        "iconUrl": ("optional", "scalar"),
    },
    "AgentProvider": {
        "url": ("required", "scalar"),
        "organization": ("required", "scalar"),
    },
    "AgentCapabilities": {
        "streaming": ("optional", "scalar"),
        "pushNotifications": ("optional", "scalar"),
        "extensions": ("plain", "repeated:message:AgentExtension"),
        "extendedAgentCard": ("optional", "scalar"),
    },
    "AgentExtension": {
        "uri": ("plain", "scalar"),
        "description": ("plain", "scalar"),
        "required": ("plain", "scalar"),
        "params": ("plain", "struct"),
    },
    "AgentSkill": {
        "id": ("required", "scalar"),
        "name": ("required", "scalar"),
        "description": ("required", "scalar"),
        "tags": ("required", "repeated:string"),
        "examples": ("plain", "repeated:string"),
        "inputModes": ("plain", "repeated:string"),
        "outputModes": ("plain", "repeated:string"),
        "securityRequirements": ("plain", "repeated:message:SecurityRequirement"),
    },
    "AgentCardSignature": {
        "protected": ("required", "scalar"),
        "signature": ("required", "scalar"),
        "header": ("plain", "struct"),
    },
    "StringList": {
        "list": ("plain", "repeated:string"),
    },
    "SecurityRequirement": {
        "schemes": ("plain", "map:message:StringList"),
    },
    "SecurityScheme": {
        "apiKeySecurityScheme": ("oneof", "message:APIKeySecurityScheme"),
        "httpAuthSecurityScheme": ("oneof", "message:HTTPAuthSecurityScheme"),
        "oauth2SecurityScheme": ("oneof", "message:OAuth2SecurityScheme"),
        "openIdConnectSecurityScheme": ("oneof", "message:OpenIdConnectSecurityScheme"),
        "mtlsSecurityScheme": ("oneof", "message:MutualTlsSecurityScheme"),
    },
    "APIKeySecurityScheme": {
        "description": ("plain", "scalar"),
        "location": ("required", "scalar"),
        "name": ("required", "scalar"),
    },
    "HTTPAuthSecurityScheme": {
        "description": ("plain", "scalar"),
        "scheme": ("required", "scalar"),
        "bearerFormat": ("plain", "scalar"),
    },
    "OAuth2SecurityScheme": {
        "description": ("plain", "scalar"),
        "flows": ("required", "message:OAuthFlows"),
        "oauth2MetadataUrl": ("plain", "scalar"),
    },
    "OpenIdConnectSecurityScheme": {
        "description": ("plain", "scalar"),
        "openIdConnectUrl": ("required", "scalar"),
    },
    "MutualTlsSecurityScheme": {
        "description": ("plain", "scalar"),
    },
    "OAuthFlows": {
        "authorizationCode": ("oneof", "message:AuthorizationCodeOAuthFlow"),
        "clientCredentials": ("oneof", "message:ClientCredentialsOAuthFlow"),
        "implicit": ("oneof", "message:ImplicitOAuthFlow"),
        "password": ("oneof", "message:PasswordOAuthFlow"),
        "deviceCode": ("oneof", "message:DeviceCodeOAuthFlow"),
    },
    "AuthorizationCodeOAuthFlow": {
        "authorizationUrl": ("required", "scalar"),
        "tokenUrl": ("required", "scalar"),
        "refreshUrl": ("plain", "scalar"),
        "scopes": ("required", "map:string"),
        "pkceRequired": ("plain", "scalar"),
    },
    "ClientCredentialsOAuthFlow": {
        "tokenUrl": ("required", "scalar"),
        "refreshUrl": ("plain", "scalar"),
        "scopes": ("required", "map:string"),
    },
    "ImplicitOAuthFlow": {
        "authorizationUrl": ("plain", "scalar"),
        "refreshUrl": ("plain", "scalar"),
        "scopes": ("plain", "map:string"),
    },
    "PasswordOAuthFlow": {
        "tokenUrl": ("plain", "scalar"),
        "refreshUrl": ("plain", "scalar"),
        "scopes": ("plain", "map:string"),
    },
    "DeviceCodeOAuthFlow": {
        "deviceAuthorizationUrl": ("required", "scalar"),
        "tokenUrl": ("required", "scalar"),
        "refreshUrl": ("plain", "scalar"),
        "scopes": ("required", "map:string"),
    },
}


def json_name(proto_name: str) -> str:
    """The JSON name protobuf gives the proto field `proto_name` (`security_requirements` -> `securityRequirements`)."""
    head, *rest = proto_name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def proto_name(json_name_: str) -> str:
    """The proto field name of the JSON name `json_name_` (`oauth2SecurityScheme` -> `oauth2_security_scheme`): every field of
    `PRESENCE` is lower snake case in the proto, so this is exact (`tests/test_a2a_proto.py` checks it against the excerpt)."""
    return "".join("_" + char.lower() if char.isupper() else char for char in json_name_)


# `message -> proto field name -> JSON name`, for the fields whose two names differ: protobuf's JSON reader accepts either
# spelling of a member (`security_requirements` for `securityRequirements`), A2A 1.0 JSON uses the JSON name.
PROTO_NAMES: dict[str, dict[str, str]] = {
    message: {proto_name(name): name for name in fields if proto_name(name) != name} for message, fields in PRESENCE.items()
}


# The members A2A 1.0 removed that a 0.x card still carries, by the message of the view they sit in, with the kind of their
# value (as in `PRESENCE`; `legacy` is read as served). Only what a snake_case spelling can hide is listed: a member whose
# snake_case name differs from its JSON name, and the members that lead to one. `SecurityScheme` lists the members of the 0.x
# `type` form of a scheme, read only in a scheme that has `type`. Their snake_case spellings are read as `a2a-sdk` 0.3 reads a
# card (pydantic with `validate_by_name=True`): the snake_case name alone is the member, and of both spellings the camelCase
# one is kept whatever the order. `a2a-sdk` 1.2.3 ignores the snake_case spelling of the four top-level members and
# @a2a-js/sdk 0.3.14 reads camelCase only, so readers disagree on a card that uses one (1.5.0, CHANGELOG).
LEGACY: dict[str, dict[str, str]] = {
    "AgentCard": {"protocolVersion": "scalar", "preferredTransport": "scalar", "additionalInterfaces": "legacy",
                  "supportsAuthenticatedExtendedCard": "scalar"},
    "AgentCapabilities": {"stateTransitionHistory": "scalar"},
    "SecurityScheme": {"bearerFormat": "scalar", "openIdConnectUrl": "scalar", "oauth2MetadataUrl": "scalar",
                       "flows": "message:LegacyOAuthFlows"},
    "LegacyOAuthFlows": {"authorizationCode": "message:LegacyOAuthFlow", "clientCredentials": "message:LegacyOAuthFlow",
                         "implicit": "message:LegacyOAuthFlow", "password": "message:LegacyOAuthFlow"},
    "LegacyOAuthFlow": {"authorizationUrl": "scalar", "tokenUrl": "scalar", "refreshUrl": "scalar", "scopes": "map:string"},
}

# `message -> snake_case name -> JSON name` of the `LEGACY` members whose two names differ.
LEGACY_NAMES: dict[str, dict[str, str]] = {
    message: {proto_name(name): name for name in fields if proto_name(name) != name} for message, fields in LEGACY.items()
}
