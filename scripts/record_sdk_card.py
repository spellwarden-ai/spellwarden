"""Records `tests/fixtures/a2a/signed/sdk-es256.json` and `jwks-sdk.json`: an agent card signed by `a2a-sdk` 1.2.3 with ES256
(O4 spec 7, slice 4; claim S3). Run once, with the SDK, which is not a dependency of the scanner (both pins matter; the
versions the command resolved are listed in `tests/fixtures/a2a/signed/README.md`):

    uv run --no-project --with "a2a-sdk[signing]==1.2.3" --with "cryptography==50.0.2" python scripts/record_sdk_card.py

The card is built as protobuf messages, signed with `a2a.utils.signing.create_agent_card_signer` and served as
`MessageToDict` writes it, which leaves out every default value but keeps `capabilities: {}`; the script then adds what a
hand-written card often carries and a protobuf serialiser never writes: an empty skill `examples` list and
`"pkceRequired": false`. The SDK signs the card without `capabilities` (its `_clean_empty` removes the empty object, which
the specification's own presence rules keep, because the member is REQUIRED), so the signature verifies over the `sdk`
payload form only. Only the public key is written."""
from __future__ import annotations

import json
from pathlib import Path

from a2a.types import (
    AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill, AuthorizationCodeOAuthFlow, OAuth2SecurityScheme,
    OAuthFlows, SecurityRequirement, SecurityScheme, StringList,
)
from a2a.utils.signing import create_agent_card_signer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.json_format import MessageToDict

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "a2a" / "signed"


def b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def main() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    flow = AuthorizationCodeOAuthFlow(authorization_url="https://auth.example.com/authorize",
                                      token_url="https://auth.example.com/token", scopes={"invoices.read": "Read invoices"})
    card = AgentCard(
        name="Invoice Helper", description="Summarises supplier invoices for the accounts team.", version="1.2.0",
        supported_interfaces=[AgentInterface(url="https://agent.example.com/a2a", protocol_binding="JSONRPC",
                                             protocol_version="1.0")],
        provider=AgentProvider(organization="Example Inc.", url="https://example.com"),
        capabilities=AgentCapabilities(),
        security_schemes={"oauth": SecurityScheme(
            oauth2_security_scheme=OAuth2SecurityScheme(flows=OAuthFlows(authorization_code=flow)))},
        security_requirements=[SecurityRequirement(schemes={"oauth": StringList(list=["invoices.read"])})],
        default_input_modes=["text/plain"], default_output_modes=["text/plain"],
        skills=[AgentSkill(id="summarise", name="Summarise invoice", description="Summarises one invoice.", tags=["invoices"])])
    sign = create_agent_card_signer(pem, {"alg": "ES256", "kid": "sdk-key", "typ": "JOSE"})
    served = MessageToDict(sign(card))
    served["skills"][0]["examples"] = []
    served["securitySchemes"]["oauth"]["oauth2SecurityScheme"]["flows"]["authorizationCode"]["pkceRequired"] = False
    numbers = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": "sdk-key", "use": "sig", "alg": "ES256",
           "x": b64(numbers.x.to_bytes(32, "big")), "y": b64(numbers.y.to_bytes(32, "big"))}
    (OUT / "sdk-es256.json").write_text(json.dumps(served, indent=2) + "\n", encoding="utf-8")
    (OUT / "jwks-sdk.json").write_text(json.dumps({"keys": [jwk]}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
