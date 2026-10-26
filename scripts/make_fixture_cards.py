"""Writes the signed agent card fixtures of `tests/fixtures/a2a/signed/` (O4 spec 7, slice 4; claims S1 to S4, S9 to S11).

    uv run python scripts/make_fixture_cards.py

It generates throwaway keys on every run, signs a small card with each algorithm the scanner verifies (and with the ones it
refuses, cannot verify or finds malformed) and writes the cards and the PUBLIC key sets, never a private key (claim S6: a
test scans `fixtures/` and `tests/` for private JWK members). The keys are discarded when the script ends, so the fixtures
are regenerated, not edited: run it only to replace the whole directory, then run the tests that read it.

`jwks.json` is the trusted key file of the fixtures (`a2a.keys`); `jwks-stranger.json` holds the key of the one card whose
signer is not in it. The card signed by `a2a-sdk` is recorded by `scripts/record_sdk_card.py`."""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from spellwarden_scan.jcs import jcs_canonicalize

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "a2a" / "signed"
HOST = "https://agent.example.com"
CARD = {
    "name": "Invoice Helper",
    "description": "Summarises supplier invoices for the accounts team.",
    "version": "1.2.0",
    "supportedInterfaces": [{"url": f"{HOST}/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
    "provider": {"organization": "Example Inc.", "url": "https://example.com"},
    "capabilities": {"streaming": True},
    "securitySchemes": {"oauth": {"oauth2SecurityScheme": {"flows": {"authorizationCode": {
        "authorizationUrl": "https://auth.example.com/authorize", "tokenUrl": "https://auth.example.com/token",
        "pkceRequired": True, "scopes": {"invoices.read": "Read invoices"}}}}}},
    "securityRequirements": [{"schemes": {"oauth": {"list": ["invoices.read"]}}}],
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "summarise", "name": "Summarise invoice", "description": "Summarises one invoice.",
                "tags": ["invoices"], "examples": ["Summarise invoice 42"]}],
}
HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
CURVES = {"ES256": (ec.SECP256R1, "P-256", 32), "ES384": (ec.SECP384R1, "P-384", 48), "ES512": (ec.SECP521R1, "P-521", 66)}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def integer(value: int, size: int | None = None) -> str:
    return b64(value.to_bytes(size or (value.bit_length() + 7) // 8, "big"))


class Signer:
    """One throwaway key: signs bytes with `alg` and publishes the public JWK under `kid`."""

    def __init__(self, alg: str, kid: str, key_type: str | None = None) -> None:
        self.alg, self.kid = alg, kid
        kind = key_type or alg
        if kind in CURVES:
            self.key = ec.generate_private_key(CURVES[kind][0]())
        elif kind.startswith(("RS", "PS")):
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif kind == "Ed448":
            self.key = ed448.Ed448PrivateKey.generate()
        else:
            self.key = ed25519.Ed25519PrivateKey.generate()

    def sign(self, data: bytes) -> bytes:
        alg = self.alg
        if alg in CURVES:
            r, s = decode_dss_signature(self.key.sign(data, ec.ECDSA(HASHES[alg[2:]]())))
            size = CURVES[alg][2]
            return r.to_bytes(size, "big") + s.to_bytes(size, "big")
        if alg.startswith("RS"):
            return self.key.sign(data, padding.PKCS1v15(), HASHES[alg[2:]]())
        if alg.startswith("PS"):
            digest = HASHES[alg[2:]]()
            return self.key.sign(data, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest)
        return self.key.sign(data)

    def der_sign(self, data: bytes) -> bytes:
        return self.key.sign(data, ec.ECDSA(hashes.SHA256()))

    def jwk(self) -> dict:
        public = self.key.public_key()
        base = {"kid": self.kid, "use": "sig", "alg": self.alg}
        if self.alg in CURVES:
            numbers = public.public_numbers()
            size = CURVES[self.alg][2]
            return {**base, "kty": "EC", "crv": CURVES[self.alg][1], "x": integer(numbers.x, size), "y": integer(numbers.y, size)}
        if self.alg.startswith(("RS", "PS")):
            numbers = public.public_numbers()
            return {**base, "kty": "RSA", "n": integer(numbers.n), "e": integer(numbers.e)}
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {**base, "kty": "OKP", "crv": "Ed448" if self.alg == "Ed448" else "Ed25519", "x": b64(raw)}


def sign_card(card: dict, header: dict, sign) -> dict:
    """`card` with a `signatures` entry over its RFC 8785 form without `signatures`, as specification 8.4.2 says."""
    body = {key: value for key, value in card.items() if key != "signatures"}
    protected = b64(json.dumps(header, separators=(",", ":")).encode())
    signing_input = protected.encode("ascii") + b"." + b64(jcs_canonicalize(body)).encode("ascii")
    return {**card, "signatures": [*card.get("signatures", []), {"protected": protected, "signature": b64(sign(signing_input))}]}


def write(name: str, document: dict) -> None:
    (OUT / name).write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in OUT.glob("*.json"):
        stale.unlink()
    trusted: list[Signer] = []
    for alg in ("ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "Ed25519"):
        signer = Signer(alg, alg.lower())
        trusted.append(signer)
        write(f"{alg.lower()}.json", sign_card(CARD, {"alg": alg, "kid": signer.kid, "typ": "JOSE"}, signer.sign))
    eddsa = Signer("EdDSA", "eddsa", "Ed25519")  # the polymorphic name RFC 9864 deprecates, with an Ed25519 key
    trusted.append(eddsa)
    write("eddsa.json", sign_card(CARD, {"alg": "EdDSA", "kid": "eddsa", "typ": "JOSE"}, eddsa.sign))
    ed448_key = Signer("Ed448", "ed448")
    trusted.append(ed448_key)
    write("ed448.json", sign_card(CARD, {"alg": "Ed448", "kid": "ed448", "typ": "JOSE"}, ed448_key.sign))
    write("jwks.json", {"keys": [signer.jwk() for signer in trusted]})

    secret = secrets.token_bytes(32)  # a shared secret, discarded
    write("hs256.json", sign_card(CARD, {"alg": "HS256", "kid": "shared", "typ": "JOSE"},
                                  lambda data: hmac.new(secret, data, hashlib.sha256).digest()))
    write("none.json", sign_card(CARD, {"alg": "none", "kid": "es256", "typ": "JOSE"}, lambda _data: b""))
    write("unknown-alg.json", sign_card(CARD, {"alg": "XX999", "kid": "es256", "typ": "JOSE"}, lambda _data: b"x" * 64))

    es256 = next(signer for signer in trusted if signer.alg == "ES256")
    header = {"alg": "ES256", "kid": "es256", "typ": "JOSE"}
    good = sign_card(CARD, header, es256.sign)
    write("es256-der.json", sign_card(CARD, header, es256.der_sign))
    tampered = copy.deepcopy(good)
    tampered["description"] = "Summarises supplier invoices for the accounts team!"
    write("es256-tampered.json", tampered)
    write("es256-reformatted.json", {key: good[key] for key in reversed(list(good))})  # members in another order
    write("es256-vendor.json", {**good, "x-vendor": {"rank": 3}})
    write("es256-legacy.json", {**good, "supportsAuthenticatedExtendedCard": True})
    write("es256-jku.json", sign_card(CARD, {**header, "jku": f"{HOST}/.well-known/jwks.json"}, es256.sign))
    write("es256-jku-off-host.json", sign_card(CARD, {**header, "jku": "https://keys.other.example/jwks.json"}, es256.sign))
    write("es256-embedded.json", sign_card(CARD, {"alg": "ES256", "kid": "inline", "jwk": es256.jwk()}, es256.sign))
    stranger = Signer("ES256", "stranger")
    write("es256-stranger.json", sign_card(CARD, {"alg": "ES256", "kid": "stranger", "typ": "JOSE"}, stranger.sign))
    write("jwks-stranger.json", {"keys": [stranger.jwk()]})
    big = copy.deepcopy(CARD)
    big["capabilities"]["extensions"] = [{"uri": "https://example.com/ext", "params": {"count": 1}}]
    signed_big = sign_card(big, header, es256.sign)
    signed_big["capabilities"]["extensions"][0]["params"]["count"] = 9007199254740993  # past 2**53: refused, not guessed
    write("es256-big-number.json", signed_big)
    twice = sign_card(sign_card(CARD, {**header, "kid": "es256"}, lambda data: b"\x01" * 64), header, es256.sign)
    write("two-signatures.json", twice)
    write("no-kid.json", sign_card(CARD, {"alg": "ES256"}, es256.sign))
    write("crit.json", sign_card(CARD, {**header, "crit": ["exp"], "exp": 1}, es256.sign))


if __name__ == "__main__":
    main()
