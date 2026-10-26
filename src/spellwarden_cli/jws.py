"""Key sets and signature verification for A2A agent cards (O4 spec 6.6). The only module of the scanner that imports
`cryptography`: `tests/test_network_boundary.py` walks the import graph the way it does for the network modules. It exposes
`load_jwks`, `candidates` and `verify` and nothing that signs.

A key set is read with the strict JSON reader, at most 64 KiB and 20 keys. A key is kept only when it has a `kid` (keys are
matched to signatures by `kid` alone) and no private member (a published key set must not hold one); an entry the scanner
cannot use (a key type or curve it does not know, numbers that are not a point or a modulus) is counted and left out.
Verification is RFC 7515 over the signing input `spellwarden_scan.a2a_signing` builds: ECDSA with the fixed-length `R || S`
of RFC 7518 3.4, RSASSA-PKCS1-v1_5 and RSASSA-PSS (salt as long as the hash, RFC 7518 3.5) and Ed25519 (RFC 8037)."""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from spellwarden_scan._json import Obj, Refused, load_json
from spellwarden_scan.a2a_signing import b64url_decode

KEYS_MAX_BYTES = 64 * 1024
KEYS_MAX = 20
RSA_MIN_BITS = 2048
PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
VERIFIED_ALGS = ("ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "Ed25519", "EdDSA")
SHARED_SECRET_ALGS = ("HS256", "HS384", "HS512")
_CURVES = {"P-256": (ec.SECP256R1, 32), "P-384": (ec.SECP384R1, 48), "P-521": (ec.SECP521R1, 66)}
_EC_ALG = {"ES256": ("P-256", hashes.SHA256), "ES384": ("P-384", hashes.SHA384), "ES512": ("P-521", hashes.SHA512)}
_HASH = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
DER_DETAIL = "DER-encoded ECDSA signature; JWS needs the fixed-length R || S form (RFC 7518 3.4)"


class JwksError(ValueError):
    """The bytes are not a key set: `args[0]` is a document error code of `_json` or `not_a_key_set` or `too_many_keys`."""


@dataclass(frozen=True)
class Jwk:
    """A public key of a key set. `public` is the `cryptography` key, None for a curve this release does not verify
    (Ed448). `bits` is the modulus size of an RSA key."""
    kid: str
    kty: str
    crv: str | None
    use: str | None
    key_ops: tuple[str, ...] | None
    alg: str | None
    public: object | None
    bits: int | None = None


@dataclass(frozen=True)
class KeySet:
    """The usable keys and what was left out: `without_kid` keys (never used), `private` keys with a private member (dropped)
    and `unusable` entries that are not a key this scanner can use."""
    keys: tuple[Jwk, ...]
    without_kid: int = 0
    private: int = 0
    unusable: int = 0


def _number(member: object) -> int | None:
    raw = b64url_decode(member) if isinstance(member, str) and member else None
    return int.from_bytes(raw, "big") if raw else None


def _key(entry: Obj) -> Jwk | None:
    kid, kty, crv = entry.get("kid"), entry.get("kty"), entry.get("crv")
    ops = entry.get("key_ops")
    common = {"kid": kid, "kty": kty, "crv": crv if isinstance(crv, str) else None,
              "use": entry.get("use") if isinstance(entry.get("use"), str) else None,
              "key_ops": tuple(ops) if isinstance(ops, list) and all(isinstance(op, str) for op in ops) else None,
              "alg": entry.get("alg") if isinstance(entry.get("alg"), str) else None}
    try:
        if kty == "EC" and crv in _CURVES:
            x, y = _number(entry.get("x")), _number(entry.get("y"))
            if x is None or y is None:
                return None
            public = ec.EllipticCurvePublicNumbers(x, y, _CURVES[crv][0]()).public_key()
            return Jwk(public=public, **common)
        if kty == "RSA":
            n, e = _number(entry.get("n")), _number(entry.get("e"))
            if n is None or e is None:
                return None
            return Jwk(public=rsa.RSAPublicNumbers(e, n).public_key(), bits=n.bit_length(), **common)
        if kty == "OKP" and crv == "Ed25519":
            raw = b64url_decode(entry.get("x")) if isinstance(entry.get("x"), str) else None
            return Jwk(public=ed25519.Ed25519PublicKey.from_public_bytes(raw), **common) if raw is not None else None
        if kty == "OKP" and crv == "Ed448":
            return Jwk(public=None, **common)  # kept so that the outcome can say Ed448 is not verified by this release
    except (ValueError, TypeError):
        return None
    return None


def load_jwks(content: bytes, *, max_keys: int = KEYS_MAX) -> KeySet:
    """The key set in `content`. Raises `JwksError` when it is not a JWKS (`{"keys": [...]}`), is over 64 KiB or lists more
    than `max_keys` keys."""
    try:
        root = load_json(content, strict=True, max_depth=8, max_bytes=KEYS_MAX_BYTES)
    except Refused as refused:
        raise JwksError(refused.code) from None
    entries = root.get("keys") if isinstance(root, Obj) else None
    if not isinstance(entries, list):
        raise JwksError("not_a_key_set")
    if len(entries) > max_keys:
        raise JwksError("too_many_keys")
    keys: list[Jwk] = []
    without_kid = private = unusable = 0
    for entry in entries:
        if not isinstance(entry, Obj):
            unusable += 1
        elif any(member in entry for member in PRIVATE_MEMBERS):
            private += 1
        elif not isinstance(entry.get("kid"), str) or not entry["kid"]:
            without_kid += 1
        else:
            key = _key(entry)
            if key is None:
                unusable += 1
            else:
                keys.append(key)
    return KeySet(tuple(keys), without_kid, private, unusable)


def candidates(keyset: KeySet, alg: str, kid: str) -> tuple[Jwk, ...]:
    """The keys that may verify a signature with `alg` and `kid` (6.6 step 2): the `kid` matches, the key type and curve fit
    the algorithm, an RSA modulus has at least 2048 bits, `use` is `sig` and `key_ops` holds `verify` when present, and a
    key `alg` equals the header's. For `EdDSA` an Ed448 key is a candidate too (it is reported, not verified)."""
    found = []
    for key in keyset.keys:
        if key.kid != kid or (key.use is not None and key.use != "sig") or (key.alg is not None and key.alg != alg):
            continue
        if key.key_ops is not None and "verify" not in key.key_ops:
            continue
        if alg in _EC_ALG:
            fits = key.kty == "EC" and key.crv == _EC_ALG[alg][0]
        elif alg.startswith(("RS", "PS")):
            fits = key.kty == "RSA" and (key.bits or 0) >= RSA_MIN_BITS
        elif alg == "Ed25519":
            fits = key.kty == "OKP" and key.crv == "Ed25519"
        elif alg == "EdDSA":
            fits = key.kty == "OKP" and key.crv in ("Ed25519", "Ed448")
        else:
            fits = False
        if fits:
            found.append(key)
    return tuple(found)


def ecdsa_problem(alg: str, signature: bytes) -> str | None:
    """Why `signature` cannot be an ECDSA signature of `alg` in the JWS form, or None: the fixed length is twice the coordinate
    size; a DER `SEQUENCE` of two integers (what cloud KMS and HSM signing APIs return) is named as such."""
    if alg not in _EC_ALG:
        return None
    size = _CURVES[_EC_ALG[alg][0]][1]
    if len(signature) == 2 * size:
        return None
    if _is_der_pair(signature):
        return DER_DETAIL
    return f"ECDSA signature of {len(signature)} bytes; {alg} needs {2 * size} bytes, R || S (RFC 7518 3.4)"


def _is_der_pair(data: bytes) -> bool:
    """A DER `SEQUENCE` that holds exactly two `INTEGER`s and nothing else."""
    if len(data) < 8 or data[0] != 0x30:
        return False
    length, offset = data[1], 2
    if length & 0x80:
        count = length & 0x7F
        if count not in (1, 2) or len(data) < 2 + count:
            return False
        length, offset = int.from_bytes(data[2:2 + count], "big"), 2 + count
    if offset + length != len(data):
        return False
    for _ in range(2):
        if offset + 2 > len(data) or data[offset] != 0x02:
            return False
        size = data[offset + 1]
        if size & 0x80 or size == 0:
            return False
        offset += 2 + size
    return offset == len(data)


def verify(alg: str, key: Jwk, signing_input: bytes, signature: bytes) -> bool:
    """Whether `signature` is `alg` over `signing_input` by `key`. Never raises: a key of the wrong type, a signature of the
    wrong length or a failed check is False. `Ed448` and the `HS*` algorithms are never verified here."""
    public = key.public
    try:
        if alg in _EC_ALG:
            curve, digest = _EC_ALG[alg]
            if not isinstance(public, ec.EllipticCurvePublicKey) or ecdsa_problem(alg, signature) is not None:
                return False
            size = _CURVES[curve][1]
            der = encode_dss_signature(int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big"))
            public.verify(der, signing_input, ec.ECDSA(digest()))
        elif alg.startswith("RS") and alg[2:] in _HASH:
            if not isinstance(public, rsa.RSAPublicKey):
                return False
            public.verify(signature, signing_input, padding.PKCS1v15(), _HASH[alg[2:]]())
        elif alg.startswith("PS") and alg[2:] in _HASH:
            if not isinstance(public, rsa.RSAPublicKey):
                return False
            digest = _HASH[alg[2:]]()
            public.verify(signature, signing_input, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest)
        elif alg in ("Ed25519", "EdDSA"):
            if not isinstance(public, ed25519.Ed25519PublicKey):
                return False
            public.verify(signature, signing_input)
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
