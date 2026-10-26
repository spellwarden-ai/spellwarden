# Signed agent card fixtures

Test inputs for the signature claims of the phase O4 spec (S1 to S4, S6, S9 to S11): what the scanner says about an agent card
signed with each algorithm, and about the ways a signature can be wrong. Every card is the same small "Invoice Helper" card
(`CARD` in `scripts/make_fixture_cards.py`) with a `signatures` entry added, except where noted.

## How the files were generated

Every file here except `sdk-es256.json` and `jwks-sdk.json` was written by one run of

    uv run python scripts/make_fixture_cards.py

The script generates **throwaway keys on every run**, signs the cards, writes the cards and the **public** key sets only, and
discards the private keys when it ends. No private key is committed (claim S6: `test_s6_no_file_under_fixtures_or_tests_holds_a_jwk_private_member`
fails if any JWK private member appears under `fixtures/` or `tests/`). The directory is regenerated as a whole, never edited by
hand: the script deletes every `*.json` here before it writes, so running it also removes the SDK card; run
`scripts/record_sdk_card.py` again after it, then the tests that read this directory.

The signing input is the RFC 7515 one: `protected + "." + base64url(RFC 8785 canonical form of the card without "signatures")`.

## Key files

| File | Content |
| --- | --- |
| `jwks.json` | The trusted key file of the fixtures (`a2a.keys`): public keys `es256`, `es384`, `es512`, `rs256`, `rs384`, `rs512`, `ps256`, `ps384`, `ps512`, `ed25519`, `eddsa` (an Ed25519 key published as `EdDSA`) and `ed448`. |
| `jwks-stranger.json` | The one public key (`stranger`) of the signer that is not in `jwks.json`; used with `es256-stranger.json`. |
| `jwks-sdk.json` | The public key (`sdk-key`, P-256) of the card signed by `a2a-sdk`; used with `sdk-es256.json`. |

## Cards signed with one algorithm (kid equals the lower-case algorithm, key in `jwks.json`)

`es256.json`, `es384.json`, `es512.json`, `rs256.json`, `rs384.json`, `rs512.json`, `ps256.json`, `ps384.json`, `ps512.json`,
`ed25519.json` (all verify), `eddsa.json` (algorithm name `EdDSA` with an Ed25519 key, the polymorphic name RFC 9864 deprecates)
and `ed448.json` (verifies nothing: the scanner reports `unverifiable_alg`, Ed448 is not verified by this release).

## Cards signed wrongly or differently

| File | What is different |
| --- | --- |
| `hs256.json` | HMAC with a discarded shared secret (`kid` `shared`): a shared-secret algorithm, reported `unverifiable_alg`. |
| `none.json` | `alg: none`, empty signature: `refused_alg`. |
| `unknown-alg.json` | `alg: XX999`: an algorithm nobody defines, `refused_alg`. |
| `es256-der.json` | ES256 signature in DER form instead of the fixed-width r and s of RFC 7518: `malformed`. |
| `es256-tampered.json` | The signed card, then `description` changed by one character: `bad_signature`. |
| `es256-reformatted.json` | The signed card with its members in reverse order: must still verify (RFC 8785 sorts members). |
| `es256-vendor.json` | The signed card plus an unsigned `x-vendor` member: verifies, with the member in `unsigned_members`. |
| `es256-legacy.json` | The signed card plus an unsigned legacy member (`supportsAuthenticatedExtendedCard`): unsigned legacy members are never allowed. |
| `es256-jku.json` | Protected header `jku` on the card's own host (`https://agent.example.com/.well-known/jwks.json`). |
| `es256-jku-off-host.json` | Protected header `jku` on another host (`https://keys.other.example/jwks.json`). |
| `es256-embedded.json` | Protected header carries the public key as `jwk` (kid `inline`) instead of naming a trusted one. |
| `es256-stranger.json` | Signed by `stranger`, whose key is only in `jwks-stranger.json`: `untrusted_key` against `jwks.json`. |
| `es256-big-number.json` | Signed with `capabilities.extensions[0].params.count` of 1, then changed to 9007199254740993 (past 2**53): `malformed`, not guessed. |
| `two-signatures.json` | Two entries in `signatures`: the first a filler (`0x01` bytes) with the same header (`bad_signature`), the second a valid ES256 signature (`verified`). |
| `no-kid.json` | Protected header without `kid`: `malformed`. |
| `crit.json` | Protected header with `crit: ["exp"]` and `exp: 1`: a critical header the scanner does not understand, `malformed`. |

## `sdk-es256.json`: a card signed by `a2a-sdk`

Not written by `make_fixture_cards.py`. It was recorded **once, on 2026-10-26**, by the then unpinned command

    uv run --no-project --with "a2a-sdk[signing]==1.2.3" --with cryptography python scripts/record_sdk_card.py

To reproduce it, pin `cryptography` as the script's docstring now does:

    uv run --no-project --with "a2a-sdk[signing]==1.2.3" --with "cryptography==50.0.2" python scripts/record_sdk_card.py

which builds the card as protobuf messages, signs it with `a2a.utils.signing.create_agent_card_signer` (algorithm **ES256**,
`kid` `sdk-key`, a throwaway P-256 key; only the public key went to `jwks-sdk.json`), serialises it with `MessageToDict`, then
adds an empty skill `examples` list and `"pkceRequired": false`, which a hand-written card often carries and a protobuf
serialiser never writes. The SDK removes empty values (`_clean_empty`) before signing, so it signs the card without
`capabilities: {}`, which the specification's presence rules keep: the signature therefore verifies over the **`sdk`** payload
form only (not `spec`).

### Versions

Resolved by the pinned command, read back with `importlib.metadata` in a scratch environment on Python 3.14.6 on 2026-10-26
after the recording (its two pins are fixed by the command; the others are what uv resolved that day, and are not pinned):

| Package | Version | Package | Version |
| --- | --- | --- | --- |
| a2a-sdk | 1.2.3 | json-rpc | 1.15.0 |
| cryptography | 50.0.2 | opentelemetry-api | 1.45.1 |
| annotated-types | 0.8.0 | packaging | 26.3 |
| anyio | 4.15.1 | proto-plus | 1.29.0 |
| certifi | 2026.10.23 | protobuf | 7.36.2 |
| cffi | 2.1.1 | pyasn1 | 0.6.4 |
| charset-normalizer | 3.5.2 | pyasn1_modules | 0.4.2 |
| google-api-core | 2.43.0 | pycparser | 3.12 |
| google-auth | 2.62.0 | pydantic | 2.14.1 |
| googleapis-common-protos | 1.76.0 | pydantic_core | 2.50.1 |
| h11 | 0.16.0 | PyJWT | 2.15.1 |
| httpcore | 1.0.9 | requests | 2.34.2 |
| httpx | 0.28.1 | typing-inspection | 0.4.4 |
| idna | 3.20 | typing_extensions | 4.16.0 |
| | | urllib3 | 2.8.0 |

Limit of this record: the recording run did not save its own environment listing, so these versions are a re-resolution of the
command made afterwards, not a capture of the original. Only `a2a-sdk` 1.2.3 is certain for the original run, which took
whatever `cryptography` uv resolved that day (50.0.2, the version the project lock holds, is the likely one but was not recorded). The fixture does not depend on the others: a test reads `sdk-es256.json` and
`jwks-sdk.json` as files, and nothing re-signs.
