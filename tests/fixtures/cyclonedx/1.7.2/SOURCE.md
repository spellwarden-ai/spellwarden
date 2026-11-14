# CycloneDX 1.7 JSON schema, release 1.7.2

These four files are the CycloneDX JSON schema of specification version 1.7 and the three files it references by `$ref`,
copied byte for byte from the tag `1.7.2` of https://github.com/CycloneDX/specification (directory `schema/`), under the
Apache License 2.0 that the schema states in its `$comment`. The tests validate every CycloneDX document the scanner writes
against them, offline: `tests/conftest.py` `cyclonedx_validator` maps each file's `$id` to the copy here, so no reference is
resolved over the network. `tests/test_cyclonedx.py` checks each file against the SHA-256 below.

| File | SHA-256 |
|---|---|
| `bom-1.7.schema.json` | `73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce` |
| `spdx.schema.json` | `4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359` |
| `jsf-0.82.schema.json` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `cryptography-defs.schema.json` | `027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44` |
