# The specification's own sample agent cards

Each file is the JSON of "Sample Agent Card" in `docs/specification.md` of `github.com/a2aproject/A2A` at the tag and commit
named below, copied byte for byte from the fenced block (a trailing newline added). They are test inputs for claim F1 and
M2 of the phase O4 spec: what the scanner says about the protocol's own examples.

| File | Tag | Commit | Notes |
|---|---|---|---|
| `v1.0.1-sample-card.json` | `v1.0.1` | `3303592` | A 1.0 card that still carries the 0.x member `security` (an erratum of the specification) |
| `v0.3.0-sample-card.json` | `v0.3.0` | `8d57eba` | Declares `protocolVersion` "0.2.9", a version that never existed, and has `signatures` |
| `v0.2.6-sample-card.json` | `v0.2.6` | `026200b` | Declares `protocolVersion` "0.2.9" as well |
