## What this changes

<!-- One concern per pull request. Say what changes and why, and link the issue it answers (a rule proposal is discussed in an issue first). -->

## Checklist

- [ ] A test that fails without the change, and `make check` passes.
- [ ] Fixtures are harmless and hold no real credentials and no other people's data.
- [ ] No sample, quote or result from a benchmark test set (the held-out half, the MaliciousSkillBench test split, the Trail of Bits skills).
- [ ] No field, value or exit code that a report already has is changed ([Schemas and compatibility](https://github.com/spellwarden-ai/spellwarden#schemas-and-compatibility)).
- [ ] A rule change has its README row, its row in `tests/data/released_rule_ids.json` and a line in `CHANGELOG.md`.

A security problem, or a working way past a rule, does not belong in a pull request: see [SECURITY.md](https://github.com/spellwarden-ai/spellwarden/blob/main/SECURITY.md). The rules for pull requests are in [CONTRIBUTING.md](https://github.com/spellwarden-ai/spellwarden/blob/main/CONTRIBUTING.md).
