# Contributing

Thank you for reading this before you open an issue or a pull request. The scanner is Apache-2.0, and reports, samples and rules from people who use it make it better.

A security problem does not belong in a public issue: see [SECURITY.md](SECURITY.md). Everyone who takes part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Report a miss, a false alarm or a new pattern

Open an issue with one of the three forms ([choose one](https://github.com/spellwarden-ai/spellwarden/issues/new/choose)):

- **False positive**: a rule reported content that is not a problem. The form asks for the rule id, why it is not a problem and the sample.
- **Missed detection**: nothing was reported on content that a rule should read. The form asks for what you expected to be found and the sample.
- **New rule proposal**: a pattern that no rule reads today. [Propose a rule](#propose-a-rule) says what the form asks.

Every form asks for the scanner version and the rules version (`spellwarden version` prints both), the command and the settings you used, the name of the file, the smallest sample that shows it, where the sample comes from, a name to credit if you want one, and a box that says you may publish the sample under the Apache License 2.0, the licence of this repository. An issue is public, so the form says how to make a sample safe to publish. A sample that comes from a benchmark's test sets is not accepted, so that the test sets stay clean: describe the technique in words instead.

Reports are unpaid. You are named, in the CHANGELOG and in the corpus record, only if you write a name in the form. If you later ask, a maintainer removes it from the main branch; released packages and the history of the repository still hold it.

A working way past a rule, or a method that would help someone hide content from the scanner before a fix is released, goes to private reporting and not to an issue: see [SECURITY.md](SECURITY.md). You get a first answer within five working days, whichever way the report comes in. A first answer is an acceptance, a request for more, or a written reason; it is not a promise of a fix date.

An accepted report becomes a test: its sample goes into `fixtures/community/` ([how a case works](fixtures/community/README.md)), and when a rule is wrong the rule changes in a pull request of its own, with a line in the CHANGELOG. A report that is not accepted gets a written reason that names the rule and what it does, in plain English. Questions that are not a bug go to [Discussions](https://github.com/spellwarden-ai/spellwarden/discussions), where every release has a thread that lists the rules that changed.

Until a rule changes, a false positive can be accepted in the baseline file with a reason and an end date: [how to handle false positives](https://spellwarden.ai/docs/false-positives?utm_source=github&utm_medium=readme&utm_campaign=contributing).

## Propose a rule

Open an issue before you write code, so that the idea can be discussed first. Say:

- what the rule detects, in one sentence, and which kind of content it reads (a skill, an MCP client configuration, Claude Code settings or hooks, a plugin marketplace, an instruction file, an A2A agent card or a probed MCP server);
- a public example of the problem, or a sample you wrote;
- why no rule in [the rules table](README.md#the-rules) finds it today;
- which harmless content the pattern would also match, as far as you checked. A rule that fires on most harmless content is not merged as it is.

A rule that is merged has:

- an id that the maintainers assign. Unused numbers stay reserved, and an id is never reused or renamed, also after its rule is retired;
- a title, a severity and its mappings to the OWASP lists, NIST SP 800-53 and MITRE ATLAS, given to `make_rule` in `src/spellwarden_scan/rules/`;
- a fix sentence beside its title: one sentence that tells the reader what to do, at most 200 characters, opening with one of the verbs of `FIX_VERBS`. `make_rule` refuses a sentence that breaks the form, and `RuleSet.baseline()` refuses a rule without one;
- a fixture it must find and a fixture it must not find. `tests/test_fixture_coverage.py` fails the build without both;
- its row in the rules table of the README, its row in `tests/data/released_rule_ids.json` with the release it first ships in, and a line in `CHANGELOG.md`.

A change to what a rule detects raises the rules version and the scanner's minor version. The maintainers make the release.

A rule that is not a skill rule is measured on a set of its own before it is released, by the method in [benchmarks/README.md](benchmarks/README.md#rules-measured-on-a-set-of-their-own), and a rule whose precision does not meet the bar is not released.

Keep the benchmark's test sets out of rule work. A rule may be worked on with the tuning half of the rule benchmark, the repository's fixtures and samples people report. The same holds for the normalisation steps the skill rules read through and for the choice of which rules read through them. The held-out half, the MaliciousSkillBench test split and the Trail of Bits skills are test sets: a pull request that changes a rule does not cite, quote or add as a fixture any sample of a test set, and does not give a test-set result as its reason. Maintainers do not open test-set samples when working on a rule. [benchmarks/README.md](benchmarks/README.md) describes the sets, and the published history shows every release's test-set rates beside its tuning-set rates. The community corpus in `fixtures/community/` is not a test set: it holds samples that people reported and rule changes were made for, so it is never used for a claim about rates, and a sample of a test set is not accepted into it.

## Work on the code

You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).

```
make check        # ruff, pytest and the package build: the gate for every pull request
make check-node   # the Zuplo export's guard and check script; needs Node 24 or newer
```

Three tests hold the design, and a pull request must keep them green:

- `tests/test_pure.py`: the engine, `spellwarden_scan`, never reaches for the network, the file system or the environment. You hand it bytes and it hands back findings.
- `tests/test_network_boundary.py`: in the command, `spellwarden_cli`, only the named modules may reach the network.
- `tests/test_fixture_coverage.py`: every rule has a fixture it finds and one it does not.

Every test runs offline. HTTP exchanges are recorded under `tests/recorded/`, and the tests make the git repositories they need.

The scanner's limits follow one rule, which a change must keep: content the scanner leaves unread never looks like a pass. The README explains it under [Limits](README.md#limits).

## Pull requests

- One concern in each pull request, with a test that fails without the change.
- The checks run on Linux and Windows and on Python 3.11, 3.12 and 3.13.
- Keep fixtures harmless and free of real credentials and of other people's data.
- Do not change a field, a value or an exit code that a report already has: the README's [Schemas and compatibility](README.md#schemas-and-compatibility) says what counts as a breaking change.

## Licence

Your contribution is under the Apache License 2.0, the licence of this repository, as its section 5 says.
