# Community corpus

Never run, install, open in an agent or follow a link of any file in this directory. Every sample here came from a report by a
person outside the project, and a maintainer made it safe to publish, but a person read it and no tool ran it. Read it as text, as
the benchmark's responsible-use terms ask of everyone.

This directory holds the samples of accepted reports: a miss (content that a rule should have read and did not) or a false positive
(harmless content that a rule reported). Each accepted report is one case, one directory, and each case is a test. The corpus is not a
test set of the rule benchmark and not a tuning set: it is never used for a claim about rates. The benchmark reads it in memory and
shows a count of its own, apart from its fixed sets ([benchmarks/README.md](../../benchmarks/README.md)).

## A case

```
fixtures/community/
  README.md           this page
  RETIRED.json        ids of cases removed on a reporter's request (an array); an id is never reused
  COM-0001/
    record.json       the record
    files/            the defanged sample, with paths as in a project (SKILL.md, scripts/run.sh, .mcp.json ...)
```

`record.json` holds exactly these members, in UTF-8 with sorted keys, a two-space indent and a final newline:

| Member | Meaning |
|---|---|
| `id` | `COM-` and four digits, the name of the directory |
| `kind` | `miss` or `false_positive` |
| `rule` | the rule the case concerns, a rule of the areas skill, config or a2a (a scan of files cannot raise the others) |
| `kept_hosts` | real host names the maintainer kept because the rule judges the host itself; usually empty |
| `reported_against` | `{"scanner": "X.Y.Z", "rules": "YYYY.MM.N"}`, the versions the reporter used |
| `outcome` | `open` (accepted, not yet fixed) or `fixed` |
| `fixed_in` | the release whose rules first behave as the record says; null while `open` |
| `credit` | the name the reporter asked to be credited by, or null |
| `date` | the day a maintainer accepted the case |
| `issue` | the issue number, or null for a case that did not start in a public issue |

The record never holds a handle, an e-mail address, the issue text, the command the reporter used or where the sample came from.

A miss passes when a scan of `files/` has at least one finding of its rule. A false positive passes when the scan has none of
its rule. Findings of other rules never matter. While a case is `open` its test is an expected failure, and the build fails on the
day the case passes, until the record says `fixed` and the CHANGELOG section of `fixed_in` holds the case's line (`Community report
COM-0001 (SW-SKL-009, missed detection), reported by Name.`, with the credit only when the record has one).

A sample has at most 20 files of at most 64 KiB each and 256 KiB in all, every file is UTF-8 text, every host in a URL or an e-mail
address is a reserved name (`example.com`, a name under `.example`, `.invalid` or `.test`, or an address of 192.0.2.0/24) or is
named in `kept_hosts`, and no text has the shape of a credential. `tests/test_community_corpus.py` checks every case on every build.

## What a maintainer does

The first answer to a report is due within five working days. An answer is an acceptance, a request for more, or a written reason.

1. Read the issue as text. Never run, install, open in an agent or follow a link of the sample.
2. Check by reading that the sample is safe: every host reserved (or kept with `--keep-host` only when the rule judges that host and
   the URL's path is a harmless one), nothing that runs when opened, no personal data, no credential-shaped text. If the sample is a
   working attack, or publishing it would help someone hide content from the scanner before a fix, do not discuss it in the public
   issue: ask the reporter to use private reporting, close the issue with a pointer and edit the public text away.
3. Check where the sample comes from. A sample from a benchmark or its test sets is not accepted: answer, "This sample comes from a
   set the benchmark keeps as a test set, so a rule change made for it would break the held-out promise in CONTRIBUTING.md. Describe
   the technique in words and I will look at that." No fixture is added. Do not open test-set samples to compare: the script's hash
   check and the reporter's answer are the means, and a doubtful case is declined, not investigated by reading the set.
4. Judge it. A false positive is accepted when the rule's own page and fix sentence do not describe the content. A miss is accepted
   when a rule should read this content; a new pattern that no rule is meant to read goes to the rule proposal path of
   `CONTRIBUTING.md`. A report about an `SW-MCP` or `SW-REG` rule, or an A2A finding that only `--probe` gives, is judged the same
   way but never becomes a case: answer in writing, and the rule change brings its own fixture in its own pull request. A report
   that the current release already handles is answered in writing with the release that changed it. A report that is not accepted
   is answered with a written reason that names the rule and what it does, in plain English, and the issue is closed.
5. Accepted: `gh issue view N --json body --jq .body > body.md`, then
   `uv run python scripts/add_community_case.py body.md --kind miss --rule SW-SKL-009 --issue N` (`--kind false-positive` for a false
   alarm; `--keep-host HOST` for a host the rule judges; `--dry-run` runs every check and writes nothing). Open a pull request for
   the case alone and comment on the issue with the case id and what happens next.
6. When the rules change for it, in the pull request that changes the rule and raises the version: set the record to `fixed` with
   `fixed_in` set to that version, add the case's line to that version's CHANGELOG section, and say in the issue which release
   carries it.
7. Credit: use the record's `credit` and nothing else. A reporter who wrote no name is never named, also not in the closing comment.

## Withdrawals

A bypass that came through private reporting can join the corpus only after the release that fixes it is published and the
reporter agrees in writing. The maintainer writes the same headings into a file, runs the script without `--issue` and with
`--outcome fixed --fixed-in X.Y.Z`, and the record's `issue` is null. In the same pull request the maintainer adds the case's line
to the CHANGELOG section of `fixed_in` on the main branch, so that the test of every fixed case holds; this and the removal of a
name are the only edits of a released CHANGELOG section. The maintainer also adds the line to the GitHub release notes and to the
release thread of `fixed_in` by hand, since neither is built again.

A reporter who asks for their name to be removed: in one pull request the maintainer sets the record's `credit` to null and rewrites
every CHANGELOG line of the case on the main branch to its form without `, reported by ...`, and edits the name out of the GitHub
release notes and the release thread by hand. Released packages and the history of the repository still hold the name.

A reporter who asks for the case to be removed: the same pull request also removes the directory and adds its id to
`RETIRED.json`. The sample stays in earlier releases and in the history, under the licence it was published under.
