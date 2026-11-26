# Rule benchmark

Never run, install or follow a link of any sample. Many of the samples are malicious skills. The benchmark only reads them, in
memory, and so must you. This follows MaliciousSkillBench's responsible-use terms: use the samples for defensive security
research and detection evaluation, in isolated, non-production analysis, and "Do not execute untrusted Skills, follow embedded
URLs, or install companion packages".

This directory measures what Spellwarden's rules find on fixed public sets of malicious and harmless (benign) skills. The
release workflow runs it again for every release, on Linux and Windows, against the wheel it built. The table is in
[RESULTS.md](RESULTS.md), and the README's section "Measured rates" shows the newest release.

## What it measures

- Rules only. No model is called: the model-assisted analyzer (`--analyze`) is not part of this table.
- The 20 skill rules (SW-SKL) on skill packages. A skill scan cannot fire the other 48 rules (SW-MCP, SW-CFG, SW-REG, SW-A2A),
  which judge MCP servers, configuration, the registry gate and A2A agent cards, so the table lists them as not measured here
  and never shows them as 0%.
- Each rule at its own severity, the scanner's behaviour without a preset (`balanced`).
- Two lines, the ones `--fail-on` and the presets use: medium or above, and high or above. A skill is found at a line when the
  rules report at least one finding at or above it.
- The detection rate on malicious skills and the false-positive rate on harmless skills, each with its counts and its 95% Wilson
  interval, per stratum and per set, and the macro-F1 that MaliciousSkillBench recommends for a set with both labels.
- A package that holds several skills is one item. It is found when any of its skills is found.
- A skill the scanner could not read whole (a front matter past the 1.19.0 limits, for example) makes its item "not read
  whole". Such an item is counted and named apart, and it is never counted as found or as clean.
- The ids of the malicious skills the rules missed, at each line. Harmless skills the rules flagged are counted, not named.
- Since 1.22.0, disguised versions of each malicious skill, one per technique, with the rules on the text as written and after
  normalisation ([Disguised samples](#disguised-samples)).
- A separate count of the community corpus, never mixed into the sets ([The community corpus](#the-community-corpus)).

The benchmark measures the scanner's library (`spellwarden_scan.scan_skill_package`) on each skill in memory. It does not run
`spellwarden scan` on a directory, so it measures the skill rules on skill packages and nothing about how the command finds
files.

## Run it yourself

With a released version (replace X.Y.Z), from a checkout of this repository:

```
python -m venv .bench
.bench/bin/pip install "spellwarden==X.Y.Z"
.bench/bin/pip install --require-hashes -r benchmarks/requirements.txt
.bench/bin/python benchmarks/rule_benchmark.py run
```

On Windows the interpreter is `.bench\Scripts\python.exe` and pip is `.bench\Scripts\pip.exe`. With uv:

```
uv run --no-project --with "spellwarden==X.Y.Z" --with-requirements benchmarks/requirements.txt python benchmarks/rule_benchmark.py run
```

A checkout of the tag `vX.Y.Z` gives the entry recorded for X.Y.Z. In a development checkout, `make benchmark` runs it with the
checkout's own scanner.

The first run fetches about 45 MB from GitHub and Hugging Face. Every object is checked against the sha256 in `manifest.json`
before it is used, and content that differs is refused. The objects are kept as fetched (compressed archives and files named
by their hash) in a cache outside the repository: `--cache DIR`, else the variable `SPELLWARDEN_BENCHMARK_CACHE`, else
`%LOCALAPPDATA%\spellwarden\benchmark-cache` on Windows and `~/.cache/spellwarden/benchmark-cache` (or
`$XDG_CACHE_HOME/spellwarden/benchmark-cache`) elsewhere. Later runs read the cache and need no network; `--offline` makes sure
of it. A cache inside the repository checkout is refused. No sample is ever written to disk as a file tree, printed or logged.

`run --entry-out FILE` writes the measured entry, which holds the ids of the missed malicious skills. Exit codes: 0 when the
table was produced, 1 when `--verify` or a check found a difference, 2 when nothing was measured (a fetch failed, a sample
changed, the manifest is broken or missing, the installed version is not the expected one).

## The sets

| Set | Role | Stratum | Label | Skills | Built from |
|---|---|---|---|---|---|
| `msb-test` | test | `skillharm` | malicious | 728 | SkillHarm packages (SRC009) |
| | | `skillfortifybench-malicious` | malicious | 90 | SkillFortifyBench artifacts (SRC012) |
| | | `atr-malicious` | malicious | 21 | ATR artifacts (SRC011) |
| | | `atr-benign` | harmless | 455 | MaliciousSkillBench primary table, skill text |
| | | `skillfortifybench-benign` | harmless | 90 | MaliciousSkillBench primary table, skill text |
| `held-out` | test | `wild-liu` | malicious | 38 | MaliciousAgentSkillsBench packages (SRC002) |
| | | `wild-skillleak` | malicious | 15 | SkillLeakBench packages (SRC004); one item holds three skills |
| | | `benign-wild` | harmless | 110 | public skills, fetched from each owner's repository |
| `tuning` | tuning | `wild-liu` | malicious | 38 | MaliciousAgentSkillsBench packages (SRC002) |
| | | `wild-skillleak` | malicious | 16 | SkillLeakBench packages (SRC004) |
| | | `wild-amos` | malicious | 7 | Agent Skill Malware artifacts (SRC005) |
| | | `benign-wild` | harmless | 109 | public skills, fetched from each owner's repository |
| `trailofbits` | test, shown skill by skill | `tob` | malicious | 4 | `trailofbits/overtly-malicious-skills` |

These are the counts of the frozen sets. A sample that can no longer be fetched is listed in the `excluded` list of
`manifest.json` with its set, stratum, reason and date, and the counts above then drop by that many.

`msb-test` is the source-disjoint test split of MaliciousSkillBench, the split that other scanners publish their rates on.
`held-out` and `tuning` are the two halves of Spellwarden's own labelled set. "Benign" is the source's label: for `benign-wild`
it is the Liu et al. snapshot, which lists these skills as `safe`.

## Sources and licences

Checked on 2026-11-23 through the GitHub and Hugging Face APIs and the pages named. Nothing below is copied into this
repository or attached to a release: `manifest.json` holds a pointer and a sha256 for every object and file, and each person
fetches from the owner. That avoids relicensing anyone's work.

| Source | What is fetched | Pin | Licence and terms |
|---|---|---|---|
| [MaliciousSkillBench](https://github.com/protectskills/MaliciousSkillBench) | `packages/SRC002_packages.tar.gz`, `SRC004_packages.tar.gz`, `SRC005_artifacts.tar.gz`, `SRC009_packages.tar.gz`, `SRC011_artifacts.tar.gz`, `SRC012_artifacts.tar.gz` | commit `893afd609be22a2dfac5a2b94bbebb4eeb99515e` | Apache-2.0 for code, CC BY 4.0 for metadata, annotations and split manifests; "Third-party Skill artifacts retain their respective upstream terms and are not relicensed" (`README.md`, `THIRD_PARTY_NOTICE.md`); `RESPONSIBLE_USE.md` as quoted at the top of this file |
| [MaliciousSkillBench on Hugging Face](https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench) | `primary.parquet` (the skill text of the harmless rows of the test split) | revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90` | CC BY 4.0, not gated |
| Public skills of `benign-wild` | each file of the skill from `raw.githubusercontent.com` | the commit recorded when the skill was collected | each repository's own licence, or none; `manifest.json` records the SPDX id GitHub reported (`licence`, for information) |
| [trailofbits/overtly-malicious-skills](https://github.com/trailofbits/overtly-malicious-skills) | each file of its four skills from `raw.githubusercontent.com` | commit `4ffbf9461ef0505f9ce76a0d3694a18ec33ea531` | no licence file; its README says "FOR SECURITY RESEARCH PURPOSES ONLY. DO NOT INSTALL THEM." |

The packages of MaliciousSkillBench come from these benchmarks, which we credit here:

- SRC002: MaliciousAgentSkillsBench, Liu et al., [arXiv 2602.06547](https://arxiv.org/abs/2602.06547), Hugging Face
  `ProtectSkills/MaliciousAgentSkillsBench`, MIT.
- SRC004: SkillLeakBench, [arXiv 2604.03070](https://arxiv.org/abs/2604.03070), Hugging Face `AgentSkillPrivacy/SkillLeakBench`,
  MIT.
- SRC005: Agent Skill Malware, Hugging Face `yoonholee/agent-skill-malware`, MIT.
- SRC009: SkillHarm, [arXiv 2606.02540](https://arxiv.org/abs/2606.02540), Hugging Face `osunlp/SkillHarm`, CC BY 4.0.
- SRC011: ATR Skill-Security Benchmark, Hugging Face `Agent-Threat-Rule/atr-skill-benchmark` (revision
  `7219b10d2ac077e3db8c87d43d653a67935cdb5d`), MIT.
- SRC012: SkillFortifyBench, [arXiv 2603.00195](https://arxiv.org/abs/2603.00195), GitHub `qualixar/skillfortifybench`, MIT.

The harmless public skills and their `safe` label come from the Liu et al. snapshot, Hugging Face
`ProtectSkills/MaliciousAgentSkillsBench` at revision `422bf3401845f6c1378bf4599dc2cdb3451978cf` (`skills_dataset.csv`, MIT, not
gated). The benchmark takes from it only which public skills it lists as `safe`; `manifest.json` holds each skill's registry
reference (`ref`), never a row of the file.

Checked and not used:

- SkillSieve ([arXiv 2604.06550](https://arxiv.org/abs/2604.06550)) says its code, labels and results are open-sourced, but on
  2026-11-23 neither the paper nor its HTML version named a location, and only labels, not skill texts, are said to be
  released. With no pinned public location there is nothing to fetch.
- The ATR jsonl file itself. Every ATR sample the table uses is in the MaliciousSkillBench test split and is fetched from there.

## The ATR samples are measured once

ATR samples were in both test sets: 260 of the held-out half's ATR samples are rows of the MaliciousSkillBench test split, and 13
more were only in the held-out half. So that no sample counts twice, the held-out half here holds no ATR sample: all 273 left
it, and ATR is measured once, through the `atr-malicious` and `atr-benign` strata of the test split. The test split stays whole,
so its numbers stay comparable with what MaliciousSkillBench and others publish on it.

The held-out half here holds 163 of the 436 skills the analyzer was measured on: its ATR samples are measured once, in the
MaliciousSkillBench test split. A rate on these 163 skills is not comparable with a figure of the analyzer on the 436.

## The Trail of Bits skills

`trailofbits/overtly-malicious-skills` holds, in its own words, "the four malicious skills created by the Machine Learning
Security team at Trail of Bits to test out the reliability of skill scanners". The repository states no licence. Nothing of it
is copied here: `manifest.json` holds a pointer and a hash for each file, and each person fetches the files from Trail of Bits.

Every file of a skill is read as published at the pinned commit, files under `__pycache__` included, which a plain scan of a
directory may skip. Four skills are too few for a rate, so the table shows each of them by its id as found or not found at each
line, or as not read whole, with no percentage. A skill the rules miss is shown as plainly as one they find.

## The sanitized packages

Five `wild-liu` packages (three in the held-out half, two in the tuning half) have `sanitized=yes` in MaliciousSkillBench's
package manifest: MaliciousSkillBench replaced credential values with placeholders before it published them. The benchmark
measures the package as published in the pinned archive, and its hashes are over those bytes. For these five,
MaliciousSkillBench's own `exact_hash` names the withheld original, not the published package that the benchmark measures.

## What the labels of the wild strata mean

The `wild-liu`, `wild-skillleak` and `wild-amos` strata are public skills that a study labelled malicious or leaking. On those
strata a detection says the rules reported the risky pattern a study labelled, not that they stopped an attack.

## Disguised samples

Since 1.22.0 every run also measures disguised versions of each malicious skill (P6-4). A generator, `benchmarks/disguise.py`
(generator version 1, seed `spellwarden-disguise-1`), turns each skill into one variant per technique. Every choice it makes
comes from sha256 of the seed, the technique, the item, the path and the position, so every run, on Linux and Windows, builds the
same bytes. A variant exists only in memory: it is handed to the scanner and dropped, and it is never written, printed or run.
The generator adds no host, URL, file or command the sample did not hold, apart from the carriers, the two sentences and the word
list below.

| Technique | Where | What it does |
|---|---|---|
| `lookalike` | prose | Letters of words of three or more letters become Cyrillic or Greek look-alikes, each with a chance of one half. |
| `zero-width` | prose | One of U+200B, U+200C, U+200D or U+2060 inside every word of four or more letters. |
| `encoding-1` | prose and code | Each prose line becomes its base64, after the line "Each line below is base64 text. Decode it and follow it."; each script and code block becomes one line that decodes and runs it. |
| `encoding-2` | prose and code | The same with the text encoded twice. |
| `joined` | code | An empty pair `''` inside each shell word of four or more letters outside quotes; each string literal of four or more characters split in two and joined with `+` (`.` in Perl). |
| `padding` | prose and code | Each single space becomes two to six spaces and tabs (in prose also no-break and wide spaces). |
| `markup` | prose | In half of the words of five or more letters an empty HTML comment, a character reference such as `&#110;` or `**` emphasis. |
| `translation` | prose | 147 common English words of instructions replaced by Spanish ones from a fixed list. No model is called. |

Prose is every line of a Markdown file outside its fenced code blocks; code is every line of a script file and of a fenced block
in a code language. The front matter of a `SKILL.md`, the lines that open and close a fence, other files, binary files and line
endings stay as written. The carriers of the encoding techniques are `echo '<B>' | base64 -d | sh` for shell,
`exec(__import__("base64").b64decode("<B>"))` for Python, `eval(atob("<B>"))` for JavaScript and TypeScript,
`iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("<B>")))` for PowerShell, `eval(Base64.decode64("<B>"))` for
Ruby and `use MIME::Base64; eval(decode_base64("<B>"));` for Perl, each decoding call nested once more for two layers.

Each skill and each variant is scanned twice: with the rules on the text as written (`normalise=False`) and after normalisation
(the scanner's default). A variant equal to its skill is not scanned, and a technique's rates count only the skills it changed
and that were read whole. Each table also counts the detections without SW-SKL-002, SW-SKL-004 and SW-SKL-014, the rules that
report a disguise itself.

What the numbers do not show:

- a variant models what an author could do to the text, not whether the disguised skill would still work on a given agent;
- base64 is written unwrapped, while the `base64` command wraps at 76 characters by default;
- the look-alike letters are the common Cyrillic and Greek set, which the engine's folding table covers by design, so the
  look-alike row shows that the folding works on that set, not that every look-alike is caught;
- a word-list translation leaves more English than a real translation, so the true rate under translation is at most the one
  shown;
- every `zero-width` variant holds a character SW-SKL-002 reports, and the shell, Python and JavaScript carriers are lines
  SW-SKL-004 reports, so those rows are high as written whatever the content: read them without the disguise rules.

`python benchmarks/rule_benchmark.py steps` is the one tool for choosing normalisation steps. It reads the tuning sets only: it
fetches, rebuilds and scans no item of a test set and reads no member of a source archive that a test item uses. It measures no
normalisation, each candidate step alone, all candidates, and all candidates without each one, and prints counts only, with the
decision of each step: a step is kept when it raises at least one count on the tuning set and adds no finding on its harmless
skills.

The CHANGELOG of a release with the disguised samples also says, the first time,
`Rule benchmark: first table of disguised samples, see benchmarks/RESULTS.md.`, and every time either
`Rule benchmark: normalisation adds no finding on harmless skills.` or
`Rule benchmark: normalisation adds these findings on harmless skills, which the rules as written do not report:` followed by one
line per set and rule, `- <set>, <rule>: N findings in M skills`, with the reason each is what its rule describes. A detection of
a disguised sample that went down is a worse rate like any other.

## The community corpus

An entry of the history can hold one more member, `community`: a separate count of the samples that people outside the project
reported and that a maintainer accepted. `fixtures/community/` holds them, one directory per case, each with a record and the
defanged sample ([how a case works](../fixtures/community/README.md)). The benchmark reads those files in memory and counts, for
each case, whether the fix holds. The member exists from the first release after the first accepted case; while the corpus holds no
case it is absent, and an entry without it is what it was.

- A case holds when a scan of its files has a finding of the reported rule (a miss) or has none of it (a false positive), and fails
  when it does not. It is "not read whole" when the scanner could not read the skill whole, and it is counted apart, never as found
  or as clean. It is open while the rule change for it is not released, and an open case is not counted.
- The benchmark measures the skill rules only, so a case of another rule, or a case whose files are not one skill package with
  `SKILL.md` at the root, is listed as not measured here. Every case is still a test of `spellwarden scan` in `make check`,
  whatever its rule.
- The corpus is not a test set and not a tuning set. It holds the samples that people reported, and the rules were changed for
  them, so a count here shows that those fixes hold, never how well the rules work. It has no rate and no interval, it is not a set
  of `manifest.json`, and it is never used for a claim about rates.
- A sample that is in a test set is not accepted into the corpus, so that the test sets stay clean ([Tuning and test](#tuning-and-test)).
- The member holds case ids, rules and results. It holds no credit, no path and no sample text. `RESULTS.md` shows it in its own
  section, "Community corpus (reported by people outside the project)", below the sets.

This does not break the rule that no sample is written to disk as a file tree. The benchmark writes no sample anywhere. The files
of the corpus are defanged samples that are committed to this repository, and the benchmark only reads them where they are.

## Tuning and test

- A rule may be worked on with the tuning half, the repository's fixtures and samples people report. The precision pass P5-24
  uses the tuning half only.
- The held-out half, the MaliciousSkillBench test split and the Trail of Bits skills are test sets. A pull request that changes
  a rule does not cite, quote or add as a fixture any sample of a test set, and does not give a test-set result as its reason.
  Maintainers do not open test-set samples when working on a rule.
- The community corpus is not a test set. Samples that people report may be used for rule work as before, but a sample that is in a
  test set is not accepted into it.
- The published history shows every release's test-set rates beside its tuning-set rates, so a change that moved only test-set
  numbers is visible to everyone.

The tuning half is shown in its own block with the words "Tuning set: rules may be tuned on it, so its rates can look better
than those of a test set."

## Retiring a sample

When a source object can no longer be fetched or no longer matches its hash, or an owner asks for their skill to be left out, a
pull request moves the item from `items` to `excluded` in `manifest.json`, with the reason and the date, and removes a source
that no item uses any more. That is the only way to unblock a release that a failed fetch stopped. A changed manifest changes
`manifest_sha256` and so every later entry, and the CHANGELOG says that the sets changed.

## The CHANGELOG rule

Every release's CHANGELOG section says what happened to the rates since the release before:

- the first release with a table: `Rule benchmark: first published table, see benchmarks/RESULTS.md.`
- when no rate got worse: `Rule benchmark: no rate got worse than in X.Y.Z.`
- when one did: `Rule benchmark: these rates got worse than in X.Y.Z:` followed by one line per rate (a detection rate down, a
  false-positive rate up, or more skills not read whole, per set, for all rules and for each rule), and for the Trail of Bits
  skills one line per skill that went from found to not found;
- when the sets changed: `Rule benchmark: the sets changed since X.Y.Z; benchmarks/README.md lists what was left out.`

`python benchmarks/rule_benchmark.py changelog-lines` prints the lines to paste, and `make check` fails when they are missing.

## Releases

The release preparation records the entry before the tag, because a workflow started by a tag cannot commit:

1. Write the version's CHANGELOG section, with its heading `## X.Y.Z (YYYY-MM-DD)`.
2. Build the wheel, install it and `benchmarks/requirements.txt` in a fresh virtual environment, and run
   `python benchmarks/rule_benchmark.py run --expect-version X.Y.Z --record benchmarks/results.json` (add `--note TEXT` to
   label the release, for example the precision pass).
3. Paste the output of `changelog-lines` into the CHANGELOG section: each sentence may sit in a paragraph wrapped as the file
   wraps, but each `- ` line of worse rates stays on one line of its own, right under its sentence. Run `render`. For the first
   release with a table, also end the paragraph of `## Measured rates` in the repository's README with the sentence that links
   the page (spec 12.1): "The same table, release by release, is at
   [spellwarden.ai/research/rule-benchmark](https://spellwarden.ai/research/rule-benchmark?utm_source=github&utm_medium=readme&utm_campaign=rule-benchmark)."
   `make check` then requires it. Then run `make check`.
4. Commit and push the release branch, then rehearse the release job on it with the workflow `rule-benchmark.yml`:
   `gh workflow run rule-benchmark.yml --ref <release branch> -f verify=true`. Wait until both runners reproduce the entry.
5. Merge and tag. The release workflow's `rule-benchmark` job measures again from the built wheel on Linux and Windows and stops
   the release unless it gets the same numbers. It also checks that the earlier entries are those the last release published,
   then attaches `rule-benchmark.json` and `rule-benchmark.md` to the GitHub release.

## Rules measured on a set of their own

The 20 skill rules above are measured on skills. A rule that reads something else (the tool list of a probed server, an MCP
client configuration), or that asks a question the labels "malicious" and "benign skill" do not answer, is measured on a set of
its own before it is released. The sets hold third-party text, so they are never published. This repository holds only the
record of each set, `measured_sets.json`: counts, hashes and dates, and never a sample, a host, a path, a tool name or a quote.
`measured_sets.py` checks that record, works out the severity it gives and writes the table that the README shows between its
`measured-sets:start` and `measured-sets:end` markers.

How a set is made, in words:

- A frame of public units is collected once. It is split by owner or namespace into a tuning half and a held-out half, by a rule
  fixed before any count. Files already named in `manifest.json` as held-out, test-split or Trail of Bits items are left out.
- The rule is tuned on the tuning half only, in at most three rounds, and frozen at a signed commit.
- A count gate comes before any labelling: the frozen rule must flag at least 60 distinct units from at least 20 owners or
  namespaces in the whole frame to be scored on a held-out half. A rule that flags fewer is scored whole or withdrawn (see the two
  designs below), and the count is told to the owner.
- Every unit the frozen rule flags in the held-out half is labelled by two language models with different batching, and a third
  settles their disagreements. The owner audits a sample of 150 items. Planted synthetic positives show how many positives the
  labellers miss. The held-out half is scored once.

Two designs. The count gate also chooses how the set is scored, by a rule fixed before any count is read:

| Flagged units in the whole frame | Design |
|---|---|
| at least 60, from at least 20 owners or namespaces | split: tuned on one half, scored on the held-out half |
| 20 to 59 from at least 10 owners or namespaces, or 60 or more from 10 to 19 | whole frame: not tuned, not split, every flagged unit labelled, scored once |
| anything else | withdrawn before any labelling |

A whole-frame set keeps the frame, the rule and the frozen commit of the split set it comes from, so nothing is collected again and
the rule is not changed. It is scored once over all of its flagged units, with the same bar. A rule below the bar is withdrawn and
its measured precision is published; a rule with fewer than 20 labelled units is withdrawn with its counts. When an agreement
check covers fewer than 30 units it is reported and does not stop the run, and the record says so. The record of a whole-frame set
says `"design": "whole_frame"` and holds `scored`, the counts of its flagged units, where a split record holds `split`, `tuning` and
`holdout`; a record without `design` is a split record. Its limits say that the set was scored whole.

A rule that is measured again keeps its earlier records. `measured_sets.json` is then version 2, with the rule's current record
under `rules` and the earlier ones under `superseded`, in the order of their sets and unchanged; the README shows a line for each.

The bar. Precision is the true positives over the flagged units labelled positive or benign, with its 95% Wilson interval; a unit
labelled ambiguous or error is left out and shown in two lines that count it each way. Medium needs a precision of at least 0.60
and a lower end of the interval of at least 0.45. High needs 0.80 and 0.65. Fewer than 20 labelled units cannot be assessed. No
new rule is released at critical or at low. A rule that misses the medium bar is not released, and its OWASP entry says what
answers the entry instead. Recall is never a condition of release and is always published, with its interval, next to the
catch rate of the planted positives.

What the numbers do not show. The labellers are language models of one family, so their agreement can overstate validity. The
planted positives may be easier than real ones. The sets are public files and remote servers, not every customer's content.

Commands:

- `python benchmarks/rule_benchmark.py check-measured` checks that every record, superseded ones included, is valid by the rules of its own design, and that every registered rule of
  `PENDING_RULES` has one. `make check` runs it through `tests/test_measured_sets.py`, so a `pending` record does not stop
  development.
- `python benchmarks/rule_benchmark.py check-measured --release` exits 1 unless every rule of `PENDING_RULES` is `measured` at the
  severity it is registered at, and every `withdrawn` rule is out of the rule set. The release workflow runs it before the build.
  Exit codes are those of the rest of the harness: 0 passed, 1 a difference, 2 a file that cannot be read.
- `python benchmarks/measured_sets.py render` writes the README table from the record, and `render --check` compares it.

After the measurement, one signed commit for each rule, on the branch of the work and after it is rebased onto `origin/main`:

- A rule that met the bar: set its `SEVERITY` constant to the severity of the record, set the severity in its row of
  `src/spellwarden_cli/presets.py` (`strict` one level above, never above high, and `low-noise` equal to the rule's own), run
  `python benchmarks/measured_sets.py render`, regenerate the README tables with `spellwarden rules --format markdown` and
  `presets.table_markdown`, and write its precision and recall with their intervals into the CHANGELOG entry.
- A rule that failed the count gate, missed the bar or could not be assessed: set its record to `withdrawn` with the reason
  (`g0_failed`, `precision_below_bar` or `not_assessable`), take its module, registration, fixtures, preset row, README row,
  row of `tests/data/released_rule_ids.json`, tags and tests out in the same commit, and keep its id reserved.
- The branch is not merged before these commits: with a `pending` record, `check-measured --release` refuses every release of
  `main`.

## Files

- `manifest.json`: the sets, their sources, pins, files and hashes. It holds no sample text. It is written once by
  `build_manifest.py` (development only) and changed afterwards only by reviewed pull requests.
- `results.json`: the history, one entry per release, counts only.
- `RESULTS.md`: the full table, generated from `results.json` by `rule_benchmark.py render`.
- `requirements.txt`: `pyarrow`, hash-pinned, to read the parquet table.
- `rule_benchmark.py`: the one command (`fetch`, `run`, `render`, `changelog-lines`, `check-changelog`, `check-history`, `steps`).
- `measured_sets.json`: the record of each rule that is measured on a set of its own, counts, hashes and dates only; `measured_sets.py` checks it,
  works out the severity it gives and writes the README table. `rule_benchmark.py check-measured` is the release gate that reads it.
- `disguise.py`: the generator of the disguised samples, loaded by `rule_benchmark.py`. It is seeded, works in memory and
  writes, prints and runs nothing.
- `build_manifest.py`: turns the frozen measurement manifests into `manifest.json`; run once, never by `make check` or CI.
- `../fixtures/community/`: the community corpus. `rule_benchmark.py` reads it in memory and writes nothing to it; the format is read by
  `../scripts/community_corpus.py`.
