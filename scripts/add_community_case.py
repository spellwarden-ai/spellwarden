#!/usr/bin/env python3
"""The maintainer's command that adds one accepted case to `fixtures/community/` from the text of an issue
(docs/specs/2026-11-25-community-reports.md, section 6.3):

    uv run python scripts/add_community_case.py BODY.md --kind miss|false-positive --rule SW-SKL-009 [--issue 68]
            [--outcome open|fixed] [--fixed-in X.Y.Z] [--keep-host HOST ...] [--date YYYY-MM-DD] [--root DIR] [--dry-run]

BODY.md is the issue's body as GitHub renders a form (`gh issue view N --json body --jq .body > BODY.md`, run by the maintainer).
The script never opens a network connection and never runs, imports or executes a sample. It checks everything, stops at the
first group of checks that fails (it prints every problem of that group, one per line, and exits 2 with nothing written), and
otherwise writes `COM-NNNN/record.json` and `COM-NNNN/files/`. It touches nothing else: the CHANGELOG line, the outcome flip and
the answer in the issue are the maintainer's. Standard library only, apart from a lazy import of the engine for the rule list."""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


def _load(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


corpus = _load("community_corpus.py", "spellwarden_community_corpus")

CONSENT_TEXT = ("I wrote this sample, or I am allowed to publish it, and I agree that it is published in this repository under "
                "the Apache License 2.0, the licence of the repository.")
ORIGIN_OPTIONS = ("I wrote it", "Adapted from public content (give the link below)", "From a benchmark or test set")
ORIGIN_TEST_SET = ORIGIN_OPTIONS[2]
TEST_SET_REASON = ("This sample comes from a set the benchmark keeps as a test set, so a rule change made for it would break the "
                   "held-out promise in CONTRIBUTING.md. Describe the technique in words and I will look at that.")
# Field id to the label of the field in the issue forms; tests/test_community_forms.py keeps this table equal to the three forms.
COMMON_LABELS = {
    "versions": "Scanner version and rules version",
    "command": "The command and settings that gave this result",
    "file": "File name of the sample, inside the project",
    "more": "More files, if the sample needs them",
    "origin": "Where the sample comes from",
    "source": "Public link, if there is one",
    "credit": "Name to credit (optional)",
    "consent": "Publishing",
}
SAMPLE_LABELS = {
    "false-positive": "The smallest sample that makes the rule fire",
    "missed-detection": "The smallest harmless sample that shows it",
    "new-rule": "A harmless sample that shows the problem",
}
FORM_LABELS = {form: {**COMMON_LABELS, "sample": label} for form, label in SAMPLE_LABELS.items()}
# r1:F1: the fields each form adds, which the record does not keep but the parser must know, since GitHub renders every field
EXTRA_LABELS = {
    "false-positive": {"rule": "Rule id", "why": "Why it is not a problem"},
    "missed-detection": {"expected": "What you expected to be found"},
    "new-rule": {"detects": "What the rule detects", "content": "Which kind of content it reads",
                 "gap": "Why no rule finds it today", "harmless": "Which harmless content the pattern would also match"},
}
ALL_LABELS = {form: {**FORM_LABELS[form], **EXTRA_LABELS[form]} for form in FORM_LABELS}
# Every field of each form in the form's order; tests/test_community_forms.py keeps this and ALL_LABELS equal to the YAML
FIELD_ORDER = {
    "false-positive": ("rule", "versions", "command", "file", "sample", "more", "why", "origin", "source", "credit", "consent"),
    "missed-detection": ("expected", "versions", "command", "file", "sample", "more", "origin", "source", "credit", "consent"),
    "new-rule": ("detects", "content", "versions", "command", "file", "sample", "more", "gap", "harmless", "origin", "source",
                 "credit", "consent"),
}
KINDS = {"miss": "miss", "false-positive": "false_positive"}
_VERSIONS = re.compile(r"^(?:spellwarden\s+)?([0-9]+\.[0-9]+\.[0-9]+)\s*(?:\(\s*rules\s+([0-9]{4}\.[0-9]{2}\.[0-9]+)\s*\)"
                       r"|[,;\s]\s*(?:rules\s+)?([0-9]{4}\.[0-9]{2}\.[0-9]+))$")
_CONSENT = re.compile(r"^- \[[xX]\] (.*)$")


class Refused(Exception):
    """One group of checks failed: `problems` are one-line messages, printed as they are."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def rule_areas() -> dict[str, str]:
    """Every rule of the baseline with its area; the one place the script uses the engine, imported when needed."""
    try:
        from spellwarden_scan import RuleSet
    except ImportError:
        raise Refused(["the engine is not installed: run the script with `uv run python scripts/add_community_case.py`"]) \
            from None
    return {rule.id: rule.area for rule in RuleSet.baseline()}


def read_form(text: str) -> tuple[str, dict[str, str]]:
    """The form that `text` answers and its answers by field id. Raises `Refused` when a required field is missing."""
    headings = set(corpus.form_headings(text))
    forms = [form for form, labels in FORM_LABELS.items() if labels["sample"] in headings]
    if len(forms) != 1:
        raise Refused(["the body is not the answer of one of the three issue forms (no field with the label of a form's sample)"])
    try:
        answers = corpus.parse_form_body(text, [ALL_LABELS[forms[0]][field] for field in FIELD_ORDER[forms[0]]])
    except corpus.CorpusError as exc:
        raise Refused([str(exc)]) from None
    labels = FORM_LABELS[forms[0]]
    missing = [labels[field] for field in ("versions", "file", "sample", "origin", "consent") if not answers.get(labels[field])]
    if missing:
        raise Refused([f"the field '{label}' is empty or missing" for label in missing])
    return forms[0], {field: answers.get(label, "") for field, label in labels.items()}


def parse_versions(text: str) -> dict[str, str]:
    match = _VERSIONS.match(" ".join(text.split()))
    if match is None:
        raise Refused(["the versions are not 'spellwarden X.Y.Z (rules YYYY.MM.N)' or two bare versions"])
    return {"scanner": match.group(1), "rules": match.group(2) or match.group(3)}


def consent_given(text: str) -> bool:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    match = _CONSENT.match(lines[0]) if len(lines) == 1 else None
    return match is not None and " ".join(match.group(1).split()) == CONSENT_TEXT


def credit_of(text: str) -> tuple[str | None, list[str]]:
    """The credit as the record holds it, and the problems with it: trimmed, one line, at most 80 characters, letters, digits,
    spaces and . , ' - only (r0:F4)."""
    if not text.strip():
        return None, []
    if "\n" in text.strip() or "\r" in text.strip():
        return None, ["the credit holds a line break"]
    value = text.strip()
    if len(value) > corpus.MAX_CREDIT or re.search(r"[\x00-\x1f\x7f]", value):
        return None, [f"the credit is longer than {corpus.MAX_CREDIT} characters or holds a control character"]
    if not corpus.credit_is_plain(value):
        return None, ["the credit holds a character other than letters, digits, spaces and . , ' -, or a host name (no mention, link or markup)"]
    return value, []


def build_files(fields: dict[str, str]) -> tuple[dict[str, bytes], list[str]]:
    """The sample's files: the form's file and sample, then each file of the `more` field."""
    problems = []
    name = fields["file"].strip()
    if "\n" in name:
        problems.append("the file name holds a line break")
    files = {name: corpus.file_bytes(fields["sample"])}
    more, more_problems = corpus.split_files(fields["more"])
    problems += more_problems
    for path, text in more.items():
        if path in files:
            problems.append(f"{corpus.shown(path)}: the path is also the file of the sample")
        files[path] = corpus.file_bytes(text)
    return files, problems


def run(args: argparse.Namespace) -> tuple[str, list[str]]:
    """Every check, in the order of 6.3, then the write. Returns the id and the paths written (or that would be written)."""
    problems: list[str] = []
    try:
        text = Path(args.body).read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise Refused([f"{Path(args.body).name} cannot be read as UTF-8 text"]) from None
    form, fields = read_form(text)
    credit, credit_problems = credit_of(fields["credit"])
    problems += credit_problems
    if args.outcome == "open" and args.fixed_in is not None:
        problems.append("--fixed-in goes with --outcome fixed")
    if args.outcome == "fixed" and args.fixed_in is None:
        problems.append("--outcome fixed needs --fixed-in")
    kept = sorted({host.lower() for host in args.keep_host})
    problems += [f"--keep-host {corpus.shown(host)} {reason}" for host in kept if (reason := corpus.host_problem(host))]
    if problems:
        raise Refused(problems)
    if not consent_given(fields["consent"]):
        raise Refused(["the consent box is not ticked, so the sample cannot be published under the repository's licence"])
    if fields["origin"].strip() == ORIGIN_TEST_SET:
        raise Refused([TEST_SET_REASON])
    if fields["origin"].strip() not in ORIGIN_OPTIONS:
        raise Refused(["the origin is not one of the three options of the form"])
    versions = parse_versions(fields["versions"])
    areas = rule_areas()
    record = {"id": "", "kind": KINDS[args.kind], "rule": args.rule, "kept_hosts": kept, "reported_against": versions,
              "outcome": args.outcome, "fixed_in": args.fixed_in, "credit": credit, "date": args.date, "issue": args.issue}
    root = Path(args.root)
    record["id"] = corpus.next_id(root)
    record_problems = corpus.record_problems(record, directory_name=record["id"], rule_areas=areas)
    if record_problems:
        raise Refused(record_problems)
    files, file_problems = build_files(fields)
    hygiene = file_problems + corpus.sample_problems(files, kept)
    if hygiene:
        raise Refused(hygiene)
    manifest = Path(args.manifest)
    if not manifest.is_file():
        raise Refused([f"{manifest.name} is not here: the check against the test sets needs the benchmark's manifest, so run "
                       "the script from a checkout"])
    try:
        duplicates = corpus.manifest_duplicates(files, manifest)
    except corpus.CorpusError as error:
        raise Refused([str(error)]) from None
    if duplicates:
        raise Refused([*duplicates, TEST_SET_REASON])
    try:
        existing = corpus.load_cases(root)
    except corpus.CorpusError as error:
        raise Refused([f"the corpus cannot be read: {error}"]) from None
    digest = corpus.files_digest(files)
    twins = [case.id for case in existing if corpus.files_digest(case.files) == digest]
    if twins:
        raise Refused([f"the sample equals the sample of {twins[0]}"])
    directory = root / record["id"]
    written = [f"{directory.as_posix()}/record.json", *(f"{directory.as_posix()}/files/{path}" for path in sorted(files))]
    if not args.dry_run:
        _write(directory, record, files)
    return record["id"], written


def _write(directory: Path, record: dict, files: dict[str, bytes]) -> None:
    directory.mkdir(parents=True)
    targets = {directory / "record.json": corpus.dump_record(record).encode("utf-8"),
               **{directory.joinpath("files", *path.split("/")): data for path, data in files.items()}}
    for target, data in targets.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chmod(target, 0o644)


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="add_community_case.py", description="Add one accepted case to fixtures/community/.")
    command.add_argument("body", help="the issue's body, as GitHub renders a form")
    command.add_argument("--kind", required=True, choices=sorted(KINDS))
    command.add_argument("--rule", required=True, help="the rule the case concerns, chosen by the maintainer")
    command.add_argument("--issue", type=int, default=None,
                         help="the issue number; leave it out for a case from a private report")
    command.add_argument("--outcome", choices=corpus.OUTCOMES, default="open")
    command.add_argument("--fixed-in", default=None, help="X.Y.Z, with --outcome fixed")
    command.add_argument("--keep-host", action="append", default=[], metavar="HOST",
                         help="a real host the rule judges itself, kept in the sample (repeat for more)")
    command.add_argument("--date", default=datetime.now(timezone.utc).date().isoformat(), help="the day of acceptance")
    command.add_argument("--root", default=str(REPOSITORY / "fixtures" / "community"))
    command.add_argument("--manifest", default=str(REPOSITORY / "benchmarks" / "manifest.json"))
    command.add_argument("--dry-run", action="store_true", help="run every check and write nothing")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        case_id, paths = run(args)
    except Refused as refusal:
        for problem in refusal.problems:
            print(f"refused: {problem}", file=sys.stderr)
        return 2
    print(f"{'would add' if args.dry_run else 'added'} {case_id}")
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
