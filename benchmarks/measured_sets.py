"""The record of a rule's own measurement (P6-9 spec 8.6): `benchmarks/measured_sets.json`, its validator, the severity the
measurement gives, the release check and the README block.

A rule that is not a skill rule has no place in the benchmark's sets of skills, so it is measured on a set of its own, built and
scored in the private `code` repository and never published (it holds third-party text). What is published, and checked here, is
the arithmetic: counts, hashes and dates. A record never holds a sample, a host, a path, a tool name or a quote, and no string of
it is longer than `MAX_STRING` characters. `severity_for` is the table of the spec's section 8.1: the severity follows from the
measured precision on the holdout, and a precision that does not reach the medium bar means the rule is not released.

Run `python benchmarks/measured_sets.py render` to write the README block from the record, and `render --check` to compare."""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Mapping
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
BENCHMARKS = REPOSITORY / "benchmarks"
RECORDS = BENCHMARKS / "measured_sets.json"
README_START, README_END = "<!-- measured-sets:start -->", "<!-- measured-sets:end -->"

# The rules of this item that are released only with a record that says `measured` (P6-9 spec 8.6).
PENDING_RULES = ("SW-SKL-038", "SW-MCP-013", "SW-CFG-015")
STATUSES = ("pending", "measured", "withdrawn")
REASONS = ("g0_failed", "precision_below_bar", "not_assessable")
SEVERITIES = ("medium", "high")
MAX_STRING = 300
G0_UNITS, G0_COMPONENTS = 60, 20  # the count gate of the spec's section 8.1
MIN_LABELLED = 20  # fewer flagged units labelled positive or benign cannot be assessed
BARS = (("high", 0.80, 0.65), ("medium", 0.60, 0.45))  # severity, least precision, least lower end of the 95% interval
WILSON_Z = 1.959963984540054
TOLERANCE = 0.0005  # a value differs when it differs in the third decimal

SET_WORDS = {
    "SW-SKL-038": "public skill packages, command and agent files and instruction files",
    "SW-MCP-013": "public tool lists of remote MCP servers",
    "SW-CFG-015": "public MCP client configuration files",
}
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_RULE_ID = re.compile(r"SW-(?:SKL|MCP|CFG)-\d{3}")
_SET_NAME = re.compile(r"[a-z0-9-]{1,60}")
_SHAPES = {
    "frame": {"units", "kind", "collected", "components"},
    "split": {"tuning_units", "holdout_units"},
    "g0": {"flagged_units", "components", "passed"},
    "tuning": {"rounds", "flagged", "positive", "benign"},
    "holdout": {"flagged", "positive", "benign", "ambiguous", "error"},
    "precision": {"value", "low", "high"},
    "recall": {"value", "low", "high", "method"},
    "planted_catch": {"caught", "planted"},
    "owner_audit": {"items", "agreement"},
}
_TOP = {"status", "set", "frozen_sha256", "frozen_at", "measured_on", "candidate_commit", "severity", "kinds", "limits", "reason",
        *_SHAPES}
_MAY_BE_NULL = {"recall", "planted_catch"}
KINDS = ("skill", "command_agent", "instruction", "tool", "mcp", "plugin", "settings")  # the kinds of unit a set holds
TUNING_ROUNDS = (1, 2, 3)  # at most three rounds (spec 8.8)
_PENDING = {"status", "set", "limits"}
_MEASURED = _TOP - {"reason", "recall", "planted_catch"}  # recall and the planted catch may be null


def wilson(found: int, total: int) -> tuple[float, float]:
    """The 95% Wilson score interval of `found` in `total`, as `rule_benchmark.wilson` (a test holds the two equal)."""
    if total == 0:
        return 0.0, 1.0
    share = found / total
    centre = share + WILSON_Z * WILSON_Z / (2 * total)
    margin = WILSON_Z * math.sqrt(share * (1 - share) / total + WILSON_Z * WILSON_Z / (4 * total * total))
    denominator = 1 + WILSON_Z * WILSON_Z / total
    return max(0.0, (centre - margin) / denominator), min(1.0, (centre + margin) / denominator)


def severity_for(positive: int, benign: int) -> str | None:
    """`high`, `medium` or None for a holdout whose flagged units were labelled `positive` and `benign` (ambiguous and error
    units are left out): the table of the spec's section 8.1. None, which is no release, also for fewer than `MIN_LABELLED`."""
    labelled = positive + benign
    if labelled < MIN_LABELLED:
        return None
    share = positive / labelled
    lower = wilson(positive, labelled)[0]
    for severity, least_share, least_lower in BARS:
        if share >= least_share and lower >= least_lower:
            return severity
    return None


def dump(document: Mapping) -> str:
    """The file's text: sorted keys, indent 2, ASCII, a final newline."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def load(path: Path) -> dict:
    """The file as a document; `ValueError` when it cannot be read or is not JSON."""
    try:
        document = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{path.name} cannot be read as JSON: {error.__class__.__name__}") from None
    return document


def _strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, inner in value.items():
            yield key
            yield from _strings(inner)
    elif isinstance(value, (list, tuple)):
        for inner in value:
            yield from _strings(inner)


def _count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _fraction(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0.0 <= value <= 1.0


def _shape_problems(rule_id: str, record: Mapping) -> list[str]:
    problems = []
    measured = record.get("status") == "measured"
    for name, keys in _SHAPES.items():
        block = record.get(name)
        if block is None and not (measured and name not in _MAY_BE_NULL):
            continue
        # A measured record is read by the consistency check and the README block: each block it holds is whole.
        if not isinstance(block, Mapping) or (set(block) != keys if measured else bool(set(block) - keys)):
            problems.append(f"{rule_id}: {name} is not an object with the members {sorted(keys)}")
            continue
        for key, value in block.items():
            ok = (_fraction(value) if key in ("value", "low", "high", "agreement") else
                  isinstance(value, bool) if key == "passed" else isinstance(value, str) if key in ("kind", "method", "collected")
                  else _count(value))
            if not ok:
                problems.append(f"{rule_id}: {name}.{key} has a value of the wrong kind")
    return problems


def check_record(rule_id: str, record: object) -> list[str]:
    """Every reason `record` is not a valid record of `rule_id`, empty when it is valid. A `measured` record must also be
    consistent: its precision and interval are those of its holdout counts to the third decimal, its severity is
    `severity_for` of them (and not None), its `flagged` count is the sum of its parts, and its count gate passed."""
    if rule_id not in PENDING_RULES and _RULE_ID.fullmatch(rule_id) is None:
        return [f"{rule_id}: not a rule id"]
    if not isinstance(record, Mapping):
        return [f"{rule_id}: the record is not an object"]
    problems = []
    status = record.get("status")
    if status not in STATUSES:
        return [f"{rule_id}: status is not one of {', '.join(STATUSES)}"]
    unknown = sorted(set(record) - _TOP)
    if unknown:
        problems.append(f"{rule_id}: unknown member {unknown[0]!r}")
    if status == "pending" and set(record) != _PENDING:
        problems.append(f"{rule_id}: a pending record holds only status, set and limits")
    if status == "measured" and not _MEASURED <= set(record):
        problems.append(f"{rule_id}: a measured record lacks {sorted(_MEASURED - set(record))[0]}")
    if status == "withdrawn" and (record.get("reason") not in REASONS or not ({"g0", "holdout"} & set(record))):
        problems.append(f"{rule_id}: a withdrawn record holds g0 or holdout and a reason, one of {', '.join(REASONS)}")
    if not isinstance(record.get("set"), str) or _SET_NAME.fullmatch(record["set"]) is None:
        problems.append(f"{rule_id}: set is not a set name")
    if any(len(text) > MAX_STRING for text in _strings(record)):
        problems.append(f"{rule_id}: a string is longer than {MAX_STRING} characters")
    limits = record.get("limits")
    if not isinstance(limits, list) or not limits or not all(isinstance(text, str) and text for text in limits):
        problems.append(f"{rule_id}: limits is not a list of sentences")
    for key, pattern in (("frozen_sha256", _SHA256), ("candidate_commit", _COMMIT)):
        if key in record and (not isinstance(record[key], str) or pattern.fullmatch(record[key]) is None):
            problems.append(f"{rule_id}: {key} is not a hash")
    for key in ("frozen_at", "measured_on"):
        if key in record and (not isinstance(record[key], str) or _DATE.fullmatch(record[key]) is None):
            problems.append(f"{rule_id}: {key} is not a date")
    problems += _shape_problems(rule_id, record)
    if "kinds" in record:
        kinds = record["kinds"]
        if not isinstance(kinds, list) or not kinds or not all(isinstance(kind, str) and kind in KINDS for kind in kinds):
            problems.append(f"{rule_id}: kinds is not a non-empty list of kinds, from {', '.join(KINDS)}")
    tuning = record.get("tuning")
    if isinstance(tuning, Mapping) and "rounds" in tuning and tuning["rounds"] not in TUNING_ROUNDS:
        problems.append(f"{rule_id}: tuning.rounds is not one of {', '.join(map(str, TUNING_ROUNDS))}")
    holdout, precision = record.get("holdout"), record.get("precision")
    if status == "measured" and isinstance(holdout, Mapping) and isinstance(precision, Mapping) and not problems:
        problems += _consistency_problems(rule_id, record, holdout, precision)
    return problems


def _consistency_problems(rule_id: str, record: Mapping, holdout: Mapping, precision: Mapping) -> list[str]:
    problems = []
    positive, benign = holdout["positive"], holdout["benign"]
    if holdout["flagged"] != positive + benign + holdout["ambiguous"] + holdout["error"]:
        problems.append(f"{rule_id}: holdout.flagged is not the sum of positive, benign, ambiguous and error")
    labelled = positive + benign
    expected = (positive / labelled if labelled else 0.0, *wilson(positive, labelled))
    for name, want in zip(("value", "low", "high"), expected, strict=True):
        if abs(precision[name] - want) > TOLERANCE:
            problems.append(f"{rule_id}: precision.{name} is {precision[name]} and the counts give {want:.3f}")
    severity = severity_for(positive, benign)
    if severity is None:
        problems.append(f"{rule_id}: the holdout does not meet the bar for medium, so the rule is not released")
    elif record["severity"] != severity:
        problems.append(f"{rule_id}: severity is {record['severity']!r} and the holdout gives {severity!r}")
    g0 = record["g0"]
    if g0["passed"] != (g0["flagged_units"] >= G0_UNITS and g0["components"] >= G0_COMPONENTS) or not g0["passed"]:
        problems.append(f"{rule_id}: the count gate G0 needs {G0_UNITS} flagged units from {G0_COMPONENTS} components, "
                        "and must have passed")
    catch = record.get("planted_catch")
    if catch is not None and catch["caught"] > catch["planted"]:
        problems.append(f"{rule_id}: planted_catch.caught is more than planted_catch.planted")
    return problems


def check_document(document: object) -> list[str]:
    """Every problem of the file: its two members, and each record."""
    if not isinstance(document, Mapping) or set(document) != {"measured_sets", "rules"} or document["measured_sets"] != 1:
        return ["the file is not {\"measured_sets\": 1, \"rules\": {...}}"]
    rules = document["rules"]
    if not isinstance(rules, Mapping):
        return ["rules is not an object"]
    return [problem for rule_id, record in sorted(rules.items()) for problem in check_record(rule_id, record)]


def release_problems(document: Mapping, registered: Mapping[str, str], *, release: bool) -> list[str]:
    """What stops a build. `registered` maps the id of each rule of the baseline to its severity. Always: the file is valid
    and each registered rule of `PENDING_RULES` has a record. With `release`: each of them is `measured` at the severity the
    record gives, and a `withdrawn` rule is not registered."""
    problems = check_document(document)
    records = document.get("rules", {}) if isinstance(document, Mapping) else {}
    for rule_id in PENDING_RULES:
        record = records.get(rule_id) if isinstance(records, Mapping) else None
        if rule_id in registered and record is None:
            problems.append(f"{rule_id}: registered, with no record in measured_sets.json")
            continue
        if not release or record is None:
            continue
        status = record.get("status") if isinstance(record, Mapping) else None
        if status == "withdrawn" and rule_id in registered:
            problems.append(f"{rule_id}: its record says withdrawn and the rule is still registered")
        elif status in ("pending", "measured") and rule_id not in registered:
            problems.append(f"{rule_id}: has a {status} record and is not registered")
        elif status == "pending":
            problems.append(f"{rule_id}: not measured yet, so it cannot be released")
        elif status == "measured" and registered[rule_id] != record.get("severity"):
            problems.append(f"{rule_id}: registered at {registered[rule_id]} and measured at {record.get('severity')}")
    return problems


def _percent(value: float) -> str:
    return f"{math.floor(value * 1000 + 0.5) / 10:.1f}"


def _range(value: Mapping) -> str:
    return f"{_percent(value['value'])}% ({_percent(value['low'])}% to {_percent(value['high'])}%)"


def block(document: Mapping) -> str:
    """The text between the README's markers: one row for each measured rule, a line for each withdrawn rule, and a sentence when
    no rule is measured. No text of a sample can reach it: it is built from counts, dates, `SET_WORDS` and the limits
    sentences."""
    records = document["rules"]
    measured = [(rule_id, records[rule_id]) for rule_id in sorted(records) if records[rule_id]["status"] == "measured"]
    withdrawn = [(rule_id, records[rule_id]) for rule_id in sorted(records) if records[rule_id]["status"] == "withdrawn"]
    lines = []
    if measured:
        lines += ["| Rule | Set | Holdout flagged | Precision | Recall | Severity | Measured | What it does not see |",
                  "|---|---|---|---|---|---|---|---|"]
        for rule_id, record in measured:
            recall = record.get("recall")
            recall_text = _range(recall) if recall else "not estimated"
            size = f"{record['frame']['units']:,} units of {SET_WORDS[rule_id]}"
            cells = (rule_id, size, record["holdout"]["flagged"], _range(record["precision"]), recall_text, record["severity"],
                     record["measured_on"], " ".join(record["limits"]))
            lines.append("| " + " | ".join(str(cell) for cell in cells) + " |")
    else:
        lines.append("No rule is measured on a set of its own in this version.")
    for rule_id, record in withdrawn:
        lines.append("")
        reason = record["reason"].replace("_", " ")
        lines.append(f"{rule_id} was measured and withdrawn before release ({reason}); its id stays reserved.")
    return "\n".join(lines) + "\n"


def with_block(readme: str, text: str) -> str:
    """The README with `text` between the markers; `ValueError` unless each marker is there once, the start first."""
    body = readme.replace("\r\n", "\n")
    start, end = README_START + "\n", README_END
    if body.count(start) != 1 or body.count(end) != 1 or body.index(start) > body.index(end):
        raise ValueError(f"README.md must hold {README_START} and {README_END} once each, in that order")
    return body[:body.index(start) + len(start)] + text + body[body.index(end):]


def main(argv: list[str] | None = None) -> int:
    """`render [--check]`: write (or, with --check, compare) the README block. Exit 0, 1 for a difference, 2 for a file that
    cannot be read."""
    parser = argparse.ArgumentParser(prog="measured_sets.py")
    parser.add_argument("command", choices=("render",))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--records", type=Path, default=RECORDS)
    parser.add_argument("--readme", type=Path, default=REPOSITORY / "README.md")
    args = parser.parse_args(argv)
    try:
        document = load(args.records)
        problems = check_document(document)
        if problems:
            print("\n".join(problems))
            return 1
        current = args.readme.read_bytes().decode("utf-8").replace("\r\n", "\n")
        wanted = with_block(current, block(document))
    except (OSError, ValueError) as error:
        print(f"measured_sets: {error}", file=sys.stderr)
        return 2
    if args.check:
        return 0 if wanted == current else 1
    args.readme.write_bytes(wanted.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
