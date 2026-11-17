"""Measures the model-assisted analyzer on one half of a frozen labelled set (Phase 4 batch B spec 11.6). Development only: not
part of the wheel, never run by `make check` or CI.

    uv run --locked python scripts/measure_analyzer.py --manifest FILE --samples DIR --half tuning|held-out \\
        --model NAME --out DIR [--workers N] [--resume]

The manifest is JSON: `{"manifest": 1, "samples": [{"id", "label": "malicious" | "benign", "half": "tuning" | "held-out",
"path", "package_sha256", "stratum", "unit"}, ...]}`, where `stratum` and `unit` are optional and any other member of a sample
(a source URL) is ignored. Each sample is a skill directory at `<samples>/<path>` whose package hash
(`spellwarden_scan.identity.package_sha256`) must equal the manifest's, so the set cannot change unseen: every sample of the
half is checked before `claude` is looked for and before the first call, so a set that changed costs no call. `stratum` (1 to
60 letters, digits, dots, underscores or hyphens) names a group the summary reports on its own; the samples of a stratum share
one label. `unit` (the form of an id) joins the samples of one package that holds several skills: they must share label, half
and stratum, and they are one item, found when any of them is found. The rates, `samples` and `held_out_size` count items;
`counts` stay per sample.

For each sample of the half the script builds the request with `spellwarden_scan.analyzer.build_request`, the one the product
sends, runs one `claude -p --output-format json` call (the `claude` first on PATH, the model of `--model`, the user message on
stdin), and reads the answer's text with `analyzer.parse_reply`. The calls run on `--workers` threads (default 4, 1 to 16), in
the order of the SHA-256 of the ids, so the order does not depend on label or stratum.

A sample is hostile data, the malicious ones by their label. So the model that reads it is given nothing to act with: no
built-in tool (`--tools ""`), no MCP server of the user's configuration (`--strict-mcp-config`), no session written to disk
(`--no-session-persistence`), no user, project or local settings file and so no hooks, memory or plugins
(`--setting-sources ""`), and a new empty directory under the system's temporary directory as its working directory. The
analyzer's system prompt goes in a file of mode 0600 beside that directory (`--system-prompt-file`), removed with it after the
call. The call gets the caller's environment without `CLAUDECODE`, `CLAUDE_EFFORT` and every variable starting with
`ANTHROPIC_`, `AWS_` or `CLAUDE_CODE_`, so it is served by the subscription the profile (`CLAUDE_CONFIG_DIR`) is signed in to,
never by an API key or a cloud provider. The request is then also closer to the one the product sends, which holds the two
messages and nothing else.

The command prints one JSON object: `is_error`, `result` (the answer's text) and `modelUsage` (the tokens per model). A row
records `served`, the models that wrote output tokens, and the input and output tokens summed. A call can be answered by
another model than the one asked: such a row still counts by its verdict, and the summary and the output say how many there
were per label (`answered_by_other_model`). Output that is not that object, or `is_error`, is a failed call, unless its text
says a usage limit was reached: then no new call starts, the rows finished so far are kept, no row is written for that sample,
and the script exits 3; `--resume` continues.

A sample counts as found when the reply names an issue at medium or high confidence in any category. The script prints counts
and rates with 95% Wilson intervals only: never a sample's text and never a model's answer. Each finished row (id, label,
model, status, reason, the categories found, the request's size, the models and tokens) is appended to `--out/rows.jsonl` at
once. Without `--resume` the script refuses an `--out` that already holds `rows.jsonl`, so a half is never measured twice by
accident; with it, a sample whose latest row is not a failed call is skipped, failed calls are tried again, and the summary is
computed over the latest row of each sample. The counts, rates, strata and an entry for `analyzer.MEASURED_MODELS` go to
`--out/summary.json` once every sample of the half has a row; a partial run prints how many are left. `--out` must be outside
this repository, so no sample, row or answer is ever committed. A sample without an answer (no verdict, not read whole, or a
failed call) counts as not found, for the detection rate and for the false-positive rate alike; the counts say how many there
were.

On Windows a file has no executable mode, so a script there is chosen by its directory (`scripts/`) and its extension only."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Mapping
from pathlib import Path
from typing import IO, NamedTuple

from spellwarden_scan import analyzer
from spellwarden_scan.identity import nested_skill_roots, package_files, package_sha256

REPOSITORY = Path(__file__).resolve().parents[1]
LABELS = ("malicious", "benign")
HALVES = ("tuning", "held-out")
FOUND_CONFIDENCE = ("medium", "high")
CLAUDE_TIMEOUT_SECONDS = 600
WORKERS_DEFAULT = 4
WORKERS_MAX = 16
# The call's environment: no key and no cloud provider, so the profile's signed-in subscription serves it.
STRIPPED_NAMES = ("CLAUDECODE", "CLAUDE_EFFORT")
STRIPPED_PREFIXES = ("ANTHROPIC_", "AWS_", "CLAUDE_CODE_")
_ID = re.compile(r"[A-Za-z0-9._-]{1,100}")
_STRATUM = re.compile(r"[A-Za-z0-9._-]{1,60}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_USAGE_LIMIT = re.compile(r"usage limit|limit reached|out of usage|out of extra usage|hit your|reached your", re.IGNORECASE)


class ManifestError(ValueError):
    pass


class UsageLimitReached(Exception):
    """A call failed with a usage-limit message: no new call starts and no row is written for its sample."""


class Reply(NamedTuple):
    """What one call printed: the answer's text (None for a failed call), whether it failed on a usage limit, the models that
    wrote output tokens, and the tokens summed over the models."""
    text: str | None
    usage_limit: bool = False
    served: tuple[str, ...] = ()
    input_tokens: int = 0
    output_tokens: int = 0


def item_key(sample: dict) -> tuple[str, str]:
    """The item a sample counts in: its unit, or the sample itself."""
    return ("unit", sample["unit"]) if sample.get("unit") is not None else ("sample", sample["id"])


def load_manifest(path: Path) -> list[dict]:
    """The samples of the manifest, checked; raises `ManifestError` naming the first problem."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManifestError(f"the manifest cannot be read: {type(exc).__name__}") from None
    if not isinstance(document, dict) or document.get("manifest") != 1 or not isinstance(document.get("samples"), list):
        raise ManifestError('the manifest must be {"manifest": 1, "samples": [...]}')
    seen: set[str] = set()
    for index, sample in enumerate(document["samples"]):
        if not isinstance(sample, dict):
            raise ManifestError(f"sample {index} is not an object")
        sample_id = sample.get("id")
        if not isinstance(sample_id, str) or not _ID.fullmatch(sample_id) or sample_id in seen:
            raise ManifestError(f"sample {index}: the id is missing, malformed or repeated")
        seen.add(sample_id)
        if sample.get("label") not in LABELS or sample.get("half") not in HALVES:
            raise ManifestError(f"sample {sample_id}: label must be malicious or benign, half tuning or held-out")
        relative = sample.get("path")
        if not isinstance(relative, str) or not relative or relative.startswith(("/", "\\")) or ".." in Path(relative).parts:
            raise ManifestError(f"sample {sample_id}: path must be relative, inside --samples")
        if not isinstance(sample.get("package_sha256"), str) or not _SHA256.fullmatch(sample["package_sha256"]):
            raise ManifestError(f"sample {sample_id}: package_sha256 must be 64 lower-case hex characters")
        stratum = sample.get("stratum")
        if stratum is not None and (not isinstance(stratum, str) or not _STRATUM.fullmatch(stratum)):
            raise ManifestError(f"sample {sample_id}: stratum must be 1 to 60 letters, digits, dots, underscores or hyphens")
        unit = sample.get("unit")
        if unit is not None and (not isinstance(unit, str) or not _ID.fullmatch(unit)):
            raise ManifestError(f"sample {sample_id}: unit must have the form of an id")
    units: dict[str, set[tuple]] = {}
    strata: dict[str, set[str]] = {}
    for sample in document["samples"]:
        if sample.get("unit") is not None:
            units.setdefault(sample["unit"], set()).add((sample["label"], sample["half"], sample.get("stratum")))
        if sample.get("stratum") is not None:
            strata.setdefault(sample["stratum"], set()).add(sample["label"])
    for unit, shared in sorted(units.items()):
        if len(shared) > 1:
            raise ManifestError(f"unit {unit}: its samples must share label, half and stratum")
    for stratum, labels in sorted(strata.items()):
        if len(labels) > 1:
            raise ManifestError(f"stratum {stratum}: its samples must share one label")
    return document["samples"]


def read_sample(directory: Path) -> tuple[dict[str, bytes], frozenset[str]]:
    """The files of a skill directory keyed by POSIX path, and the executable ones (none on Windows). A link is refused."""
    files: dict[str, bytes] = {}
    executable: set[str] = set()
    for current, directories, names in os.walk(directory):
        directories.sort()
        for name in sorted(names):
            full = Path(current) / name
            if full.is_symlink():
                raise ManifestError(f"{full.relative_to(directory).as_posix()} is a link")
            relative = full.relative_to(directory).as_posix()
            files[relative] = full.read_bytes()
            if os.name != "nt" and full.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                executable.add(relative)
    return files, frozenset(executable)


def sample_hash(files: dict[str, bytes]) -> str:
    return package_sha256(package_files(files, "", nested_skill_roots(files, "")).files)


def call_order(samples: list[dict]) -> list[dict]:
    """The samples in the order of the SHA-256 of their ids, which depends on neither label nor stratum."""
    return sorted(samples, key=lambda sample: hashlib.sha256(sample["id"].encode("utf-8")).hexdigest())


def wilson(found: int, total: int) -> tuple[float, float]:
    """The 95% Wilson score interval of `found` in `total` ((0.0, 1.0) when `total` is 0)."""
    if total == 0:
        return 0.0, 1.0
    z = 1.959963984540054
    share = found / total
    centre = share + z * z / (2 * total)
    margin = z * math.sqrt(share * (1 - share) / total + z * z / (4 * total * total))
    denominator = 1 + z * z / total
    return max(0.0, (centre - margin) / denominator), min(1.0, (centre + margin) / denominator)


def child_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """The caller's environment without `CLAUDECODE`, `CLAUDE_EFFORT` and every `ANTHROPIC_*`, `AWS_*` and `CLAUDE_CODE_*`
    variable (Windows names compare in upper case)."""
    return {name: value for name, value in environ.items()
            if name.upper() not in STRIPPED_NAMES and not name.upper().startswith(STRIPPED_PREFIXES)}


def _tokens(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def read_output(stdout: str, returncode: int) -> Reply:
    """The reply in the one JSON object `claude -p --output-format json` prints. Anything else, `is_error`, a missing text or
    an exit code other than 0 is a failed call; a failed call whose text matches a usage-limit message is marked so."""
    try:
        document = json.loads(stdout)
    except ValueError:
        return Reply(None)
    if not isinstance(document, dict):
        return Reply(None)
    served: list[str] = []
    input_tokens = output_tokens = 0
    usage = document.get("modelUsage")
    for name, entry in (usage.items() if isinstance(usage, dict) else ()):
        if not isinstance(entry, dict):
            continue
        output = _tokens(entry.get("outputTokens"))
        output_tokens += output
        input_tokens += sum(_tokens(entry.get(key)) for key in ("inputTokens", "cacheReadInputTokens",
                                                                 "cacheCreationInputTokens"))
        if output > 0:
            served.append(str(name))
    text = document.get("result")
    counted = {"served": tuple(sorted(served)), "input_tokens": input_tokens, "output_tokens": output_tokens}
    if document.get("is_error") is not False or returncode != 0 or not isinstance(text, str):
        return Reply(None, usage_limit=isinstance(text, str) and bool(_USAGE_LIMIT.search(text)), **counted)
    return Reply(text, **counted)


def ask_claude(claude: str, model: str, request: analyzer.AnalyzerRequest) -> Reply:
    """One `claude -p` call without built-in tools, MCP servers of the user's configuration, a saved session or any settings
    file, in a stripped environment and a new empty directory; nothing of a failed call is shown. `claude` is an absolute path,
    because the working directory is not the caller's."""
    command = [claude, "-p", "--model", model, "--output-format", "json", "--tools", "", "--strict-mcp-config",
               "--no-session-persistence", "--setting-sources", ""]
    try:
        with tempfile.TemporaryDirectory(prefix="spellwarden-measure-", ignore_cleanup_errors=True) as call_dir:
            prompt = Path(call_dir) / "system-prompt.txt"
            descriptor = os.open(prompt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(request.system.encode("utf-8"))
            empty = Path(call_dir) / "work"
            empty.mkdir()
            done = subprocess.run([*command, "--system-prompt-file", str(prompt)], input=request.user, capture_output=True,
                                  text=True, encoding="utf-8", errors="replace", timeout=CLAUDE_TIMEOUT_SECONDS, cwd=empty,
                                  env=child_environment(os.environ))
    except (OSError, subprocess.TimeoutExpired):
        return Reply(None)
    return read_output(done.stdout, done.returncode)


def checked_sample(sample: dict, samples_dir: Path) -> tuple[dict[str, bytes], frozenset[str]]:
    """The files of one sample and its executable ones, after its package hash was compared with the manifest's."""
    files, executable = read_sample(samples_dir / sample["path"])
    if sample_hash(files) != sample["package_sha256"]:
        raise ManifestError(f"sample {sample['id']} changed: its package hash is not the manifest's")
    return files, executable


def judge(sample: dict, samples_dir: Path, claude: str, model: str) -> dict:
    """The row of one sample: id, label, model, status, reason, the categories found, the request's size, the models that
    answered and the tokens. Raises `UsageLimitReached` when the call hit a usage limit."""
    files, executable = checked_sample(sample, samples_dir)
    row = {"id": sample["id"], "label": sample["label"], "model": model, "status": "", "reason": None, "found": [],
           "input_bytes": None, "served": [], "input_tokens": 0, "output_tokens": 0}
    request = analyzer.build_request(files, root="", executable_paths=executable)
    if isinstance(request, analyzer.NotAnalyzed):
        return {**row, "status": "incomplete", "reason": request.code}
    row["input_bytes"] = request.input_bytes
    reply = ask_claude(claude, model, request)
    if reply.text is None and reply.usage_limit:
        raise UsageLimitReached
    row.update(served=list(reply.served), input_tokens=reply.input_tokens, output_tokens=reply.output_tokens)
    if reply.text is None:
        return {**row, "status": "not_analyzed", "reason": "claude_failed"}
    result = analyzer.parse_reply(reply.text, request)
    if result.status != "analyzed":
        return {**row, "status": "no_verdict", "reason": result.reason}
    found = [category.id for category in result.categories
             if category.verdict == "issue" and category.confidence in FOUND_CONFIDENCE]
    return {**row, "status": "analyzed", "found": found}


def run_calls(pending: list[dict], samples_dir: Path, claude: str, model: str, workers: int, rows_file: IO[str]) -> dict:
    """Judges `pending` on `workers` threads, appending each finished row to `rows_file` at once. Stops starting calls on a
    usage limit or a sample that changed; returns {"usage_limit": bool, "error": ManifestError | None}."""
    stop = threading.Event()
    lock = threading.Lock()
    outcome: dict = {"usage_limit": False, "error": None}

    def one(sample: dict) -> None:
        if stop.is_set():
            return
        try:
            row = judge(sample, samples_dir, claude, model)
        except UsageLimitReached:
            outcome["usage_limit"] = True
            stop.set()
            return
        except ManifestError as exc:  # a sample that changed between the check and its call
            with lock:
                outcome["error"] = outcome["error"] or exc
            stop.set()
            return
        except BaseException:
            stop.set()
            raise
        with lock:
            rows_file.write(json.dumps(row, sort_keys=True) + "\n")
            rows_file.flush()

    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="measure")
    try:
        for future in [pool.submit(one, sample) for sample in pending]:
            future.result()
    except BaseException:
        stop.set()
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    return outcome


def read_rows(path: Path) -> tuple[dict[str, dict], int]:
    """The latest row of each id in `rows.jsonl`, and how many lines were not a row (a line cut by a stopped run)."""
    latest: dict[str, dict] = {}
    unreadable = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            unreadable += 1
            continue
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not isinstance(row.get("status"), str):
            unreadable += 1
            continue
        latest[row["id"]] = row
    return latest, unreadable


def _rate_block(found: int, total: int) -> dict:
    low, high = wilson(found, total)
    return {"found": found, "total": total, "rate": found / total if total else None, "interval_95": [round(low, 4),
                                                                                                     round(high, 4)]}


def summarise(samples: list[dict], rows_by_id: dict[str, dict], *, model: str, half: str, manifest_sha256: str) -> dict:
    """The counts per call, the two rates and the strata over items with their intervals, and an entry for
    `analyzer.MEASURED_MODELS` (its `name` and `aliases` are the session's to write). Every sample has a row."""
    rows = [rows_by_id[sample["id"]] for sample in samples]
    counts = {status: sum(1 for row in rows if row["status"] == status)
              for status in ("analyzed", "no_verdict", "incomplete", "not_analyzed")}
    other = {label: sum(1 for sample in samples if sample["label"] == label
                        and rows_by_id[sample["id"]]["status"] in ("analyzed", "no_verdict")
                        and rows_by_id[sample["id"]].get("served") != [model]) for label in LABELS}
    items: dict[tuple[str, str], dict] = {}
    for sample in samples:
        row = rows_by_id[sample["id"]]
        item = items.setdefault(item_key(sample), {"label": sample["label"], "stratum": sample.get("stratum"),
                                                   "found": False, "without_answer": False})
        item["found"] = item["found"] or bool(row.get("found"))
        item["without_answer"] = item["without_answer"] or row["status"] != "analyzed"
    rates = {}
    for label, key in (("malicious", "detection_rate"), ("benign", "false_positive_rate")):
        mine = [item for item in items.values() if item["label"] == label]
        rates[key] = _rate_block(sum(1 for item in mine if item["found"]), len(mine))
    strata = {}
    for name in sorted({item["stratum"] for item in items.values() if item["stratum"] is not None}):
        mine = [item for item in items.values() if item["stratum"] == name]
        strata[name] = {"label": mine[0]["label"], **_rate_block(sum(1 for item in mine if item["found"]), len(mine))}
    entry = {"name": model, "aliases": [], "detection_rate": rates["detection_rate"]["rate"],
             "false_positive_rate": rates["false_positive_rate"]["rate"], "held_out_size": len(items),
             "measured_on": datetime.date.today().isoformat(), "set": manifest_sha256}
    return {"half": half, "model": model, "analyzer_version": analyzer.ANALYZER_VERSION, "samples": len(items),
            "counts": counts, "items_with_a_call_without_answer": sum(1 for item in items.values() if item["without_answer"]),
            "answered_by_other_model": other, **rates, "strata": strata, "entry": entry}


def _rate_line(name: str, block: dict) -> str:
    if block["rate"] is None:
        return f"{name}: no samples"
    low, high = block["interval_95"]
    return f"{name} {block['rate']:.3f} ({block['found']} of {block['total']}), 95% interval {low:.3f} to {high:.3f}"


def _workers(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be a whole number from 1 to {WORKERS_MAX}") from None
    if not 1 <= number <= WORKERS_MAX:
        raise argparse.ArgumentTypeError(f"must be a whole number from 1 to {WORKERS_MAX}")
    return number


def _needs_call(row: dict | None) -> bool:
    return row is None or row["status"] == "not_analyzed"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="measure_analyzer.py", description="Measure the analyzer on one half of the set.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--samples", required=True, type=Path)
    parser.add_argument("--half", required=True, choices=HALVES)
    parser.add_argument("--model", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--workers", type=_workers, default=WORKERS_DEFAULT, help=f"parallel calls, 1 to {WORKERS_MAX}")
    parser.add_argument("--resume", action="store_true", help="continue a run whose rows are in --out")
    args = parser.parse_args(argv)
    out = args.out.resolve()
    if out == REPOSITORY or REPOSITORY in out.parents:
        print("measure_analyzer: --out must be outside this repository", file=sys.stderr)
        return 2
    rows_path, summary_path = out / "rows.jsonl", out / "summary.json"
    if rows_path.exists() and not args.resume:
        print("measure_analyzer: --out already holds rows.jsonl; pass --resume to continue that run, or choose another --out",
              file=sys.stderr)
        return 2
    try:
        samples = [sample for sample in load_manifest(args.manifest) if sample["half"] == args.half]
        for sample in samples:  # the whole half before the first call: a set that changed costs no call
            checked_sample(sample, args.samples)
    except ManifestError as exc:
        print(f"measure_analyzer: {exc}", file=sys.stderr)
        return 2
    ids = {sample["id"] for sample in samples}
    latest, unreadable = read_rows(rows_path) if rows_path.exists() else ({}, 0)
    latest = {sample_id: row for sample_id, row in latest.items() if sample_id in ids}
    if any(row.get("model") != args.model for row in latest.values()):
        print("measure_analyzer: rows.jsonl holds rows of another model than --model; resume with the same --model, or choose "
              "another --out", file=sys.stderr)
        return 2
    if unreadable:
        print(f"ignored {unreadable} unreadable lines of rows.jsonl")
    pending = [sample for sample in call_order(samples) if _needs_call(latest.get(sample["id"]))]
    outcome: dict = {"usage_limit": False, "error": None}
    out.mkdir(parents=True, exist_ok=True)
    if pending:
        found_claude = shutil.which("claude")
        if found_claude is None:
            print("measure_analyzer: no claude on PATH", file=sys.stderr)
            return 2
        summary_path.unlink(missing_ok=True)  # written again once every sample has a row
        cut = rows_path.exists() and rows_path.stat().st_size > 0 and not rows_path.read_bytes().endswith(b"\n")
        with rows_path.open("a", encoding="utf-8", newline="\n") as rows_file:
            if cut:
                rows_file.write("\n")
            outcome = run_calls(pending, args.samples, os.path.abspath(found_claude), args.model, args.workers, rows_file)
        latest = {sample_id: row for sample_id, row in read_rows(rows_path)[0].items() if sample_id in ids}
    left = sum(1 for sample in samples if _needs_call(latest.get(sample["id"])))
    if outcome["error"] is not None:
        print(f"measure_analyzer: {outcome['error']}", file=sys.stderr)
        print(f"{left} of {len(samples)} samples of the half still need a call; the finished rows are in {out}")
        return 2
    if outcome["usage_limit"]:
        print(f"usage limit reached: {left} of {len(samples)} samples of the half still need a call; the finished rows are in "
              f"{out}; run again with --resume to continue")
        return 3
    missing = sum(1 for sample in samples if sample["id"] not in latest)
    if missing:  # not reached while every pending call ends in a row, kept so a partial half never gets a summary
        print(f"{missing} of {len(samples)} samples of the half have no row yet; run again with --resume to continue")
        return 1
    summary = summarise(samples, latest, model=args.model, half=args.half,
                        manifest_sha256=hashlib.sha256(args.manifest.read_bytes()).hexdigest())
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    counts, other = summary["counts"], summary["answered_by_other_model"]
    malicious, benign = summary["detection_rate"]["total"], summary["false_positive_rate"]["total"]
    print(f"half {args.half}, model {args.model}, {summary['samples']} items from {len(samples)} samples "
          f"({malicious} malicious, {benign} benign)")
    print(f"analysed {counts['analyzed']}, no verdict {counts['no_verdict']}, not read whole {counts['incomplete']}, "
          f"failed calls {counts['not_analyzed']}")
    print(f"items with a call without an answer {summary['items_with_a_call_without_answer']}")
    print(f"answered by another model: malicious {other['malicious']}, benign {other['benign']}")
    print(_rate_line("detection rate", summary["detection_rate"]))
    print(_rate_line("false-positive rate", summary["false_positive_rate"]))
    for name, block in summary["strata"].items():
        print(_rate_line(f"stratum {name} ({block['label']})", block))
    print(f"rows and summary: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
