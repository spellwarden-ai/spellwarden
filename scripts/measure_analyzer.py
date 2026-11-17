"""Measures the model-assisted analyzer on one half of a frozen labelled set (Phase 4 batch B spec 11.6). Development only: not
part of the wheel, never run by `make check` or CI.

    uv run --locked python scripts/measure_analyzer.py --manifest FILE --samples DIR --half tuning|held-out \\
        --model NAME --out DIR

The manifest is JSON: `{"manifest": 1, "samples": [{"id", "label": "malicious" | "benign", "half": "tuning" | "held-out",
"path", "package_sha256"}, ...]}`, any other member of a sample (a source URL) is ignored. Each sample is a skill directory
at `<samples>/<path>` whose package hash (`spellwarden_scan.identity.package_sha256`) must equal the manifest's, so the
set cannot change unseen: every sample of the half is checked before the first call, so a set that changed costs no call
and leaves no half measured in part. For each sample of the half the script builds the request with
`spellwarden_scan.analyzer.build_request`, the one the product sends, runs one `claude -p` call (the `claude` first on PATH,
the model of `--model`, the analyzer's system prompt, the user message on stdin), and reads the answer with
`analyzer.parse_reply`.

A sample is hostile data, the malicious ones by their label. So the model that reads it is given nothing to act with: no
built-in tool (`--tools ""`), no MCP server of the user's configuration (`--strict-mcp-config`), no session written to
disk (`--no-session-persistence`), and a new empty directory under the system's temporary directory as its working
directory, so no project's CLAUDE.md, settings or memory is found from it. The request is then also closer to the one the
product sends, which holds the two messages and nothing else. What the user's own profile adds to every session (a memory
file, hooks) is not turned off by these flags: run the measurement from a profile that has none.

A sample counts as found when the reply names an issue at medium or high confidence in any category. It prints counts and
rates with 95% Wilson intervals only: never a sample's text and never a model's answer. Its per-sample rows (id, label,
status, reason, the categories found, the request's size) go to `--out/rows.jsonl`, and the counts, rates and an entry for
`analyzer.MEASURED_MODELS` to `--out/summary.json`; `--out` must be outside this repository, so no sample, row or answer is
ever committed. A sample without an answer (no verdict, not read whole, or a failed call) counts as not found, for the
detection rate and for the false-positive rate alike; the counts say how many there were.

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
from pathlib import Path

from spellwarden_scan import analyzer
from spellwarden_scan.identity import nested_skill_roots, package_files, package_sha256

REPOSITORY = Path(__file__).resolve().parents[1]
LABELS = ("malicious", "benign")
HALVES = ("tuning", "held-out")
FOUND_CONFIDENCE = ("medium", "high")
CLAUDE_TIMEOUT_SECONDS = 600
_ID = re.compile(r"[A-Za-z0-9._-]{1,100}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class ManifestError(ValueError):
    pass


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


def ask_claude(claude: str, model: str, request: analyzer.AnalyzerRequest) -> str | None:
    """One `claude -p` call without built-in tools, without the user's MCP servers and without a saved session, run in a
    new empty directory; the answer's text, or None when the call failed (nothing of it is shown). `claude` is an absolute
    path, because the working directory is not the caller's."""
    command = [claude, "-p", "--model", model, "--output-format", "text", "--tools", "", "--strict-mcp-config",
               "--no-session-persistence", "--system-prompt", request.system]
    try:
        with tempfile.TemporaryDirectory(prefix="spellwarden-measure-") as empty:
            done = subprocess.run(command, input=request.user, capture_output=True, text=True, encoding="utf-8",
                                  timeout=CLAUDE_TIMEOUT_SECONDS, cwd=empty)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout if done.returncode == 0 else None


def checked_sample(sample: dict, samples_dir: Path) -> tuple[dict[str, bytes], frozenset[str]]:
    """The files of one sample and its executable ones, after its package hash was compared with the manifest's."""
    files, executable = read_sample(samples_dir / sample["path"])
    if sample_hash(files) != sample["package_sha256"]:
        raise ManifestError(f"sample {sample['id']} changed: its package hash is not the manifest's")
    return files, executable


def judge(sample: dict, samples_dir: Path, claude: str, model: str) -> dict:
    """The row of one sample: id, label, status, reason, the categories found and the request's size."""
    files, executable = checked_sample(sample, samples_dir)
    row = {"id": sample["id"], "label": sample["label"], "status": "", "reason": None, "found": [], "input_bytes": None}
    request = analyzer.build_request(files, root="", executable_paths=executable)
    if isinstance(request, analyzer.NotAnalyzed):
        return {**row, "status": "incomplete", "reason": request.code}
    row["input_bytes"] = request.input_bytes
    answer = ask_claude(claude, model, request)
    if answer is None:
        return {**row, "status": "not_analyzed", "reason": "claude_failed"}
    result = analyzer.parse_reply(answer, request)
    if result.status != "analyzed":
        return {**row, "status": "no_verdict", "reason": result.reason}
    found = [category.id for category in result.categories
             if category.verdict == "issue" and category.confidence in FOUND_CONFIDENCE]
    return {**row, "status": "analyzed", "found": found}


def summarise(rows: list[dict], *, model: str, half: str, manifest_sha256: str) -> dict:
    """The counts, the two rates with their intervals, and an entry for `analyzer.MEASURED_MODELS` (its `name` and `aliases`
    are the session's to write)."""
    counts = {status: sum(1 for row in rows if row["status"] == status)
              for status in ("analyzed", "no_verdict", "incomplete", "not_analyzed")}
    rates = {}
    for label, key in (("malicious", "detection_rate"), ("benign", "false_positive_rate")):
        mine = [row for row in rows if row["label"] == label]
        found = sum(1 for row in mine if row["found"])
        low, high = wilson(found, len(mine))
        rates[key] = {"found": found, "total": len(mine), "rate": found / len(mine) if mine else None,
                      "interval_95": [round(low, 4), round(high, 4)]}
    entry = {"name": model, "aliases": [], "detection_rate": rates["detection_rate"]["rate"],
             "false_positive_rate": rates["false_positive_rate"]["rate"], "held_out_size": len(rows),
             "measured_on": datetime.date.today().isoformat(), "set": manifest_sha256}
    return {"half": half, "model": model, "analyzer_version": analyzer.ANALYZER_VERSION, "samples": len(rows),
            "counts": counts, **rates, "entry": entry}


def _rate_line(name: str, block: dict) -> str:
    if block["rate"] is None:
        return f"{name}: no samples"
    low, high = block["interval_95"]
    return f"{name} {block['rate']:.3f} ({block['found']} of {block['total']}), 95% interval {low:.3f} to {high:.3f}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="measure_analyzer.py", description="Measure the analyzer on one half of the set.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--samples", required=True, type=Path)
    parser.add_argument("--half", required=True, choices=HALVES)
    parser.add_argument("--model", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    out = args.out.resolve()
    if out == REPOSITORY or REPOSITORY in out.parents:
        print("measure_analyzer: --out must be outside this repository", file=sys.stderr)
        return 2
    try:
        samples = [sample for sample in load_manifest(args.manifest) if sample["half"] == args.half]
        for sample in samples:  # the whole half before the first call: a set that changed costs no call
            checked_sample(sample, args.samples)
    except ManifestError as exc:
        print(f"measure_analyzer: {exc}", file=sys.stderr)
        return 2
    claude = shutil.which("claude")
    if claude is None:
        print("measure_analyzer: no claude on PATH", file=sys.stderr)
        return 2
    try:
        rows = [judge(sample, args.samples, os.path.abspath(claude), args.model) for sample in samples]
    except ManifestError as exc:  # a sample that changed between the check and its call
        print(f"measure_analyzer: {exc}", file=sys.stderr)
        return 2
    summary = summarise(rows, model=args.model, half=args.half,
                        manifest_sha256=hashlib.sha256(args.manifest.read_bytes()).hexdigest())
    out.mkdir(parents=True, exist_ok=True)
    (out / "rows.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    counts = summary["counts"]
    malicious, benign = summary["detection_rate"]["total"], summary["false_positive_rate"]["total"]
    print(f"half {args.half}, model {args.model}, {len(rows)} samples ({malicious} malicious, {benign} benign)")
    print(f"analysed {counts['analyzed']}, no verdict {counts['no_verdict']}, not read whole {counts['incomplete']}, "
          f"failed calls {counts['not_analyzed']}")
    print(_rate_line("detection rate", summary["detection_rate"]))
    print(_rate_line("false-positive rate", summary["false_positive_rate"]))
    print(f"rows and summary: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
