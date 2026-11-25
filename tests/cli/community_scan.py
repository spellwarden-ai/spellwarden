"""What `spellwarden scan` says about the files of a community case (docs/specs/2026-11-25-community-reports.md, D-4): the helper of
tests/cli/test_community_cases.py and of the test that the benchmark agrees with the command."""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path

from conftest import write_tree


def scan_rules(files: Mapping[str, bytes], work: Path, run_cli: Callable) -> tuple[int, set[str]]:
    """The exit code of `spellwarden scan <copy of files> --no-telemetry --format json` (run in process, with CI and Spellwarden
    environment variables removed and git hermetic, by `run_cli`) and the rule ids of its findings (none when the exit code is 2)."""
    sample = write_tree(work / "sample", dict(files))
    code, out, _err = run_cli(["scan", str(sample), "--no-telemetry", "--format", "json"])
    if code == 2:
        return code, set()
    return code, {finding["rule_id"] for finding in json.loads(out)["findings"]}


def finding_problems(case, work: Path, run_cli: Callable) -> list[str]:
    """Why the scan of a case's files does not give the corrected behaviour its record describes (6.5), or an empty list: a miss
    needs a finding of its rule, a false positive needs none. An exit code of 2 (a sample the scanner could not read) is its own
    problem, never a pass."""
    code, found = scan_rules(case.files, work, run_cli)
    if code == 2:
        return [f"{case.id}: the command could not read the sample (exit 2)"]
    rule = case.record["rule"]
    if case.record["kind"] == "miss" and rule not in found:
        return [f"{case.id}: the scan has no finding of {rule}, which a miss needs"]
    if case.record["kind"] == "false_positive" and rule in found:
        return [f"{case.id}: the scan still has a finding of {rule}, which a false positive must not have"]
    return []
