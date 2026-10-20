"""Spec 2 invariant 4 and claim C2 (slice 0): the fingerprint, severity, location and evidence of every finding
of every existing fixture, recorded from `1566547` (0.2.0) into `tests/golden/fingerprints-0.2.0.json`.
`tests/test_golden_fingerprints.py` compares the live engine with that file after every later change.

Recording is done once, by phase O slice 0: `uv run --locked python tests/golden_record.py`. Re-recording later
would hide the very change the file exists to catch; a rule change that is meant to move a fingerprint gets its
own golden file and its own release note instead."""
from __future__ import annotations

import json
from pathlib import Path

from conftest import PROBE_FIXTURES, SKILL_FIXTURES, load_probe_fixture, load_skill_fixture

from spellwarden_scan.model import Finding
from spellwarden_scan.probe import evaluate_probe
from spellwarden_scan.rules import RuleSet
from spellwarden_scan.scan import scan_skill_package

GOLDEN = Path(__file__).resolve().parent / "golden" / "fingerprints-0.2.0.json"


def _row(fixture: str, finding: Finding) -> dict:
    return {
        "fixture": fixture, "rule_id": finding.rule_id, "severity": finding.severity, "path": finding.location.path,
        "line": finding.location.line, "evidence": finding.evidence, "malicious_indicator": finding.malicious_indicator,
        "fingerprint": finding.fingerprint,
    }


def entries() -> list[dict]:
    """Every finding of every skill fixture (both sides, generated ones included) and every probe fixture
    (rule fixtures and the product spec samples), in a total order."""
    rules = RuleSet.baseline()
    rows: list[dict] = []
    for directory in sorted(p for p in SKILL_FIXTURES.iterdir() if p.is_dir()):
        for side in ("positive", "negative"):
            files, expected = load_skill_fixture(directory.name, side)
            result = scan_skill_package(files, rules, root=expected.get("root", ""))
            rows.extend(_row(f"skills/{directory.name}/{side}", finding) for finding in result.findings)
    for path in sorted(PROBE_FIXTURES.rglob("*.json")):
        name = path.relative_to(PROBE_FIXTURES).with_suffix("").as_posix()
        probe, _ = load_probe_fixture(name)
        rows.extend(_row(f"probes/{name}", finding) for finding in evaluate_probe(probe, rules).findings)
    return sorted(rows, key=lambda r: (r["fixture"], r["rule_id"], r["path"], r["line"] or 0, r["fingerprint"]))


def render(rows: list[dict]) -> str:
    return json.dumps(rows, indent=1, sort_keys=True) + "\n"


if __name__ == "__main__":
    GOLDEN.write_text(render(entries()))
    print(f"wrote {GOLDEN.relative_to(Path.cwd())}: {len(entries())} findings")
