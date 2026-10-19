"""The curation score, the curated flag and quarantine (spec 5.9)."""
from __future__ import annotations

from collections.abc import Iterable

from spellwarden_scan.model import CurationInputs, Finding

CURATED_THRESHOLD = 8.0
MALICIOUS_RULES = frozenset({"SW-SKL-004", "SW-SKL-008"})
_WEIGHTS = {"critical": 6.0, "high": 3.0, "medium": 1.0, "low": 0.25}


def severities_of(items: Iterable[Finding | str]) -> list[str]:
    """The severity of each item: a `Finding`'s `severity`, or the string itself (spec 5.2 allows
    severity-only inputs). An unknown string raises `ValueError`."""
    found: list[str] = []
    for item in items:
        severity = item.severity if isinstance(item, Finding) else item
        if severity not in _WEIGHTS:
            raise ValueError(f"unknown severity {severity!r}")
        found.append(severity)
    return found


def severity_weights(findings: Iterable[Finding | str]) -> float:
    """`6c + 3h + m + 0.25l` over the findings (or severity strings)."""
    return sum(_WEIGHTS[severity] for severity in severities_of(findings))


def curation_score(inputs: CurationInputs) -> float:
    """`round(12 * (0.6 S + 0.2 M + 0.2 E), 1)`; accepted findings weigh half."""
    weighted = severity_weights(inputs.open_findings) + severity_weights(inputs.accepted_findings) / 2
    s = max(0.0, 1.0 - weighted / 12.0)
    m = max(0, min(5, inputs.metadata_present)) / 5.0
    e = max(0.0, min(1.0, inputs.eval_component))
    return round(12.0 * (0.6 * s + 0.2 * m + 0.2 * e), 1)


def is_curated(inputs: CurationInputs, score: float) -> bool:
    if score < CURATED_THRESHOLD or inputs.quarantined or not inputs.sha256_matches:
        return False
    return not any(severity in ("critical", "high") for severity in severities_of(inputs.open_findings))


def is_quarantined(findings: Iterable[Finding | str]) -> bool:
    """True when any open finding comes from a malicious-indicator rule (a bare severity string
    carries no rule and never quarantines)."""
    return any(isinstance(f, Finding) and (f.malicious_indicator or f.rule_id in MALICIOUS_RULES) for f in findings)
