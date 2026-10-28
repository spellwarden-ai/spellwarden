"""Spec 4.9 and claim E11: a 10,000-span body decodes and normalises in under 2.0 s, content off and on, times
`SPELLWARDEN_SPEED_FACTOR` when it is set (CI sets 3). The body repeats every span of the fixtures (the synthetic
ones, and the recordings once the release gate has added them)."""
from __future__ import annotations

import os
import time

import pytest

from otel_support import fixture_bodies, reference_protobuf
from spellwarden_scan.otel import decode, normalise

BUDGET_S = 2.0 * float(os.environ.get("SPELLWARDEN_SPEED_FACTOR", "1"))
SPANS = 10_000


def _big_request() -> dict:
    import json

    spans = []
    for _name, signal, encoding, body in fixture_bodies():
        if signal == "traces" and encoding == "json":
            document = json.loads(body)
            spans += [span for resource in document["resourceSpans"] for scope in resource["scopeSpans"] for span in scope["spans"]]
    assert spans, "the fixtures hold no spans"
    repeated = [spans[n % len(spans)] for n in range(SPANS)]
    return {"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "speed"}}]},
                               "scopeSpans": [{"scope": {"name": "speed"}, "spans": repeated}]}]}


@pytest.mark.slow
@pytest.mark.parametrize("content", [False, True])
def test_ten_thousand_spans_decode_and_normalise_within_the_budget(content):
    body = reference_protobuf(_big_request(), "traces")
    started = time.perf_counter()
    result = normalise(decode(body, signal="traces", encoding="protobuf"), content=content)
    elapsed = time.perf_counter() - started
    assert result.stats.spans == SPANS
    assert elapsed < BUDGET_S, f"{elapsed:.2f} s for {SPANS} spans (budget {BUDGET_S:.1f} s)"
