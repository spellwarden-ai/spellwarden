"""Spec 4.4, 4.5 and claim E4: one vector per row of the dialect and kind tables and per field source, shared with
the hosted side (`tests/vectors/otel/`)."""
from __future__ import annotations

import pytest

from otel_support import build_request, json_bytes, matches, reference_protobuf, vectors
from spellwarden_scan.otel import decode, normalise

FILES = ("dialects.json", "fields.json", "identifiers.json", "content.json")
CASES = [(name, vector) for name in FILES for vector in vectors(name)]


@pytest.mark.parametrize(("file", "vector"), CASES, ids=[f"{name}:{vector['name']}" for name, vector in CASES])
@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_vector(file, vector, encoding):  # noqa: ARG001 -- `file` is the id
    document = build_request(vector)
    body = json_bytes(document) if encoding == "json" else reference_protobuf(document, vector["signal"])
    result = normalise(decode(body, signal=vector["signal"], encoding=encoding), content=vector.get("content", False))
    records = [record.to_dict(content=True) for record in result.records]
    assert len(records) == len(vector["expect"]), records
    for index, (expected, actual) in enumerate(zip(vector["expect"], records, strict=True)):
        assert matches(expected, actual) == [], (index, actual)
    if "resources" in vector:
        assert [resource.to_dict() for resource in result.resources] == vector["resources"]
    stats = result.stats.to_dict()
    for key, value in vector.get("stats", {}).items():
        assert stats[key] == value, (key, stats)


def test_every_vector_has_a_unique_name():
    names = [vector["name"] for _, vector in CASES]
    assert len(names) == len(set(names))
