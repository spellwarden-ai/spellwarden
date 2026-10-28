"""Zuplo export spec claims G1 (the Python half) and G2: every vector of `fixtures/zuplo_vectors.json` gives its expected
outcome through `tests/zuplo_reference.py`, and the reference, with its switches off, reads a pattern as the engine does.
The Node half of G1 is `tests/node/zuplo_guard.test.mjs`."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import zuplo_reference as R

from spellwarden_scan.orgrules import compile_pattern, pattern_search
from spellwarden_scan.rules.patterns import INJECTION
from spellwarden_scan.rules.skill import visible

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / "fixtures" / "zuplo_vectors.json").read_text(encoding="utf-8"))
SETS = DATA["check_sets"]
VECTORS = DATA["vectors"]


def test_the_fixture_is_what_the_cases_build():
    done = subprocess.run([sys.executable, str(ROOT / "tests" / "zuplo_vector_cases.py"), "check"], capture_output=True, text=True,
                          check=False)
    assert done.returncode == 0, done.stderr


def test_there_are_vectors_for_every_reason_the_guard_blocks_for():
    reasons = {vector["expect"].get("reason") for vector in VECTORS if vector["expect"]["outcome"] == "block"}
    assert reasons == {"matched", "too_large", "encoded", "not_json", "not_mcp", "not_post", "server_request", "not_text",
                       "too_deep", "too_many_events", "too_many_strings", "bad_options"}


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["name"])
def test_g1_the_reference_gives_the_expected_outcome(vector):
    got = R.decide(vector, SETS)
    expect = vector["expect"]
    assert got["outcome"] == expect["outcome"]
    if expect["outcome"] == "block":
        assert got["reason"] == expect["reason"]
        assert got["rule_ids"] == expect["rule_ids"]
        if "id" in expect:
            assert got["id"] == expect["id"]


def has_astral(text: str) -> bool:
    return any(ord(char) > 0xFFFF for char in text)


def strings_of(vector: dict) -> list[str]:
    """The strings a JSON vector holds, as the guard walks them (blobs left as they are)."""
    if vector.get("media", "application/json") != "application/json" or "body" not in vector:
        return []
    try:
        messages = R.messages_of(json.loads(vector["body"]))
    except (ValueError, R.Stop):
        return []
    try:
        return R.strings_of(messages)
    except R.Stop:
        return []


def engine_hit(pattern: str, case_sensitive: bool, text: str) -> bool:
    compiled = compile_pattern(pattern, case_sensitive=case_sensitive)
    lines = R.NEWLINE.split(text)
    if lines and lines[-1] == "":
        lines.pop()
    return any(pattern_search(compiled, line) for line in lines)


def g2_cases():
    for vector in VECTORS:
        if vector.get("engine_differs") or vector["checks"] not in ("baseline", "mixed", *DATA["g2_patterns"]):
            continue
        for text in strings_of(vector):
            if not has_astral(text):
                yield pytest.param(vector, text, id=f"{vector['name']}: {text[:30]!r}")


@pytest.mark.parametrize(("vector", "text"), list(g2_cases()))
def test_g2_the_reference_with_its_switches_off_agrees_with_the_engine(vector, text):
    for name in ("alpha", "secret_cs", "leak_end", "token", "foo_s", "aaa_zzz"):
        if vector["checks"] != name:
            continue
        pattern, case_sensitive = DATA["g2_patterns"][name]
        got = bool(R.hits([text], [R.Check(entry, js=False) for entry in SETS[name]], strip_invisible=False, nfkc=False))
        assert got == engine_hit(pattern, case_sensitive, text)
    if vector["checks"] in ("baseline", "mixed"):
        baseline = [R.Check(entry, js=False) for entry in SETS["baseline"]]
        got = bool(R.hits([text], baseline, strip_invisible=True, nfkc=False))
        lines = R.NEWLINE.split(visible(text))
        assert got == any(pattern.search(line) for pattern in INJECTION for line in lines)
