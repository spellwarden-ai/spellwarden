"""Spec 6.3 and claim C9: the bounded YAML loader refuses hostile documents
before building any object, within one second and 50 MiB."""
from __future__ import annotations

import time
import tracemalloc

import pytest

from spellwarden_cli.safe_yaml import BASELINE_MAX, CONFIG_MAX, YamlRefused, loads


def _billion_laughs() -> bytes:
    lines = ['a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    for index in range(1, 10):
        name, prev = chr(ord("a") + index), chr(ord("a") + index - 1)
        lines.append(f"{name}: &{name} [{', '.join(['*' + prev] * 9)}]")
    return ("\n".join(lines) + "\n").encode()


HOSTILE = {
    "alias_bomb": (_billion_laughs(), "anchor"),
    "deep_nesting": (b"[" * 10_000 + b"]" * 10_000, "too_deep"),
    "huge_scalar": (b"a: " + b"x" * (10 * 2**20) + b"\n", "too_large"),
    "long_scalar": (b"a: " + b"x" * 5000 + b"\n", "scalar_too_long"),
    "python_tag": (b"a: !!python/object/apply:os.system ['echo pwned']\n", "tag"),
    "local_tag": (b"a: !custom 1\n", "tag"),
    "merge_key": (b"base: {x: 1}\nderived:\n  <<: {x: 2}\n", "merge_key"),
    "alias_only": (b"a: *missing\n", "alias"),
    "many_entries": (b"[" + b"1," * 10_001 + b"1]\n", "too_many_entries"),
    "not_utf8": (b"a: \xff\n", "not_yaml"),
    "two_documents": (b"a: 1\n---\nb: 2\n", "not_yaml"),
    "syntax": (b"a: [1, 2\n", "not_yaml"),
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_documents_are_refused_fast_and_small(name):
    data, rule = HOSTILE[name]
    limit = BASELINE_MAX if name == "many_entries" else CONFIG_MAX
    # Time and memory are measured on separate calls: tracemalloc slows the parser several times over.
    started = time.perf_counter()
    with pytest.raises(YamlRefused) as caught:
        loads(data, max_bytes=limit, name=".spellwarden/config.yml")
    elapsed = time.perf_counter() - started
    tracemalloc.start()
    try:
        with pytest.raises(YamlRefused):
            loads(data, max_bytes=limit, name=".spellwarden/config.yml")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert caught.value.rule == rule
    assert ".spellwarden/config.yml" in str(caught.value) and rule in str(caught.value)
    assert elapsed < 1.0, f"{name} took {elapsed:.2f} s"
    assert peak < 50 * 2**20, f"{name} peaked at {peak} bytes"


def test_ordinary_documents_load():
    text = b"version: 1\ninclude: []\nexclude: ['tests/fixtures/**']\nfail-on: high\nprobe: false\ntelemetry: true\n"
    assert loads(text, max_bytes=CONFIG_MAX, name="c") == {
        "version": 1, "include": [], "exclude": ["tests/fixtures/**"], "fail-on": "high", "probe": False,
        "telemetry": True}


def test_a_quoted_merge_marker_as_a_value_and_dates_are_ordinary():
    loaded = loads(b"a: '<<'\nadded: 2026-12-01\n", max_bytes=CONFIG_MAX, name="c")
    assert loaded["a"] == "<<"
    assert loaded["added"].isoformat() == "2026-12-01"


def test_eight_levels_load_and_nine_do_not():
    eight = b"a:" + b"".join(b"\n" + b"  " * level + b"k:" for level in range(1, 8)) + b" 1\n"
    loads(eight, max_bytes=CONFIG_MAX, name="c")
    with pytest.raises(YamlRefused) as caught:
        loads(b"[" * 9 + b"]" * 9, max_bytes=CONFIG_MAX, name="c")
    assert caught.value.rule == "too_deep"
