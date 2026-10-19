"""Spec 5.5 and claim P3: the canonical hash is stable across order and changes with one byte."""
from __future__ import annotations

import hashlib

from spellwarden_scan.canonical import canonical_sha256


def test_stable_across_insertion_order_and_sensitive_to_one_byte():
    a = {"SKILL.md": b"---\nname: x\n---\n", "scripts/run.sh": b"echo hi\n", "docs/notes.md": b"n\n"}
    b = {"docs/notes.md": b"n\n", "SKILL.md": b"---\nname: x\n---\n", "scripts/run.sh": b"echo hi\n"}
    c = {"scripts/run.sh": b"echo hi\n", "docs/notes.md": b"n\n", "SKILL.md": b"---\nname: x\n---\n"}
    assert canonical_sha256(a) == canonical_sha256(b) == canonical_sha256(c)
    changed = dict(a)
    changed["scripts/run.sh"] = b"echo hi!\n"
    assert canonical_sha256(changed) != canonical_sha256(a)


def test_the_definition_is_sorted_path_nul_content_nul():
    files = {"b": b"2", "a": b"1"}
    digest = hashlib.sha256(b"a\x001\x00b\x002\x00").hexdigest()
    assert canonical_sha256(files) == digest
    assert len(canonical_sha256({})) == 64
