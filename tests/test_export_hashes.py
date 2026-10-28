"""Zuplo export spec invariant 1 and claim E9: the `claude-code-hooks` (both modes) and `kong` exports of every valid
fixture pack are byte-identical to the 1.5.0 exports. `fixtures/export_hashes_1.5.0.json` holds the SHA-256 of every
file of every such export, recorded with the 1.5.0 code before the Zuplo target existed:

    uv run --locked python tests/test_export_hashes.py record      (only on a tree whose exports are those of 1.5.0)

A fixture added after 1.5.0 is not in the file and is not checked here."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from spellwarden_scan.exports import build
from spellwarden_scan.packs import validate_pack

ROOT = Path(__file__).resolve().parents[1]
PACKS = ROOT / "fixtures" / "packs" / "valid"
HASHES = ROOT / "fixtures" / "export_hashes_1.5.0.json"
BUILT = "2026-12-01T10:00:00Z"
VARIANTS = (("claude-code-hooks", "project"), ("claude-code-hooks", "managed"), ("kong", "project"))


def hashes_of(name: str) -> dict[str, dict[str, str]]:
    doc = validate_pack(json.loads((PACKS / f"{name}.json").read_text(encoding="utf-8")))
    result: dict[str, dict[str, str]] = {}
    for target, mode in VARIANTS:
        files = build(doc, target, built_at=BUILT, mode=mode)
        result[f"{target}:{mode}"] = {path: hashlib.sha256(content).hexdigest() for path, content in sorted(files.items())}
    return result


def recorded() -> dict:
    return json.loads(HASHES.read_text(encoding="utf-8"))


def test_the_recorded_fixtures_are_the_valid_fixtures_of_1_5_0():
    assert sorted(recorded()) == ["all-off", "baseline", "names-quotes", "names-unicode", "with-org-rules"]


@pytest.mark.parametrize("name", ["all-off", "baseline", "names-quotes", "names-unicode", "with-org-rules"])
def test_hooks_and_kong_exports_equal_the_1_5_0_hashes(name):
    assert hashes_of(name) == recorded()[name]


if __name__ == "__main__":
    if sys.argv[1:] != ["record"]:
        raise SystemExit("usage: python tests/test_export_hashes.py record")
    names = sorted(path.stem for path in PACKS.glob("*.json"))
    HASHES.write_text(json.dumps({name: hashes_of(name) for name in names}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("recorded", ", ".join(names))
