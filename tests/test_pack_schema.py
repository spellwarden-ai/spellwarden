"""Phase C spec 5.4 and claim E6 (the schema half): `schemas/pack.schema.json`
is valid draft 2020-12, its closed lists equal the engine's, it accepts and
refuses the same fixtures as `validate_pack`, and its character classes
refuse exactly the characters `text.valid_line` and `valid_block` refuse."""
from __future__ import annotations

import json
import re
import sys
import unicodedata
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from spellwarden_scan.orgrules import PROBE_PREDICATES
from spellwarden_scan.packs import ENFORCEMENT_IDS, PackError, validate_pack
from spellwarden_scan.rules import ALLOWED_NIST, ALLOWED_OWASP
from spellwarden_scan.text import valid_block, valid_line

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "pack.schema.json").read_text(encoding="utf-8"))
PACKS = ROOT / "fixtures" / "packs"
VALIDATOR = Draft202012Validator(SCHEMA)


def fixtures(kind: str) -> list[Path]:
    return sorted((PACKS / kind).rglob("*.json"))


def test_the_schema_is_valid_draft_2020_12():
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_the_closed_lists_equal_the_engine():
    rules = SCHEMA["properties"]["rules"]["prefixItems"]
    assert [item["properties"]["id"]["const"] for item in rules] == list(ENFORCEMENT_IDS)
    org = SCHEMA["$defs"]["orgRule"]["properties"]
    assert org["owasp"]["items"]["enum"] == list(ALLOWED_OWASP)
    assert org["nist"]["items"]["enum"] == list(ALLOWED_NIST)
    assert org["targets"]["items"]["enum"] == ["claude-code-hooks", "kong"]
    predicates = [branch["properties"]["predicate"]["const"] for branch in SCHEMA["$defs"]["probeDetection"]["oneOf"]]
    assert predicates == list(PROBE_PREDICATES)


@pytest.mark.parametrize("path", fixtures("valid"), ids=lambda p: p.stem)
def test_the_schema_accepts_every_valid_fixture(path):
    VALIDATOR.validate(json.loads(path.read_text(encoding="utf-8")))


@pytest.mark.parametrize("path", fixtures("invalid"), ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_the_schema_refuses_every_invalid_fixture_the_code_refuses(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    with pytest.raises(PackError):
        validate_pack(doc)
    assert not VALIDATOR.is_valid(doc), path.name


def _class(name: str) -> re.Pattern[str]:
    if name == "line":
        return re.compile(SCHEMA["properties"]["pack"]["properties"]["name"]["not"]["pattern"])
    return re.compile(SCHEMA["properties"]["pack"]["properties"]["description"]["anyOf"][1]["not"]["pattern"])


def test_the_schema_character_classes_equal_the_text_rules():
    """Every assigned code point (and the tag block, refused whole): the schema refuses it exactly when the text
    rules do. Unassigned code points are skipped, since a newer Unicode may assign them."""
    line, block = _class("line"), _class("block")
    for cp in range(sys.maxunicode + 1):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        ch = chr(cp)
        if unicodedata.category(ch) == "Cn" and not 0xE0000 <= cp <= 0xE007F:
            continue
        assert (line.search(ch) is not None) == (not valid_line(f"a{ch}a", 80)), hex(cp)
        assert (block.search(ch) is not None) == (not valid_block(f"a{ch}a", 80)), hex(cp)
