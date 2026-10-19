"""Spec 5.5 and claim P8."""
from __future__ import annotations

import pytest

from spellwarden_scan.frontmatter import FrontmatterError, metadata_of, parse_frontmatter


def test_a_valid_block_gives_the_mapping_and_the_body():
    mapping, body = parse_frontmatter("---\nname: demo\ndescription: Does things.\n---\n# Demo\nBody.\n")
    assert mapping == {"name": "demo", "description": "Does things."}
    assert body == "# Demo\nBody.\n"


@pytest.mark.parametrize("text, reason", [
    ("# No block\n", "missing"),
    ("---\nname: demo\n", "unclosed"),
    ("---\n- a\n- b\n---\n", "not_a_mapping"),
    ("---\nname: !!python/object/apply:os.system ['true']\n---\n", "invalid_yaml"),
    ("---\nname: [unclosed\n---\n", "invalid_yaml"),
])
def test_rejections_carry_a_reason(text, reason):
    with pytest.raises(FrontmatterError) as caught:
        parse_frontmatter(text)
    assert caught.value.reason == reason


def test_a_byte_order_mark_and_windows_line_endings_still_parse():
    mapping, body = parse_frontmatter("\ufeff---\r\nname: demo\r\ndescription: Does things.\r\n---\r\nBody\r\n")
    assert mapping == {"name": "demo", "description": "Does things."} and body == "Body\r\n"
    assert metadata_of({"SKILL.md": "\ufeff---\nname: demo\ndescription: D.\n---\n".encode()}).frontmatter_ok


def test_metadata_reads_nested_fields_and_author_as_publisher():
    files = {"SKILL.md": b"---\nname: demo\ndescription: Does things.\nauthor: Ada\nmetadata:\n  version: 2.1.0\n  license: MIT\n---\nBody\n"}
    meta = metadata_of(files)
    assert (meta.name, meta.description, meta.version, meta.license, meta.publisher) == ("demo", "Does things.", "2.1.0", "MIT", "Ada")
    assert meta.present == frozenset({"name", "description", "version", "license", "publisher"})
    assert meta.frontmatter_ok and meta.problems == ()


def test_metadata_problems_name_each_defect():
    meta = metadata_of({"SKILL.md": b"---\nname: Bad Name\ndescription: ''\n---\n"})
    assert not meta.frontmatter_ok
    assert meta.problems == ("name must match ^[a-z0-9][a-z0-9-]{0,63}$", "description is missing or blank")
    assert metadata_of({"README.md": b"x"}).problems == ("SKILL.md is missing",)
    assert metadata_of({"SKILL.md": b"no block"}).problems == ("frontmatter is missing",)
    long = "x" * 1025
    assert metadata_of({"SKILL.md": f"---\nname: ok\ndescription: {long}\n---\n".encode()}).problems == ("description is over 1024 characters",)


def test_metadata_honours_the_root():
    files = {"plugins/a/SKILL.md": b"---\nname: a\ndescription: A.\n---\n", "SKILL.md": b"---\nname: top\ndescription: Top.\n---\n"}
    assert metadata_of(files, root="plugins/a").name == "a"
    assert metadata_of(files, root="plugins/a/").name == "a"
