"""SKILL.md frontmatter (spec 5.5): a leading `---` block, YAML loaded with
the safe loader, the five metadata fields with their fallbacks."""
from __future__ import annotations

import re
from collections.abc import Mapping

import yaml

from spellwarden_scan.model import Metadata

NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")  # always `fullmatch`: `$` would accept a trailing newline
_LINE = re.compile(r"[^\n]*\n|[^\n]+$")
DESCRIPTION_MAX = 1024
FIELDS = ("name", "description", "version", "license", "publisher")


class FrontmatterError(ValueError):
    """`reason` is one of `missing`, `unclosed`, `invalid_yaml`, `not_a_mapping`."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """`(mapping, body)` of a file that starts with a `---` line (spec 5.5)."""
    if text.startswith("\ufeff"):  # a byte-order mark is not part of the first line
        text = text[1:]
    # Split on `\n` only, like `package.split_lines`: `splitlines()` also breaks at `\x0c`, `\x85` or U+2028,
    # which would let a `---` hidden behind one of them end the frontmatter here but not for an agent.
    lines = _LINE.findall(text)
    if not lines or lines[0].rstrip("\r\n") != "---":
        raise FrontmatterError("missing")
    for index in range(1, len(lines)):
        if lines[index].rstrip("\r\n") == "---":
            block = "".join(lines[1:index])
            body = "".join(lines[index + 1:])
            try:
                loaded = yaml.safe_load(block)
            except yaml.YAMLError as exc:
                raise FrontmatterError("invalid_yaml") from exc
            if loaded is None:
                loaded = {}
            if not isinstance(loaded, dict):
                raise FrontmatterError("not_a_mapping")
            return loaded, body
    raise FrontmatterError("unclosed")


def _string(mapping: Mapping, key: str) -> str | None:
    value = mapping.get(key)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    return value if isinstance(value, str) else None


def _field(mapping: Mapping, key: str) -> str | None:
    """The top-level key, else the same key under a nested `metadata` mapping."""
    value = _string(mapping, key)
    if value is None:
        nested = mapping.get("metadata")
        if isinstance(nested, Mapping):
            value = _string(nested, key)
    return value


def skill_md_path(files: Mapping[str, bytes], root: str = "") -> str | None:
    """The path of `SKILL.md` under `root` (a directory without a trailing slash), or `None`."""
    prefix = root.strip("/")
    wanted = f"{prefix}/SKILL.md" if prefix else "SKILL.md"
    return wanted if wanted in files else None


def metadata_of(files: Mapping[str, bytes], root: str = "") -> Metadata:
    """The `Metadata` of a package (spec 5.5): fields, which are present, and
    the problems rule SW-SKL-015 reports."""
    path = skill_md_path(files, root)
    if path is None:
        return Metadata(None, None, None, None, None, frozenset(), False, ("SKILL.md is missing",))
    text = files[path].decode("utf-8", errors="replace")
    try:
        mapping, _ = parse_frontmatter(text)
    except FrontmatterError as exc:
        reason = {"missing": "frontmatter is missing", "unclosed": "frontmatter is not closed",
                  "invalid_yaml": "frontmatter is not valid YAML", "not_a_mapping": "frontmatter is not a mapping"}[exc.reason]
        return Metadata(None, None, None, None, None, frozenset(), False, (reason,))
    values = {key: _field(mapping, key) for key in FIELDS}
    if values["publisher"] is None:
        values["publisher"] = _field(mapping, "author")
    present = frozenset(key for key, value in values.items() if value is not None and value.strip())
    problems: list[str] = []
    name = values["name"]
    if name is None or NAME_RE.fullmatch(name) is None:
        problems.append("name must match ^[a-z0-9][a-z0-9-]{0,63}$")
    description = values["description"]
    if description is None or not description.strip():
        problems.append("description is missing or blank")
    elif len(description) > DESCRIPTION_MAX:
        problems.append("description is over 1024 characters")
    return Metadata(values["name"], values["description"], values["version"], values["license"], values["publisher"],
                    present, not problems, tuple(problems))
