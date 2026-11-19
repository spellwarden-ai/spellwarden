"""SKILL.md frontmatter (spec 5.5): a leading `---` block, YAML loaded with
the safe loader, the five metadata fields with their fallbacks. Since 1.19.0 a
block past one of four limits is refused before it is loaded (`FrontmatterLimit`)."""
from __future__ import annotations

import re
from collections.abc import Mapping

import yaml

from spellwarden_scan.model import Metadata
from spellwarden_scan.text import replace_lone_surrogates_in_json

NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")  # always `fullmatch`: `$` would accept a trailing newline
_LINE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+$")
DESCRIPTION_MAX = 1024
FIELDS = ("name", "description", "version", "license", "publisher")
# 1.19.0: what one front matter may hold. Content the user controls: a block past one is not read, and the caller reports it as
# an error (the command: `unreadable`, exit 2), never as a finding. Each is at least ten times the largest front matter of the
# repository's fixtures (tests/test_frontmatter_limits.py).
FRONTMATTER_MAX_BYTES = 64 * 1024
FRONTMATTER_MAX_NODES = 2_000
FRONTMATTER_MAX_DEPTH = 32
FRONTMATTER_MAX_ALIASES = 50
_COLLECTION_STARTS = (yaml.MappingStartEvent, yaml.SequenceStartEvent)
_COLLECTION_ENDS = (yaml.MappingEndEvent, yaml.SequenceEndEvent)


class FrontmatterError(ValueError):
    """`reason` is one of `missing`, `unclosed`, `invalid_yaml`, `not_a_mapping`, and since 1.19.0 `over_limit`
    (`FrontmatterLimit`)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class FrontmatterLimit(FrontmatterError):
    """1.19.0: the front matter is past one of the limits above and was not read. `limit` is `bytes`, `nodes`, `depth` or
    `aliases`, `detail` says it in words, `path` names the file when the raiser knows it (`metadata_of` and the rules that read
    front matter set it; `parse_frontmatter`, which gets text only, leaves it None). `scan_skill_package` raises it: unread
    content is the caller's error to report, never a finding and never a malformed front matter."""

    def __init__(self, limit: str, detail: str, path: str | None = None) -> None:
        super().__init__("over_limit")
        self.limit = limit
        self.detail = detail
        self.path = path

    def at(self, path: str) -> FrontmatterLimit:
        """The same refusal, naming the file `path`."""
        return FrontmatterLimit(self.limit, self.detail, path)


def split_frontmatter(text: str) -> tuple[str, str]:
    """`(block, body)` of a file that starts with a `---` line: the text up to the next `---` line, and the rest. Raises
    `FrontmatterError` (`missing`, `unclosed`)."""
    if text.startswith("\ufeff"):  # a byte-order mark is not part of the first line
        text = text[1:]
    # Split at `\r\n`, `\r` and `\n` only, like `package.split_lines`: `splitlines()` also breaks at `\x0c`, `\x85` or U+2028,
    # which would let a `---` hidden behind one of them end the frontmatter here but not for an agent.
    lines = _LINE.findall(text)
    if not lines or lines[0].rstrip("\r\n") != "---":
        raise FrontmatterError("missing")
    for index in range(1, len(lines)):
        if lines[index].rstrip("\r\n") == "---":
            return "".join(lines[1:index]), "".join(lines[index + 1:])
    raise FrontmatterError("unclosed")


def measure(block: str, *, enforce: bool = False) -> tuple[int, int, int, int]:
    """`(bytes, nodes, depth, aliases)` of a front-matter block: its UTF-8 size, its scalars, mappings and sequences, its deepest
    nesting (the top mapping is depth 1) and its aliases, read from the YAML event stream; `yaml.YAMLError` for text that is not
    YAML. With `enforce`, raises `FrontmatterLimit` at the first limit passed: the size before any parsing, the others while the
    events are read, so a refused block costs one pass over at most 64 KiB."""
    size = len(block.encode("utf-8", "surrogatepass"))
    if enforce and size > FRONTMATTER_MAX_BYTES:
        raise FrontmatterLimit("bytes", f"the front matter is {size:,} bytes, more than the {FRONTMATTER_MAX_BYTES:,} the "
                                        "scanner reads")
    nodes = depth = deepest = aliases = 0
    for event in yaml.parse(block, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            aliases += 1
            if enforce and aliases > FRONTMATTER_MAX_ALIASES:
                raise FrontmatterLimit("aliases", f"the front matter holds more than {FRONTMATTER_MAX_ALIASES} YAML aliases")
        elif isinstance(event, (yaml.ScalarEvent, *_COLLECTION_STARTS)):
            nodes += 1
            if enforce and nodes > FRONTMATTER_MAX_NODES:
                raise FrontmatterLimit("nodes", f"the front matter holds more than {FRONTMATTER_MAX_NODES:,} YAML nodes")
            if not isinstance(event, yaml.ScalarEvent):
                depth += 1
                deepest = max(deepest, depth)
                if enforce and depth > FRONTMATTER_MAX_DEPTH:
                    raise FrontmatterLimit("depth", f"the front matter is nested deeper than {FRONTMATTER_MAX_DEPTH}")
        elif isinstance(event, _COLLECTION_ENDS):
            depth -= 1
    return size, nodes, deepest, aliases


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """`(mapping, body)` of a file that starts with a `---` line (spec 5.5). Since 1.19.0 a block past one of the limits raises
    `FrontmatterLimit` before it is loaded."""
    block, body = split_frontmatter(text)
    try:  # 1.18.0: the one YAML boundary of the engine; a lone surrogate from a quoted escape becomes U+FFFD here
        measure(block, enforce=True)
        loaded = replace_lone_surrogates_in_json(yaml.safe_load(block))
    except yaml.YAMLError as exc:
        raise FrontmatterError("invalid_yaml") from exc
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise FrontmatterError("not_a_mapping")
    return loaded, body


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
    the problems rule SW-SKL-015 reports. Since 1.19.0 a front matter past a limit raises `FrontmatterLimit` naming the
    SKILL.md: it was not read, so no metadata problem is made of it."""
    path = skill_md_path(files, root)
    if path is None:
        return Metadata(None, None, None, None, None, frozenset(), False, ("SKILL.md is missing",))
    text = files[path].decode("utf-8", errors="replace")
    try:
        mapping, _ = parse_frontmatter(text)
    except FrontmatterLimit as exc:
        raise exc.at(path) from None
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
