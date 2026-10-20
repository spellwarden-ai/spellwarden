"""The bounded YAML loader (spec 6.3) for the two files the scanned revision
supplies (`.spellwarden/config.yml`, `.spellwarden/baseline.yml`). It walks the
parser's event stream first and refuses, before any Python object is built:
an oversized file, anchors and aliases, the merge key, explicit tags, deep
nesting, huge collections and long scalars. Only then does `SafeLoader` build
the value."""
from __future__ import annotations

import yaml

CONFIG_MAX = 64 * 1024
BASELINE_MAX = 2**20
MAX_DEPTH = 8
MAX_ENTRIES = 10_000
MAX_SCALAR = 4096

_COLLECTION_STARTS = (yaml.MappingStartEvent, yaml.SequenceStartEvent)
_COLLECTION_ENDS = (yaml.MappingEndEvent, yaml.SequenceEndEvent)


class YamlRefused(ValueError):
    """`rule` names what was refused (spec 6.3)."""

    def __init__(self, name: str, rule: str, detail: str = "") -> None:
        super().__init__(f"{name}: refused ({rule}){': ' + detail if detail else ''}")
        self.rule = rule


def loads(data: bytes, *, max_bytes: int, name: str) -> object:
    if len(data) > max_bytes:
        raise YamlRefused(name, "too_large", f"more than {max_bytes} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise YamlRefused(name, "not_yaml", "not UTF-8") from exc
    try:
        _check_events(text, name)
        return yaml.load(text, Loader=yaml.SafeLoader)  # noqa: S506 - every refusal above has been checked
    except yaml.YAMLError as exc:
        raise YamlRefused(name, "not_yaml", str(exc).splitlines()[0] if str(exc) else "") from exc


def _check_events(text: str, name: str) -> None:
    # One frame per open collection: [is_mapping, entries, next scalar is a key]
    stack: list[list] = []
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            raise YamlRefused(name, "alias")
        if isinstance(event, (yaml.ScalarEvent, *_COLLECTION_STARTS)):
            if event.anchor is not None:
                raise YamlRefused(name, "anchor")
            if _explicit_tag(event):
                raise YamlRefused(name, "tag", str(event.tag))
            is_key = _count_node(stack, name)
            if isinstance(event, yaml.ScalarEvent):
                if len(event.value) > MAX_SCALAR:
                    raise YamlRefused(name, "scalar_too_long", f"more than {MAX_SCALAR} characters")
                if is_key and event.value == "<<":
                    raise YamlRefused(name, "merge_key")
            else:
                if len(stack) >= MAX_DEPTH:
                    raise YamlRefused(name, "too_deep", f"nesting deeper than {MAX_DEPTH}")
                stack.append([isinstance(event, yaml.MappingStartEvent), 0, True])
        elif isinstance(event, _COLLECTION_ENDS):
            stack.pop()


def _explicit_tag(event) -> bool:
    if event.tag is None:
        return False
    if isinstance(event, yaml.ScalarEvent):
        return not (event.implicit[0] or event.implicit[1])
    return not event.implicit


def _count_node(stack: list[list], name: str) -> bool:
    """Counts the node in its parent collection; True when the node is a mapping key."""
    if not stack:
        return False
    frame = stack[-1]
    is_mapping, _, expecting_key = frame
    if is_mapping:
        frame[2] = not expecting_key
        if not expecting_key:
            return False
    frame[1] += 1
    if frame[1] > MAX_ENTRIES:
        raise YamlRefused(name, "too_many_entries", f"more than {MAX_ENTRIES} entries")
    return is_mapping


__all__ = ["BASELINE_MAX", "CONFIG_MAX", "MAX_DEPTH", "MAX_ENTRIES", "MAX_SCALAR", "YamlRefused", "loads"]
