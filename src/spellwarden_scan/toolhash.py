"""The canonical listing of what a probed MCP server advertised, and its hashes (1.15.0).

One listing per probe: the server's tools, prompts, resources, resource templates and instructions, each item with its
own hash, one hash per kind and one digest for the whole. The hosted product stores a server's first listing as its
approved list and passes it back to `evaluate_probe(..., baseline=...)`, which raises SW-MCP-012 for every item that
was added, removed or changed since; the scanner pins the kind hashes in its lock file. Both sides use this module, so a
listing hashes the same wherever it is computed.

- Items. A tool is `{name, description, input_schema}` (annotations are not hashed), a prompt `{name, title, description,
  arguments}` with its arguments `{name, description}` sorted by name, a resource `{uri, name, title, description}`, a
  resource template `{uri_template, name, title, description}` and the instructions `{text}` (one item, "" when the server
  sent none). Item keys: `tool:<name>`, `prompt:<name>`, `resource:<uri>`, `resource_template:<uri_template>`,
  `instructions`.
- Text normalisation, the only whitespace the hash ignores. In a description, a title and the instructions: `None` is "",
  Unicode NFC, `\\r\\n` and `\\r` become `\\n`, spaces and tabs at the end of each line are removed, and so is the leading
  and trailing whitespace of the whole text. Line endings, trailing spaces and the NFC form differ between server
  frameworks, operating systems and serialisers without any change of meaning, and a hash that saw them would raise
  findings no person could act on. Spaces inside a line, blank lines inside a text, case and every other character are
  content: an instruction can hide in them. Names, URIs and URI templates are compared exactly.
- Schemas. An input schema is serialised with RFC 8785 (`jcs`), so key order and number spelling do not matter; strings
  inside it are not normalised; a missing schema, or one that is not an object, is `null`.
- Never raising on what a server sent. A lone surrogate in any string field becomes U+FFFD before anything else, in the
  hash and in the snapshot. A schema that `jcs` refuses (an integer above 2**53, such as `9223372036854775807`, or a
  string it cannot encode) is held as `input_schema: null` plus `input_schema_text`, its sorted-key compact JSON text:
  key order still does not matter for such a schema, number spelling does (`1.0` and `1` differ). So is a schema that
  nests objects and arrays deeper than `MAX_SCHEMA_DEPTH` (128) levels, which is never handed to `jcs`: `jcs` recurses
  once per level, and neither a failure nor a hash may depend on how much of the interpreter's recursion limit is left
  where the listing is computed. `change_details` shows no body for a schema that deep.
- Hashes. Item hash: SHA-256 hex of `ITEM_PREFIX + JCS(normalised fields)`. Kind hash: SHA-256 hex of the JCS of the
  sorted list of `[key, item hash]`, so the order the server returned does not matter and a duplicate name counts. Digest:
  SHA-256 hex of `JCS({"format": 1, "kinds": {kind: kind hash}})` over the kinds the probe read.
- Read and complete. `tools` is read when `tools_source` is `probe` and complete when `tools_complete`; `prompts`,
  `resources` and `resource_templates` are read when named in `lists_read` and complete when their `*_complete` flag is
  true; `instructions` is read when the probe was reachable and `server/discover` or `initialize` answered, and complete
  when the text was not cut.

Pure: no I/O (tests/test_pure.py)."""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from spellwarden_scan.jcs import JcsError, jcs_canonicalize
from spellwarden_scan.model import ProbeResult

FORMAT = 1
ITEM_PREFIX = b"spellwarden-tool-item-v1\x00"
KINDS = ("tools", "prompts", "resources", "resource_templates", "instructions")
# A schema nested deeper than this is hashed and stored as text, never handed to `jcs` (the module docstring says why).
MAX_SCHEMA_DEPTH = 128
CHANGES = ("changed", "added", "removed")
TEXT_FIELDS = ("description", "title", "text")
# The fields `change_details` shows for each side of a change (the changes route of the hosted product).
BODY_FIELDS = ("title", "description", "input_schema", "arguments", "uri")
UNSERIALISABLE = "(schema not serialisable)"
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
_TRAILING_BLANKS = re.compile(r"[ \t]+$", re.MULTILINE)


def clean(value: object) -> str:
    """A string field as it is hashed and stored: a non-string (`None`) is "", a lone surrogate is U+FFFD."""
    if not isinstance(value, str):
        return ""
    return _LONE_SURROGATE.sub("\ufffd", value)


def normalise_text(value: object) -> str:
    """The normalisation of a description, a title or the instructions (the module docstring says why)."""
    text = unicodedata.normalize("NFC", clean(value))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _TRAILING_BLANKS.sub("", text).strip()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _too_deep(value: object) -> bool:
    """Whether `value` nests objects and arrays deeper than MAX_SCHEMA_DEPTH levels (`{}` is one level). A loop, not a
    recursion, so the answer is the same at every depth of the caller's stack and no depth raises."""
    pending = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if isinstance(current, dict):
            inner = list(current.values())
        elif isinstance(current, (list, tuple)):
            inner = list(current)
        else:
            continue
        if depth > MAX_SCHEMA_DEPTH:
            return True
        pending.extend((item, depth + 1) for item in inner)
    return False


def _schema_fields(schema: object) -> dict:
    """`{"input_schema": ...}`, or `{"input_schema": None, "input_schema_text": ...}` for a schema `jcs` refuses or one
    nested deeper than MAX_SCHEMA_DEPTH."""
    if not isinstance(schema, dict):
        return {"input_schema": None}
    if _too_deep(schema):
        return {"input_schema": None, "input_schema_text": _schema_text(schema)}
    try:
        jcs_canonicalize(schema)
    except (JcsError, RecursionError):
        return {"input_schema": None, "input_schema_text": _schema_text(schema)}
    return {"input_schema": schema}


def _schema_text(schema: dict) -> str:
    """The sorted-key compact JSON text the probe measured (`_schema_of`), lone surrogates replaced."""
    try:
        text = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except ValueError:
        try:
            text = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError, RecursionError):
            return UNSERIALISABLE
    except (TypeError, RecursionError):
        return UNSERIALISABLE
    return clean(text)


def _hash_fields(fields: Mapping) -> dict:
    """The fields the item hash sees: the texts normalised, everything else as stored."""
    seen = {}
    for name, value in fields.items():
        if name in TEXT_FIELDS:
            seen[name] = normalise_text(value)
        elif name == "arguments":
            seen[name] = [{"name": argument["name"], "description": normalise_text(argument["description"])}
                          for argument in value]
        else:
            seen[name] = value
    return seen


def item_hash(fields: Mapping) -> str:
    return _sha256(ITEM_PREFIX + jcs_canonicalize(_hash_fields(fields)))


@dataclass(frozen=True)
class ListedItem:
    """One item of a kind: its key, its hash and its fields as probed (lone surrogates replaced, texts not normalised)."""
    key: str
    hash: str
    fields: dict


@dataclass(frozen=True)
class KindListing:
    """One kind the probe read. `complete` is false when the server sent only part of it (the probe's caps) or when the
    probe cut a text or dropped a schema in it (a change past a cut is not seen). `entries_complete` says whether every
    entry was read, cut or not; None means the same as `complete`. A list whose entries are all present proves that an
    entry is new or gone even when a text in it was cut."""
    read: bool
    complete: bool
    hash: str
    items: tuple[ListedItem, ...]
    entries_complete: bool | None = None

    @property
    def entries_whole(self) -> bool:
        return self.complete if self.entries_complete is None else self.entries_complete


def _item(key: str, fields: dict) -> ListedItem:
    return ListedItem(key=key, hash=item_hash(fields), fields=fields)


def _kind(items: Iterable[ListedItem], *, complete: bool, cut: bool = False) -> KindListing:
    """`complete`: every entry was read; `cut`: a text in it was cut or a schema dropped."""
    ordered = tuple(sorted(items, key=lambda item: (item.key, item.hash)))
    pairs = [[item.key, item.hash] for item in ordered]
    return KindListing(read=True, complete=complete and not cut, hash=_sha256(jcs_canonicalize(pairs)), items=ordered,
                       entries_complete=complete if cut else None)


def kinds_digest(kinds: Mapping[str, str]) -> str:
    """The digest of a listing whose kind hashes are `kinds`."""
    return _sha256(jcs_canonicalize({"format": FORMAT, "kinds": dict(kinds)}))


@dataclass(frozen=True)
class ToolListing:
    """The canonical listing of one probe: `kinds` holds only the kinds the probe read, in `KINDS` order."""
    digest: str
    kinds: dict[str, KindListing] = field(default_factory=dict)

    def kind_hashes(self) -> dict[str, str]:
        return {kind: listed.hash for kind, listed in self.kinds.items()}

    def to_json(self) -> bytes:
        """The snapshot the hosted product stores: the JCS of `{"format": 1, "digest", "kinds": {kind: {"complete",
        "hash", "items": [{"key", "hash", "fields"}]}}}`, plus `"entries_complete"` in a kind only when it differs from
        `complete` (a list with a cut text). Equal listings give equal bytes."""
        def kind_of(listed: KindListing) -> dict:
            value = {"complete": listed.complete, "hash": listed.hash,
                     "items": [{"key": item.key, "hash": item.hash, "fields": item.fields} for item in listed.items]}
            if listed.entries_complete is not None and listed.entries_complete != listed.complete:
                value["entries_complete"] = listed.entries_complete
            return value
        return jcs_canonicalize({"format": FORMAT, "digest": self.digest,
                                 "kinds": {kind: kind_of(listed) for kind, listed in self.kinds.items()}})

    @classmethod
    def from_json(cls, data: bytes) -> ToolListing:
        """The listing a snapshot holds. Raises ValueError for bytes that are not a format 1 snapshot."""
        try:
            document = json.loads(data.decode("utf-8"))
            if document.get("format") != FORMAT or not isinstance(document.get("digest"), str):
                raise ValueError("not a tool listing snapshot of format 1")
            kinds = {}
            for kind in KINDS:
                if kind not in document["kinds"]:
                    continue
                listed = document["kinds"][kind]
                items = tuple(ListedItem(key=entry["key"], hash=entry["hash"], fields=entry["fields"])
                              for entry in listed["items"])
                entries = listed.get("entries_complete")
                kinds[kind] = KindListing(read=True, complete=bool(listed["complete"]), hash=listed["hash"], items=items,
                                          entries_complete=None if entries is None else bool(entries))
        except (UnicodeDecodeError, AttributeError, KeyError, TypeError, RecursionError) as exc:
            raise ValueError("not a tool listing snapshot of format 1") from exc
        return cls(digest=document["digest"], kinds=kinds)


def _listing(kinds: Mapping[str, KindListing]) -> ToolListing:
    ordered = {kind: kinds[kind] for kind in KINDS if kind in kinds}
    return ToolListing(digest=kinds_digest({kind: listed.hash for kind, listed in ordered.items()}), kinds=ordered)


def _tool(tool) -> ListedItem:
    fields = {"name": clean(tool.name), "description": clean(tool.description), **_schema_fields(tool.input_schema)}
    return _item(f"tool:{fields['name']}", fields)


def _prompt(prompt) -> ListedItem:
    arguments = sorted(({"name": clean(argument.name), "description": clean(argument.description)}
                        for argument in prompt.arguments), key=lambda argument: (argument["name"], argument["description"]))
    fields = {"name": clean(prompt.name), "title": clean(prompt.title), "description": clean(prompt.description),
              "arguments": arguments}
    return _item(f"prompt:{fields['name']}", fields)


def _resource(resource) -> ListedItem:
    fields = {"uri": clean(resource.uri), "name": clean(resource.name), "title": clean(resource.title),
              "description": clean(resource.description)}
    return _item(f"resource:{fields['uri']}", fields)


def _template(template) -> ListedItem:
    fields = {"uri_template": clean(template.uri_template), "name": clean(template.name), "title": clean(template.title),
              "description": clean(template.description)}
    return _item(f"resource_template:{fields['uri_template']}", fields)


def listing_of(probe: ProbeResult) -> ToolListing | None:
    """The listing of `probe` (the module docstring says which kinds are read), or None when it read no kind."""
    kinds: dict[str, KindListing] = {}
    cut = set(getattr(probe, "lists_cut", ()) or ())  # a text cut at the prober's cap hides any change past the cut
    if probe.tools_source == "probe":
        kinds["tools"] = _kind((_tool(tool) for tool in probe.tools), complete=probe.tools_complete, cut="tools" in cut)
    if "prompts" in probe.lists_read:
        kinds["prompts"] = _kind((_prompt(prompt) for prompt in probe.prompts), complete=probe.prompts_complete,
                                 cut="prompts" in cut)
    if "resources" in probe.lists_read:
        kinds["resources"] = _kind((_resource(resource) for resource in probe.resources), complete=probe.resources_complete,
                                   cut="resources" in cut)
    if "resource_templates" in probe.lists_read:
        kinds["resource_templates"] = _kind((_template(template) for template in probe.resource_templates),
                                            complete=probe.resource_templates_complete, cut="resource_templates" in cut)
    if probe.reachable and (probe.discover is not None or probe.initialize is not None):
        # one entry, always present: instructions cut at the prober's cap are a cut text, not a missing entry (1.16.1)
        kinds["instructions"] = _kind([_item("instructions", {"text": clean(probe.instructions)})],
                                      complete=True, cut=probe.instructions_truncated)
    return _listing(kinds) if kinds else None


@dataclass(frozen=True)
class Baseline:
    """The approved list a probe is compared with. `kinds` are its kind hashes; `listing` its snapshot, which may be None
    when every kind both sides read has the same hash (nothing to list); `lost` is true when the snapshot was needed and
    is gone. `approved_at` is an ISO date or time, shown in the finding of a lost baseline."""
    kinds: Mapping[str, str]
    listing: ToolListing | None
    approved_at: str | None
    lost: bool = False


@dataclass(frozen=True)
class ItemChange:
    """One added, removed or changed item. `description_changed` covers every field but the schema (for a prompt its
    title and arguments, for a resource its name and title, the instructions' text); `schema_changed` a tool's schema.
    A key held by several items (duplicate names) has its hashes joined with `+` in sorted order."""
    kind: str
    key: str
    change: str
    description_changed: bool
    schema_changed: bool
    old_hash: str | None
    new_hash: str | None
    old_fields: dict | None
    new_fields: dict | None


@dataclass(frozen=True)
class ToolDiff:
    """What `diff` found. `not_compared`: kinds the baseline read and the current listing did not; `incomplete`: kinds
    sent in part on either side (a list read in part proves presence, never absence: see `diff`); `adopted`: kinds read
    now and not in the baseline, with their hash (the hosted product adds them to the baseline without a finding);
    `baseline_lost`: a compared kind differs and the baseline's snapshot is not available, so the changes cannot be
    listed."""
    changes: tuple[ItemChange, ...]
    not_compared: tuple[str, ...]
    incomplete: tuple[str, ...]
    adopted: dict[str, str]
    baseline_lost: bool


def _by_key(listed: KindListing) -> dict[str, list[ListedItem]]:
    groups: dict[str, list[ListedItem]] = {}
    for item in listed.items:
        groups.setdefault(item.key, []).append(item)
    return {key: sorted(group, key=lambda item: item.hash) for key, group in groups.items()}


def _joined(group: list[ListedItem] | None) -> str | None:
    return "+".join(item.hash for item in group) if group else None


def _first(group: list[ListedItem] | None, other: list[ListedItem] | None = None) -> dict | None:
    """The fields shown for one side of a change: with duplicate names, the first item whose hash the other side lacks, so
    the body that changed is the one shown; else the first item."""
    if not group:
        return None
    seen = {item.hash for item in other or ()}
    return next((item.fields for item in group if item.hash not in seen), group[0].fields)


def _schema_of_fields(fields: Mapping) -> tuple:
    return fields.get("input_schema"), fields.get("input_schema_text")


def _change(kind: str, key: str, old: list[ListedItem] | None, new: list[ListedItem] | None) -> ItemChange:
    old_fields, new_fields = _first(old, new), _first(new, old)
    if old_fields is None or new_fields is None:
        description_changed = schema_changed = False
    else:
        old_seen, new_seen = _hash_fields(old_fields), _hash_fields(new_fields)
        schema_changed = _schema_of_fields(old_seen) != _schema_of_fields(new_seen)
        rest = [name for name in {*old_seen, *new_seen} if name not in ("input_schema", "input_schema_text")]
        description_changed = any(old_seen.get(name) != new_seen.get(name) for name in rest)
        if not (description_changed or schema_changed):  # duplicate names whose multisets differ in count only
            description_changed = True
    change = "changed" if old and new else ("added" if new else "removed")
    return ItemChange(kind=kind, key=key, change=change, description_changed=description_changed,
                      schema_changed=schema_changed, old_hash=_joined(old), new_hash=_joined(new), old_fields=old_fields,
                      new_fields=new_fields)


def diff(baseline: Baseline, current: ToolListing) -> ToolDiff:
    """`current` against the approved list. A kind is compared when both sides read it; in a kind sent in part on either side
    a key present on both sides is compared, a key present now is an addition only when the baseline held every entry, and
    a key missing now is a removal only when the current list holds every entry (a list missing entries proves presence,
    never absence; a cut text does not make an entry missing); a kind read only now is adopted; a kind read only in the
    baseline is not compared. Keys whose multisets of item hashes differ are one change of that key."""
    changes: list[ItemChange] = []
    not_compared: list[str] = []
    incomplete: list[str] = []
    adopted: dict[str, str] = {}
    lost = False
    old_listing = None if baseline.lost else baseline.listing
    for kind in KINDS:
        in_baseline, now = kind in baseline.kinds, current.kinds.get(kind)
        if in_baseline and now is None:
            not_compared.append(kind)
            continue
        if now is None:
            continue
        if not in_baseline:
            adopted[kind] = now.hash
            continue
        old = old_listing.kinds.get(kind) if old_listing is not None else None
        partial = not now.complete or (old is not None and not old.complete)
        if partial:
            incomplete.append(kind)
        if baseline.kinds[kind] == now.hash:
            continue
        if old is None:
            lost = True
            continue
        old_keys, new_keys = _by_key(old), _by_key(now)
        for key in sorted(old_keys.keys() | new_keys.keys()):
            before, after = old_keys.get(key), new_keys.get(key)
            if before is not None and after is not None:
                if [item.hash for item in before] != [item.hash for item in after]:
                    changes.append(_change(kind, key, before, after))
            elif after is not None and old.entries_whole:  # present now, absent from a baseline with every entry: added
                changes.append(_change(kind, key, before, after))
            elif before is not None and now.entries_whole:  # absent from a current list with every entry: removed
                changes.append(_change(kind, key, before, after))
    if lost:
        changes = []
    return ToolDiff(changes=tuple(changes), not_compared=tuple(not_compared), incomplete=tuple(incomplete), adopted=adopted,
                    baseline_lost=lost)


def name_of(key: str) -> str:
    """The item's name in a key: what follows the kind prefix (`tool:search` is `search`; `instructions` is "")."""
    return key.split(":", 1)[1] if ":" in key else ""


def _body(kind: str, fields: Mapping | None) -> dict | None:
    if fields is None:
        return None
    schema = fields.get("input_schema")
    text = fields.get("input_schema_text")
    if schema is None and isinstance(text, str):
        try:
            schema = json.loads(text)
        except (ValueError, RecursionError):
            schema = None
        if _too_deep(schema):  # never hand a caller a value it cannot walk
            schema = None
    uri = fields.get("uri") if kind == "resources" else fields.get("uri_template") if kind == "resource_templates" else None
    description = fields.get("text") if kind == "instructions" else fields.get("description")
    return {"title": fields.get("title"), "description": description, "input_schema": schema,
            "arguments": fields.get("arguments"), "uri": uri}


def change_details(baseline_listing: ToolListing, current_listing: ToolListing) -> list[dict]:
    """Every change of `current_listing` against `baseline_listing`, in the order changed, added, removed, then kind and
    name: `{kind, name, change, description_changed, schema_changed, old, new, body_omitted}` with `old` and `new` the
    item's `title`, `description`, `input_schema` (parsed back from its text for a schema `jcs` refuses; None for one
    nested deeper than MAX_SCHEMA_DEPTH), `arguments` and `uri` as probed, None for the side that does not exist. No text
    is masked here: the caller masks."""
    found = diff(Baseline(kinds=baseline_listing.kind_hashes(), listing=baseline_listing, approved_at=None), current_listing)
    ordered = sorted(found.changes, key=lambda c: (CHANGES.index(c.change), KINDS.index(c.kind), name_of(c.key), c.key))
    return [{"kind": c.kind, "name": name_of(c.key), "change": c.change, "description_changed": c.description_changed,
             "schema_changed": c.schema_changed, "old": _body(c.kind, c.old_fields), "new": _body(c.kind, c.new_fields),
             "body_omitted": False} for c in ordered]


def adopt(baseline_listing: ToolListing, current_listing: ToolListing, kinds: Iterable[str]) -> ToolListing:
    """The baseline's kinds plus the named kinds of `current_listing`, with a recomputed digest."""
    merged = dict(baseline_listing.kinds)
    for kind in kinds:
        if kind in current_listing.kinds:
            merged[kind] = current_listing.kinds[kind]
    return _listing(merged)


def carry(current: ToolListing | None, previous: ToolListing) -> ToolListing:
    """The kinds `current` read, plus every kind only `previous` holds, exactly as `previous` holds it, with a recomputed
    digest: a list a probe did not read this time is compared as it was last read."""
    merged = dict(previous.kinds)
    if current is not None:
        merged.update(current.kinds)
    return _listing(merged)


__all__ = [
    "BODY_FIELDS", "Baseline", "CHANGES", "FORMAT", "ITEM_PREFIX", "ItemChange", "KINDS", "KindListing", "ListedItem",
    "MAX_SCHEMA_DEPTH", "TEXT_FIELDS", "ToolDiff", "ToolListing", "UNSERIALISABLE", "adopt", "carry", "change_details",
    "clean", "diff", "item_hash", "kinds_digest", "listing_of", "name_of", "normalise_text",
]
