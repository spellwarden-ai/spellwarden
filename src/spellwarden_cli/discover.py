"""Items from the file set (spec 6.5). Every document and skill is keyed by
its scan-root-relative path, so a file reached both by the global filename
rules and through a plugin is parsed once and listed once (one owner per
file). Only skill packages and configuration documents are read (plan P12)."""
from __future__ import annotations

import os
import posixpath
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import NamedTuple

from spellwarden_scan.agentconfig import ConfigDocument, parse_document, reference_kind
from spellwarden_scan.archive import DEFAULT_LIMITS
from spellwarden_scan.relpath import UnsafePath, contain

from spellwarden_cli import paths
from spellwarden_cli.files import FileEntry, FileSet
from spellwarden_cli.report import Notice

SKILL_FILE = "SKILL.md"
_ITEM_KIND = {"mcp": "mcp-config", "settings": "settings", "marketplace": "marketplace", "hooks": "hooks",
              "plugin": "plugin-manifest"}


@dataclass(frozen=True)
class Item:
    kind: str
    path: str
    name: str
    plugin: str | None = None

    def to_dict(self) -> dict:
        return {"kind": self.kind, "path": self.path, "name": self.name, "plugin": self.plugin}


@dataclass(frozen=True)
class SkillPackage:
    path: str  # the skill directory, "." for a SKILL.md at the scan root (plan P13)
    name: str
    files: dict[str, bytes] = field(hash=False)
    executable: frozenset[str] = frozenset()
    plugin: str | None = None
    # member links that could not be followed (r2:F6): link path -> target text, hashed into the lock, never scanned
    links: dict[str, bytes] = field(default_factory=dict, hash=False)
    # a case variant of SKILL.md where agents load skills (`skills/<name>/skill.md`), as written; None for SKILL.md
    variant: str | None = None

    def engine_key(self) -> str:
        """The key the engine reads the skill file under (`frontmatter.skill_md_path`)."""
        return SKILL_FILE if self.path == "." else f"{self.path}/{SKILL_FILE}"

    def engine_files(self) -> dict[str, bytes]:
        """`files` as the engine reads them: a case variant under `engine_key()`, every other path as written."""
        if self.variant is None:
            return self.files
        return {self.engine_key() if path == self.variant else path: content for path, content in self.files.items()}

    def engine_executable(self) -> frozenset[str]:
        if self.variant is None or self.variant not in self.executable:
            return self.executable
        return (self.executable - {self.variant}) | {self.engine_key()}

    def as_written(self, path: str) -> str:
        """A path the engine reported, as the package writes it: `engine_key()` back to the variant."""
        return self.variant if self.variant is not None and path == self.engine_key() else path


@dataclass(frozen=True)
class PluginDir:
    path: str  # the plugin directory; files keyed by scan-root-relative paths, like SkillPackage.files
    files: dict[str, bytes] = field(hash=False)
    links: dict[str, bytes] = field(default_factory=dict, hash=False)  # as SkillPackage.links


@dataclass(frozen=True)
class Discovery:
    items: tuple[Item, ...]
    skills: tuple[SkillPackage, ...]
    documents: tuple[ConfigDocument, ...]
    plugin_dirs: tuple[PluginDir, ...]
    notices: tuple[Notice, ...]
    errors: tuple[Notice, ...]


def _fold(path: str) -> str:
    """The form names are matched in: NFC, then case folding, as macOS and Windows open them and as the
    `case_collision` check of the file set compares paths (6.4). Outputs keep each path as it is written."""
    return unicodedata.normalize("NFC", path).casefold()


def _named(path: str, suffix: str) -> bool:
    return path == suffix or path.endswith("/" + suffix)


def _is_skill_file(path: str) -> bool:
    """A skill is a directory holding a file named exactly `SKILL.md` (spec 6.5): the engine reads that one name
    (`frontmatter.skill_md_path`), and an agent on a case-sensitive file system loads no other (r2:F2). A case
    variant is a skill file too where agents load skills, `skills/<name>/<variant>` (`_is_loaded_variant`)."""
    return posixpath.basename(path) == SKILL_FILE or _is_loaded_variant(path)


def _is_loaded_variant(path: str) -> bool:
    """A case variant of `SKILL.md` whose directory's parent is named `skills` in any case (`.claude/skills/x/`, a
    plugin's or a skill repository's `skills/x/`): an agent on macOS or Windows loads it as that skill's SKILL.md,
    so it is judged as one (orchestrator decision after r2:F2). Elsewhere a variant is ordinary content."""
    parts = path.split("/")
    return len(parts) >= 3 and _fold(parts[-3]) == "skills" and _is_skill_name_variant(path)


def _is_skill_name_variant(path: str) -> bool:
    """A file whose name folds to `skill.md` but is not exactly `SKILL.md`: notice `skill_name_case`, else content."""
    name = posixpath.basename(path)
    return name != SKILL_FILE and _fold(name) == _fold(SKILL_FILE)


def _global_kind(path: str) -> str | None:
    """The document kind a file has by its name alone, wherever it sits (spec 6.5), whatever its case."""
    path = _fold(path)
    if posixpath.basename(path) == ".mcp.json" or _named(path, ".vscode/mcp.json") or _named(path, ".cursor/mcp.json"):
        return "mcp"
    if _named(path, ".claude/settings.json") or _named(path, ".claude/settings.local.json"):
        return "settings"
    if _named(path, ".claude-plugin/marketplace.json"):
        return "marketplace"
    return None


def _under(path: str, directory: str) -> bool:
    return directory == "." or path.startswith(directory + "/")


def _join(directory: str, name: str) -> str:
    """`name` inside the scan-root directory `directory`, `"."` being the scan root (a plugin source `"./"`)."""
    return name if directory == "." else f"{directory}/{name}"


class _Outside(UnsafePath):
    """A link target outside the scan root: not repository content."""


class _Resolution(NamedTuple):
    target: str | None  # the file of the set the link names, when it can be followed
    text: bytes | None  # the target text, None when it could not be read
    refusal: Notice | None  # why the link is not followed
    outside: bool  # the target is outside the scan root (absolute there, or climbing out of it)


class _Builder:
    def __init__(self, fileset: FileSet) -> None:
        self.fileset = fileset
        self.paths = set(fileset.paths())  # grows by the symbolic links followed (`follow`)
        self.entries = {entry.path: entry for entry in fileset.entries}
        self.links = {link.path: link for link in fileset.links}
        # colliding names were dropped from the file set (6.4), so one folded name is one path
        self.folded = {_fold(p): p for p in (*self.paths, *self.links)}
        self.followed: set[str] = set()  # every link followed, or refused with an error
        self.resolved: dict[str, _Resolution] = {}  # package member links, resolved once, adopted only when accepted
        self.skipped: set[str] = set()  # member links of an accepted package whose target is outside the scan root
        self.directories = {posixpath.dirname(p) for p in (*self.paths, *self.links)}
        for directory in list(self.directories):
            while directory:
                directory = posixpath.dirname(directory)
                self.directories.add(directory)
        self.documents: dict[str, ConfigDocument] = {}
        self.owners: dict[str, str] = {}  # document path -> plugin name
        self.roles: dict[str, set[str]] = {}  # document path -> every kind it was parsed as
        self.notices: list[Notice] = []
        self.errors: list[Notice] = []
        self.contents: dict[str, bytes] = {}  # each file is read at most once, whoever asks

    def read(self, path: str) -> bytes | None:
        if path in self.contents:
            return self.contents[path]
        try:
            content = self.fileset.read(path)
        except UnsafePath as exc:
            self.errors.append(Notice("unsafe_path", path, str(exc)))
            return None
        except paths.TooLarge:
            self.errors.append(Notice("unreadable", path, "grew past the size limit while it was read"))
            return None
        except OSError as exc:
            self.errors.append(Notice("unreadable", path, f"cannot be read ({exc.strerror or type(exc).__name__})"))
            return None
        self.contents[path] = content
        return content

    def find(self, path: str) -> str:
        """The listed path an agent opening `path` reads on a case-insensitive file system, else `path`."""
        if path in self.paths or path in self.links:
            return path
        return self.folded.get(_fold(path), path)

    def follow(self, path: str) -> bool:
        """Whether `path` is a file of the set, following it first when it is a listed symbolic link at an
        agent-content path (owner decision, 2026-10-20). A link is followed when its target, resolved against the
        link's directory by the containment rule (6.13), is a regular file of the set; the target's bytes are then
        the link path's content, and findings, items and the lock name the link. An absolute or escaping target, a
        target that is itself a link and a target outside the file set are `unsafe_path`."""
        if path not in self.links:
            return path in self.paths
        if path in self.followed:
            return path in self.paths
        self.followed.add(path)
        resolution = self._resolve(path)
        if resolution.target is None:
            self.errors.append(resolution.refusal)  # type: ignore[arg-type]
            return False
        return self.adopt(path, resolution.target)

    def member(self, path: str) -> _Resolution | None:
        """The resolution of a link inside a skill package or local plugin directory, by the rules of `follow`
        (r2:F6); None for a link already followed or already an error. A member link that names repository content
        is followed or is an error: a chain, a path through a directory link, a link to a directory, a missing or
        excluded target inside the scan root and an unreadable target text are `unsafe_path` or `unreadable`, so
        what the lock covers cannot change behind it. Only a target outside the scan root (a skill may link outside
        the repository) is skipped, with its target text in the package's lock hash. Only the target text is read
        here; resolving marks nothing followed (a package over the limits leaves its links to the next package),
        `adopt` does."""
        if path not in self.links or path in self.followed:
            return None
        if path not in self.resolved:
            resolution = self._resolve(path)
            if resolution.refusal is not None and not (resolution.outside and resolution.text is not None):
                self.errors.append(resolution.refusal)
                self.followed.add(path)
                return None
            self.resolved[path] = resolution
        return self.resolved[path]

    def _resolve(self, path: str) -> _Resolution:
        """The file of the set the listed link `path` names, or the `unsafe_path` or `unreadable` notice saying why
        it is not followed."""
        try:
            raw = self.fileset.link_target(path)
        except (UnsafePath, paths.TooLarge) as exc:
            return _Resolution(None, None, Notice("unsafe_path", path, f"symbolic link: {exc}"), False)
        except OSError as exc:
            return _Resolution(None, None, Notice("unreadable", path, "symbolic link cannot be read "
                                                  f"({exc.strerror or type(exc).__name__})"), False)
        try:
            target = self.find(self._link_target(path, raw.decode("utf-8")))
        except UnicodeDecodeError:
            return _Resolution(None, raw, Notice("unsafe_path", path, "symbolic link: target is not UTF-8"), False)
        except UnsafePath as exc:
            return _Resolution(None, raw, Notice("unsafe_path", path, f"symbolic link: {exc}"), isinstance(exc, _Outside))
        if target in self.links:
            return _Resolution(None, raw, Notice("unsafe_path", path, f"symbolic link to {target!r}, itself a symbolic "
                                                 "link"), False)
        if target not in self.entries and (target in self.directories or target == ""):
            return _Resolution(None, raw, Notice("unsafe_path", path, f"symbolic link to {target!r}, a directory inside "
                                                 "the scan root; a link to a directory is not followed: replace it with "
                                                 "the files it should hold"), False)
        if target not in self.entries:
            return _Resolution(None, raw, Notice("unsafe_path", path, f"symbolic link to {target!r}, not a file of the "
                                                 "file set"), False)
        return _Resolution(target, raw, None, False)

    def adopt(self, path: str, target: str) -> bool:
        """The followed link `path` becomes a file of the set holding `target`'s bytes, named by the link."""
        self.followed.add(path)
        content = self.read(target)
        if content is None:
            return False
        entry = self.entries[target]
        self.entries[path] = FileEntry(path, entry.size, entry.executable, self.links[path].tracked)
        self.contents[path] = content
        self.paths.add(path)
        return True

    def _link_target(self, link: str, text: str) -> str:
        """The scan-root path a link's target names. Every refusal of the containment rule (6.13) applies except
        the parent segment: a link may climb with `..` (`.cursor/mcp.json -> ../.mcp.json` is common) as long as it
        stays inside the scan root and climbs through no directory that is itself a link (an agent's file system
        would resolve that link, the scanner reads paths as written). An absolute target, or one that climbs out
        of the scan root, raises `_Outside` unless it names a place inside the scan root."""
        if os.path.isabs(text):
            if self._inside_root(text):
                raise UnsafePath("absolute target inside the scan root; use a relative link")
            raise _Outside("absolute target outside the scan root")
        contain("", "/".join("_" if segment == ".." else segment for segment in text.split("/")))
        segments = (text[2:] if text.startswith("./") else text).rstrip("/").split("/")
        parts = posixpath.dirname(link).split("/") if posixpath.dirname(link) else []
        for index, segment in enumerate(segments):
            if segment == "..":
                if not parts:
                    raise _Outside("target leaves the scan root")
                parts.pop()
            else:
                parts.append(segment)
            if index < len(segments) - 1 and "/".join(parts) in self.links:
                raise UnsafePath("target passes through a symbolic link")
        return "/".join(parts)

    def _inside_root(self, target: str) -> bool:
        full = os.path.normcase(os.path.normpath(target))
        for base in {os.path.normpath(self.fileset.root), os.path.realpath(self.fileset.root)}:
            base = os.path.normcase(base)
            if full == base or full.startswith(base.rstrip(os.sep) + os.sep):
                return True
        return False

    def document(self, kind: str, path: str, plugin: str | None = None, *,
                 drop_references: bool = False) -> ConfigDocument | None:
        """The one document of `path`. A file reached in a second role (a global name, a plugin's conventional
        path, a manifest reference read by its JSON shape) stays one document of its first kind, but is also
        parsed in the new role and keeps what that role finds (r1:F1): what an agent loads in either role is
        judged, listed and locked."""
        path = self.find(path)
        if path in self.documents:
            if plugin is not None:
                self.owners.setdefault(path, plugin)
            if kind not in self.roles[path]:
                self.roles[path].add(kind)
                content = self.contents.get(path)
                if content is not None:
                    self.documents[path] = self._merge(self.documents[path], _parse(kind, path, content))
            return self.documents[path]
        if not self.follow(path):
            return None
        content = self.read(path)
        if content is None:
            return None
        parsed = _parse(kind, path, content)
        if drop_references:
            parsed = replace(parsed, references=())
        self.documents[path] = parsed
        self.roles[path] = {kind}
        if plugin is not None:
            self.owners[path] = plugin
        self._report(parsed.error, path)
        return parsed

    def _report(self, error: str | None, path: str) -> None:
        if error is not None:
            self.errors.append(Notice(error, path, _DOCUMENT_MESSAGES.get(error, error)))

    def _merge(self, document: ConfigDocument, role: ConfigDocument) -> ConfigDocument:
        """`document` plus the servers and hooks `role` (the same bytes read by another parser) adds. Its kind,
        path and hash stay (both parses hash the same canonical JSON). A document that is already an error stays
        as it is; a role that refuses the bytes (a server name under both `mcpServers` and `servers`, which the
        settings parser does not read) makes the document that error, as one parser alone would."""
        if document.error not in (None, "truncated") or role.error is None and not role.servers and not role.hooks:
            return document
        if role.error not in (None, "truncated"):
            self._report(role.error, document.path)
            return replace(document, error=role.error, servers=(), hooks=(), settings=(), plugins=(), references=(),
                           truncated=False, sha256=role.sha256)
        names = {server.name for server in document.servers}
        seen = {(hook.event, hook.matcher, hook.command, hook.line) for hook in document.hooks}
        added = [hook for hook in role.hooks if (hook.event, hook.matcher, hook.command, hook.line) not in seen]
        hooks = document.hooks + tuple(replace(hook, index=len(document.hooks) + offset) for offset, hook in enumerate(added))
        truncated = document.truncated or role.truncated
        if truncated and not document.truncated:
            self._report("truncated", document.path)
        return replace(document, servers=document.servers + tuple(s for s in role.servers if s.name not in names),
                       hooks=hooks, truncated=truncated, error="truncated" if truncated else None)


def _parse(kind: str, path: str, content: bytes) -> ConfigDocument:
    """`parse_document`, with a marketplace parsed under its name in lower case so that its root (the parent of
    `.claude-plugin`, 5.6) does not depend on the case it is written in; the document keeps its real path."""
    if kind != "marketplace":
        return parse_document(kind, path, content)
    parent = posixpath.dirname(posixpath.dirname(path))
    parsed = parse_document(kind, posixpath.join(parent, ".claude-plugin", "marketplace.json"), content)
    return replace(parsed, path=path)


_SKILL_NAME_CASE = ("an agent on a case-insensitive file system may load this as SKILL.md; rename it to SKILL.md to "
                    "have it scanned as a skill, or rename it away")

_DOCUMENT_MESSAGES = {
    "too_large": "configuration document over 1 MiB; not judged",
    "not_utf8": "configuration document is not UTF-8; not judged",
    "not_json": "configuration document is not valid JSON (comments and trailing commas are accepted); not judged",
    "duplicate_key": "a key repeats in one object, and agents disagree on which value wins; not judged",
    "too_deep": "configuration document nests deeper than 32 levels; not judged",
    "not_an_object": "configuration document is not a JSON object; not judged",
    "truncated": "more entries than the scanner reads; the first entries were judged, the rest were not",
}


def _follow_references(builder: _Builder, manifest: ConfigDocument, directory: str, plugin: str) -> None:
    """Every reference of a plugin manifest that the containment rule accepts and that names a file of the set is
    followed, whatever its name; the JSON shape picks the parser (`reference_kind`). A referenced manifest's own
    references are not followed (one level). A file that is no configuration gets a notice and stays covered by
    the plugin directory's hash in the lock. A file that is already a document (a global name such as
    `.claude/settings.json`, a plugin's conventional path, an earlier reference) stays one document of its kind and
    is also judged in the role its shape gives it here (`_Builder.document`, r1:F1)."""
    for reference in manifest.references:
        try:
            target = builder.find(contain(directory, reference))
        except UnsafePath as exc:
            builder.errors.append(Notice("unsafe_path", manifest.path, f"reference {reference!r}: {exc}"))
            continue
        if not builder.follow(target):
            if target not in builder.links:  # a link that could not be followed is already an error
                builder.notices.append(Notice("file_missing", target, f"referenced by {manifest.path} but not in the file set"))
            continue
        content = builder.read(target)
        if content is None:
            continue
        kind = reference_kind(content)
        if kind is not None:
            builder.document(kind, target, plugin, drop_references=kind == "plugin")
        elif target in builder.documents:  # one owner per file: the plugin is recorded, the document is unchanged
            builder.document(builder.documents[target].kind, target, plugin)
        else:
            builder.notices.append(Notice("reference_not_config", target,
                                          f"referenced by {manifest.path} but holds no hooks or MCP servers; not parsed"))


def discover(fileset: FileSet) -> Discovery:
    builder = _Builder(fileset)
    builder.notices.extend(Notice("skill_name_case", path, _SKILL_NAME_CASE)
                           for path in sorted({*builder.paths, *builder.links}) if _is_skill_name_variant(path))
    plugin_dirs: dict[str, str] = {}  # directory -> plugin name
    plugin_items: list[Item] = []
    for path in sorted(builder.links):  # links at a global name; plugin paths and references follow theirs below
        if _global_kind(path) is not None or _is_skill_file(path):
            builder.follow(path)
    for path in sorted(p for p in builder.paths if _global_kind(p) == "marketplace"):
        marketplace = builder.document("marketplace", path)
        if marketplace is None or marketplace.error not in (None, "truncated"):
            continue
        for plugin in marketplace.plugins:
            plugin_items.append(Item("plugin", f"{path}#{plugin.name}", plugin.name))
            source = plugin.source
            if source.kind == "local" and source.error is not None:  # an error entry, never skipped silently (r2:F12)
                builder.errors.append(Notice("unsafe_path", path, f"plugin {plugin.name!r}: local source "
                                             f"{source.canonical.removeprefix('local-raw:')} is not a path inside the "
                                             "marketplace root; not read"))
                continue
            if source.kind != "local" or source.local_path is None:
                continue  # remote plugins are inventory only: listed, locked, judged by SW-CFG-009, never fetched
            directory = source.local_path
            plugin_dirs.setdefault(directory, plugin.name)
    # A file's kind is the first role that reaches it: its global name, then a plugin's conventional path, then a
    # manifest reference; every later role adds what it finds to that one document (r1:F1).
    for path in sorted(builder.paths):
        kind = _global_kind(path)
        if kind is not None and kind != "marketplace":
            builder.document(kind, path)
    for directory, name in plugin_dirs.items():
        builder.document("mcp", _join(directory, ".mcp.json"), name)
        builder.document("hooks", _join(directory, "hooks/hooks.json"), name)
        builder.document("plugin", _join(directory, ".claude-plugin/plugin.json"), name)
    for directory, name in plugin_dirs.items():
        manifest = builder.documents.get(builder.find(_join(directory, ".claude-plugin/plugin.json")))
        if manifest is not None:
            _follow_references(builder, manifest, "" if directory == "." else directory, name)
    skills = _skills(builder, plugin_dirs)
    # A local plugin whose directory holds no file of the set is listed and locked by its source only; one over the
    # package limits is an item error and is not read whole, like a skill (r0:F8).
    dirs: list[PluginDir] = []
    for directory in sorted(plugin_dirs):
        package = _package(builder, directory, _inside(directory, []), "plugin directory")
        if package is not None and (package[0] or package[1]):
            dirs.append(PluginDir(directory, _read_all(builder, package[0]), package[1]))
    for path in sorted(builder.links):
        if path in builder.skipped:
            refusal = builder.resolved[path].refusal
            builder.notices.append(Notice("symlink_skipped", path, f"{refusal.message if refusal else 'symbolic link'}; "
                                                                   "not followed, and its target text is in the "
                                                                   "package's lock hash"))
        elif path not in builder.followed:
            builder.notices.append(Notice("symlink_skipped", path, "symbolic link; skipped"))
    items = _items(builder, skills, plugin_items)
    if not items:
        builder.notices.append(Notice("no_agent_content", "", "No agent content found"))
    return Discovery(tuple(items), tuple(skills), tuple(builder.documents[p] for p in sorted(builder.documents)),
                     tuple(dirs), tuple(builder.notices), tuple(builder.errors))


def _inside(directory: str, nested: list[str]) -> Callable[[str], bool]:
    return lambda path: _under(path, directory) and not any(_under(path, inner) for inner in nested)


def _package(builder: _Builder, directory: str, inside: Callable[[str], bool],
             what: str) -> tuple[list[str], dict[str, bytes]] | None:
    """`(members, links)` of a skill package or local plugin directory: its files of the set, with every member link
    the rules of `_Builder.follow` accept followed (its target's bytes are the member's content under the link's
    path, r2:F6), and the target text of each member link they refuse. None, with the item error recorded, when the
    package is over the limits, judged before any member or link target is read: the count with every link, the
    bytes with the listed size of each target followed."""
    regular = sorted(p for p in builder.paths if inside(p))
    pending = sorted(p for p in builder.links if inside(p) and p not in builder.paths)
    count = len(regular) + len(pending)
    size = sum(builder.entries[p].size for p in regular)
    if _too_large(builder, directory, count, size, what):
        return None
    resolved = {link: resolution for link in pending if (resolution := builder.member(link)) is not None}
    targets = {link: r.target for link, r in resolved.items() if r.target is not None}
    if _too_large(builder, directory, count, size + sum(builder.entries[t].size for t in targets.values()), what):
        return None
    for link, target in targets.items():
        builder.adopt(link, target)
    skipped = {link: r.text for link, r in resolved.items() if r.target is None and r.text is not None}
    builder.skipped.update(skipped)
    members = sorted(p for p in builder.paths if inside(p))
    return members, skipped  # type: ignore[return-value]


def _too_large(builder: _Builder, directory: str, count: int, size: int, what: str) -> bool:
    """A package over the `ArchiveLimits` totals (spec 6.5) is the item error `package_too_large`, judged from
    the listing's sizes before any member is read."""
    if count <= DEFAULT_LIMITS.max_files and size <= DEFAULT_LIMITS.max_uncompressed:
        return False
    builder.errors.append(Notice("package_too_large", directory,
                                 f"{what} of {count} files and {size} bytes is over the limits "
                                 f"({DEFAULT_LIMITS.max_files} files, {DEFAULT_LIMITS.max_uncompressed // 2**20} MiB)"))
    return True


def _read_all(builder: _Builder, files: list[str]) -> dict[str, bytes]:
    read: dict[str, bytes] = {}
    for path in files:
        content = builder.read(path)
        if content is not None:
            read[path] = content
    return read


def _skills(builder: _Builder, plugin_of_dir: dict[str, str]) -> list[SkillPackage]:
    entries = builder.entries
    directories = sorted({posixpath.dirname(p) or "." for p in builder.paths if _is_skill_file(p)})
    packages: list[SkillPackage] = []
    for directory in directories:
        nested = [d for d in directories if d != directory and _under(d, directory)]
        before = len(builder.errors)
        package = _package(builder, directory, _inside(directory, nested), "skill package")
        if package is None:
            continue
        members, links = package
        files = _read_all(builder, members)
        if len(builder.errors) != before:
            continue  # an unreadable member makes the skill an item error, not a partial scan
        owners = [d for d in plugin_of_dir if _under(directory, d)]  # "." is a plugin at the scan root (r2:F12)
        plugin = plugin_of_dir[max(owners, key=lambda d: 0 if d == "." else len(d))] if owners else None
        # the root skill is "." and never the checkout directory's name: a lock and a report must not depend on where
        # the repository sits on disk (r0:F4)
        name = posixpath.basename(directory) if directory != "." else "."
        # one skill file per directory: two names that fold alike are a `case_collision` and left out of the set
        variant = next((p for p in members if posixpath.dirname(p) == directory and _is_loaded_variant(p)), None)
        packages.append(SkillPackage(directory, name, files, frozenset(p for p in members if entries[p].executable), plugin,
                                     links, variant))
    return packages


def _items(builder: _Builder, skills: list[SkillPackage], plugin_items: list[Item]) -> list[Item]:
    items = [Item("skill", skill.path, skill.name, skill.plugin) for skill in skills]
    items.extend(plugin_items)
    for path, document in builder.documents.items():
        owner = builder.owners.get(path)
        items.append(Item(_ITEM_KIND[document.kind], path, posixpath.basename(path), owner))
        for server in document.servers:
            items.append(Item("mcp-server", f"{path}#{server.name}", server.name, owner))
    return sorted(items, key=lambda item: (item.kind, item.path))


__all__ = ["Discovery", "Item", "PluginDir", "SkillPackage", "discover"]
