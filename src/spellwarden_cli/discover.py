"""Items from the file set (spec 6.5). Every document and skill is keyed by
its scan-root-relative path, so a file reached both by the global filename
rules and through a plugin is parsed once and listed once (one owner per
file). Only skill packages and configuration documents are read (plan P12)."""
from __future__ import annotations

import bisect
import ntpath
import os
import posixpath
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import NamedTuple

from spellwarden_scan import parse_agent_card
from spellwarden_scan.a2a import AgentCardDocument
from spellwarden_scan.agentconfig import MAX_PLUGINS, ConfigDocument, parse_document, reference_kind
from spellwarden_scan.archive import DEFAULT_LIMITS
# The skill-file rule and the folding of names live in the engine (O3 plan P52): the gate's package identity and this
# module must call a file a skill file for the same reasons. `_fold`: NFC, then case folding, as macOS and Windows open
# names and as the `case_collision` check of the file set compares paths (6.4); targets and references are never
# resolved through it (`_Builder.twin`), and outputs keep each path as written.
from spellwarden_scan.identity import fold_skill_name as _fold
from spellwarden_scan.identity import is_loaded_variant as _is_loaded_variant
from spellwarden_scan.identity import is_skill_file as _is_skill_file
from spellwarden_scan.identity import is_skill_name_variant as _is_skill_name_variant
from spellwarden_scan.relpath import UnsafePath, contain

from spellwarden_cli import instruction_files, paths, userdocs
from spellwarden_cli.files import FILE_MAX, FileEntry, FileSet
from spellwarden_cli.report import Notice

SKILL_FILE = "SKILL.md"
MAX_CARDS = 300  # discovered and listed agent cards together (O4 spec 6.3; 300 since 1.13.0); more is the error `a2a_cards_limit`
# 1.18.0: the paths the pre-commit hook runs on (`.pre-commit-hooks.yaml`, written from this by scripts/write_hooks_yaml.py):
# every kind of path a scan discovers as agent content or settings, and more, since a regular expression cannot know which
# folders hold a SKILL.md: SKILL.md anywhere, everything under the agent folders, the MCP configuration names, a plugin's hooks
# file, the instruction file names and agent cards. Since 1.20.0 also everything under `.gemini`, `.devin`, `.windsurf`, `.agents`
# and four `.github` folders, and the memory-file variants (Engine 1.20.0: scan selection, 7.17). A local plugin's `commands/`
# and `agents/`, and the target of a followed link, cannot be told from ordinary folders by a pattern. The scan itself always
# covers the whole root, so a change this misses is judged the next time the hook runs, or in CI. Matched with `re.search`
# against a POSIX path, whatever its case.
AGENT_CONTENT_REGEX = (
    r"(?i)(^|/)("
    r"skill\.md"
    r"|(skills|\.claude|\.cursor|\.codex|\.gemini|\.devin|\.windsurf|\.agents|\.vscode|\.claude-plugin|\.spellwarden"
    r"|\.well-known)/.+"
    r"|\.github/(hooks|instructions|agents|copilot)/.+"
    r"|\.mcp\.json|mcp\.json|claude_desktop_config\.json|hooks/hooks\.json"
    r"|agents\.md|claude\.md|gemini\.md|claude\.local\.md|agents\.(override|local)\.md|agent\.md"
    r"|\.github/copilot-instructions\.md|\.cursorrules|\.windsurfrules"
    r"|agent-card\.json"
    r")$"
)
_ITEM_KIND = {"mcp": "mcp-config", "settings": "settings", "marketplace": "marketplace", "hooks": "hooks",
              "plugin": "plugin-manifest"}


@dataclass(frozen=True)
class Item:
    kind: str
    path: str
    name: str
    plugin: str | None = None
    # Instruction files only (kind `instructions`, Phase 3 batch 1 spec 10.3): the `format` of the table of
    # `instruction_files` and the front matter of a rule file, None when it has none or it could not be read.
    format: str | None = None
    front_matter: dict | None = field(default=None, hash=False)
    # `scan --user` only (phase 3 batch 2a spec 11.3): the clients whose table rows reach the item, in the order of
    # `clients.CLIENTS`, and the project directory of a project-scoped server (`~/...` or `outside-home:<8 hex>/<name>`).
    # Written only when set, so a repository report is byte-identical to 1.13.0's.
    clients: tuple[str, ...] = ()
    scope: str | None = None

    def to_dict(self) -> dict:
        data = {"kind": self.kind, "path": self.path, "name": self.name, "plugin": self.plugin}
        if self.kind == "instructions":  # written for these items only, so every other item is byte-identical to 1.12.0's
            data["format"], data["front_matter"] = self.format, self.front_matter
        if self.clients:
            data["clients"] = list(self.clients)
        if self.scope is not None:
            data["scope"] = self.scope
        return data


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
    # member links followed to the lock itself (`lockfile.LOCK_PATH`): scanned, left out of the lock hash
    own: frozenset[str] = frozenset()
    # the skill directories inside this one (`identity.nested_skill_roots` over the file set), scan-root paths: their
    # files are not part of this package's identity
    nested: tuple[str, ...] = ()
    # the files the followed member links point at, scan-root paths (O3 spec 6.6: a change to one is a change to the skill)
    targets: frozenset[str] = frozenset()
    # 1.13.0 (Phase 3 batch 1 spec 10.2): the instruction files this skill owns, scan-root paths, which its scan reads as
    # Markdown whatever their suffix (a `.mdc`, `.cursorrules` or `.windsurfrules` file); empty with `instructions: false`
    markdown: frozenset[str] = frozenset()

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
    own: frozenset[str] = frozenset()  # as SkillPackage.own


@dataclass(frozen=True)
class InstructionFile:
    """An instruction file (Phase 3 batch 1 spec 10.2): `path` is the scan-root path, `name` the file name without its directory,
    `format` one of `instruction_files.FORMATS`, `front_matter` as `instruction_files.front_matter_of` read it, `content` the
    bytes (a followed link holds its target's, under the link's path). `plugin` (Engine 1.20.0: scan selection, 7.7) names the
    local plugin directory whose `commands/` or `agents/` holds the file, None for every other file."""
    path: str
    name: str
    format: str
    front_matter: dict | None
    content: bytes = field(hash=False)
    plugin: str | None = None


@dataclass(frozen=True)
class CardFile:
    """A file to be checked as an A2A agent card (O4 spec 6.3). `path_form` is `well_known`, `legacy_path`, `named` or
    `listed` (`a2a.cards`); `content` is what was read, whatever it holds (`agents.py` parses it). `read_error` is
    `(code, message)` with `code` `unsafe_path` or `unreadable` for a `well_known` or `listed` file that could not be read (a
    link that escapes the scan root, dangles or names a link or a directory; a read the OS refuses): `content` is then empty
    and the card is the finding SW-A2A-018, never a run error (r1:F2, invariant 10)."""
    path: str
    path_form: str
    content: bytes = field(hash=False)
    read_error: tuple[str, str] | None = None


def is_card(card: CardFile, document: AgentCardDocument | None = None) -> bool:
    """Whether a card file is checked as a card: a `well_known` or `listed` file always is (its read failure is SW-A2A-018, a
    missing shape SW-A2A-001), a `legacy_path` or `named` file only when it parses strictly and has the card shape. `document` is
    the parse of `card.content` when the caller has it (O4 spec 6.3)."""
    if card.path_form in ("well_known", "listed"):
        return True
    document = document if document is not None else parse_agent_card(card.path, card.content)
    return document.error is None and document.card_shape


@dataclass(frozen=True)
class Discovery:
    items: tuple[Item, ...]
    skills: tuple[SkillPackage, ...]
    documents: tuple[ConfigDocument, ...]
    plugin_dirs: tuple[PluginDir, ...]
    notices: tuple[Notice, ...]
    errors: tuple[Notice, ...]
    # The file set this discovery came from (O3 Task 9): the connected gate reads the directories the walk skipped, the
    # paths the settings dropped and the resolver files from it. None for a discovery built by hand.
    fileset: FileSet | None = field(default=None, compare=False, repr=False)
    # O4 spec 6.3: the files checked as agent cards, sorted by path. Not items and not in the lock (P6).
    agent_cards: tuple[CardFile, ...] = ()
    # Phase 3 batch 1 spec 10.2: the instruction files, sorted by path, each also an item of kind `instructions` and a lock item.
    instruction_files: tuple[InstructionFile, ...] = ()
    # Engine 1.20.0 (scan selection, 7.8): the facts of the items that are no document, server or skill (the `[plugins]` and
    # `[marketplaces]` entries of a repository's `.codex/config.toml`), merged into `details` by `run.scan_details`.
    facts: dict[str, dict] = field(default_factory=dict, compare=False)


def _lock_path() -> str:
    from spellwarden_cli.lockfile import LOCK_PATH  # lockfile imports this module

    return LOCK_PATH


def _named(path: str, suffix: str) -> bool:
    return path == suffix or path.endswith("/" + suffix)


@dataclass(frozen=True)
class _Reader:
    """How the repository scan reads a configuration document at a path (Engine 1.20.0: scan selection, 7.1, 7.2, D1): `kind` is
    the document's kind; `read` the workstation scan's reader of the same shape, None for the three kinds of 1.19.0, which
    `_parse` reads as before; `toml` marks Codex's `config.toml`, read by `userdocs.read_codex_config` without `notify` (D3)."""
    kind: str
    read: Callable[[str, bytes], ConfigDocument] | None = None
    toml: bool = False


def _named_any(path: str, *suffixes: str) -> bool:
    return any(_named(path, suffix) for suffix in suffixes)


def _copilot_hooks_file(path: str) -> bool:
    """A `.json` file directly in a `.github/hooks/` folder, at any depth (a folded path)."""
    parts = path.split("/")
    return len(parts) >= 3 and parts[-3:-1] == [".github", "hooks"] and parts[-1].endswith(".json")


# One table from a path to its reader (Engine 1.20.0: scan selection, 7.2.1, D1, D10), matched on the folded path at any depth,
# first match wins. Its first three rows are the `_global_kind` of 1.19.0, unchanged. The link loop, the document loop,
# `_oversize_files` and the gate's base revision (`base_parses`) all read it.
_READERS: tuple[tuple[Callable[[str], bool], _Reader], ...] = (
    (lambda p: posixpath.basename(p) == ".mcp.json" or _named_any(p, ".vscode/mcp.json", ".cursor/mcp.json"), _Reader("mcp")),
    (lambda p: _named_any(p, ".claude/settings.json", ".claude/settings.local.json"), _Reader("settings")),
    (lambda p: _named(p, ".claude-plugin/marketplace.json"), _Reader("marketplace")),
    (lambda p: _named(p, ".codex/config.toml"), _Reader("settings", toml=True)),
    (lambda p: _named(p, ".codex/hooks.json"), _Reader("hooks", userdocs.read_hooks)),
    (lambda p: _named(p, ".gemini/settings.json"), _Reader("settings", userdocs.read_gemini_settings)),
    (lambda p: _named_any(p, ".cursor/hooks.json", ".windsurf/hooks.json"), _Reader("hooks", userdocs.read_cursor_hooks)),
    (lambda p: _named_any(p, ".devin/mcp_config.json", ".devin/mcp_config.local.json"),
     _Reader("mcp", userdocs.read_windsurf_mcp)),
    (lambda p: _named(p, ".devin/hooks.v1.json"), _Reader("hooks", userdocs.read_devin_hooks)),
    (lambda p: _named_any(p, ".devin/config.json", ".devin/config.local.json"), _Reader("settings", userdocs.read_devin_config)),
    (_copilot_hooks_file, _Reader("hooks", userdocs.read_copilot_hooks)),
    (lambda p: _named_any(p, ".github/copilot/settings.json", ".github/copilot/settings.local.json"),
     _Reader("settings", userdocs.read_copilot_settings)),
    (lambda p: _named(p, ".github/mcp.json"), _Reader("mcp", userdocs.read_copilot_mcp)),
)


def _reader(path: str) -> _Reader | None:
    """The row of `_READERS` whose path `path` is, after NFC and case folding; None for any other path."""
    folded = _fold(path)
    return next((reader for matches, reader in _READERS if matches(folded)), None)


def _global_kind(path: str) -> str | None:
    """The document kind a file has by its name alone, wherever it sits (spec 6.5), whatever its case: the kind of its row of
    `_READERS`."""
    reader = _reader(path)
    return None if reader is None else reader.kind


def _card_form(path: str) -> str | None:
    """How a file name makes an agent card (O4 spec 6.3), after NFC and case folding like the global names: the `path_form`
    of `.well-known/agent-card.json` (`well_known`), `.well-known/agent.json` (`legacy_path`) and any other file named
    `agent-card.json` (`named`); None for every other name."""
    folded = _fold(path)
    if _named(folded, ".well-known/agent-card.json"):
        return "well_known"
    if _named(folded, ".well-known/agent.json"):
        return "legacy_path"
    return "named" if posixpath.basename(folded) == "agent-card.json" else None


def _under(path: str, directory: str) -> bool:
    return directory == "." or path.startswith(directory + "/")


def _join(directory: str, name: str) -> str:
    """`name` inside the scan-root directory `directory`, `"."` being the scan root (a plugin source `"./"`)."""
    return name if directory == "." else f"{directory}/{name}"


class _Escape(UnsafePath):
    """A relative link target refused because it resolves, lexically, outside the scan root (`_Builder._link_target`).
    Since 1.23.0 (P6-10 spec 7.7, owner spec:Q1) it is an error wherever it leads, like every other refusal; the class
    only lets a member link and a linked instruction directory name the case in their message."""


class _LockDirAbsent(UnsafePath):
    """`_Builder._link_target`'s refusal of a target whose walk, through directories of the file set and no link, reaches
    `.spellwarden` at the scan root, which is not a directory of the file set, with `lock.json` as its last segment: the lock
    before the first `spellwarden lock` (1.16.2), if `_Builder._lock_absent` confirms nothing is there. Any other refusal of
    the walk is raised as a plain `UnsafePath`."""


# Case-insensitive by default: there the real scan root and a target that climbs out and back in are compared folded.
_CASE_INSENSITIVE = sys.platform in ("win32", "darwin")
# POSIX directories whose paths mean something different to every process that reads them (`/proc/self/cwd`,
# `/dev/fd`): a target that enters one outside the scan root is never "outside", wherever it ends (r3:N2).
_PROCESS_RELATIVE = ("proc", "dev")


def _absolute(text: str) -> bool:
    """Whether a link target is absolute in the sense of ANY operating system, whichever one runs the scan (r3:N1): a
    leading `/` or `\\` (POSIX, UNC `//host` and `\\\\host`, device `\\\\?\\` and `\\\\.\\`), or a drive (`C:`, `C:x`)."""
    return posixpath.isabs(text) or text.startswith("\\") or ntpath.isabs(text) or bool(ntpath.splitdrive(text)[0])


def _parts(path: str) -> list[str]:
    """The components of the operator's real scan root below its anchor (drive and root)."""
    rest = os.path.splitdrive(path)[1]
    for separator in filter(None, (os.altsep,)):
        rest = rest.replace(separator, os.sep)
    return [part for part in rest.split(os.sep) if part]


def _same(a: str, b: str) -> bool:
    a, b = os.path.normcase(a), os.path.normcase(b)
    return _fold(a) == _fold(b) if _CASE_INSENSITIVE else a == b


def _may_name(segment: str, component: str) -> bool:
    """Whether a file system might open `segment` as the directory `component`, on any OS and any volume: NFC and case
    folding everywhere (APFS, a case-insensitive Linux volume), trailing dots and spaces stripped (Windows), and any
    `~` (an 8.3 short name such as `REPO~1`), `:` (an NTFS stream) or non-ASCII character taken as possibly equal: HFS+
    and older Linux casefold directories ignore default-ignorable code points (`n\u200c4` opens `n4`), and other
    look-alikes are a file system's own business (r4:R4-4). Liberal on purpose: a yes fails closed (orchestrator
    decision after r3:N1)."""
    if "~" in segment or ":" in segment or not segment.isascii():
        return True
    return _fold(segment).rstrip(". ") == _fold(component).rstrip(". ")


class _Resolution(NamedTuple):
    target: str | None  # the file of the set the link names, when it can be followed
    text: bytes | None  # the target text, None when it could not be read
    refusal: Notice | None  # why the link is not followed
    outside: bool  # a relative target that resolves, lexically, outside the scan root (`_Builder._link_target`)


class _Builder:
    def __init__(self, fileset: FileSet) -> None:
        self.fileset = fileset
        self.paths = set(fileset.paths())  # grows by the symbolic links followed (`follow`)
        self.entries = {entry.path: entry for entry in fileset.entries}
        self.links = {link.path: link for link in fileset.links}
        # Every path a package can hold, sorted: `paths` only grows by links it follows, so this never goes stale. A
        # directory's files are one slice of it (`_under_range`), which keeps discovery linear in the repository's size.
        self.universe = tuple(sorted({*self.paths, *self.links}))
        # colliding names were dropped from the file set (6.4), so one folded name is one path; used only to name the
        # listed spelling when a target or reference matches one only after folding (`twin`, r4:R4-2)
        self.folded = {_fold(p): p for p in (*self.paths, *self.links)}
        self.followed: set[str] = set()  # every link followed, or refused with an error
        self.resolved: dict[str, _Resolution] = {}  # package member links, resolved once, adopted only when accepted
        self.own: dict[str, str] = {}  # member links followed to the lock itself -> the lock's path
        # links whose target text names the lock while the file set holds none (`_resolve`); a package member among them is
        # the package's own, like a member link followed to the lock (`member`, 1.16.2), any other stays `unsafe_path`
        self.to_lock: set[str] = set()
        self.lock_links: set[str] = set()  # package member links to the lock before it exists: members left out of the hash
        self.targets: dict[str, str] = {}  # every link followed -> the file it names
        # an oversize file's directory is one of the set too, so a link through it names the file (1.16.1)
        self.directories = {posixpath.dirname(p) for p in (*self.paths, *self.links, *fileset.too_large)}
        for directory in list(self.directories):
            while directory:
                directory = posixpath.dirname(directory)
                self.directories.add(directory)
        self.folded_directories = {_fold(d): d for d in self.directories}
        self.twins: set[str] = set()  # document paths already reported as naming a listed path in another spelling
        self.real_root: list[str] | None = None  # `_root_parts`: computed once, from the operator's scan root only
        self.documents: dict[str, ConfigDocument] = {}
        self.owners: dict[str, str] = {}  # document path -> plugin name
        self.roles: dict[str, set[str]] = {}  # document path -> every kind it was parsed as
        self.notices: list[Notice] = []
        self.errors: list[Notice] = []
        self.contents: dict[str, bytes] = {}  # each file is read at most once, whoever asks
        self.card_failures: dict[str, tuple[str, str]] = {}  # card links that could not be followed or read -> (code, message)
        self.too_large = frozenset(fileset.too_large)  # files over `FILE_MAX`: not read, never entries (1.16.1)
        self.too_large_links: set[str] = set()  # links refused because their target is one of them
        # Engine 1.20.0 (scan selection, 7.2.1, 7.8): the `.codex/config.toml` paths read by the TOML reader, whether it read them
        # or refused them (no JSON role is parsed over one), and the `[plugins]` and `[marketplaces]` entries of each it read
        self.toml: set[str] = set()
        self.listings: dict[str, userdocs.Listing] = {}

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

    def twin(self, path: str) -> str | None:
        """The listed file, link or directory that `path`, or the first of its directories the file set does not hold,
        names only after NFC normalisation and case folding; None when `path` is listed exactly or nothing folds alike.
        A link target, its directories, a manifest reference and a plugin's conventional path resolve by exact match
        only: on a case-sensitive file system the other spelling is another file, which may be one the file set does
        not list (inside a submodule, under `node_modules`), so a folded match is `unsafe_path`, never a fallback
        (orchestrator decision after r4:R4-2)."""
        if path in self.paths or path in self.links or path in self.directories:
            return None
        listed = self.folded.get(_fold(path)) or self.folded_directories.get(_fold(path))
        if listed is not None:
            return listed
        parts = path.split("/")
        for depth in range(1, len(parts)):
            directory = "/".join(parts[:depth])
            if directory not in self.directories:
                return self.folded_directories.get(_fold(directory))
        return None

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

    def follow_card(self, path: str) -> bool:
        """`follow` for a `well_known` or `listed` card: a link that cannot be followed is not a run error but a failure of that
        card, kept in `card_failures` (the first one, whoever asks first) for SW-A2A-018. The link stays marked followed, so it is
        no `symlink_skipped` either (r1:F2, invariant 10). A link to a file over `FILE_MAX` stays the run error `unreadable`, as
        for every agent-content path: repository content left unread makes the scan incomplete (1.16.1)."""
        mark = len(self.errors)
        followed = self.follow(path)
        if len(self.errors) > mark and path not in self.too_large_links:
            refusal = self.errors[mark]
            self.card_failures.setdefault(path, (refusal.code, refusal.message))
            del self.errors[mark:]
        return followed

    def member(self, path: str) -> _Resolution | None:
        """The resolution of a link inside a skill package or local plugin directory, by the rules of `follow`
        (r2:F6); None for a link already followed or already an error. A member link is followed or is an error: a
        chain, a path through a directory link, a link to a directory, a missing or excluded target inside the scan
        root and an unreadable target text are `unsafe_path` or `unreadable`, so what the lock covers cannot change
        behind it. Since 1.23.0 (P6-10 spec 7.7, owner spec:Q1) a target outside the scan root is the error
        `unsafe_path` too, with the way out (`_MEMBER_OUTSIDE`): it was a notice with its target text in the
        package's lock hash. Only the target text is read here; resolving marks nothing followed (a package over the
        limits leaves its links to the next package), `adopt` does."""
        if path not in self.links or path in self.followed:
            return None
        if path not in self.resolved:
            resolution = self._resolve(path)
            if path in self.to_lock:  # the lock file before the first `spellwarden lock` (1.16.2): no content, no error
                self.lock_links.add(path)
                self.followed.add(path)
                return None
            if resolution.refusal is not None:
                self.errors.append(Notice("unsafe_path", path, _MEMBER_OUTSIDE) if resolution.outside else resolution.refusal)
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
            text = raw.decode("utf-8")
            target = self._link_target(path, text)
        except UnicodeDecodeError:
            return _Resolution(None, raw, Notice("unsafe_path", path, "symbolic link: target is not UTF-8"), False)
        except _Escape as exc:
            return _Resolution(None, raw, Notice("unsafe_path", path, f"symbolic link: {exc}"), True)
        except UnsafePath as exc:
            # before the first lock `.spellwarden/` may not be a directory of the file set yet (1.16.2): a target the walk
            # followed to it through real directories only is the lock not yet written, when nothing is there on disk
            # (`member` decides whether that is allowed); the link text is never normalised across a segment
            if isinstance(exc, _LockDirAbsent) and self._lock_absent(directory_too=True):
                self.to_lock.add(path)
            return _Resolution(None, raw, Notice("unsafe_path", path, f"symbolic link: {exc}"), False)
        if target in self.links:
            return _Resolution(None, raw, Notice("unsafe_path", path, f"symbolic link to {target!r}, itself a symbolic "
                                                 "link"), False)
        if target not in self.entries and (target in self.directories or target == ""):
            return _Resolution(None, raw, Notice("unsafe_path", path, f"symbolic link to {target!r}, a directory inside "
                                                 "the scan root; a link to a directory is not followed: replace it with "
                                                 "the files it should hold"), False)
        if target not in self.entries and (twin := self.twin(target)) is not None:
            return _Resolution(None, raw, Notice("unsafe_path", path, f"symbolic link to {target!r}, which names "
                                                 f"{twin!r} only in another case or Unicode form; use the exact name"),
                               False)
        if target in self.too_large:  # repository content an agent loads through the link, left unread (1.16.1)
            self.too_large_links.add(path)
            return _Resolution(None, raw, Notice("unreadable", path, f"symbolic link to {target!r}, {_TOO_LARGE}"), False)
        if target not in self.entries:
            # before the first `spellwarden lock`, `.spellwarden/` a real directory of the file set: a package member is its
            # own (`member`), when no file of any kind is at the lock's path
            if target == _lock_path() and self._lock_absent(directory_too=False):
                self.to_lock.add(path)
            return _Resolution(None, raw, Notice("unsafe_path", path, f"symbolic link to {target!r}, not a file of the "
                                                 "file set"), False)
        return _Resolution(target, raw, None, False)

    def directory_link(self, path: str) -> _Resolution:
        """With `--follow-links` (Engine 1.20.0: scan selection, 7.20.3, D40, D41): the directory of the file set that the listed
        link `path` in an instruction folder names, read from the link's text by `_link_target`, as every link is (no file-system
        call receives the text). `target` is that directory when the link can be followed: inside the scan root, reached through
        real directories only, not the scan root and not a directory that holds the link. No `target` and no `refusal`: the link
        names a regular file of the set, left to the rules of 1.19.0. Otherwise `refusal` says why: `unreadable` for a text the
        system cannot read, `unsafe_path` for every other target, with the way out; since 1.23.0 (P6-10 spec 7.7, owner
        spec:Q1) a relative target outside the scan root is `unsafe_path` too (it was the notice `symlink_skipped`)."""
        try:
            raw = self.fileset.link_target(path)
        except (UnsafePath, paths.TooLarge) as exc:
            return _Resolution(None, None, _link_refused(path, f"symbolic link: {exc}"), False)
        except OSError as exc:
            return _Resolution(None, None, Notice("unreadable", path, "symbolic link cannot be read "
                                                  f"({exc.strerror or type(exc).__name__})"), False)
        try:
            target = self._link_target(path, raw.decode("utf-8"))
        except UnicodeDecodeError:
            return _Resolution(None, raw, _link_refused(path, "symbolic link: target is not UTF-8"), False)
        except _Escape:
            return _Resolution(None, raw, _link_refused(path, "symbolic link to a place outside the scan root"), True)
        except UnsafePath as exc:
            return _Resolution(None, raw, _link_refused(path, f"symbolic link: {exc}"), False)
        if target in self.links:
            return _Resolution(None, raw, _link_refused(path, f"symbolic link to {target!r}, itself a symbolic link"), False)
        if target in self.entries or target in self.too_large:
            return _Resolution(None, raw, None, False)
        if target == "":
            return _Resolution(None, raw, _link_refused(path, "symbolic link to the scan root"), False)
        if path.startswith(target + "/"):
            return _Resolution(None, raw, _link_refused(path, f"symbolic link to {target!r}, a directory that holds the link"),
                               False)
        if target not in self.directories:
            twin = self.twin(target)
            why = (f"symbolic link to {target!r}, which names {twin!r} only in another case or Unicode form; use the exact name"
                   if twin is not None else f"symbolic link to {target!r}, not a directory of the file set")
            return _Resolution(None, raw, _link_refused(path, why), False)
        return _Resolution(target, raw, None, False)

    def adopt(self, path: str, target: str) -> bool:
        """The followed link `path` becomes a file of the set holding `target`'s bytes, named by the link."""
        self.followed.add(path)
        content = self.read(target)
        if content is None:
            return False
        self.targets[path] = target
        entry = self.entries[target]
        self.entries[path] = FileEntry(path, entry.size, entry.executable, self.links[path].tracked)
        self.contents[path] = content
        self.paths.add(path)
        return True

    def _link_target(self, link: str, text: str) -> str:
        """The scan-root path a link's target names, decided from the text alone: no file-system call ever receives
        link-target text from the repository (r3:N1). A target absolute in the sense of any OS is refused first. Every
        other refusal of the containment rule (6.13) applies except the parent segment: the target is resolved
        lexically, `os.path.normpath(os.path.join(REALROOT, link_dir, text))` with REALROOT the real path of the
        operator's scan root, and compared lexically with REALROOT (`_same`). Inside, it may climb with `..`, out and
        back in by the root's own name included, through directories of the file set that are not links (an agent's
        file system would resolve a link, the scanner reads paths as written). Outside, it is `_Escape`, except when it
        enters `/proc` or `/dev` on the way, whose paths depend on the process reading them (r3:N2). It fails closed
        where a file system might read the text otherwise: a target that names a directory above the root, a segment
        of only dots and spaces, and a descent from above the root by a name that `_may_name` the root's own
        directory at that depth without being it (`REPO`, `repo.`, `REPO~1`) are `unsafe_path`."""
        if _absolute(text):
            raise UnsafePath("absolute target; use a relative link or a real file")
        contain("", "/".join("_" if segment == ".." else segment for segment in text.split("/")))
        segments = (text[2:] if text.startswith("./") else text).rstrip("/").split("/")
        root = self._root_parts()
        directory = posixpath.dirname(link)
        stack = [*root, *(directory.split("/") if directory else [])]
        for index, segment in enumerate(segments):
            if segment == "..":
                if stack:  # `..` at the anchor stays there, as `normpath` and every file system do
                    stack.pop()
            else:
                if not segment.rstrip(". "):  # Windows may read `...` as `.`, so the lexical walk would be wrong
                    raise UnsafePath(f"target holds the segment {segment!r}, only dots and spaces")
                depth = len(stack)
                if depth < len(root) and self._ancestor(stack, root) and not _same(segment, root[depth]) \
                        and _may_name(segment, root[depth]):
                    raise UnsafePath(f"target climbs out of the scan root and {segment!r} may lead back into it under "
                                     "another spelling; use a path that stays inside the scan root")
                stack.append(segment)
            inside = self._inside_root(stack, root)
            if inside is None:
                if segment != ".." and os.name != "nt" and stack[0] in _PROCESS_RELATIVE:
                    raise UnsafePath(f"target passes through /{stack[0]}, where a path depends on the process "
                                     "reading it")
                continue
            if index == len(segments) - 1:
                continue
            if inside in self.links:
                raise UnsafePath("target passes through a symbolic link")
            if inside not in self.directories:
                twin = self.twin(inside)
                message = f"target passes through {inside!r}, " + (
                    f"which names {twin!r} only in another case or Unicode form; use the exact name" if twin
                    else "not a directory of the file set")
                lock_dir, lock_name = _lock_path().split("/")
                if twin is None and inside == lock_dir and index == len(segments) - 2 and segments[-1] == lock_name:
                    raise _LockDirAbsent(message)  # every segment before it was a directory of the file set, no link
                raise UnsafePath(message)
        inside = self._inside_root(stack, root)
        if inside is not None:
            return inside
        if self._ancestor(stack, root):
            raise UnsafePath("target names a directory above the scan root")
        raise _Escape("target leaves the scan root")

    def _lock_absent(self, *, directory_too: bool) -> bool:
        """Whether the lock file is not there at all (1.16.2), judged on the fixed paths `.spellwarden` and
        `.spellwarden/lock.json` under the operator's scan root, never on link text: no entry, link, oversize file or path
        the settings dropped at the lock's path or (`directory_too`) at `.spellwarden` or below it, and on disk nothing at
        the lock's path (`lstat`) and `.spellwarden` absent (`directory_too`) or a real directory, never a link."""
        lock = _lock_path()
        lock_dir = lock.split("/")[0]
        listed = (self.entries.keys() | self.links | set(self.too_large) | set(self.fileset.deselected))
        if lock in listed or lock_dir in self.links or lock_dir in self.paths:
            return False
        if directory_too and any(name == lock_dir or name.startswith(lock_dir + "/") for name in listed):
            return False
        if self.fileset.index is not None:  # 1.19.0, `--staged`: the index is the whole file set, so nothing listed is absent
            return True
        try:
            directory = os.lstat(os.path.join(self.fileset.root, lock_dir))
        except FileNotFoundError:
            return directory_too
        except OSError:
            return False
        if not stat.S_ISDIR(directory.st_mode):
            return False
        try:
            os.lstat(os.path.join(self.fileset.root, lock))
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return False

    def _root_parts(self) -> list[str]:
        """The components of the real path of the operator's scan root, computed once (never from repository text);
        a root that cannot be resolved refuses every link target (fail closed)."""
        if self.real_root is None:
            try:
                self.real_root = _parts(os.path.realpath(self.fileset.root))
            except (OSError, ValueError) as exc:
                raise UnsafePath(f"the scan root cannot be resolved ({type(exc).__name__})") from exc
        return self.real_root

    @staticmethod
    def _ancestor(stack: list[str], root: list[str]) -> bool:
        """Whether the absolute components `stack` name a directory above the real root (one of its ancestors)."""
        return len(stack) < len(root) and all(_same(a, b) for a, b in zip(stack, root, strict=False))

    @staticmethod
    def _inside_root(stack: list[str], root: list[str]) -> str | None:
        """The scan-root path of the absolute components `stack`, or None when they are not under the real root."""
        if len(stack) < len(root) or not all(_same(a, b) for a, b in zip(stack, root, strict=False)):
            return None
        return "/".join(stack[len(root):])

    def document(self, kind: str, path: str, plugin: str | None = None, *,
                 drop_references: bool = False, reader: _Reader | None = None) -> ConfigDocument | None:
        """The one document of `path`. A file reached in a second role (a global name, a plugin's conventional
        path, a manifest reference read by its JSON shape) stays one document of its first kind, but is also
        parsed in the new role and keeps what that role finds (r1:F1): what an agent loads in either role is
        judged, listed and locked. A path the file set holds only in another spelling is `unsafe_path` (`twin`).
        `reader` (Engine 1.20.0: scan selection, 7.2.1): the row of `_READERS` that reaches a path by its name first. A row of
        1.19.0's three kinds reads it as before; a new row reads it with its own reader, which counts as no role, so a later
        role of any kind, the row's own included, parses the bytes again and adds what it finds; the TOML row takes no JSON
        role at all."""
        if path in self.documents:
            if plugin is not None:
                self.owners.setdefault(path, plugin)
            if path in self.toml:  # 7.2.1: no JSON role is parsed over Codex's TOML
                return self.documents[path]
            if kind not in self.roles[path]:
                self.roles[path].add(kind)
                content = self.contents.get(path)
                if content is not None:
                    self.documents[path] = self._merge(self.documents[path], _parse(kind, path, content))
            return self.documents[path]
        if path in self.toml:  # a `config.toml` the TOML reader refused: its error is reported once
            return None
        if (twin := self.twin(path)) is not None:
            if path not in self.twins:  # reported once, whichever role asks again
                self.twins.add(path)
                self.errors.append(Notice("unsafe_path", path, f"names {twin!r} only in another case or Unicode form; "
                                          "use the exact name"))
            return None
        if not self.follow(path):
            return None
        content = self.read(path)
        if content is None:
            return None
        if reader is not None and reader.toml:
            return self._codex(path, content, plugin)
        roles = {kind}
        if reader is not None and reader.read is not None:
            parsed = reader.read(path, content)
            roles = set()  # the row's own read is no role (7.2.1)
        else:
            parsed = _parse(kind, path, content)
        if drop_references:
            parsed = replace(parsed, references=())
        self.documents[path] = parsed
        self.roles[path] = roles
        if plugin is not None:
            self.owners[path] = plugin
        self._report(parsed.error, path)
        return parsed

    def _codex(self, path: str, content: bytes, plugin: str | None) -> ConfigDocument | None:
        """A repository's `.codex/config.toml` (Engine 1.20.0: scan selection, 7.2.3, 7.8): one settings document without
        `notify` (D3) and its `[plugins]` and `[marketplaces]` entries (`listings`). A file that is not UTF-8 TOML is the error
        `unreadable` with its way out and no document; entries whose item path a server takes, and more than `MAX_PLUGINS`
        plugins or marketplaces, are errors as in `scan --user`: the scan is incomplete, never a pass."""
        self.toml.add(path)
        config = userdocs.read_codex_config(path, content, notify=False)
        if config.document is None:
            self.errors.append(Notice("unreadable", path, f"{config.error}; not judged, so the scan is incomplete: fix the file, "
                                      "or leave it out with `exclude` in .spellwarden/config.yml"))
            return None
        self.documents[path] = config.document
        self.roles[path] = set()
        if plugin is not None:
            self.owners[path] = plugin
        self._report(config.document.error, path)
        self.listings[path] = config.listing
        if config.error is not None:
            self.errors.append(Notice("unreadable", path, f"{config.error}; not judged"))
        if config.listing.cut:
            self.errors.append(Notice("truncated", path, f"{config.listing.cut} more entries were not read: the scanner reads at "
                                      f"most {MAX_PLUGINS} plugins and {MAX_PLUGINS} marketplaces per file, so the scan is "
                                      "incomplete; leave the file out with `exclude` in .spellwarden/config.yml"))
        return config.document

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


def base_parses(kind: str, path: str, content: bytes) -> tuple[ConfigDocument, ...]:
    """The parses of a gated document's base revision (`connected._base_view`; Engine 1.20.0: scan selection, 7.2.1): at a path
    of 1.19.0's three kinds, or a path no row of `_READERS` names, by `kind` and then by the MCP parser, as before; at a new JSON
    path by its row's reader and then by the MCP parser; at `.codex/config.toml` by the TOML reader only, none when it refuses."""
    reader = _reader(path)
    if reader is None or (reader.read is None and not reader.toml):
        return tuple(_parse(parse_as, path, content) for parse_as in dict.fromkeys((kind, "mcp")))
    if reader.toml:
        config = userdocs.read_codex_config(path, content, notify=False)
        return () if config.document is None else (config.document,)
    return reader.read(path, content), _parse("mcp", path, content)


_SKILL_NAME_CASE = ("an agent on a case-insensitive file system may load this as SKILL.md; rename it to SKILL.md to "
                    "have it scanned as a skill, or rename it away")
# a variant under `skills/<name>/` is scanned as the skill's SKILL.md (`_is_loaded_variant`), so it says so (r3:N5)
_SKILL_NAME_CASE_LOADED = ("scanned as a skill because agents on case-insensitive file systems load it as SKILL.md; "
                           "rename it to SKILL.md so every agent loads it the same way")

_DOCUMENT_MESSAGES = {
    "too_large": "configuration document over 1 MiB; not judged",
    "not_utf8": "configuration document is not UTF-8; not judged",
    "not_json": "configuration document is not valid JSON (comments and trailing commas are accepted); not judged",
    "duplicate_key": "a key repeats in one object, and agents disagree on which value wins; not judged",
    "too_deep": "configuration document nests deeper than 32 levels; not judged",
    "not_an_object": "configuration document is not a JSON object; not judged",
    "truncated": "more entries than the scanner reads; the first entries were judged, the rest were not",
}


_TOO_LARGE = (f"larger than {FILE_MAX // 2**20} MiB; not read, so the scan is incomplete: make the file smaller, or leave it "
              "out with `exclude` in .spellwarden/config.yml")

# Engine 1.20.0 (scan selection, 7.20.3, D41): a linked instruction directory that `--follow-links` cannot follow
_LINK_WAY_OUT = ("not followed, so the scan is incomplete: replace the link with the files it should hold, or leave it out with "
                 "`exclude` in .spellwarden/config.yml")
# P6-10 spec 7.7 (1.23.0, owner spec:Q1): a link inside a skill or a local plugin directory whose target leaves the scan root
_MEMBER_OUTSIDE = ("symbolic link to a place outside the scan root; not followed, so the scan is incomplete: replace the link "
                   "with the file it names, or leave it out with `exclude` in .spellwarden/config.yml")


def _link_refused(path: str, why: str) -> Notice:
    return Notice("unsafe_path", path, f"{why}; {_LINK_WAY_OUT}")


def _follow_references(builder: _Builder, manifest: ConfigDocument, directory: str, plugin: str) -> None:
    """Every reference of a plugin manifest that the containment rule accepts and that names a file of the set is
    followed, whatever its name; the JSON shape picks the parser (`reference_kind`). A referenced manifest's own
    references are not followed (one level). A file that is no configuration gets a notice and stays covered by
    the plugin directory's hash in the lock. A file that is already a document (a global name such as
    `.claude/settings.json`, a plugin's conventional path, an earlier reference) stays one document of its kind and
    is also judged in the role its shape gives it here (`_Builder.document`, r1:F1)."""
    for reference in manifest.references:
        try:
            target = contain(directory, reference)
        except UnsafePath as exc:
            builder.errors.append(Notice("unsafe_path", manifest.path, f"reference {reference!r}: {exc}"))
            continue
        if (twin := builder.twin(target)) is not None:
            builder.errors.append(Notice("unsafe_path", manifest.path, f"reference {reference!r} names {twin!r} only in "
                                         "another case or Unicode form; use the exact name"))
            continue
        if not builder.follow(target):
            if target not in builder.links and target not in builder.too_large:  # either is already an error
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


def discover(fileset: FileSet, *, listed_cards: Sequence[str] = (), agents_configured: bool = False,
             instructions: bool = True, follow_links: bool = False) -> Discovery:
    """`listed_cards` are the paths of `a2a.cards`; `agents_configured` says `a2a.agents` is not empty (so that a repository
    whose only agent content is a configured agent is not told there is none). `instructions` is the setting of that name: with
    it off, no instruction file is looked for (Phase 3 batch 1 spec 10.5). `follow_links` is `--follow-links` (Engine 1.20.0:
    scan selection, 7.20): with it, and with instruction files on, a linked directory in an instruction folder is followed and
    its files are instruction files under the link's path; without it, such a link is the notice `symlink_skipped`, as on
    1.19.0."""
    builder = _Builder(fileset)
    builder.notices.extend(Notice("skill_name_case", path,
                                  _SKILL_NAME_CASE_LOADED if _is_loaded_variant(path) else _SKILL_NAME_CASE)
                           for path in sorted({*builder.paths, *builder.links}) if _is_skill_name_variant(path))
    plugin_dirs: dict[str, str] = {}  # directory -> plugin name
    plugin_items: list[Item] = []
    for path in sorted(builder.links):  # links at a global name; plugin paths and references follow theirs below
        if _card_form(path) == "well_known":
            builder.follow_card(path)  # a failure is the card's, found again by `_agent_cards` (r1:F2)
        elif _global_kind(path) is not None or _is_skill_file(path):
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
    # manifest reference; every later role adds what it finds to that one document (r1:F1). Since 1.20.0 the global name's row
    # of `_READERS` picks the reader (Engine 1.20.0: scan selection, 7.2.1).
    for path in sorted(builder.paths):
        reader = _reader(path)
        if reader is not None and reader.kind != "marketplace":
            builder.document(reader.kind, path, reader=reader)
    for directory, name in plugin_dirs.items():
        builder.document("mcp", _join(directory, ".mcp.json"), name)
        builder.document("hooks", _join(directory, "hooks/hooks.json"), name)
        builder.document("plugin", _join(directory, ".claude-plugin/plugin.json"), name)
    for directory, name in plugin_dirs.items():
        manifest = builder.documents.get(_join(directory, ".claude-plugin/plugin.json"))
        if manifest is not None:
            _follow_references(builder, manifest, "" if directory == "." else directory, name)
    skills = _skills(builder, plugin_dirs)
    # A local plugin whose directory holds no file of the set is listed and locked by its source only; one over the
    # package limits is an item error and is not read whole, like a skill (r0:F8).
    dirs: list[PluginDir] = []
    for directory in sorted(plugin_dirs):
        members = _package(builder, directory, _inside(directory, []), "plugin directory")
        if members:
            dirs.append(PluginDir(directory, _read_all(builder, members), own=frozenset(p for p in members if p in builder.own)))
    cards = _agent_cards(builder, listed_cards)
    # Before the loop below: a link followed here is no `symlink_skipped`.
    skill_directories = frozenset(skill.path for skill in skills)
    linked = (_linked_files(builder, _linked_directories(builder, skill_directories, plugin_dirs))
              if instructions and follow_links else {})
    instruction_list = _instruction_files(builder, skill_directories, plugin_dirs, linked) if instructions else []
    if instructions:
        # an instruction file inside a skill is scanned by that skill, once (one owner per file), and read as Markdown there
        # as it would be on its own: otherwise a root SKILL.md would turn the Markdown rules off for every rule file
        skills = [replace(skill, markdown=frozenset(p for p in skill.files if instruction_files.format_of(p) is not None))
                  for skill in skills]
    for path in sorted(builder.links):
        if path in builder.lock_links:  # 1.16.2: as `own`, before the lock exists
            builder.notices.append(Notice("symlink_skipped", path, "symbolic link to the scanner's own file "
                                                                   "'.spellwarden/lock.json', which does not exist yet: left "
                                                                   "out of the package's lock hash like that file"))
        elif path in builder.own:  # r3 nit: hashing the lock into itself would make every lock stale
            builder.notices.append(Notice("symlink_skipped", path, f"symbolic link to the scanner's own file "
                                                                   f"{builder.own[path]!r}: scanned, but left out of the "
                                                                   "package's lock hash like that file"))
        elif path not in builder.followed:
            builder.notices.append(Notice("symlink_skipped", path, "symbolic link; skipped"))
    unread = _oversize_files(builder, frozenset(skill.path for skill in skills), plugin_dirs, listed_cards, instructions)
    items = _items(builder, skills, plugin_items)
    items = sorted([*items, *(Item("instructions", f.path, f.name, f.plugin, f.format, f.front_matter)
                              for f in instruction_list)], key=lambda item: (item.kind, item.path))
    # a look-alike file that is not a card is no agent content (r0:F3)
    if not items and not any(is_card(card) for card in cards) and not agents_configured and not unread:
        builder.notices.append(Notice("no_agent_content", "", "No agent content found"))
    return Discovery(tuple(items), tuple(skills), tuple(builder.documents[p] for p in sorted(builder.documents)),
                     tuple(dirs), tuple(builder.notices), tuple(builder.errors), fileset, tuple(cards),
                     instruction_files=tuple(instruction_list), facts=_facts(builder))


def _oversize_files(builder: _Builder, skill_directories: frozenset[str], plugin_dirs: dict[str, str],
                    listed_cards: Sequence[str], instructions: bool) -> bool:
    """The files over `FILE_MAX` (1.16.1, README "Limits"). One that is agent content by the rules discovery reads it by (a
    configuration document's name, a skill file or any file of a skill, any file of a local plugin directory, an instruction
    file while they are on, a file named like an agent card or listed in `a2a.cards`) is the error `unreadable`: what the
    repository holds and the scanner leaves unread makes the scan incomplete (exit 2), and `exclude` is the way out. Any other
    file is the notice `file_too_large`, as before. Returns whether one was agent content."""
    listed = frozenset(listed_cards)
    unread = False
    for path in sorted(builder.too_large):
        agent = (_global_kind(path) is not None or _is_skill_file(path) or _owned_by_a_skill(path, skill_directories)
                 or any(_under(path, directory) for directory in plugin_dirs)
                 or (instructions and instruction_files.format_of(path) is not None)
                 or _card_form(path) is not None or path in listed)
        if agent:
            unread = True
            builder.errors.append(Notice("unreadable", path, _TOO_LARGE))
        else:
            builder.notices.append(Notice("file_too_large", path, f"larger than {FILE_MAX // 2**20} MiB; skipped"))
    return unread


def _owned_by_a_skill(path: str, skill_directories: frozenset[str]) -> bool:
    """Whether `path` is inside a skill directory (`"."` is the scan root, so a root skill owns every file): the skill's scan
    already reads it, so it is not listed again and a finding appears once (spec 10.2, one owner per file). A plugin directory
    scans none of its files, so it owns none."""
    if "." in skill_directories:
        return True
    head = path
    while (cut := head.rfind("/")) > 0:
        head = head[:cut]
        if head in skill_directories:
            return True
    return False


def _plugin_instruction(path: str, plugin_dirs: Mapping[str, str]) -> tuple[str, str] | None:
    """`(format, plugin name)` of a Markdown file below the `commands/` or `agents/` folder of a local plugin directory, at every
    depth (Engine 1.20.0: scan selection, 7.7, D16): `claude-command` or `claude-agent`. Matched after NFC and case folding, as
    the instruction formats are; a plugin at the marketplace root (`.`) reads the root folders; the deepest plugin directory that
    holds the path names it. None for any other path."""
    folded = _fold(path)
    if not folded.endswith(".md"):
        return None
    for directory in sorted(plugin_dirs, key=lambda d: 0 if d == "." else len(d), reverse=True):
        base = "" if directory == "." else _fold(directory) + "/"
        for folder, format in (("commands/", "claude-command"), ("agents/", "claude-agent")):
            if folded.startswith(base + folder):
                return format, plugin_dirs[directory]
    return None


def _instruction_files(builder: _Builder, skill_directories: frozenset[str], plugin_dirs: Mapping[str, str],
                       linked: Mapping[str, str] | None = None) -> list[InstructionFile]:
    """The instruction files of the file set (Phase 3 batch 1 spec 10.2, 10.3), in path order, at most
    `instruction_files.MAX_FILES`, root places first (the error `instructions_limit` counts the rest, which are not read).
    Since 1.20.0 also the commands and agents of a local plugin directory that no format names (`_plugin_instruction`), which
    carry the plugin's name, count toward the limit and are never loaded first (Engine 1.20.0: scan selection, 7.7), and, with
    `--follow-links`, the files of `linked` (`{linked path: file of the set}`, `_linked_files`), which are read from their file
    and named by their linked path, ordered by it like every other (7.20.4).
    A symbolic link at one of these names is followed when it can be, as at the names of a configuration file; one that cannot
    be followed is the notice
    `symlink_skipped` it was on 1.12.0, never an error. A rule file whose front matter cannot be read still scans and has the
    notice `instructions_front_matter`."""
    # Past the limit, the files an agent reads at the root of the repository come first (`instruction_files.loaded_first`),
    # then the rest shallowest first: decoys anywhere in the tree cannot push the root `AGENTS.md`, `CLAUDE.md` or a root
    # Cursor or Windsurf rule out of the scan. What is read is then handled in path order.
    candidates: dict[str, tuple[str, str | None, str]] = {}  # path -> (format, plugin, the file of the set it reads)
    for path in {*builder.paths, *builder.links}:
        if _owned_by_a_skill(path, skill_directories):
            continue
        format = instruction_files.format_of(path)
        if format is not None:
            candidates[path] = (format, None, path)
        elif (local := _plugin_instruction(path, plugin_dirs)) is not None:
            candidates[path] = (local[0], local[1], path)
    for path, source in (linked or {}).items():
        format = instruction_files.format_of(path)
        if format is not None:  # `_linked_files` offers only such paths
            candidates[path] = (format, None, source)
    chosen = sorted(candidates, key=lambda path: (not instruction_files.loaded_first(path), path.count("/"), path))
    limit = instruction_files.MAX_FILES
    if len(chosen) > limit:
        builder.errors.append(Notice("instructions_limit", "", f"{len(chosen) - limit} more instruction files were not read: the "
                                     f"scanner reads at most {limit} per scan root, so the scan is incomplete; leave directories "
                                     "out with `exclude` in .spellwarden/config.yml"))
    found: list[InstructionFile] = []
    for path in sorted(chosen[:limit]):
        format, plugin, source = candidates[path]
        if source == path and not _follow_quietly(builder, path):
            continue
        content = builder.read(source)
        if content is None:
            continue
        front_matter, readable = instruction_files.front_matter_of(format, content)
        if not readable:
            builder.notices.append(Notice("instructions_front_matter", path, "the front matter of this rule file could not be "
                                          "read, so its scope is not shown; the file is still scanned"))
        found.append(InstructionFile(path, posixpath.basename(path), format, front_matter, content, plugin))
    return found


def _linked_directories(builder: _Builder, skill_directories: frozenset[str],
                        plugin_dirs: Mapping[str, str]) -> list[tuple[str, str]]:
    """With `--follow-links` (Engine 1.20.0: scan selection, 7.20.2, 7.20.3, D39 to D42): `(link, target directory)` of each
    linked instruction directory that is followed, in the order of `instruction_files.linked_first` and then path, at most
    `instruction_files.MAX_LINKED_DIRECTORIES`. A candidate is a link of the file set not yet followed or refused, at a path where
    a directory could hold an instruction file (`holds_instructions`), and not inside a skill or a local plugin directory, whose
    own link rules of 1.19.0 hold. A refusal of `directory_link` is recorded, and a link to a regular file is left to the rules of
    1.19.0. Every link counted here, followed or past the limit, is marked followed: it gives no `symlink_skipped`."""
    followed: list[tuple[str, str]] = []
    for path in sorted(builder.links):
        if (path in builder.followed or not instruction_files.holds_instructions(path)
                or _owned_by_a_skill(path, skill_directories) or any(_under(path, directory) for directory in plugin_dirs)):
            continue
        resolution = builder.directory_link(path)
        if resolution.refusal is not None:
            builder.followed.add(path)
            builder.errors.append(resolution.refusal)
        elif resolution.target is not None:
            followed.append((path, resolution.target))
    followed.sort(key=lambda pair: (not instruction_files.linked_first(pair[0]), pair[0]))
    limit = instruction_files.MAX_LINKED_DIRECTORIES
    if len(followed) > limit:
        builder.errors.append(Notice("instructions_limit", "", f"{len(followed) - limit} more linked directories in instruction "
                                     f"folders were not followed: the scanner follows at most {limit} per scan root, so the scan "
                                     "is incomplete; leave them out with `exclude` in .spellwarden/config.yml"))
    builder.followed.update(link for link, _ in followed)
    return followed[:limit]


def _linked_files(builder: _Builder, linked: Sequence[tuple[str, str]]) -> dict[str, str]:
    """`{linked path: file of the set}` for the files below each followed directory (7.20.4, D40): each regular file `T/r` of the
    set, at every depth, is offered at `L/r`, and is an instruction file there when `format_of(L/r)` names one (the folder's own
    rule). Only instruction files are made: no document, skill, plugin or agent card. A link below `T` is not followed through
    `L`: where its linked path would be an instruction file or a linked instruction directory it is the error `unsafe_path`, else
    nothing. A file of `T` over 10 MiB whose linked path has a format is the error `unreadable` at that path."""
    offered: dict[str, str] = {}
    for link, target in linked:
        prefix = target + "/"
        for path in _under_range(builder, target):
            linked_path = link + "/" + path[len(prefix):]
            if path in builder.links:
                if (instruction_files.format_of(linked_path) is not None
                        or instruction_files.holds_instructions(linked_path)):
                    builder.errors.append(Notice("unsafe_path", linked_path, f"reached through the link `{link}`; a link is "
                                                 "followed one level only: replace it with the file or directory it names"))
            elif path in builder.paths and instruction_files.format_of(linked_path) is not None:
                offered[linked_path] = path
        for path in sorted(builder.too_large):
            if path.startswith(prefix):
                linked_path = link + "/" + path[len(prefix):]
                if instruction_files.format_of(linked_path) is not None:
                    builder.errors.append(Notice("unreadable", linked_path, _TOO_LARGE))
    return offered


def _agent_cards(builder: _Builder, listed: Sequence[str]) -> list[CardFile]:
    """The agent card files (O4 spec 6.3): every file whose name makes a card and every path of `a2a.cards`, in path order,
    at most `MAX_CARDS` (the error `a2a_cards_limit` counts the rest). A listed path that is not in the file set is the notice
    `file_missing`. A path both discovered and listed is one card: `listed` when its name alone would make it only a
    `named` or `legacy_path` card (an unreadable one is then a finding, not a notice), else the form its name gives. A
    `well_known` or `listed` card that cannot be followed or read is a `CardFile` with `read_error` (SW-A2A-018), never an error
    of the run (r1:F2)."""
    forms: dict[str, str] = {}
    for path in sorted({*builder.paths, *builder.links}):
        form = _card_form(path)
        if form is None:
            continue
        if form == "well_known":
            if builder.follow_card(path) or path in builder.card_failures:
                forms[path] = form
        elif _follow_quietly(builder, path):
            forms[path] = form
    for path in dict.fromkeys(listed):
        if not builder.follow_card(path) and path not in builder.card_failures:
            if path in builder.too_large or path in builder.too_large_links:  # the error `unreadable`, not a missing file
                continue
            builder.notices.append(Notice("file_missing", path, "listed in a2a.cards but not in the file set"))
            continue
        if forms.get(path) != "well_known":
            forms[path] = "listed"
    chosen = sorted(forms)
    if len(chosen) > MAX_CARDS:
        builder.errors.append(Notice("a2a_cards_limit", "", f"{len(chosen) - MAX_CARDS} more agent cards were not read: the "
                                     f"scanner checks at most {MAX_CARDS} per run, so the scan is incomplete; leave directories "
                                     "out with `exclude` in .spellwarden/config.yml"))
    cards = []
    for path in chosen[:MAX_CARDS]:
        mark = len(builder.errors)
        failure = builder.card_failures.get(path)
        content = None if failure is not None else builder.read(path)
        if content is None and failure is None and len(builder.errors) > mark:
            failure = (builder.errors[mark].code, builder.errors[mark].message)
        del builder.errors[mark:]  # a card that cannot be read is a finding or a notice, never an error (r0:F2, r1:F2)
        if content is not None:
            cards.append(CardFile(path, forms[path], content))
        elif forms[path] in ("legacy_path", "named"):
            builder.notices.append(Notice("a2a_not_card", path, "not checked as an agent card: cannot be read"))
        else:
            cards.append(CardFile(path, forms[path], b"", failure or ("unreadable", "cannot be read")))
    return cards


def _follow_quietly(builder: _Builder, path: str) -> bool:
    """`builder.follow` for a look-alike name (`legacy_path`, `named`), which other software uses: a link that cannot be
    followed records no error and is not marked followed, so it stays the notice `symlink_skipped` it was in 1.2.1 (r0:F2,
    spec 6.3, invariant 10). A path listed in `a2a.cards` follows the link again and records the error then."""
    if path not in builder.links or path in builder.followed:
        return builder.follow(path)
    mark = len(builder.errors)
    if builder.follow(path):
        return True
    if path in builder.too_large_links:  # its target is repository content left unread: the error stays (1.16.1)
        return False
    del builder.errors[mark:]
    builder.followed.discard(path)
    return False


def _owns(plugin: str, skill: str) -> bool:
    """Whether the local plugin directory `plugin` owns the skill directory `skill`. A plugin at the marketplace root
    (`"."`, r2:F12) owns only the skills of its conventional `skills/` directory, whatever its case: the rest of the
    repository (`.claude/skills/<x>` above all) holds project skills, not the plugin's (r3 nit). A plugin in a
    subdirectory owns every skill under it."""
    if plugin == ".":
        return _fold(skill).startswith("skills/")
    return _under(skill, plugin)


def _under_range(builder: _Builder, directory: str) -> Sequence[str]:
    """The paths and links of the file set under the scan-root directory `directory` (`"."` is all of them), sorted:
    the names starting with `directory/` are one contiguous slice of the sorted universe, ending before `directory0`
    (`0` follows `/`). Reading a package's slice rather than every path keeps a repository with thousands of skills
    from taking minutes (rule growth follow-up, 2026-11-03)."""
    keys = builder.universe
    if directory == ".":
        return keys
    return keys[bisect.bisect_left(keys, directory + "/"):bisect.bisect_left(keys, directory + "0")]


def _nested_roots(builder: _Builder, directory: str) -> tuple[str, ...]:
    """The skill directories strictly under `directory`, sorted, as `identity.nested_skill_roots(builder.paths, ...)`
    finds them, from the directory's own slice."""
    root = "" if directory == "." else directory
    found = {p.rpartition("/")[0] for p in _under_range(builder, directory) if p in builder.paths and _is_skill_file(p)}
    return tuple(sorted(d for d in found if d != root))


def _inside(directory: str, nested: Sequence[str]) -> Callable[[str], bool]:
    """Whether a path is in the package at `directory` and in none of the skills nested in it. A path is under a nested
    root exactly when one of its parent directories is that root, so the test walks the parents (its depth) rather
    than every nested root."""
    inner = frozenset(nested)

    def inside(path: str) -> bool:
        if not _under(path, directory):
            return False
        head = path
        while (cut := head.rfind("/")) > 0:
            head = head[:cut]
            if head in inner:
                return False
        return True

    return inside


def _package(builder: _Builder, directory: str, inside: Callable[[str], bool], what: str) -> list[str] | None:
    """The members of a skill package or local plugin directory: its files of the set, with every member link the rules
    of `_Builder.follow` accept followed (its target's bytes are the member's content under the link's path, r2:F6); a
    member link they refuse is an error (`_Builder.member`; since 1.23.0 one whose target leaves the scan root too,
    P6-10 spec 7.7). None, with the item error recorded, when the package is over the limits, judged before any member
    or link target is read: the count with every link, the bytes with the listed size of each target followed."""
    candidates = _under_range(builder, directory)
    regular = [p for p in candidates if p in builder.paths and inside(p)]
    pending = [p for p in candidates if p in builder.links and p not in builder.paths and inside(p)]
    count = len(regular) + len(pending)
    size = sum(builder.entries[p].size for p in regular)
    if _too_large(builder, directory, count, size, what):
        return None
    resolved = {link: resolution for link in pending if (resolution := builder.member(link)) is not None}
    targets = {link: r.target for link, r in resolved.items() if r.target is not None}
    if _too_large(builder, directory, count, size + sum(builder.entries[t].size for t in targets.values()), what):
        return None
    from spellwarden_cli.lockfile import LOCK_PATH  # lockfile imports this module

    # Only a link to the lock is left out of the lock hash (it would hash the lock into itself); a link to the settings
    # or the baseline is package content like any other file it reaches (r4:R4-3).
    for link, target in targets.items():
        if builder.adopt(link, target) and target == LOCK_PATH:
            builder.own[link] = target
    return [p for p in candidates if p in builder.paths and inside(p)]


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
        nested = _nested_roots(builder, directory)
        before = len(builder.errors)
        members = _package(builder, directory, _inside(directory, list(nested)), "skill package")
        if members is None:
            continue
        files = _read_all(builder, members)
        if len(builder.errors) != before:
            continue  # an unreadable member makes the skill an item error, not a partial scan
        owners = [d for d in plugin_of_dir if _owns(d, directory)]
        plugin = plugin_of_dir[max(owners, key=lambda d: 0 if d == "." else len(d))] if owners else None
        # the root skill is "." and never the checkout directory's name: a lock and a report must not depend on where
        # the repository sits on disk (r0:F4)
        name = posixpath.basename(directory) if directory != "." else "."
        # one skill file per directory: two names that fold alike are a `case_collision` and left out of the set
        variant = next((p for p in members if posixpath.dirname(p) == directory and _is_loaded_variant(p)), None)
        packages.append(SkillPackage(directory, name, files, frozenset(p for p in members if entries[p].executable), plugin,
                                     variant=variant, own=frozenset(p for p in members if p in builder.own), nested=nested,
                                     targets=frozenset(builder.targets[p] for p in members if p in builder.targets)))
    return packages


def _items(builder: _Builder, skills: list[SkillPackage], plugin_items: list[Item]) -> list[Item]:
    items = [Item("skill", skill.path, skill.name, skill.plugin) for skill in skills]
    items.extend(plugin_items)
    for path, document in builder.documents.items():
        owner = builder.owners.get(path)
        items.append(Item(_ITEM_KIND[document.kind], path, posixpath.basename(path), owner))
        for server in document.servers:
            items.append(Item("mcp-server", f"{path}#{server.name}", server.name, owner))
    for path, listing in builder.listings.items():  # 1.20.0 (7.8): Codex's entries, covered by the document's lock hash
        owner = builder.owners.get(path)
        items.extend(Item(entry.kind, entry.path, entry.name, owner) for entry in listing.entries)
    return sorted(items, key=lambda item: (item.kind, item.path))


def _facts(builder: _Builder) -> dict[str, dict]:
    """The facts of the `[plugins]` and `[marketplaces]` entries of each `.codex/config.toml` read (Engine 1.20.0: scan selection,
    7.8), as `scan --user` gives them: a marketplace's reduced source URL, or its local source as the file wrote it; a plugin's
    `marketplace_item` when the same file lists that marketplace."""
    facts: dict[str, dict] = {}
    for path, listing in builder.listings.items():
        listed = {entry.path for entry in listing.entries}
        for entry in listing.entries:
            if entry.kind == "marketplace":
                source = entry.facts.get("source_url") or entry.facts.get("source_path")
                facts[entry.path] = {"source": source} if source else {}
            elif entry.facts.get("marketplace"):
                item = f"{path}#marketplaces.{entry.facts['marketplace']}"
                facts[entry.path] = {"marketplace_item": item} if item in listed else {}
    return facts


__all__ = ["Discovery", "InstructionFile", "Item", "PluginDir", "SkillPackage", "discover"]
