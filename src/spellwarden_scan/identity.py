"""Gate identities, defined once (O3 spec 5.1): what the private registry compares for a skill package, a remote MCP
server, a plugin and a marketplace, so that the command and the hosted side cannot drift. Pure: URLs are split with
`agentconfig.url_parts` (the engine imports no `urllib`), files arrive as `{path: bytes}`.

The vector files `tests/vectors/normalise_url.json` and `tests/vectors/command_identity.json` pin these functions and
are shared with the hosted side."""
from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from spellwarden_scan.agentconfig import has_declared_pin, url_parts
from spellwarden_scan.canonical import canonical_sha256
from spellwarden_scan.model import PluginSource

# Directories whose content a checkout may hold and a forge archive does not (or the other way round): code a skill may
# load that the package hash would not cover, so a package that has one is not identified. The command walks past them
# too (`spellwarden_cli.files.SKIP_DIRS` is ".git" followed by these).
SKIP_DIRS = ("node_modules", ".venv", "venv", "__pycache__")
SKILL_FILE = "SKILL.md"
# dropped at the top of a package: repository metadata, the lock and the archive leftovers of macOS
_TOP_DROPPED = (".git", ".spellwarden", "__MACOSX")
_DS_STORE = ".DS_Store"


# --- skills --------------------------------------------------------------------------------------------------------

def fold_skill_name(name: str) -> str:
    """The form agent-content names are recognised in: NFC, then case folding, as macOS and Windows open them. The
    engine's own copy of the command's `discover._fold` (the engine imports nothing from the command)."""
    return unicodedata.normalize("NFC", name).casefold()


def is_skill_name_variant(path: str) -> bool:
    """A file whose name folds to `skill.md` but is not exactly `SKILL.md`."""
    name = path.rpartition("/")[2]
    return name != SKILL_FILE and fold_skill_name(name) == fold_skill_name(SKILL_FILE)


def is_loaded_variant(path: str) -> bool:
    """A case variant of `SKILL.md` whose directory's parent is named `skills` in any case (`.claude/skills/x/`, a
    plugin's `skills/x/`): an agent on macOS or Windows loads it as that skill's `SKILL.md`. Elsewhere a variant is
    ordinary content."""
    parts = path.split("/")
    return len(parts) >= 3 and fold_skill_name(parts[-3]) == "skills" and is_skill_name_variant(path)


def is_skill_file(path: str) -> bool:
    """A skill is a directory holding a file named exactly `SKILL.md` (the engine reads that one name; an agent on a
    case-sensitive file system loads no other), or a case variant under `skills/<name>/` (`is_loaded_variant`)."""
    return path.rpartition("/")[2] == SKILL_FILE or is_loaded_variant(path)


def nested_skill_roots(paths: Iterable[str], root: str) -> tuple[str, ...]:
    """The directories strictly under `root` that hold a skill file by `is_skill_file`, sorted, as scan-root paths. A
    case variant elsewhere under a skill is package content (P52): dropping it from the identity would drop files the
    agent loads with the skill."""
    root = root.strip("/")
    prefix = f"{root}/" if root else ""
    found = {path.rpartition("/")[0] for path in paths if path.startswith(prefix) and is_skill_file(path)}
    return tuple(sorted(directory for directory in found if directory != root))


@dataclass(frozen=True, slots=True)
class PackageFiles:
    files: dict[str, bytes]
    # every SKIP_DIRS directory under the root, scan-root relative, sorted, deduplicated; () when the package is hashable
    unhashable: tuple[str, ...]


def package_files(files: Mapping[str, bytes], root: str, nested_roots: Iterable[str]) -> PackageFiles:
    """The files under `root` keyed relative to it, as a forge archive of the directory holds them: without the files
    under a nested skill root, `.git/`, `.spellwarden/` and `__MACOSX/` at the top, any `.DS_Store`, and without the
    content of a `SKIP_DIRS` directory, whose presence makes the package `unhashable`. A case variant of `SKILL.md`
    directly under the root is renamed to `SKILL.md` (the name the engine reads it under)."""
    root = root.strip("/")
    prefix = f"{root}/" if root else ""
    nested = tuple(f"{inner.strip('/')}/" for inner in nested_roots if inner.strip("/") and inner.strip("/") != root)
    kept: dict[str, bytes] = {}
    unhashable: set[str] = set()
    for path, content in files.items():
        if not path.startswith(prefix) or path.startswith(nested):
            continue
        relative = path[len(prefix):]
        parts = relative.split("/")
        if not relative or parts[0] in _TOP_DROPPED or parts[-1] == _DS_STORE:
            continue
        offending = next((index for index, part in enumerate(parts[:-1]) if part in SKIP_DIRS), None)
        if offending is not None:
            unhashable.add(prefix + "/".join(parts[:offending + 1]))
            continue
        kept[relative] = content
    variants = [path for path in kept if "/" not in path and is_skill_name_variant(path)]
    if SKILL_FILE not in kept and len(variants) == 1:
        kept[SKILL_FILE] = kept.pop(variants[0])
    return PackageFiles(kept, tuple(sorted(unhashable)))


def package_sha256(files: Mapping[str, bytes]) -> str:
    """The package hash: `canonical_sha256` of `PackageFiles.files`. With `root=""` and nothing dropped it equals the
    scan's `sha256`; it is over bytes, so a checkout that rewrites line endings is a different package."""
    return canonical_sha256(files)


# --- remote servers ------------------------------------------------------------------------------------------------

_DEFAULT_PORTS = {"https": 443, "http": 80}
_PERCENT = re.compile(rb"%([0-9A-Fa-f]{2})")
_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _normalised(url: object) -> tuple[str, str] | None:
    """`(base, query)`: the rules of the hosted `normalise_url` (scheme and host lower-cased, a default port, userinfo,
    the fragment and trailing slashes dropped, IPv6 brackets dropped as it drops them, the query as given) over
    `url_parts`. None for a URL the splitter refuses, a port over 65535, a control character or a lone surrogate."""
    if not isinstance(url, str):
        return None
    text = url.strip()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        return None
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return None
    parts = url_parts(text)
    if parts is None:
        return None
    port = None
    if parts.port is not None:
        port = int(parts.port)
        if port > 65535:
            return None
    netloc = parts.host if port is None or port == _DEFAULT_PORTS.get(parts.scheme) else f"{parts.host}:{port}"
    query = text.split("#", 1)[0].partition("?")[2]
    return f"{parts.scheme}://{netloc}{parts.path.rstrip('/')}", query


def normalise_url(url: str) -> str | None:
    """The hosted `normalise_url` over `url_parts`: the same output for every URL both accept; None where the
    splitter refuses (a port over 65535, a control character, a tab or newline inside, no scheme or host). The shared
    vectors pin both."""
    normalised = _normalised(url)
    if normalised is None:
        return None
    base, query = normalised
    return f"{base}?{query}" if query else base


def _sorted_query(query: str) -> str:
    """`name=value` pairs sorted by `(name, value)` after one round of percent-decoding, re-encoded with upper-case
    `%XX` for anything outside the RFC 3986 unreserved characters. Empty segments are dropped."""
    pairs = []
    for segment in query.split("&"):
        if segment:
            name, _, value = segment.partition("=")
            pairs.append(tuple(_PERCENT.sub(lambda match: bytes([int(match.group(1), 16)]), part.encode("utf-8"))
                               for part in (name, value)))
    pairs.sort()
    return "&".join(f"{_encode(name)}={_encode(value)}" for name, value in pairs)


def _encode(raw: bytes) -> str:
    return "".join(chr(byte) if byte in _UNRESERVED else f"%{byte:02X}" for byte in raw)


def server_identity(url: str) -> str | None:
    """`sha256` hex of the normalised URL with its query sorted (userinfo and fragment are gone). Only the hash
    leaves the runner, so keeping the query's values in the preimage costs no secrecy, and a change of tenant, role or
    key in the query is a different endpoint. None when the URL holds `${` (its identity would differ on every
    machine) or `normalise_url` is None."""
    if "${" in url:
        return None
    normalised = _normalised(url)
    if normalised is None:
        return None
    base, query = normalised
    query = _sorted_query(query)
    return hashlib.sha256((f"{base}?{query}" if query else base).encode("utf-8")).hexdigest()


def request_link_url(url: str) -> str:
    """`scheme://host[:port]/path` for the add dialog's link: userinfo, query and fragment removed, the rest as
    `normalise_url` gives it. An empty string for a URL the splitter refuses, so no userinfo can leak through it."""
    normalised = _normalised(url)
    return "" if normalised is None else normalised[0]


# --- plugins and marketplaces --------------------------------------------------------------------------------------

def canonical_repo_url(source: PluginSource) -> str | None:
    """One canonical repository URL for a `github` or `url` source (P36): `https://github.com/<owner>/<repo>`
    lower-cased for the `github` form, the `agentconfig` canonical URL (lower-cased host, `.git` and trailing slash
    dropped) for the `url` form with the path lower-cased when the host is `github.com`. None for `local`, `other`,
    an error and a value the parser could only keep raw."""
    if source.error is not None:
        return None
    if source.kind == "github" and source.canonical.startswith("github:"):
        return "https://github.com/" + source.canonical[len("github:"):]
    if source.kind == "url" and source.canonical.startswith("url:"):
        url = source.canonical[len("url:"):]
        parts = url_parts(url)
        if parts is not None and parts.host == "github.com":
            return url.lower()
        return url
    return None


def plugin_identity(source: PluginSource) -> str | None:
    """`git:<canonical_repo_url>@<40 hex>` when the source declares a full commit (`sha`, or a 40-hex `ref` without
    one), else None (`unpinned`)."""
    repository = canonical_repo_url(source)
    if repository is None or not has_declared_pin(source):
        return None
    commit = source.sha if source.sha is not None else source.ref
    return f"git:{repository}@{commit.lower()}"  # type: ignore[union-attr]


def marketplace_identity(source: PluginSource) -> str | None:
    """Admitting a marketplace at a commit admits the catalogue at that commit: the same function as a plugin's."""
    return plugin_identity(source)
