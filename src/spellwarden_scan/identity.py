"""Gate identities, defined once (O3 spec 5.1): what the private registry compares for a skill package, a remote MCP
server, a plugin and a marketplace, so that the command and the hosted side cannot drift. Pure: URLs are split with
`agentconfig.url_parts` (the engine imports no `urllib`), files arrive as `{path: bytes}`.

The vector files `tests/vectors/normalise_url.json` and `tests/vectors/command_identity.json` pin these functions and
are shared with the hosted side."""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
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


# --- pinned commands -----------------------------------------------------------------------------------------------

LAUNCHER_FAMILY: Mapping[str, str] = {"npx": "npm", "bunx": "npm", "pnpm dlx": "npm", "uvx": "python", "pipx run": "python",
                                      "docker run": "docker"}
LAUNCH_OVERRIDE_ENV = frozenset({
    "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "UV_INDEX", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL",
    "UV_FIND_LINKS", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIPX_DEFAULT_PYTHON", "BUN_CONFIG_REGISTRY",
    "DOCKER_HOST", "DOCKER_CONFIG",
})
_PACKAGE_QUIET = frozenset({"-y", "--yes", "-q", "--quiet", "--silent"})
_DOCKER_QUIET = frozenset({"--rm", "-i", "--interactive", "-t", "--tty", "--init", "--name"})
# flags that change no behaviour, per launcher: dropped from the identity when they come before the package or image
QUIET_FLAGS: Mapping[str, frozenset[str]] = {
    "npx": _PACKAGE_QUIET, "bunx": _PACKAGE_QUIET, "pnpm dlx": _PACKAGE_QUIET, "uvx": _PACKAGE_QUIET,
    "pipx run": _PACKAGE_QUIET, "docker run": _DOCKER_QUIET,
}
_SOURCE_OPTIONS = frozenset({"--registry", "--index-url", "--extra-index-url", "--index", "--default-index", "--find-links"})
_VERSION = r"[0-9]+(?:\.[0-9]+){0,2}(?:[-+][0-9A-Za-z.-]+)?"
_EXACT = {
    "npm": re.compile(rf"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+@{_VERSION}"),
    "python": re.compile(rf"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9._,-]+\])?=={_VERSION}"),
    "docker": re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}"),
}
_ARGS_HASH = re.compile(r"[0-9a-f]{32}")
_EXECUTABLE_SEPARATORS = re.compile(r"[\\/]")


@dataclass(frozen=True, slots=True)
class _Spec:
    artefacts: frozenset[str]  # options whose value is an artefact (the launch selects that package)
    primary: frozenset[str]  # of those, the ones after which the positional is the command to run, not a package
    values: frozenset[str]  # other options that take a value, so that the value is not read as the package or image
    sources: frozenset[str]


_NPM_VALUES = frozenset({"--cache", "-C", "--prefix", "--userconfig", "-w", "--workspace", "--loglevel", "--node-arg"})
_UVX_VALUES = frozenset({
    "-p", "--python", "--with-requirements", "--with-editable", "--env-file", "--index-strategy", "-c", "--constraints",
    "-b", "-C", "--config-setting", "--config-settings-package",
    "--overrides", "--build-constraints", "--directory", "--project", "--config-file", "--cache-dir", "--resolution",
    "--prerelease", "--fork-strategy", "--keyring-provider", "--link-mode", "--python-preference", "--exclude-newer",
    "-P", "--upgrade-package", "--reinstall-package", "--refresh-package", "--color", "--allow-insecure-host",
    "--no-binary-package", "--no-build-package",
})
_DOCKER_VALUES = frozenset({
    "-a", "--attach", "--add-host", "--annotation", "--blkio-weight", "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns",
    "--cidfile", "--cpu-period", "--cpu-quota", "--cpu-rt-period", "--cpu-rt-runtime", "--cpu-shares", "-c", "--cpus",
    "--cpuset-cpus", "--cpuset-mems", "--detach-keys", "--device", "--device-cgroup-rule", "--device-read-bps",
    "--device-read-iops", "--device-write-bps", "--device-write-iops", "--dns", "--dns-option", "--dns-search", "--domainname",
    "--entrypoint", "-e", "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd", "--health-interval",
    "--health-retries", "--health-start-period", "--health-timeout", "-h", "--hostname", "--ip", "--ip6", "--ipc",
    "--isolation", "--kernel-memory", "-l", "--label", "--label-file", "--link", "--link-local-ip", "--log-driver",
    "--log-opt", "--mac-address", "-m", "--memory", "--memory-reservation", "--memory-swap", "--memory-swappiness",
    "--mount", "--name", "--network", "--network-alias", "--oom-score-adj", "--pid", "--pids-limit", "--platform", "-p",
    "--publish", "--pull", "--restart", "--runtime", "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout",
    "--storage-opt", "--sysctl", "--tmpfs", "-u", "--user", "--ulimit", "--userns", "--uts", "-v", "--volume",
    "--volume-driver", "--volumes-from", "-w", "--workdir",
})
_NONE: frozenset[str] = frozenset()
_PACKAGE = frozenset({"-p", "--package"})
_SPECS: dict[str, _Spec] = {
    "npx": _Spec(_PACKAGE, _NONE, _NPM_VALUES | {"-c", "--call"}, _SOURCE_OPTIONS),
    "bunx": _Spec(_PACKAGE, _NONE, _NONE, _SOURCE_OPTIONS),
    "pnpm dlx": _Spec(_PACKAGE, _NONE, _NONE, _SOURCE_OPTIONS),
    # uv's short aliases mean their long forms: `-w` is `--with`, `-i` `--index-url`, `-f` `--find-links`
    "uvx": _Spec(frozenset({"--from", "--with", "-w"}), frozenset({"--from"}), _UVX_VALUES, _SOURCE_OPTIONS | {"-i", "-f"}),
    "pipx run": _Spec(frozenset({"--spec"}), frozenset({"--spec"}), frozenset({"--python", "--pip-args", "--path"}),
                      _SOURCE_OPTIONS),
    "docker run": _Spec(_NONE, _NONE, _DOCKER_VALUES, _NONE),
}


def is_launch_override_env(name: str) -> bool:
    """An environment variable that redirects what a launcher runs or from where it fetches (`LAUNCH_OVERRIDE_ENV`, and
    any `npm_config_*`). Compared case-insensitively: Windows reads environment names that way, and a name that only
    looks like an override on one platform is refused on all."""
    upper = name.upper()
    return upper in LAUNCH_OVERRIDE_ENV or upper.startswith("NPM_CONFIG_")


@dataclass(frozen=True, slots=True)
class CommandIdentity:
    identity: str | None
    reason: str | None  # unpinned, unknown_launcher, unresolved or launch_override when identity is None


@dataclass(frozen=True, slots=True)
class ParsedCommandIdentity:
    launcher: str
    artefacts: tuple[str, ...]
    sources: tuple[str, ...]
    args_hash: str | None


def _launcher_of(command: str, args: Sequence[str]) -> tuple[str, list[str]] | None:
    base = _EXECUTABLE_SEPARATORS.split(command)[-1]
    if base in ("npx", "bunx", "uvx"):
        return base, list(args)
    if args and (base, args[0]) in (("pnpm", "dlx"), ("pipx", "run"), ("docker", "run")):
        return f"{base} {args[0]}", list(args[1:])
    return None


def _reduce_source(value: str) -> str | None:
    """`scheme://host[:port]/path`: userinfo, query and fragment removed, scheme and host lower-cased. None for a value
    that is not an absolute URL (a directory, `file:`), holds `${`, or has a comma in its path (the encoding joins
    sources with commas)."""
    if not isinstance(value, str) or "${" in value:
        return None
    parts = url_parts(value)
    if parts is None or "," in parts.path:
        return None
    host = f"[{parts.host}]" if ":" in parts.host else parts.host
    return f"{parts.scheme}://{host}{':' + parts.port if parts.port else ''}{parts.path}"


def command_identity(command: str, args: Sequence[str], env: Mapping[str, str]) -> CommandIdentity:
    """The identity of a pinned stdio launch (spec 5.1): `cmd:<launcher> <artefacts>[ src=<sources>][ args=<hash>]`,
    or why there is none. The artefacts are the packages or image the launch selects, each at an exact version; the
    sources are the registries and indexes it names, reduced to `scheme://host[:port]/path`; everything else but the
    quiet flags (every other option and positional, docker options before the image included) enters `args` as a hash.
    No credential of a source and no value of the arguments or of `env` is ever in the identity."""
    if "${" in command:
        return CommandIdentity(None, "unresolved")
    found = _launcher_of(command, args)
    if found is None:
        return CommandIdentity(None, "unknown_launcher")
    launcher, tokens = found
    spec, quiet = _SPECS[launcher], QUIET_FLAGS[launcher]
    artefacts: list[str] = []
    sources: list[str] = []
    rest: list[str] = []
    override = any(is_launch_override_env(key) for key in env)
    primary = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if len(token) < 2 or not token.startswith("-"):
            # the first positional ends the launcher's own options: the package (or image), then its arguments
            if LAUNCHER_FAMILY[launcher] == "python" and primary:
                rest.append(token)
            else:
                artefacts.append(token)
            rest.extend(tokens[index:])
            break
        if token.startswith("--"):
            option, equals, value = token.partition("=")
        else:
            # a one-dash cluster as the launchers read it: `-qwfoo` is `-q -w foo`, `-qw foo` is `-q -w foo`, `-w=foo`
            # is `-w foo`; the first value-taking, artefact or source option takes the rest of the token, or the next
            # token when nothing is left, so no value hides inside a cluster as an argument
            option, equals, value = token, "", ""
            if len(token) > 2 and all("-" + char in quiet for char in token[1:]):
                continue  # `-it` is `-i -t`: quiet flags, dropped as their separate forms are
            unknown = False
            for cut in range(1, len(token)):
                short = "-" + token[cut]
                if short in spec.values or short in spec.artefacts or short in spec.sources:
                    if unknown:
                        # a letter this table does not know before one that takes a value: whether the launcher reads the
                        # next token as that value or as the package cannot be told, so nothing is identified
                        return CommandIdentity(None, "unresolved")
                    attached = token[cut + 1:].removeprefix("=")
                    option, equals, value = short, ("=" if attached else ""), attached
                    break
                unknown = unknown or short not in quiet  # an unknown letter alone leaves the token an argument, as before
        takes_value = option in spec.values or option in spec.artefacts or option in spec.sources
        consumed = [token]
        given: str | None = value if equals else None
        if not equals and takes_value and index < len(tokens):
            given = tokens[index]
            index += 1
            consumed.append(given)
        if option == "--entrypoint" and launcher == "docker run":
            override = True
        elif option in quiet and (given is not None if option in spec.values else not equals):
            continue
        elif option in spec.artefacts:
            artefacts.append(given if given is not None else "")
            primary = primary or option in spec.primary
        elif option in spec.sources:
            sources.append(given if given is not None else "")
        else:
            rest.extend(consumed)
    if override:
        return CommandIdentity(None, "launch_override")
    reduced = [_reduce_source(source) for source in sources]
    if any("${" in item for item in (*artefacts, *sources)) or None in reduced:
        return CommandIdentity(None, "unresolved")
    try:
        digest = hashlib.sha256(json.dumps(rest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()[:32]
    except UnicodeEncodeError:
        return CommandIdentity(None, "unresolved")
    family = LAUNCHER_FAMILY[launcher]
    if not artefacts or not all(_EXACT[family].fullmatch(artefact) for artefact in artefacts):
        return CommandIdentity(None, "unpinned")
    parsed = ParsedCommandIdentity(launcher, tuple(sorted(set(artefacts))), tuple(reduced),  # type: ignore[arg-type]
                                   digest if rest else None)
    return CommandIdentity(format_command_identity(parsed), None)


def format_command_identity(parsed: ParsedCommandIdentity) -> str:
    """The canonical encoding: `parse_command_identity(format_command_identity(x)) == x` and the other way round."""
    parts = [f"cmd:{parsed.launcher}", *parsed.artefacts]
    if parsed.sources:
        parts.append("src=" + ",".join(parsed.sources))
    if parsed.args_hash is not None:
        parts.append("args=" + parsed.args_hash)
    return " ".join(parts)


def parse_command_identity(identity: str) -> ParsedCommandIdentity:
    """The parts of an identity `command_identity` produced. Strict: ValueError("<part>: <why>") for anything it never
    produces (one space between tokens, artefacts exact, sorted and distinct, sources reduced and non-empty, `args=`
    exactly 32 lowercase hex), so a hand-edited string never reaches the registry."""
    if not isinstance(identity, str) or not identity.startswith("cmd:"):
        raise ValueError("launcher: an identity starts with cmd:")
    body = identity[len("cmd:"):]
    launcher = next((name for name in LAUNCHER_FAMILY if body.startswith(name + " ")), None)
    if launcher is None:
        raise ValueError("launcher: not one of " + ", ".join(LAUNCHER_FAMILY))
    tokens = body[len(launcher) + 1:].split(" ")
    if "" in tokens:
        raise ValueError("identity: one space between tokens, none at the end")
    position = 0
    while position < len(tokens) and not tokens[position].startswith(("src=", "args=")):
        position += 1
    artefacts = tokens[:position]
    exact = _EXACT[LAUNCHER_FAMILY[launcher]]
    if not artefacts or not all(exact.fullmatch(artefact) for artefact in artefacts):
        raise ValueError("artefacts: at least one, each at an exact version")
    if any(left >= right for left, right in zip(artefacts, artefacts[1:], strict=False)):
        raise ValueError("artefacts: sorted and distinct")
    sources: tuple[str, ...] = ()
    if position < len(tokens) and tokens[position].startswith("src="):
        listed = tokens[position][len("src="):].split(",")
        if not all(item and _reduce_source(item) == item for item in listed):
            raise ValueError("src: each source is scheme://host[:port]/path without userinfo, query or fragment")
        sources = tuple(listed)
        position += 1
    args_hash = None
    if position < len(tokens) and tokens[position].startswith("args="):
        args_hash = tokens[position][len("args="):]
        if _ARGS_HASH.fullmatch(args_hash) is None:
            raise ValueError("args: 32 lowercase hex characters")
        position += 1
    if position < len(tokens):
        raise ValueError("identity: unexpected " + tokens[position].split("=")[0])
    return ParsedCommandIdentity(launcher, tuple(artefacts), sources, args_hash)


# --- resolver files ------------------------------------------------------------------------------------------------

_RESOLVER_FILES = {".npmrc": "npm", ".yarnrc.yml": "npm", "bunfig.toml": "npm", "uv.toml": "python", "pip.conf": "python",
                   "pyproject.toml": "python"}
_RESOLVER_CAP = 64 * 1024
# npm's ini reader and the TOML readers accept a quoted key (`"registry"=`), a dotted key (`install.registry =`) and an
# inline table (`install = {registry = ...}`) for the same setting, so the match is on the key as the tool reads it, not
# on one spelling of the line. Line-based still, no TOML parser (plan Task 2): a form this misses is a gap, not a crash.
_NPMRC = re.compile(r"""^\s*(?:"(?:@[^"\s:=]+:)?registry"|'(?:@[^'\s:=]+:)?registry'|(?:@[^\s:=]+:)?registry)\s*=""",
                    re.MULTILINE)
_YARNRC = re.compile(r"""^\s*["']?(?:npmRegistryServer|npmScopes)["']?\s*:""", re.MULTILINE)
_INDEX_NAMES = frozenset({"index-url", "extra-index-url", "find-links", "index", "default-index", "index_url",
                          "extra_index_url", "find_links", "default_index"})
_INDEX_LINE = re.compile(r"^\s*(?:index-url|extra-index-url|find-links|index|default-index|index_url|extra_index_url|"
                         r"find_links|default_index)\s*[=:]")
_TABLE_HEADER = re.compile(r"^\s*\[\[?([^\[\]]*)\]\]?\s*(?:#.*)?$")
_KEY_SEGMENT = r"""(?:"[^"]*"|'[^']*'|[A-Za-z0-9_-]+)"""
_KEY_LINE = re.compile(rf"^\s*({_KEY_SEGMENT}(?:\s*\.\s*{_KEY_SEGMENT})*)\s*=\s*(.*?)\s*$")
_INLINE_KEY = re.compile(rf"^\s*({_KEY_SEGMENT}(?:\s*\.\s*{_KEY_SEGMENT})*)\s*=")
_SEGMENT = re.compile(_KEY_SEGMENT)


def _dotted(raw: str) -> str:
    """A TOML key or header as a dotted name, each segment without its quotes."""
    return ".".join(segment.strip("\"'") for segment in _SEGMENT.findall(raw))


def _keys(text: str):
    """`(kind, dotted)` for every header (`"table"`) and every key (`"key"`, prefixed by its table) of a TOML-like text,
    the keys of inline tables at any depth included. The lines of a multi-line string are neither headers nor keys."""
    table = ""
    closing: str | None = None  # inside a multi-line string: the delimiter that ends it
    for line in text.splitlines():
        if closing is not None:
            if closing in line:
                closing = None
            continue
        header = _TABLE_HEADER.match(line)
        if header is not None:
            table = _dotted(header.group(1))
            yield "table", table
            continue
        key = _KEY_LINE.match(line)
        if key is None:
            continue
        full = ".".join(part for part in (table, _dotted(key.group(1))) if part)
        yield "key", full
        value = key.group(2)
        for delimiter in ('"""', "'''"):
            if value.startswith(delimiter) and delimiter not in value[3:]:
                closing = delimiter
        if value.startswith("{"):
            for inner in _inline_keys(full, value[1:]):
                yield "key", inner


def _inline_keys(prefix: str, text: str):
    """The dotted keys of an inline table body, nested tables flattened; a quoted string is skipped whole."""
    depth, quote, start = 0, None, 0
    pairs: list[str] = []
    escaped = False
    for position, char in enumerate(text):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\" and quote == '"':  # a basic string escapes; a literal string does not
                escaped = True
            elif char == quote:
                quote = None
        elif char in '"\'':
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            if depth == 0:
                pairs.append(text[start:position])
                start = len(text)
                break
            depth -= 1
        elif char == "," and depth == 0:
            pairs.append(text[start:position])
            start = position + 1
    pairs.append(text[start:])
    for pair in pairs:
        key = _INLINE_KEY.match(pair)
        if key is None:
            continue
        full = prefix + "." + _dotted(key.group(1))
        yield full
        value = pair[key.end():].lstrip()
        if value.startswith("{"):
            yield from _inline_keys(full, value[1:])


def _redirects(name: str, text: str) -> bool:
    if name == ".npmrc":
        return _NPMRC.search(text) is not None
    if name == ".yarnrc.yml":
        return _YARNRC.search(text) is not None
    if name == "pip.conf" and any(_INDEX_LINE.match(line) for line in text.splitlines()):
        return True
    for kind, dotted in _keys(text):
        prefix, _, last = dotted.rpartition(".")
        if name == "pip.conf":
            if kind == "key" and last in _INDEX_NAMES:
                return True
        elif name == "bunfig.toml":
            if dotted == "install.registry" or dotted.startswith(("install.registry.", "install.scopes.")):
                return True
        elif name == "uv.toml":
            indexed = kind == "table" and (dotted == "index" or dotted.startswith("index."))
            if indexed or (kind == "key" and last in _INDEX_NAMES):
                return True
        elif kind == "table" and (dotted == "tool.uv.index" or dotted.startswith("tool.uv.index.")):
            return True
        elif kind == "key" and last in _INDEX_NAMES and prefix in ("tool.uv", "tool.uv.pip"):
            return True
    return False


def resolver_files(files: Iterable[str], read: Callable[[str], bytes]) -> dict[str, tuple[str, ...]]:
    """Per launcher family, the files of the tree that redirect package resolution when the command runs there:
    `.npmrc`, `.yarnrc.yml` and `bunfig.toml` with a registry or scope-registry line (npm family); `uv.toml`,
    `pip.conf` and `pyproject.toml` with an index entry (python family). Line-based, no TOML parser; `read` is called
    only for a file of those names, and a file over 64 KiB or one `read` cannot deliver counts as a resolver file (a
    gate that cannot look says no). A stdio entry of a family that has any is `resolver_override`."""
    found: dict[str, list[str]] = {}
    for path in files:
        name = path.rpartition("/")[2]
        family = _RESOLVER_FILES.get(name)
        if family is None:
            continue
        try:
            content = read(path)
            hit = len(content) > _RESOLVER_CAP or _redirects(name, content.decode("utf-8", errors="replace"))
        except OSError:
            hit = True
        if hit:
            found.setdefault(family, []).append(path)
    return {family: tuple(sorted(paths)) for family, paths in found.items()}
