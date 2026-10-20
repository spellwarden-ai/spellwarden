"""The ten `config` rules of spec 5.3: MCP client configurations, Claude Code settings and hooks, and plugin
marketplaces, judged from parsed `ConfigDocument`s. Each `detect(config: AgentConfig)` yields `Finding`s whose
location is the configuration file and the entry's line. The fingerprint's `matched` is the JSON encoding of
`[item kind, item name, field, value]` (a hook: `["hook", event, matcher, "command", value]`), so it is
collision-safe whatever names hold and a hook keeps its identity when another hook is inserted above it."""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Iterator, Sequence
from typing import NamedTuple

from spellwarden_scan.agentconfig import has_declared_pin
from spellwarden_scan.evidence import bounded_evidence, fingerprint
from spellwarden_scan.model import ConfigDocument, Finding, HookCommand, Location, MarketplacePlugin, McpServerEntry, SettingFlag
from spellwarden_scan.package import CodeBlock
from spellwarden_scan.rules import Rule, make_rule
from spellwarden_scan.rules import patterns as P
from spellwarden_scan.rules.skill import (
    _host_of, _legacy_ipv4, decodes_and_runs, logical_commands, pipes_remote_to_shell,
    sends_file_contents,
)

TITLES = {
    "SW-CFG-001": "Remote MCP server over plain HTTP",
    "SW-CFG-002": "Credential written into an MCP server configuration",
    "SW-CFG-003": "MCP server launched from an unpinned package",
    "SW-CFG-004": "MCP server at a raw IP address or behind a URL shortener",
    "SW-CFG-005": "Hook pipes remote content to a shell",
    "SW-CFG-006": "Hook sends local file contents to an external host",
    "SW-CFG-007": "Hook decodes and runs an encoded payload",
    "SW-CFG-008": "Settings switch off approval prompts",
    "SW-CFG-009": "Marketplace plugin source not pinned to a commit",
    "SW-CFG-010": "Literal value under a secret name in an MCP server configuration",
}
_SEVERITY = {"SW-CFG-001": "high", "SW-CFG-002": "critical", "SW-CFG-003": "medium", "SW-CFG-004": "medium",
             "SW-CFG-005": "high", "SW-CFG-006": "critical", "SW-CFG-007": "critical", "SW-CFG-008": "high",
             "SW-CFG-009": "medium", "SW-CFG-010": "high"}
_MALICIOUS = frozenset({"SW-CFG-006", "SW-CFG-007"})


class AgentConfig:
    """What config rules see: the judged documents (no error, or `truncated`) and their entries, in path order."""

    def __init__(self, documents: Iterable[ConfigDocument]) -> None:
        self.documents: tuple[ConfigDocument, ...] = tuple(sorted(documents, key=lambda d: d.path))

    def servers(self) -> Iterator[tuple[ConfigDocument, McpServerEntry]]:
        return ((doc, entry) for doc in self.documents for entry in doc.servers)

    def hooks(self) -> Iterator[tuple[ConfigDocument, HookCommand]]:
        return ((doc, hook) for doc in self.documents for hook in doc.hooks)

    def settings(self) -> Iterator[tuple[ConfigDocument, SettingFlag]]:
        return ((doc, flag) for doc in self.documents for flag in doc.settings)

    def plugins(self) -> Iterator[tuple[ConfigDocument, MarketplacePlugin]]:
        return ((doc, plugin) for doc in self.documents for plugin in doc.plugins)


def _json(items: list) -> str:
    return json.dumps(items, ensure_ascii=False, separators=(",", ":"))


def config_matched(item_kind: str, item_name: str, field: str, value: str) -> str:
    return _json([item_kind, item_name, field, value])


def hook_matched(event: str, matcher: str | None, value: str) -> str:
    return _json(["hook", event, matcher or "", "command", value])


def _finding(rule_id: str, path: str, line: int, matched: str, evidence: str) -> Finding:
    return Finding(rule_id, _SEVERITY[rule_id], TITLES[rule_id], Location(path, line), bounded_evidence(evidence),
                   fingerprint(rule_id, path, matched), rule_id in _MALICIOUS)


# --- names and values (SW-CFG-002, SW-CFG-010) -------------------------------------------------------------------

# Plan decision P16: `authorization` (any header holding it: Proxy-Authorization, X-Authorization) and `cookie`
# (a literal Cookie value is a session credential) are secret tokens too.
_SECRET_TOKENS = frozenset({"token", "secret", "password", "passwd", "pwd", "credential", "credentials", "apikey",
                            "privatekey", "authorization", "cookie"})
_SECRET_PAIRS = frozenset({("api", "key"), ("access", "key"), ("private", "key"), ("client", "secret"),
                           ("auth", "token"), ("bearer", "token")})
_CASE_CHANGE = re.compile(r"(?<=[a-z])(?=[A-Z])")
_REFERENCE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$\{env:[A-Za-z_][A-Za-z0-9_]*\}|\$\{input:[A-Za-z0-9_.-]+\}"
                        r"|\$[A-Za-z_][A-Za-z0-9_]*")
_SCHEME = re.compile(r"(Bearer|Basic)\s+(.*)", re.IGNORECASE | re.DOTALL)


def name_tokens(name: str) -> tuple[str, ...]:
    """Lower-case tokens split at every non-alphanumeric character and at lower-to-upper changes (`apiKey`)."""
    tokens: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", name):
        tokens.extend(piece.lower() for piece in _CASE_CHANGE.split(part) if piece)
    return tuple(tokens)


def secret_named(name: str) -> bool:
    tokens = name_tokens(name)
    return any(token in _SECRET_TOKENS for token in tokens) or any(pair in _SECRET_PAIRS for pair in zip(tokens, tokens[1:], strict=False))


def is_reference(value: str) -> bool:
    return _REFERENCE.fullmatch(value) is not None


def is_placeholder(value: str) -> bool:
    return P.PLACEHOLDER_VALUE.fullmatch(value) is not None


def _literal(value: str) -> str:
    """The value without a leading `Bearer`/`Basic` scheme word: what a reference or placeholder test reads."""
    match = _SCHEME.fullmatch(value)
    return match.group(2) if match else value


def _credential_shaped(value: str) -> bool:
    return any(pattern.search(value) for pattern in P.CREDENTIAL_PATTERNS)


def _literal_authorization(name: str, value: str) -> bool:
    match = _SCHEME.fullmatch(value)
    if "authorization" not in name_tokens(name) or match is None:
        return False
    literal = match.group(2).strip()
    return bool(literal) and not is_reference(literal) and not is_placeholder(literal)


def _valued_fields(entry: McpServerEntry) -> Iterator[tuple[str, str, str, bool]]:
    """`(field, name, value, is_header)` of every env value, header value and argument; an argument's name is the
    option it belongs to (`--api-key=v`, or `--api-key v`), else empty."""
    for name, value in entry.env.items():
        yield f"env.{name}", name, value, False
    for name, value in entry.headers.items():
        yield f"headers.{name}", name, value, True
    args = entry.args
    for index, arg in enumerate(args):
        if arg.startswith("-") and "=" in arg:
            option, value = arg.split("=", 1)
            yield f"args[{index}]", option, value, False
        elif index > 0 and args[index - 1].startswith("-") and "=" not in args[index - 1]:
            yield f"args[{index}]", args[index - 1], arg, False
        else:
            yield f"args[{index}]", "", arg, False


def _cfg_002_fires(name: str, value: str, header: bool) -> bool:
    return _credential_shaped(value) or (header and _literal_authorization(name, value))


def _cfg_002(config: AgentConfig) -> Iterator[Finding]:
    for doc, entry in config.servers():
        for field, name, value, header in _valued_fields(entry):
            if _cfg_002_fires(name, value, header):
                yield _finding("SW-CFG-002", doc.path, entry.line, config_matched("server", entry.name, field, value),
                               f"{entry.name}: {field} = {value[:4]}***")


def _cfg_010(config: AgentConfig) -> Iterator[Finding]:
    for doc, entry in config.servers():
        for field, name, value, header in _valued_fields(entry):
            if not name or not secret_named(name) or _cfg_002_fires(name, value, header):
                continue
            literal = _literal(value)
            if len(literal) < 8 or is_reference(literal) or is_placeholder(literal):
                continue
            yield _finding("SW-CFG-010", doc.path, entry.line, config_matched("server", entry.name, field, value),
                           f"{entry.name}: {field} holds a literal value (***)")


# --- URLs (SW-CFG-001, SW-CFG-004) ---------------------------------------------------------------------------------

# Judging reads the URL as clients do; the fingerprint keeps the URL exactly as written. A browser (WHATWG) strips
# leading and trailing C0 controls and spaces, removes every tab, CR and LF, accepts any run of `/` and `\` after
# `http:`, and ends the authority at `\`; curl does not end it at `\`. Both readings are judged, like SW-SKL-013,
# and the rule fires when either fires. Userinfo ends at the last `@` (`_host_of`).
_C0_AND_SPACE = "".join(chr(code) for code in range(0x21))
_TAB_CR_LF = re.compile(r"[\t\r\n]")
_SCHEME_PREFIX = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):(.*)", re.DOTALL)
_AUTHORITY_END = {"whatwg": re.compile(r"[/?#\\]"), "curl": re.compile(r"[/?#]")}
_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})


def url_readings(url: str) -> tuple[str | None, tuple[str, ...]]:
    """`(scheme, hosts)`: the lower-cased scheme (None when `url` has none) and the distinct non-empty hosts of
    the WHATWG and curl readings, in that order."""
    text = _TAB_CR_LF.sub("", url.strip(_C0_AND_SPACE))
    match = _SCHEME_PREFIX.fullmatch(text)
    if match is None:
        return None, ()
    rest = match.group(2).lstrip("/\\")
    hosts: list[str] = []
    for end in _AUTHORITY_END.values():
        found = end.search(rest)
        host = _host_of(rest[:found.start()] if found else rest)
        if host and host not in hosts:
            hosts.append(host)
    return match.group(1).lower(), tuple(hosts)


_DISPLAY_AUTHORITY = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*:[/\\]*)([^/?#]*)")


def display_url(url: str) -> str:
    """The URL for evidence: tab, CR and LF dropped, and everything between the scheme's `:` plus its run of `/`
    and `\\` and the last `@` of the authority (the curl reading, which contains the WHATWG one) replaced by `***@`,
    so no userinfo (`user:password@`, `token@`) reaches a report. The fingerprint keeps the URL as written."""
    text = _TAB_CR_LF.sub("", url).strip(_C0_AND_SPACE)
    match = _DISPLAY_AUTHORITY.match(text)
    if match is None or "@" not in match.group(2):
        return text
    return match.group(1) + "***@" + match.group(2).rsplit("@", 1)[1] + text[match.end():]


def _cfg_001(config: AgentConfig) -> Iterator[Finding]:
    # Every entry with a URL, whatever its transport (plan decision P15): an agent may connect to it.
    for doc, entry in config.servers():
        if entry.url is None:
            continue
        scheme, hosts = url_readings(entry.url)
        if scheme == "http" and (not hosts or any(host not in _LOOPBACK_NAMES for host in hosts)):
            yield _finding("SW-CFG-001", doc.path, entry.line, config_matched("server", entry.name, "url", entry.url),
                           f"{entry.name}: {display_url(entry.url)}")


def _raw_ip_or_shortener(host: str) -> bool:
    try:
        address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host)
    except ValueError:
        address = _legacy_ipv4(host)
    if address is not None:
        return not address.is_loopback
    return (host[4:] if host.startswith("www.") else host) in P.SHORTENERS


def _cfg_004(config: AgentConfig) -> Iterator[Finding]:
    for doc, entry in config.servers():
        if entry.url is None:
            continue
        scheme, hosts = url_readings(entry.url)
        if scheme is None:
            continue
        matched = config_matched("server", entry.name, "url", entry.url)
        if not hosts:  # a scheme and no host under either reading: no client should be trusted to read it alike
            yield _finding("SW-CFG-004", doc.path, entry.line, matched, f"{entry.name}: unparseable host in {display_url(entry.url)}")
        elif any(_raw_ip_or_shortener(host) for host in hosts):
            yield _finding("SW-CFG-004", doc.path, entry.line, matched, f"{entry.name}: {display_url(entry.url)}")


# --- launchers (SW-CFG-003) ----------------------------------------------------------------------------------------

# Options that take the next word as their value. Compiled on 2026-10-20 from the Docker CLI reference
# (`docker container run`, `docker` global options) and podman-run(1) / podman(1), and npm-exec(1), uv's `uvx`
# and pipx's `run` help. An option outside these sets that has no `=` is read both ways (`_candidates`), so an
# omission can only add a reading, never hide an image or package.
_DOCKER_RUN_VALUE = frozenset({
    "-a", "--attach", "--add-host", "--annotation", "--blkio-weight", "--blkio-weight-device", "--cap-add", "--cap-drop",
    "--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-count", "--cpu-percent", "--cpu-period", "--cpu-quota",
    "--cpu-rt-period", "--cpu-rt-runtime", "-c", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems",
    "--detach-keys", "--device", "--device-cgroup-rule", "--device-read-bps", "--device-read-iops",
    "--device-write-bps", "--device-write-iops", "--dns", "--dns-opt", "--dns-option", "--dns-search", "--domainname",
    "--entrypoint", "-e", "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd",
    "--health-interval", "--health-retries", "--health-start-interval", "--health-start-period", "--health-timeout",
    "-h", "--hostname", "--io-maxbandwidth", "--io-maxiops", "--ip", "--ip6", "--ipc", "--isolation",
    "--kernel-memory", "-l", "--label", "--label-file", "--link", "--link-local-ip", "--log-driver", "--log-opt",
    "--mac-address", "-m", "--memory", "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount",
    "--name", "--network", "--net", "--network-alias", "--net-alias", "--oom-score-adj", "--pid", "--pids-limit",
    "--platform", "-p", "--publish", "--pull", "--restart", "--runtime", "--security-opt", "--shm-size",
    "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl", "--tmpfs", "--ulimit", "-u", "--user",
    "--userns", "--uts", "-v", "--volume", "--volume-driver", "--volumes-from", "-w", "--workdir",
})
_PODMAN_RUN_VALUE = _DOCKER_RUN_VALUE | frozenset({
    "--arch", "--authfile", "--cert-dir", "--cgroup-conf", "--cgroups", "--chrootdirs", "--conmon-pidfile", "--creds",
    "--decryption-key", "--env-merge", "--gidmap", "--group-entry", "--hostuser", "--hosts-file", "--image-volume",
    "--init-path", "--os", "--passwd-entry", "--personality", "--pod", "--pod-id-file", "--preserve-fd",
    "--preserve-fds", "--rdt-class", "--requires", "--retry", "--retry-delay", "--sdnotify", "--seccomp-policy",
    "--secret", "--shm-size-systemd", "--subgidname", "--subuidname", "--systemd", "--timeout", "--tz", "--uidmap",
    "--umask", "--unsetenv", "--variant",
})
_DOCKER_GLOBAL_VALUE = frozenset({"--config", "-c", "--context", "-H", "--host", "-l", "--log-level", "--tlscacert",
                                  "--tlscert", "--tlskey"})
_PODMAN_GLOBAL_VALUE = frozenset({
    "--cgroup-manager", "--config", "--conmon", "-c", "--connection", "--events-backend", "--hooks-dir", "--identity",
    "--imagestore", "--log-level", "--module", "--network-cmd-path", "--network-config-dir", "--out", "--root",
    "--runroot", "--runtime", "--runtime-flag", "--ssh", "--storage-driver", "--storage-opt", "--tmpdir", "--url",
    "--volumepath",
})
_NPX_VALUE = frozenset({"-c", "--call", "--registry", "--cache", "--prefix", "--userconfig", "-w", "--workspace",
                        "--node-options"})
_UVX_VALUE = frozenset({"-p", "--python", "--index",
                        "--default-index", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-c",
                        "--constraint", "--overrides", "--directory", "--project", "--cache-dir", "--config-file",
                        "--env-file", "--python-preference", "--resolution", "--prerelease", "--exclude-newer",
                        "--index-strategy", "--keyring-provider", "--link-mode", "--color"})
_PIPX_RUN_VALUE = frozenset({"--python", "-i", "--index-url", "--pip-args", "--backend"})
# Options known to take no value; an option in neither set is read both ways.
_DOCKER_RUN_FLAGS = frozenset({"-d", "--detach", "-i", "--interactive", "-t", "--tty", "--rm", "--privileged", "--init",
                               "--read-only", "-P", "--publish-all", "--oom-kill-disable", "--no-healthcheck",
                               "--sig-proxy", "--disable-content-trust", "-q", "--quiet", "--use-api-socket"})
_PODMAN_RUN_FLAGS = _DOCKER_RUN_FLAGS | frozenset({"--replace", "--rootfs", "--rmi", "--http-proxy", "--no-hosts",
                                                   "--read-only-tmpfs", "--env-host", "--passwd", "--tls-verify"})
_NPX_FLAGS = frozenset({"-y", "--yes", "--no", "-q", "--quiet", "--silent", "--ignore-existing", "--prefer-offline",
                        "--prefer-online", "--offline", "--verbose", "-d"})
_UVX_FLAGS = frozenset({"-q", "--quiet", "-v", "--verbose", "--offline", "--isolated", "-n", "--no-cache", "--refresh",
                        "-U", "--upgrade", "--native-tls", "--no-config", "--no-progress", "--no-python-downloads"})
_PIPX_RUN_FLAGS = frozenset({"--verbose", "-q", "--quiet", "--no-cache", "--system-site-packages", "--pypackages"})
# Options whose value is a package, every occurrence judged. The first set replaces the positional word (which is
# then the command to run, not a package); the second adds packages; a requirements file cannot be judged
# statically, so it always fires.
_PACKAGE_OPTIONS = {"node": frozenset({"-p", "--package"}), "uvx": frozenset({"--from"}), "pipx": frozenset({"--spec"})}
_EXTRA_PACKAGE_OPTIONS = {"node": frozenset(), "uvx": frozenset({"--with", "--with-editable"}), "pipx": frozenset()}
_REQUIREMENTS_OPTIONS = {"node": frozenset(), "uvx": frozenset({"--with-requirements"}), "pipx": frozenset()}


def _words(entry: McpServerEntry) -> list[tuple[str, str]]:
    """`(field, word)` of the command line: the words of `command` (field `command`), then `args[N]`."""
    words = [("command", word) for word in (entry.command or "").split()]
    return words + [(f"args[{index}]", arg) for index, arg in enumerate(entry.args)]


def _program(word: str) -> str:
    name = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith((".exe", ".cmd")) else name


def _takes_value(word: str, values: frozenset[str], flags: frozenset[str]) -> bool | None:
    """True, False, or None when unknown: an option in neither `values` nor `flags` with no `=` may or may not take
    a value. A secret-named option always takes one (its value is never judged or shown)."""
    if "=" in word or word in flags:
        return False
    if word in values or secret_named(word):
        return True
    if not word.startswith("--") and len(word) > 2 and "-" + word[-1] in values:  # `-it`, `-ie VALUE`
        return True
    if not word.startswith("--") and len(word) > 2:
        return False
    return None


class _Scan(NamedTuple):
    """What a launcher's words name: every package option's value `(field, word, option)`, every requirements file
    `(field, word, option)`, and the positional candidates `(field, word, ambiguous option)` (empty when a replacing
    package option made the positional word the command)."""
    packages: list[tuple[str, str, str]]
    requirements: list[tuple[str, str, str]]
    positional: list[tuple[str, str, str | None]]


def _scan_words(words: Sequence[tuple[str, str]], values: frozenset[str], flags: frozenset[str],
                replacing: frozenset[str] = frozenset(), extra: frozenset[str] = frozenset(),
                requirements: frozenset[str] = frozenset()) -> _Scan:
    """Every option up to the positional word, under both readings of an unknown option (it takes the next word,
    preferred; it takes none). The positional word's `ambiguous option` is set when it directly follows an unknown
    option, so it may be that option's value (a token): the evidence never shows it."""
    packages: dict[tuple[str, str], str] = {}
    files: dict[tuple[str, str], str] = {}
    positional: dict[tuple[str, str], str | None] = {}
    named = replacing | extra | requirements
    for unknown_takes_value in (True, False):
        index, after = 0, None
        while index < len(words):
            field, word = words[index]
            if word == "--":
                if index + 1 < len(words):
                    positional.setdefault(words[index + 1], None)
                break
            if not word.startswith("-") or word == "-":
                positional.setdefault((field, word), after)
                break
            option, equals, inline = word.partition("=")
            if option in named:
                target = files if option in requirements else packages
                if equals:
                    target.setdefault((field, inline), option)
                elif index + 1 < len(words):
                    target.setdefault(words[index + 1], option)
                index, after = index + (1 if equals else 2), None
                continue
            takes = _takes_value(word, values, flags)
            index += 2 if (takes if takes is not None else unknown_takes_value) else 1
            after = word if takes is None and not unknown_takes_value else None
    replaced = any(option in replacing for option in packages.values())
    return _Scan([(f, w, o) for (f, w), o in packages.items()], [(f, w, o) for (f, w), o in files.items()],
                 [] if replaced else [(f, w, a) for (f, w), a in positional.items()])


def _container_run(program: str, rest: Sequence[tuple[str, str]]) -> list[tuple[str, str]] | None:
    """The words after `run` (or `container run`) of a docker or podman command line, global options skipped;
    None when the command is not a run."""
    globals_ = _DOCKER_GLOBAL_VALUE if program == "docker" else _PODMAN_GLOBAL_VALUE
    index = 0
    while index < len(rest):
        word = rest[index][1]
        if word == "run":
            return list(rest[index + 1:])
        if word == "container" and index + 1 < len(rest) and rest[index + 1][1] == "run":
            return list(rest[index + 2:])
        if not word.startswith("-"):
            return None
        following = rest[index + 1][1] if index + 1 < len(rest) else ""
        takes = "=" not in word and (word in globals_ or following not in ("run", "container"))
        index += 2 if takes and not following.startswith("-") else 1
    return None


# Plan decision P16: launchers are judged stricter than SW-SKL-009 (which stays unchanged, invariant 4). A Python
# launcher is pinned only by `==X`, `===X` or uv's `pkg@X` with X a PEP 440 release; a Node launcher only by an
# exact semver after the final `@`. Tags (`@latest`, `@main`, `@next`), ranges (`>=`, `~=`, `^`, `~`, `x`, `*`) and
# empty specs are unpinned.
_PEP440_RELEASE = re.compile(r"\d+(\.\d+)*([abrc]+\d+)?(\.post\d+)?(\.dev\d+)?")
_EXACT_SEMVER = re.compile(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?")


# P16, remote sources: only a local path (`.`, `/`, `~`, `C:\\`) is exempt. Everything else is pinned only by an
# immutable pin, read per launcher. A VCS spec (`git+...`, a forge shorthand such as `github:x/y`, an npm
# `owner/repo`) is pinned by exactly 40 hex characters: the ref after the final `@` of its path (query and fragment
# removed), or for npm also its `#` fragment. A Python archive URL is pinned by a `#sha256=<64 hex>` fragment
# parameter; an npm tarball URL has no immutable pin. Hex in a query string or an unrelated fragment never counts.
_REMOTE_SHORTHANDS = ("git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:")
_NPM_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.*)?")
_HEX40 = re.compile(r"[0-9a-fA-F]{40}")
_SHA256_PARAM = re.compile(r"sha256=[0-9a-fA-F]{64}")
_DRIVE_PATH = re.compile(r"[A-Za-z]:[\\/]")


def _local_path(spec: str) -> bool:
    return spec.startswith((".", "/", "~")) or _DRIVE_PATH.match(spec) is not None


def _remote(spec: str, *, npm: bool) -> bool:
    return ("://" in spec or spec.startswith(_REMOTE_SHORTHANDS)
            or (npm and not spec.startswith("@") and _NPM_REPO.fullmatch(spec) is not None))


def _vcs(spec: str, *, npm: bool) -> bool:
    return spec.startswith(_REMOTE_SHORTHANDS) or (npm and "://" not in spec)


def _path_ref(spec: str) -> str | None:
    """The ref after the final `@` of a VCS spec's path, query and fragment removed; an authority's userinfo
    (`git@github.com`) is not a ref."""
    base = spec.split("#", 1)[0].split("?", 1)[0]
    if "://" in base:
        rest = base.split("://", 1)[1]
        path = rest.split("/", 1)[1] if "/" in rest else ""
    else:
        path = base.split(":", 1)[1] if ":" in base else base
    return path.rsplit("@", 1)[1] if "@" in path else None


def _commit_pinned(spec: str, *, fragment_counts: bool) -> bool:
    ref = _path_ref(spec)
    if ref is not None and _HEX40.fullmatch(ref):
        return True
    fragment = spec.split("#", 1)[1] if "#" in spec else None
    return fragment_counts and fragment is not None and _HEX40.fullmatch(fragment) is not None


def _python_unpinned(spec: str) -> bool:
    if " @ " in spec:  # a PEP 508 direct reference: `name @ url`
        spec = spec.split(" @ ", 1)[1].strip()
    if _local_path(spec):
        return False
    if _remote(spec, npm=False):
        if _vcs(spec, npm=False):
            return not _commit_pinned(spec, fragment_counts=False)
        fragment = spec.split("#", 1)[1] if "#" in spec else ""
        return not any(_SHA256_PARAM.fullmatch(part) for part in fragment.split("&"))
    for operator in ("===", "=="):
        if operator in spec:
            return _PEP440_RELEASE.fullmatch(spec.split(operator, 1)[1].strip()) is None
    if "@" in spec:
        return _PEP440_RELEASE.fullmatch(spec.rsplit("@", 1)[1].strip()) is None
    return True


def _node_unpinned(word: str) -> bool:
    if _local_path(word):
        return False
    if _remote(word, npm=True):
        return not _vcs(word, npm=True) or not _commit_pinned(word, fragment_counts=True)
    name = word[1:] if word.startswith("@") else word
    return "@" not in name or _EXACT_SEMVER.fullmatch(name.rsplit("@", 1)[1]) is None


def _image_unpinned(image: str) -> bool:
    if "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.rsplit(":", 1)[1] in ("", "latest")


def _unpinned_launches(entry: McpServerEntry) -> list[tuple[str, str, str, str]]:
    """`(launcher, field, matched word, evidence word)` of every unpinned package, image or requirements file of a
    launch: each package option's value, the first unpinned positional candidate, each requirements file."""
    words = _words(entry)
    if not words:
        return []
    program, rest = _program(words[0][1]), words[1:]
    second = rest[0][1] if rest else ""
    if program in ("npx", "bunx"):
        launcher, kind, args, values, flags = program, "node", rest, _NPX_VALUE, _NPX_FLAGS
    elif program == "uvx":
        launcher, kind, args, values, flags = program, "uvx", rest, _UVX_VALUE, _UVX_FLAGS
    elif (program, second) in (("pnpm", "dlx"), ("yarn", "dlx")):
        launcher, kind, args, values, flags = f"{program} dlx", "node", rest[1:], _NPX_VALUE, _NPX_FLAGS
    elif (program, second) == ("pipx", "run"):
        launcher, kind, args, values, flags = "pipx run", "pipx", rest[1:], _PIPX_RUN_VALUE, _PIPX_RUN_FLAGS
    elif program in ("docker", "podman"):
        run_args = _container_run(program, rest)
        if run_args is None:
            return []
        values, flags = (_DOCKER_RUN_VALUE, _DOCKER_RUN_FLAGS) if program == "docker" else (_PODMAN_RUN_VALUE, _PODMAN_RUN_FLAGS)
        for field, image, after in _scan_words(run_args, values, flags).positional:
            if _image_unpinned(image):
                return [(f"{program} run", field, image, _shown(image, after))]
        return []
    else:
        return []
    unpinned = _node_unpinned if kind == "node" else _python_unpinned
    scan = _scan_words(args, values, flags, _PACKAGE_OPTIONS[kind], _EXTRA_PACKAGE_OPTIONS[kind], _REQUIREMENTS_OPTIONS[kind])
    found = [(launcher, field, package, package) for field, package, _option in scan.packages if unpinned(package)]
    for field, package, after in scan.positional:
        if unpinned(package):
            found.append((launcher, field, package, _shown(package, after)))
            break
    found.extend((launcher, field, path, f"{option} {path}") for field, path, option in scan.requirements)
    return found


def _shown(word: str, after: str | None) -> str:
    return f"*** (the word after {after})" if after else word


def _cfg_003(config: AgentConfig) -> Iterator[Finding]:
    # Every entry with a command, whatever its transport (plan decision P15). The evidence names the launcher and
    # the matched package, image or requirements file only: other arguments may carry a value no masking
    # recognises. A word that may be an unknown option's value is shown as `***`; the fingerprint keeps it raw.
    for doc, entry in config.servers():
        if entry.command is None:
            continue
        for launcher, field, value, shown in _unpinned_launches(entry):
            yield _finding("SW-CFG-003", doc.path, entry.line, config_matched("server", entry.name, field, value),
                           f"{entry.name}: {launcher} {shown}")


# --- hooks (SW-CFG-005, 006, 007) ----------------------------------------------------------------------------------

def _hook_rule(config: AgentConfig, rule_id: str, detector) -> Iterator[Finding]:
    """A hook command normalised like a skill script (spec 5.4); one finding per hook identity (event, matcher,
    matched command), at the first such hook's line."""
    seen: set[str] = set()
    for doc, hook in sorted(config.hooks(), key=lambda pair: (pair[0].path, pair[1].index)):
        unit = CodeBlock(doc.path, "sh", hook.command, hook.line)
        for _path, _line, text in detector(logical_commands(unit)):
            matched = hook_matched(hook.event, hook.matcher, text)
            key = fingerprint(rule_id, doc.path, matched)
            if key in seen:
                continue
            seen.add(key)
            yield _finding(rule_id, doc.path, hook.line, matched, f"{hook.event}: {text}")


def _cfg_005(config: AgentConfig) -> Iterator[Finding]:
    return _hook_rule(config, "SW-CFG-005", pipes_remote_to_shell)


def _cfg_006(config: AgentConfig) -> Iterator[Finding]:
    return _hook_rule(config, "SW-CFG-006", sends_file_contents)


def _cfg_007(config: AgentConfig) -> Iterator[Finding]:
    return _hook_rule(config, "SW-CFG-007", decodes_and_runs)


# --- settings (SW-CFG-008) -----------------------------------------------------------------------------------------

_UNRESTRICTED_BASH = frozenset({"Bash", "Bash(*)", "Bash(:*)"})


def _cfg_008(config: AgentConfig) -> Iterator[Finding]:
    for doc, flag in config.settings():
        fires = ((flag.key == "permissions.defaultMode" and flag.value == "bypassPermissions")
                 or (flag.key == "enableAllProjectMcpServers" and flag.value is True)
                 or (flag.key == "permissions.allow" and flag.value in _UNRESTRICTED_BASH))
        if fires:
            value = "true" if flag.value is True else str(flag.value)
            yield _finding("SW-CFG-008", doc.path, flag.line, config_matched("setting", flag.key, flag.key, value),
                           f"{flag.key}: {value}")


# --- marketplace (SW-CFG-009) --------------------------------------------------------------------------------------

def _cfg_009(config: AgentConfig) -> Iterator[Finding]:
    for doc, plugin in config.plugins():
        source = plugin.source
        if source.kind not in ("github", "url") or has_declared_pin(source):
            continue
        value = shown = source.canonical
        if source.kind == "url" and shown.startswith("url-raw:") and source.url is not None:
            # a raw URL source may carry userinfo: the evidence shows it without, the fingerprint keeps it
            shown = "url-raw:" + json.dumps(display_url(source.url), ensure_ascii=False)
        if source.sha is not None and source.ref is not None:
            value = f"{value} sha={source.sha} ref={source.ref}"
            shown = f"{shown} sha={source.sha} ref={source.ref}"
        yield _finding("SW-CFG-009", doc.path, plugin.line, config_matched("plugin", plugin.name, "source", value),
                       f"{plugin.name}: {shown} (no declared commit pin)")


RULES: tuple[Rule, ...] = (
    make_rule("SW-CFG-001", TITLES["SW-CFG-001"], "high", "config", owasp=("MCP01",), nist=("SC-7",), detect=_cfg_001),
    make_rule("SW-CFG-002", TITLES["SW-CFG-002"], "critical", "config", owasp=("MCP01",), nist=("IA-5",), detect=_cfg_002),
    make_rule("SW-CFG-003", TITLES["SW-CFG-003"], "medium", "config", owasp=("ASI04",), nist=("SR-3",), detect=_cfg_003),
    make_rule("SW-CFG-004", TITLES["SW-CFG-004"], "medium", "config", owasp=("ASI10",), nist=("SC-7",), detect=_cfg_004),
    make_rule("SW-CFG-005", TITLES["SW-CFG-005"], "high", "config", owasp=("ASI04",), nist=("SR-3",), detect=_cfg_005, targets=("claude-code-hooks",)),
    make_rule("SW-CFG-006", TITLES["SW-CFG-006"], "critical", "config", owasp=("ASI10",), nist=("SC-7",), detect=_cfg_006, malicious=True, targets=("claude-code-hooks",)),
    make_rule("SW-CFG-007", TITLES["SW-CFG-007"], "critical", "config", owasp=("ASI04",), nist=("SR-3",), detect=_cfg_007, malicious=True, targets=("claude-code-hooks",)),
    make_rule("SW-CFG-008", TITLES["SW-CFG-008"], "high", "config", owasp=("ASI10",), nist=("AC-6",), detect=_cfg_008),
    make_rule("SW-CFG-009", TITLES["SW-CFG-009"], "medium", "config", owasp=("ASI04",), nist=("SR-3",), detect=_cfg_009),
    make_rule("SW-CFG-010", TITLES["SW-CFG-010"], "high", "config", owasp=("MCP01",), nist=("IA-5",), detect=_cfg_010),
)
