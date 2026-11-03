"""SW-CFG-014: insecure or credential-bearing MCP server in a configuration copy.

Read over the servers of copies of MCP client configurations (`.mcp.json.bak`, `.mcp.json.disabled`,
`.vscode/mcp.json.old`, ...; document kind `mcp_copy`, found by discovery and by no other rule). A copy is not loaded by
any agent today, but it is committed, and whoever renames it back loads it as it stands. Per server, one finding for:

* a remote `url` over plain `http` to a host that is not loopback (the reading of SW-CFG-001, both URL readings);
* a literal credential in `env`, `headers` or `args`: a value with a known token prefix, or a value of 16 characters or
  more under a secret-like name (a name with a `key`, `token`, `secret`, `password`, `auth` or `bearer` word, or any name
  `rules/patterns.secret_named` accepts) that has some entropy and is not a path or a URL;
* a package launched on a moving distribution tag (`pkg@latest`, `@scope/pkg@next`; a bare unpinned name stays quiet
  in a copy), outside container launchers;
* a filesystem server (`...server-filesystem`) granted a home directory or a root (`/`, `~`, `$HOME`, `/home/<user>`,
  `/Users/<user>`, `/root`, a drive root, `C:/Users/<user>`, `/mnt/<drive>`); the evidence names the kind, never the path;
* a shell server whose `ALLOW_COMMANDS` / `ALLOWED_COMMANDS` names a general tool (`awk`, `sed`, `find`, `xargs`, `env`,
  `bash`, `sh`, `python`, `node`, `perl`, `docker`, `kubectl`, `git`).

A reference (`${VAR}`, `$VAR`), a placeholder (`<...>`, `{{...}}`, `your-`, `YOUR_`, `_HERE`, `xxx`, `changeme`,
`example`, `sample`, `fake`, `dummy`, `op://`), a short value and a low-entropy value are quiet. A `disabled` entry still
counts: the copy is the point. Evidence is masked and names the server and the field. Every scan is a plain string scan,
linear in the size of the value. The module is registered by the rule set, not here."""
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator

from spellwarden_scan.evidence import bounded_evidence, fingerprint
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.rules.patterns import name_tokens, secret_named

RULE_ID = "SW-CFG-014"
TITLE = "Insecure or credential-bearing MCP server in a configuration copy"
SEVERITY = "high"
OWASP = ("MCP01", "ASI04")
NIST = ("IA-5", "CM-7")
MALICIOUS = False

_SECRET_WORDS = frozenset({"key", "token", "secret", "password", "auth", "bearer"})
_PLACEHOLDER_WORDS = ("your-", "your_", "_here", "xxx", "changeme", "example", "sample", "fake", "dummy", "op://", "${", "{{")
_MIN_LENGTH = 16
_MIN_ENTROPY = 3.0  # bits per character: below it a value repeats too few characters to be a generated secret
_MAX_ENTROPY_SCAN = 512  # characters counted for the entropy: a secret is far shorter, a long value need not be counted whole


def _secret_like(name: str) -> bool:
    return bool(name) and (secret_named(name) or any(token in _SECRET_WORDS for token in name_tokens(name)))


def _entropy(value: str) -> float:
    sample = value[:_MAX_ENTROPY_SCAN]
    counts = Counter(sample)
    return -sum(n / len(sample) * math.log2(n / len(sample)) for n in counts.values())


def _placeholder(value: str) -> bool:
    lowered = value.lower()
    return (any(word in lowered for word in _PLACEHOLDER_WORDS)
            or ("<" in value and ">" in value[value.find("<"):]))


def _path_or_url(value: str) -> bool:
    return value.startswith(("/", "~", "./", "../", ".\\")) or "://" in value or value[1:3] == ":\\"


def _credential(name: str, value: str) -> tuple[str, str] | None:
    """`(how, literal)` when a value is a literal credential: `known` (a token prefix) or `named` (long, entropic, under a
    secret-like name); None otherwise. `literal` is the value without a leading `Bearer` or `Basic`."""
    # Imported here, not at the top: rules/config.py will import this module to register it (import cycle).
    from spellwarden_scan.rules.config import _credential_shaped, _literal, is_placeholder, is_reference

    literal = _literal(value).strip()
    if not literal or is_reference(literal) or is_placeholder(literal) or _placeholder(literal):
        return None
    if _credential_shaped(literal):
        return "known", literal
    if not _secret_like(name) or len(literal) < _MIN_LENGTH or _path_or_url(literal):
        return None
    return ("named", literal) if _entropy(literal) >= _MIN_ENTROPY else None


_DIST_TAG = re.compile(r"(?![vV][0-9])[A-Za-z][A-Za-z0-9._-]*")
_CONTAINERS = frozenset({"docker", "podman", "nerdctl"})
_HOME_OR_ROOT = re.compile(
    r"/|~|\$home|\$\{home\}|\$\{env:home\}|\$\{userhome\}|%userprofile%|/root|/home/[^/]+|/users/[^/]+|[a-z]:|"
    r"[a-z]:/users/[^/]+|/mnt/[a-z]")
_BROAD_COMMANDS = frozenset({"awk", "sed", "find", "xargs", "env", "bash", "sh", "python", "node", "perl", "docker",
                             "kubectl", "git"})
_ALLOW_NAMES = frozenset({"allow_commands", "allowed_commands"})


def _moving_tag(word: str) -> str | None:
    """The distribution tag of `pkg@tag` / `@scope/pkg@tag` when it is a moving name (`latest`, `next`), else None."""
    from spellwarden_scan.rules.config import _REMOTE_SHORTHANDS, _local_path

    if "://" in word or word.startswith(_REMOTE_SHORTHANDS) or _local_path(word):
        return None
    body = word[1:] if word.startswith("@") else word
    if "@" not in body:
        return None
    tag = body.rsplit("@", 1)[1]
    return tag if _DIST_TAG.fullmatch(tag) else None


def _home_or_root(path: str) -> bool:
    text = re.sub(r"[\\/]+", "/", path.strip().strip("\"'")).lower()
    if len(text) > 1:
        text = text.rstrip("/") or "/"
    return _HOME_OR_ROOT.fullmatch(text) is not None


def _filesystem_grants(entry) -> Iterator[tuple[str, str]]:
    """`(field, word)` of each home-or-root path given to a filesystem server."""
    from spellwarden_scan.rules.config import _launch_lines, _program, _words

    for _wrapper, words in _launch_lines(_words(entry)):
        server = False
        for field, word in words:
            name = _program(word)
            if not server:
                package = name[1:] if name.startswith("@") else name
                server = package.split("@", 1)[0].endswith("server-filesystem")
                continue
            if not word.startswith("-") and _home_or_root(word):
                yield field, word


def _broad_allowlist(entry) -> tuple[str, list[str]] | None:
    from spellwarden_scan.rules.config import _program

    for name, value in entry.env.items():
        if name.lower() not in _ALLOW_NAMES or not isinstance(value, str):
            continue
        tools = []
        for token in re.split(r"[,\s]+", value[:4096]):
            program = _program(token)
            program = "python" if re.fullmatch(r"python[0-9.]*", program) else program
            if program in _BROAD_COMMANDS and program not in tools:
                tools.append(program)
        if tools:
            return f"env.{name}", tools
    return None


def _finding(path: str, line: int, matched: str, evidence: str) -> Finding:
    return Finding(RULE_ID, SEVERITY, TITLE, Location(path, line), bounded_evidence(evidence),
                   fingerprint(RULE_ID, path, matched), MALICIOUS)


def detect(config) -> Iterator[Finding]:
    # Imported here, not at the top: rules/config.py will import this module to register it (import cycle).
    from spellwarden_scan.rules.config import _LOOPBACK_NAMES, _valued_fields, config_matched, display_url, url_readings

    for doc, entry in config.copy_servers():
        if entry.url is not None:
            scheme, hosts = url_readings(entry.url)
            if scheme == "http" and (not hosts or any(host not in _LOOPBACK_NAMES for host in hosts)):
                yield _finding(doc.path, entry.line, config_matched("server", entry.name, "url", entry.url),
                               f"{entry.name}: {display_url(entry.url)}")
        for field, name, value, _header in _valued_fields(entry):
            found = _credential(name, value)
            if found is None:
                continue
            how, literal = found
            shown = f"{field} = {literal[:4]}***" if how == "known" else f"{field} holds a literal value (***)"
            yield _finding(doc.path, entry.line, config_matched("server", entry.name, field, value),
                           f"{entry.name}: {shown}")
        if entry.command is not None:
            from spellwarden_scan.rules.config import _unpinned_launches

            for launcher, field, value, shown in _unpinned_launches(entry):
                if launcher in _CONTAINERS or _moving_tag(value) is None:
                    continue
                yield _finding(doc.path, entry.line, config_matched("server", entry.name, field, value),
                               f"{entry.name}: {launcher} {shown}")
        for field, word in _filesystem_grants(entry):
            yield _finding(doc.path, entry.line, config_matched("server", entry.name, field, word),
                           f"{entry.name}: filesystem server granted a home directory or a root")
        broad = _broad_allowlist(entry)
        if broad is not None:
            field, tools = broad
            yield _finding(doc.path, entry.line, config_matched("server", entry.name, field, ",".join(tools)),
                           f"{entry.name}: shell allowlist includes {', '.join(tools)}")
