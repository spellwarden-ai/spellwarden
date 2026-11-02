"""SW-SKL-034: TLS certificate checks switched off where credentials are sent.

Read over the scripts of a skill package (`.py`, `.js`, `.mjs`, `.ts`, `.go`, `.sh`) and the fenced code blocks of its
Markdown files. A line fires when it holds a TLS-verification switch (`verify=False`, `ssl._create_unverified_context`,
`CERT_NONE`, `check_hostname = False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED` set to 0,
`InsecureSkipVerify: true`, `curl -k` / `--insecure` or a short-flag cluster holding `k`, `wget --no-check-certificate`)
and a credential appears in the same statement or within five lines either side (an `Authorization` or `Bearer` header,
an API key, `auth=`, a password, token or secret name, a cookie jar, an SMTP or IMAP login). The finding is at the
switch's line.

Quiet: a loopback target in the call or in a default URL constant the call uses; a switch inside a branch that tests an
opt-in variable or flag (insecure, skip-verify, allow-self-signed, ...); a line that says never or must not, or names
the pattern as something a scanner detects (a pattern table, a regular expression); files under `test` or `tests`
directories and files named `test_*` or `*_test.*`. Everything is a plain string scan or a bounded pattern with at most
one variable repeat, so a long line is read in linear time. The module is registered by the rule set, not here."""
from __future__ import annotations

import re
from collections.abc import Iterator

from spellwarden_scan.evidence import excerpt, fingerprint
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.package import CodeBlock, Package

RULE_ID = "SW-SKL-034"
TITLE = "TLS certificate checks switched off where credentials are sent"
SEVERITY = "high"
OWASP = ("MCP01",)
NIST = ("SC-8", "IA-5")
MALICIOUS = False

_SUFFIXES = (".py", ".js", ".mjs", ".ts", ".go", ".sh")
_NEAR = 5  # lines either side of the switch searched for a credential or a target
_GATE_LINES = 3  # lines above the switch searched for an opt-in condition
_CONTEXT_LINES = 3  # comment or prose lines above the switch read for guidance
_PER_UNIT = 10
_PER_PACKAGE = 50

# Switches, matched on the lower-cased line with spaces and tabs removed. Each has one variable-free shape.
_SWITCHES = re.compile(
    r"""(?<![a-z0-9_])verify(?:_ssl)?["']?[=:]false(?![a-z0-9_])"""
    r"""|_create_unverified_context"""
    r"""|(?<![a-z0-9_])cert_none(?![a-z0-9_])"""
    r"""|(?<![a-z0-9_])check_hostname["']?=false(?![a-z0-9_])"""
    r"""|rejectunauthorized["']?[:=]false"""
    r"""|node_tls_reject_unauthorized["']?\]?[=:]["']?0(?![0-9])"""
    r"""|insecureskipverify["']?[:=]true"""
    r"""|--no-check-certificate""")
_CURL_FLAGS = re.compile(r"-[A-Za-z]*k[A-Za-z]*")
_COMMAND_END = frozenset({"|", "||", "&&", ";", "&"})
_WORD = re.compile(r"[a-z0-9]+")
_IDENT = re.compile(r"[a-z_][a-z0-9_]*")
_AUTH_ARG = re.compile(r"(?<![a-z0-9_])auth\s*[:=]")
_CRED_PHRASES = ("authorization", "bearer ", "x-api-key", "cookiejar", "cookie-jar", "cookie_jar", "cookie jar")
_CRED_WORDS = frozenset({"password", "passwd", "pwd", "secret", "token", "apikey", "cookie", "cookies"})
_URL_HOST = re.compile(r"""[a-z][a-z0-9+.-]{0,15}://([^/\s"'`?#)>]*)""")
_LOOPBACK_V4 = re.compile(r"(?<![0-9.])127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9])")
_LOOPBACK_V6 = re.compile(r"(?<![0-9a-f:])::1(?![0-9a-f:])")
_ASSIGNED = re.compile(r"""^\s*(?:export\s+|const\s+|let\s+|var\s+|final\s+)?([a-z_][a-z0-9_]*)\s*(?::\s*[a-z_][a-z0-9_.\[\]]*\s*)?=""")
_OPT_IN = ("insecure", "unsafe", "skip_tls", "skip_ssl", "skip_verify", "skip-tls", "skip-verify", "no_verify",
           "no-verify", "noverify", "no_tls", "no_ssl", "disable_tls", "disable_ssl", "disable_verify",
           "allow_self", "self_signed", "selfsigned", "self-signed", "allow_untrusted")
_CONDITION = frozenset({"if", "elif", "unless", "when", "case", "while"})
_AVOID_PHRASES = ("must not", "mustn't", "should not", "shouldn't", "do not", "don't", "never ", "avoid", "anti-pattern",
                  "antipattern", "not recommended", "not allowed", "forbidden", "disallow")
_DETECTION = frozenset({"detect", "detects", "detected", "detecting", "detection", "detector", "pattern", "patterns",
                        "regex", "regexp", "grep", "linter", "lint", "scanner", "ioc", "iocs", "blocklist", "denylist"})
_REGEX_CUES = ("re.compile", "re.search", "new regexp", "(?:", "\\s*", "\\b")


def _is_test_path(path: str) -> bool:
    parts = path.lower().split("/")
    name = parts[-1]
    stem = name.rsplit(".", 1)[0]
    return (any(part in ("test", "tests") for part in parts[:-1]) or name.startswith("test_")
            or stem.endswith("_test"))


def _squeezed(low: str) -> str:
    return low.replace(" ", "").replace("\t", "")


def _curl_switch_lines(lines: tuple[str, ...]) -> set[int]:
    """Indexes of lines where a curl command is given `-k`, `--insecure` or a short-flag cluster holding `k`,
    including flags on `\\`-continued lines."""
    found: set[int] = set()
    in_curl = False
    for index, line in enumerate(lines):
        for raw in line.split():
            token = raw.lstrip("\"'`($!{")
            if token == "curl" or token.endswith("/curl"):
                in_curl = True
            elif token in _COMMAND_END or token.endswith(";"):
                in_curl = False
            elif in_curl and (token == "--insecure" or _CURL_FLAGS.fullmatch(token)):
                found.add(index)
        if not line.rstrip().endswith("\\"):
            in_curl = False
    return found


def _words(low: str) -> frozenset[str]:
    return frozenset(_WORD.findall(low))


def _has_credential(low: str, words: frozenset[str]) -> bool:
    return (any(p in low for p in _CRED_PHRASES) or bool(words & _CRED_WORDS) or ("api" in words and "key" in words)
            or _AUTH_ARG.search(low) is not None)


def _hosts(low: str) -> list[str]:
    hosts = []
    for match in _URL_HOST.finditer(low):
        host = match.group(1).rsplit("@", 1)[-1]
        hosts.append(host)
    return hosts


def _is_loopback_host(host: str) -> bool:
    if host.startswith("["):  # [::1]:8443
        bare = host[1:].split("]", 1)[0]
    else:
        bare = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return bare == "localhost" or bare.endswith(".localhost") or _LOOPBACK_V4.fullmatch(bare) is not None or bare == "::1"


def _templated(host: str) -> bool:
    return not host or "$" in host or "{" in host or "%" in host


def _loopback_marker(low: str) -> bool:
    return "localhost" in low or _LOOPBACK_V4.search(low) is not None or _LOOPBACK_V6.search(low) is not None


class _Unit:
    """One scanned body: its lines and the per-line facts computed once."""

    def __init__(self, path: str, lines: tuple[str, ...], first_line: int, context: tuple[str, ...]) -> None:
        self.path = path
        self.lines = lines
        self.first_line = first_line
        self.context = context  # prose above a fenced block, lower case
        self.low = [line.lower().replace("’", "'") for line in lines]
        self.words = [_words(low) for low in self.low]
        self._cred: dict[int, bool] = {}
        self.loopback_names = self._loopback_names()

    def _loopback_names(self) -> frozenset[str]:
        names = set()
        for low in self.low:
            if not _loopback_marker(low):
                continue
            if any(not _templated(h) and not _is_loopback_host(h) for h in _hosts(low)):
                continue
            match = _ASSIGNED.match(low)
            if match:
                names.add(match.group(1))
        return frozenset(names)

    def credential(self, index: int) -> bool:
        if index not in self._cred:
            self._cred[index] = _has_credential(self.low[index], self.words[index])
        return self._cred[index]

    def window(self, index: int) -> range:
        return range(max(0, index - _NEAR), min(len(self.lines), index + _NEAR + 1))

    def credential_near(self, index: int) -> bool:
        window = self.window(index)
        if any(self.credential(i) for i in window):
            return True
        # an SMTP or IMAP login carries the credential in its arguments
        if any("login" in self.words[i] for i in window):
            return any(w.startswith(("smtp", "imap")) for i in window for w in self.words[i])
        return False

    def loopback_only(self, index: int) -> bool:
        """The call's target is loopback: a loopback host or a default URL constant in reach, and no remote host."""
        window = self.window(index)
        hosts = [h for i in window for h in _hosts(self.low[i])]
        if any(not _templated(h) and not _is_loopback_host(h) for h in hosts):
            return False
        if any(_loopback_marker(self.low[i]) for i in window):
            return True
        if not self.loopback_names:
            return False
        return any(name in self.loopback_names for i in window for name in _IDENT.findall(self.low[i]))

    def opt_in(self, index: int) -> bool:
        """The switch sits in a branch that tests an opt-in variable or flag."""
        lines = range(max(0, index - _GATE_LINES), index + 1)
        branch = any(self.words[i] & _CONDITION or "&&" in self.low[i] or "?" in self.low[i] for i in lines)
        return branch and any(term in self.low[i] for i in lines for term in _OPT_IN)

    def guidance(self, index: int) -> list[str]:
        """The switch line and the comment lines (or prose above a fenced block) that introduce it."""
        found = [self.low[index]]
        if self.context:
            return found + list(self.context)
        i = index - 1
        while i >= 0 and len(found) <= _CONTEXT_LINES and self.low[i].lstrip().startswith(("#", "//", "*", "/*")):
            found.append(self.low[i])
            i -= 1
        return found

    def describes(self, index: int, squeezed: str) -> bool:
        """The line only warns about, lists or tests for the pattern."""
        text = "\n".join(self.guidance(index))
        if any(phrase in text for phrase in _AVOID_PHRASES) or _words(text) & _DETECTION:
            return True
        low = self.low[index]
        if any(cue in low for cue in _REGEX_CUES):
            return True
        # a quoted pattern in a list or table: more than one switch on a line, or a switch that opens a string literal
        matches = list(_SWITCHES.finditer(squeezed))
        if len({m.group(0) for m in matches}) > 1:
            return True
        return any(m.start() and squeezed[m.start() - 1] in "\"'`" and squeezed[m.end():m.end() + 1] in ("\"", "'", "`")
                   for m in matches[:1])


def _finding(path: str, line: int, matched: str) -> Finding:
    return Finding(RULE_ID, SEVERITY, TITLE, Location(path, line), excerpt(matched), fingerprint(RULE_ID, path, matched), MALICIOUS)


def _units(package: Package) -> Iterator[_Unit]:
    for source in package.text_files:
        if source.path.lower().endswith(_SUFFIXES) and not _is_test_path(source.path):
            yield _Unit(source.path, source.lines, 1, ())
    by_path = {f.path: f for f in package.instructions()}
    for block in package.code_blocks:
        if _is_test_path(block.path):
            continue
        yield _Unit(block.path, block.lines, block.first_line, _prose_above(by_path.get(block.path), block))


def _prose_above(source, block: CodeBlock) -> tuple[str, ...]:
    """The two nearest non-blank lines above a block's opening fence."""
    if source is None:
        return ()
    found: list[str] = []
    index = block.first_line - 2  # the fence is the line before the first body line (1-based first_line)
    while index > 0 and len(found) < 2:
        index -= 1
        text = source.lines[index].strip()
        if text:
            found.append(text.lower().replace("’", "'"))
    return tuple(found)


def detect(package: Package) -> Iterator[Finding]:
    total = 0
    for unit in _units(package):
        curl = _curl_switch_lines(unit.lines)
        count = 0
        for index, low in enumerate(unit.low):
            squeezed = _squeezed(low)
            if index not in curl and _SWITCHES.search(squeezed) is None:
                continue
            if unit.describes(index, squeezed) or unit.opt_in(index) or unit.loopback_only(index):
                continue
            if not unit.credential_near(index):
                continue
            yield _finding(unit.path, unit.first_line + index, unit.lines[index])
            count += 1
            total += 1
            if count >= _PER_UNIT or total >= _PER_PACKAGE:
                break
        if total >= _PER_PACKAGE:
            return
