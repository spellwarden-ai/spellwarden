"""SW-SKL-034: TLS certificate checks switched off where credentials are sent.

Read over the scripts of a skill package (`.py`, `.js`, `.mjs`, `.ts`, `.go`, `.sh`) and the fenced code blocks of its
Markdown files. A line fires when it holds a TLS-verification switch (`verify=False`, `ssl._create_unverified_context`,
`CERT_NONE`, `check_hostname = False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED` set to 0,
`InsecureSkipVerify: true`, `curl -k` / `--insecure` or a short-flag cluster holding `k`, `wget --no-check-certificate`)
and a credential appears in the same statement or within five lines either side (an `Authorization` or `Bearer` header,
an API key, `auth=`, a password, token or secret name, a cookie jar, an SMTP or IMAP login, a database connection string
or `DATABASE_URL`). The finding is at the switch's line.

A credential further away still counts in three cases. (1) Through the bound object: when the switch is an attribute set
(`ctx.check_hostname = False`) or sits in a client, context or constructor binding (`client = httpx.Client(verify=False)`,
`ws = new WebSocket(url, { rejectUnauthorized: false })`, `with ... as client`), but not in an HTTP-verb call, the next
40 lines are scanned for uses of that name, stopping at a rebinding and at a def, class, function or func line indented
less than the switch. A use counts when its statement (bracket balance, at most 8 lines) holds a credential, or when it
passes the name as a call argument and another bare identifier argument resolves to its nearest earlier assignment
(within 30 lines) whose statement (at most 12 lines) holds one. (2) Through a variable: a name assigned a value that holds
an `Authorization` header, a bearer token, an API-key header, a cookie jar, a connection string or `DATABASE_URL`, in any
code block of the same Markdown file or in the same script, is a credential when referenced as `$NAME` or `${NAME}`; a
variable whose value is just a URL is not, whatever its name. The finding is at the switch line in every case, and the
describes, opt-in and loopback checks run before any credential source.

Quiet: a loopback target in the call or in a default URL constant the call uses (a constant read from an environment or
configuration lookup with only a loopback fallback stays loopback, unless a Markdown file of the package documents a
non-loopback URL for that key: the key followed by `=` or `:`, or its stem joined by `.`, `_` or `-` to url, host,
endpoint or server); a switch inside a branch that tests an opt-in variable or flag (insecure, skip-verify, allow-self-signed, ...); a line that says never or must not, or names
the pattern as something a scanner detects (a pattern table, a regular expression); files under `test` or `tests`
directories and files named `test_*` or `*_test.*`. Everything is a plain string scan or a bounded pattern with at most
one variable repeat, and the object scan is capped, so a long line is read in linear time. The module is registered by the rule set, not here."""
from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

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
_OBJECT_LINES = 40  # lines after a binding scanned for uses of the bound name
_USE_SPAN = 8  # lines of the statement around a use of the bound name
_ARGUMENT_BACK = 30  # lines above a use searched for the assignment of another argument
_ARGUMENT_SPAN = 12  # lines of the statement that assigns the other argument
_URL_WORDS = ("url", "host", "endpoint", "server")
_NOT_AN_ARGUMENT = frozenset({"none", "true", "false", "null", "nil", "undefined", "self", "this", "cls"})
_NOT_AN_OBJECT = frozenset({"process", "os", "env", "self", "this", "cls"})

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
_TOKEN = re.compile(r"[a-z0-9_.-]+")
_REFERENCE = re.compile(r"\$\{?([a-z_][a-z0-9_]*)")
_PLAIN_URL = re.compile(r"[a-z][a-z0-9+.-]{0,15}://[^\s@]*")
# an environment or configuration lookup: `${KEY:-default}`, `process.env.KEY`, `get("key"`, `environ["KEY"]`
_LOOKUP_KEY = re.compile(
    r"""\$\{([a-z_][a-z0-9_]*):?-"""
    r"""|process\.env\.([a-z_][a-z0-9_]*)"""
    r"""|(?:get|getenv|getproperty|env|environ|config|settings|cfg|conf)\s*[(\[]\s*["']([a-z0-9_.-]{1,64})["']""")
_ATTRIBUTE_SET = re.compile(r"^\s*(?:self\.|this\.)?([a-z_][a-z0-9_]*)(?:\.[a-z_][a-z0-9_]*)*\.[a-z_][a-z0-9_]*\s*=(?!=)")
_WITH_AS = re.compile(r"^\s*(?:async\s+)?with\s.*\sas\s+([a-z_][a-z0-9_]*)\s*[:,]")
_HTTP_VERB_CALL = re.compile(r"\.(?:get|post|put|patch|delete|head|options|request)\s*\(|(?<![a-z0-9_.])(?:fetch|urlopen)\s*\(")
_SCOPE_START = re.compile(r"^\s*(?:(?:export|default|async|public|private|static)\s+)*(?:def|class|function|func)(?![a-z0-9_])")
_ARGUMENT = re.compile(r"[(,]\s*(?:[a-z_][a-z0-9_]*\s*[=:]\s*)?([a-z_][a-z0-9_]*)\s*(?=[,)])")
_AUTH_ARG = re.compile(r"(?<![a-z0-9_])auth\s*[:=]")
_CRED_PHRASES = ("authorization", "bearer ", "x-api-key", "cookiejar", "cookie-jar", "cookie_jar", "cookie jar",
                 "connectionstring", "database_url")
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


def _balance(low: str) -> int:
    return (low.count("(") + low.count("[") + low.count("{")) - (low.count(")") + low.count("]") + low.count("}"))


def _indent_of(line: str) -> int:
    expanded = line.expandtabs(4)
    return len(expanded) - len(expanded.lstrip(" "))


def _lookup_key(low: str) -> str | None:
    match = _LOOKUP_KEY.search(low)
    if match is None:
        return None
    return next(group for group in match.groups() if group)


def _stem(key: str) -> str | None:
    """`acme_url` -> `acme`: the key without a trailing url, host, endpoint or server word; `None` when it has none."""
    for word in _URL_WORDS:
        if key.endswith(word) and len(key) > len(word) + 1 and key[-len(word) - 1] in "._-":
            return key[:-len(word) - 1]
    return None


def _remote_url(low: str) -> bool:
    return any(not _templated(h) and "<" not in h and not _is_loopback_host(h) for h in _hosts(low))


class _Documented:
    """The keys the package's Markdown documents with a remote URL: the key followed by `=` or `:`, and the stems of
    `stem.url`, `stem_host`, `stem-endpoint` ... names on such a line. Built once per scan."""

    def __init__(self, package: Package) -> None:
        self.keys: set[str] = set()
        self.stems: set[str] = set()
        for source in package.instructions():
            for line in source.lines:
                low = line.lower()
                if "://" in low and _remote_url(low):
                    self._read(low)

    def _read(self, low: str) -> None:
        for match in _TOKEN.finditer(low):
            token = match.group(0)
            stem = _stem(token)
            if stem:
                self.stems.add(stem)
            j = match.end()
            while j < len(low) and low[j] in " \t`\"'*":
                j += 1
            if j < len(low) and low[j] in "=:":
                self.keys.add(token)

    def has(self, key: str) -> bool:
        return key in self.keys or (_stem(key) or key) in self.stems


def _assigned_names(lines: Iterable[str]) -> tuple[set[str], set[str]]:
    """Names assigned a value that holds a credential phrase, and names assigned just a URL (no user info)."""
    credential: set[str] = set()
    url: set[str] = set()
    for line in lines:
        low = line.lower()
        match = _ASSIGNED.match(low)
        if match is None or low[match.end():match.end() + 1] == "=":
            continue
        value = low[match.end():]
        if any(phrase in value for phrase in _CRED_PHRASES):
            credential.add(match.group(1))
        elif _PLAIN_URL.fullmatch(value.strip().strip("\"'`;")):
            url.add(match.group(1))
    return credential, url - credential


def _loopback_marker(low: str) -> bool:
    return "localhost" in low or _LOOPBACK_V4.search(low) is not None or _LOOPBACK_V6.search(low) is not None


class _Unit:
    """One scanned body: its lines and the per-line facts computed once."""

    def __init__(self, path: str, lines: tuple[str, ...], first_line: int, context: tuple[str, ...],
                 documented_remote: _Documented, cred_vars: frozenset[str], url_vars: frozenset[str]) -> None:
        self.path = path
        self.lines = lines
        self.first_line = first_line
        self.context = context  # prose above a fenced block, lower case
        self.low = [line.lower().replace("’", "'") for line in lines]
        self.words = [_words(low) for low in self.low]
        self.documented_remote = documented_remote
        self.cred_vars = cred_vars
        self.url_vars = url_vars
        self._cred: dict[int, bool] = {}
        self.documented_fallback: set[int] = set()  # loopback fallback lines whose key the package documents as remote
        self.loopback_names = self._loopback_names()

    def _loopback_names(self) -> frozenset[str]:
        names = set()
        for index, low in enumerate(self.low):
            if not _loopback_marker(low):
                continue
            if any(not _templated(h) and not _is_loopback_host(h) for h in _hosts(low)):
                continue
            key = _lookup_key(low)
            if key is not None and self.documented_remote.has(key):
                self.documented_fallback.add(index)
                continue
            match = _ASSIGNED.match(low)
            if match:
                names.add(match.group(1))
        return frozenset(names)

    def credential(self, index: int) -> bool:
        if index not in self._cred:
            self._cred[index] = self._credential(index)
        return self._cred[index]

    def _credential(self, index: int) -> bool:
        low = self.low[index]
        words = self.words[index]
        if "$" in low and (self.cred_vars or self.url_vars):
            references = list(_REFERENCE.finditer(low))
            if any(m.group(1) in self.cred_vars for m in references):
                return True
            if any(m.group(1) in self.url_vars for m in references):  # a URL variable is not a credential, whatever its name
                low = _REFERENCE.sub(lambda m: " " if m.group(1) in self.url_vars else m.group(0), low)
                words = _words(low)
        return _has_credential(low, words)

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
        if any(_loopback_marker(self.low[i]) for i in window if i not in self.documented_fallback):
            return True
        if not self.loopback_names:
            return False
        return any(name in self.loopback_names for i in window for name in _IDENT.findall(self.low[i]))

    def _bound_name(self, index: int) -> str | None:
        """The object the switch configures: the target of an attribute set, or the name bound to a client, context or
        constructor call (not to an HTTP-verb call) that holds the switch on this line or on one of the 3 lines above."""
        low = self.low[index]
        attribute = _ATTRIBUTE_SET.match(low)
        if attribute is not None:
            name = attribute.group(1)
            return None if name in _NOT_AN_OBJECT else name
        open_brackets = 0  # brackets the lines above the switch leave unclosed
        for i in range(index, max(-1, index - 4), -1):
            if i != index:
                open_brackets += _balance(self.low[i])
                if open_brackets <= 0:
                    continue
            match = _ASSIGNED.match(self.low[i])
            if match is not None:
                value = self.low[i][match.end():]
                if "(" in value and _HTTP_VERB_CALL.search(value) is None:
                    return match.group(1)
            opened = _WITH_AS.match(self.low[i])
            if opened is not None and _HTTP_VERB_CALL.search(self.low[i]) is None:
                return opened.group(1)
        return None

    def _span(self, index: int, limit: int) -> range:
        """The lines of the statement that holds `index`, by bracket balance, at most `limit` lines."""
        start, depth = index, _balance(self.low[index])
        while depth < 0 and start > 0 and index - start < limit - 1:
            start -= 1
            depth += _balance(self.low[start])
        end = index
        while depth > 0 and end + 1 < len(self.lines) and end - start + 1 < limit:
            end += 1
            depth += _balance(self.low[end])
        return range(start, end + 1)

    def _assignment_credential(self, name: str, before: int) -> bool:
        """The nearest assignment of `name` within 30 lines above `before` has a credential in its statement."""
        for i in range(before - 1, max(-1, before - _ARGUMENT_BACK - 1), -1):
            match = _ASSIGNED.match(self.low[i])
            if match is not None and match.group(1) == name:
                return any(self.credential(j) for j in self._span(i, _ARGUMENT_SPAN))
        return False

    def credential_via_object(self, index: int) -> bool:
        """A credential is used with the object the switch configures, further away than the near window."""
        name = self._bound_name(index)
        if name is None:
            return False
        indent = _indent_of(self.lines[index])
        use = re.compile(rf"(?<![a-z0-9_.$]){re.escape(name)}(?![a-z0-9_])")
        passed = re.compile(rf"[(,]\s*(?:[a-z_][a-z0-9_]*\s*[=:]\s*)?{re.escape(name)}\s*[,)]")
        for i in range(index + 1, min(len(self.lines), index + 1 + _OBJECT_LINES)):
            low = self.low[i]
            if _SCOPE_START.match(low) is not None and _indent_of(self.lines[i]) < indent:
                break
            match = _ASSIGNED.match(low)
            if match is not None and match.group(1) == name:
                break
            if use.search(low) is None:
                continue
            span = self._span(i, _USE_SPAN)
            if any(self.credential(j) for j in span):
                return True
            text = " ".join(self.low[j] for j in span)
            if passed.search(text) is None:
                continue
            others = {m.group(1) for m in _ARGUMENT.finditer(text)} - {name} - _NOT_AN_ARGUMENT
            if any(self._assignment_credential(other, i) for other in sorted(others)):
                return True
        return False

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
    documented_remote = _Documented(package)
    for source in package.text_files:
        if source.path.lower().endswith(_SUFFIXES) and not _is_test_path(source.path):
            cred_vars, url_vars = _assigned_names(source.lines)
            yield _Unit(source.path, source.lines, 1, (), documented_remote, frozenset(cred_vars), frozenset(url_vars))
    by_path = {f.path: f for f in package.instructions()}
    blocks = [block for block in package.code_blocks if not _is_test_path(block.path)]
    block_lines = {id(block): block.lines for block in blocks}
    by_file: dict[str, list[str]] = {}
    for block in blocks:  # per Markdown file, across all its code blocks
        by_file.setdefault(block.path, []).extend(block_lines[id(block)])
    names = {path: _assigned_names(lines) for path, lines in by_file.items()}
    for block in blocks:
        cred_vars, url_vars = map(frozenset, names[block.path])
        yield _Unit(block.path, block_lines[id(block)], block.first_line, _prose_above(by_path.get(block.path), block),
                    documented_remote, cred_vars, url_vars)


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
            if not unit.credential_near(index) and not unit.credential_via_object(index):
                continue
            yield _finding(unit.path, unit.first_line + index, unit.lines[index])
            count += 1
            total += 1
            if count >= _PER_UNIT or total >= _PER_PACKAGE:
                break
        if total >= _PER_PACKAGE:
            return
