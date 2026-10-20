"""Regular expressions and word lists shared by rules (spec 5.3, 5.4). Each
constant names the rules that use it. All patterns are case-insensitive
unless the rule says otherwise."""
from __future__ import annotations

import re

_I = re.IGNORECASE


class Then:
    """`A.*B.*C` without the regex: each part searched after the end of the previous one. The regex form
    backtracks quadratically on a line that repeats `A` without a `B` (a 1 MB line of `curl ` is hours);
    this is one linear pass per part. Truthy match or `None`, like `re.Pattern.search`."""

    __slots__ = ("parts",)

    def __init__(self, *parts: str, flags: int = _I) -> None:
        self.parts = tuple(re.compile(part, flags) for part in parts)

    def search(self, text: str, pos: int = 0):
        match = None
        for part in self.parts:
            match = part.search(text, pos)
            if match is None:
                return None
            pos = match.end()
        return match


class Within:
    """`OPEN[^C]*INNER` without the regex: `inner` searched between the end of each `opener` and the next
    `close` character (or the end of the line). An opener inside an earlier opener's span is skipped, its
    span being a suffix of that one, so the line is read once."""

    __slots__ = ("opener", "inner", "close")

    def __init__(self, opener: str, inner: str, close: str, flags: int = _I) -> None:
        self.opener, self.inner, self.close = re.compile(opener, flags), re.compile(inner, flags), close

    def search(self, text: str, pos: int = 0):
        reached = -1
        for opened in self.opener.finditer(text, pos):
            if opened.start() < reached:
                continue
            end = text.find(self.close, opened.end())
            end = len(text) if end < 0 else end
            match = self.inner.search(text, opened.end(), end)
            if match:
                return match
            reached = end
        return None


class Piped:
    """`SOURCE[^|]*\\|\\s*SINK` without the regex: the line is cut at every `|` and a segment holding
    `source` must be followed by a segment that starts with `sink`."""

    __slots__ = ("source", "sink")

    def __init__(self, source: str, sink: str, flags: int = _I) -> None:
        self.source, self.sink = re.compile(source, flags), re.compile(sink, flags)

    def search(self, text: str, pos: int = 0):
        segments = text[pos:].split("|")
        for index in range(len(segments) - 1):
            if self.source.search(segments[index]) and (match := self.sink.match(segments[index + 1])):
                return match
        return None


class AnyOf:
    """The first of several matchers (`re.Pattern`, `Then`, `Within`, `Piped`) that matches."""

    __slots__ = ("matchers",)

    def __init__(self, *matchers) -> None:
        self.matchers = matchers

    def search(self, text: str, pos: int = 0):
        for matcher in self.matchers:
            match = matcher.search(text, pos)
            if match:
                return match
        return None

# SW-SKL-001, SW-MCP-011
INJECTION: tuple[re.Pattern, ...] = tuple(re.compile(p, _I) for p in (
    r"ignore (all |any |the |your )?(previous|prior|above|earlier) (instructions|prompts|rules)",
    r"disregard (the |your )?(system|previous|prior)",
    r"you are now (a|an|the)\b",
    r"(do not|don't|never) (tell|inform|mention|reveal) (this |it )?(to )?the user",
    r"without (telling|informing|asking) the user",
    r"pretend (you|to be|that)\b",
    r"override (the |your |any )?(instructions|rules|guidelines|safety)",
    r"new (system )?instructions:",
    r"from now on,? you",
))

# SW-SKL-013
SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy", "tiny.cc",
    "shorturl.at", "rebrand.ly", "t.ly", "v.gd", "s.id",
})

# SW-SKL-011 and evidence.mask_credentials (case-sensitive: the shapes are exact)
# The JWT shape starts only where a token starts (the lookbehind): it is the one shape that can fail after a long
# run, so a line repeating `eyJ` is read once instead of once per repetition. The others match anywhere (spec 5.3).
CREDENTIAL_PATTERNS: tuple[re.Pattern, ...] = tuple(re.compile(p) for p in (
    r"AKIA[0-9A-Z]{16}",
    r"ASIA[0-9A-Z]{16}",
    r"gh[pousr]_[A-Za-z0-9]{36,}",
    r"github_pat_[A-Za-z0-9_]{22,}",
    r"glpat-[A-Za-z0-9_-]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"sk-ant-[A-Za-z0-9_-]{20,}",
    r"sk-[A-Za-z0-9]{32,}",
    r"AIza[0-9A-Za-z_-]{35}",
    r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}",
))
# SW-SKL-011: an assignment of a secret-like name to a quoted value that is not a placeholder
ASSIGNED_SECRET = re.compile(r"""(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*["']([^"'\s]{8,})["']""", _I)
# evidence.mask_credentials only: the value of any secret-like assignment, quoted or not and of any length (it is
# masked whole; SW-SKL-011 still fires on ASSIGNED_SECRET alone, so prose such as `token: see below` stays quiet).
# Also (r2:F7) `authorization` and `cookie` before `=` only (`Authorization:` is a header, masked keeping its scheme
# word), and any name ending in `pwd` or `pass` (`MYSQL_PWD`, `DB_PASS`) before `=` or `:`.
ASSIGNED_VALUE = re.compile(
    r"""(password|passwd|secret|api[_-]?key|apikey|token|access[_-]?key|private[_-]?key|credentials?|"""
    r"""(?:authorization|cookie)(?=["']?\s*=)|(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*?(?:pwd|pass)(?=["']?\s*[:=]))"""
    r"""(["']?\s*[:=]\s*)"""
    # triple-quoted, quoted with backslash escapes, a quote never closed (masked to the end of the line), a `<...>`,
    # `$(...)` or `${...}` placeholder kept whole, bare
    r"""("{3}[^\n]*?"{3}|'{3}[^\n]*?'{3}|"(?:[^"\\\n]|\\.)*"(?!")|'(?:[^'\\\n]|\\.)*'(?!')|["'][^\n]*|<[^<>\n]*>(?=[\s"']|$)|"""
    r"""\$\([^()\n]*\)(?=[\s"']|$)|\$\{[^{}\n]*\}(?=[\s"']|$)|[^\s"']+)""", _I)
# evidence.mask_credentials only: a value that is nothing but a placeholder stays readable (`$TOKEN`, `<your-key>`)
# Only a bare reference or a word placeholder: `${VAR:-default}` and `$(command args)` may carry the secret itself, so
# they are masked like any value.
PLACEHOLDER_VALUE = re.compile(r"(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|<[A-Za-z][A-Za-z _-]*>|x{3,}|\.{3}|\*+|your[-_][A-Za-z0-9_-]*|changeme|example)", _I)
# SW-CFG-002, SW-CFG-010 and evidence masking: secret-named names. Plan decision P16: `authorization` (any header holding
# it: Proxy-Authorization, X-Authorization) and `cookie` (a literal Cookie value is a session credential) are secret
# tokens too.
SECRET_TOKENS = frozenset({"token", "secret", "password", "passwd", "pwd", "credential", "credentials", "apikey",
                           "privatekey", "authorization", "cookie"})
SECRET_PAIRS = frozenset({("api", "key"), ("access", "key"), ("private", "key"), ("client", "secret"),
                          ("auth", "token"), ("bearer", "token")})
_CASE_CHANGE = re.compile(r"(?<=[a-z])(?=[A-Z])")


def name_tokens(name: str) -> tuple[str, ...]:
    """Lower-case tokens split at every non-alphanumeric character and at lower-to-upper changes (`apiKey`)."""
    tokens: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", name):
        tokens.extend(piece.lower() for piece in _CASE_CHANGE.split(part) if piece)
    return tuple(tokens)


def secret_named(name: str) -> bool:
    """Spec 5.3: the name's tokens hold a secret token or an adjacent secret pair."""
    tokens = name_tokens(name)
    return any(token in SECRET_TOKENS for token in tokens) or any(pair in SECRET_PAIRS for pair in zip(tokens, tokens[1:], strict=False))


PLACEHOLDER = re.compile(r"(xxx|\.\.\.|<|your[_-]|example|changeme|\$\{|\$[A-Z_]+)", _I)

# SW-SKL-008, SW-SKL-012
SECRET_PATHS = re.compile(
    r"(~?/?\.ssh/|id_(rsa|ed25519|ecdsa)|~?/?\.aws/|\.env\b|~?/?\.netrc|~?/?\.npmrc|~?/?\.pypirc|~?/?\.git-credentials|"
    r"~?/?\.docker/config\.json|~?/?\.kube/config|/etc/(passwd|shadow)|~?/?\.config/gh/hosts\.yml|~?/?\.claude\.json|"
    r"credentials(\.json)?\b)", _I)
# SW-SKL-012 only
MORE_SECRET_PATHS = re.compile(r"(~?/?\.gnupg/|~?/?\.password-store|\.pem\b|\.p12\b|keychain)", _I)

# SW-SKL-005
AGENT_CONFIG_PATHS = re.compile(
    r"(\.claude/settings(\.local)?\.json|~?/?\.claude\.json|\.claude/hooks|\.mcp\.json|\.cursor/mcp\.json|\.vscode/mcp\.json|"
    r"\.codex/config\.toml|\.gemini/settings\.json|claude_desktop_config\.json)", _I)
