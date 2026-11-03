"""SW-SKL-033: skill drives the user's own signed-in browser over a remote-debugging port.

Read over the Markdown files and the scripts (`.js`, `.mjs`, `.ts`, `.py`, `.ps1`, `.sh`) of a skill package. Two paths:

* attach: text that turns remote debugging on in the user's running browser (the `inspect/#remote-debugging` page in any
  browser scheme, `chrome://`, `brave://`, `edge://` or a templated `${browser}://`, with or without the slash after
  `inspect`; "Allow remote debugging"), `chrome-devtools-mcp` started with `--auto-connect` (or `--autoConnect`) when it
  names no profile of its own, a Chinese line that says the skill connects through CDP to the user's everyday browser
  (`日常浏览器`) unless it is negated, code that reads `DevToolsActivePort` next to a default browser profile directory, or a
  launch with `--remote-debugging-port` that names no profile of its own (`--profile-directory`, `Default` included, names a
  profile inside the user data directory: it is the user's own only when no dedicated `--user-data-dir` is given). It fires only when the same file, or the skill's
  SKILL.md, says the point is to reuse the user's identity ("your existing Chrome", "attach to existing Chrome", "日常浏览器", "already logged in", ...);
* clone: a default profile root (Chrome, Edge or Brave under the user's home) used as the source of a recursive copy, or as
  the user data directory, in a skill that also launches with a debugging port or a persistent context. In a script, a
  recursive copy with no root nearby is also followed one hop: its source is a root returned by a function (or kept in a
  variable assigned from one), or a parameter of the function that holds the copy while some call of that function passes
  such a root as that argument. No further recursion.

A dedicated or temporary profile folder, a headless test browser on localhost, an optional attach flag next to a
self-managed default browser, profile paths inside a regular expression or a deny list, and prose that describes the abuse
do not fire. One finding per file, at its first attach or copy step. Everything is a plain string scan or a bounded
pattern, so a long line is read in linear time. The module is registered by the rule set, not here."""
from __future__ import annotations

import re
from collections.abc import Iterator

from spellwarden_scan.evidence import excerpt, fingerprint
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.package import Package, TextFile

RULE_ID = "SW-SKL-033"
TITLE = "Skill drives the user's own signed-in browser over a remote-debugging port"
SEVERITY = "high"
OWASP = ("ASI03",)
NIST = ("AC-6", "IA-5")
MALICIOUS = False

_SUFFIXES = (".md", ".js", ".mjs", ".ts", ".py", ".ps1", ".sh")
# Default profile roots, written with `/` and in lower case (see `_normal`). A match must not continue into a longer
# name: `.config/google-chrome-agent` is a folder of its own.
_ROOTS = ("application support/google/chrome", ".config/google-chrome", "google/chrome/user data",
          "microsoft/edge/user data", "bravesoftware")
_JOIN = re.compile(r"""["'`]\s{0,3}[,/]\s{0,3}["'`]""")  # "a", "b" and "a" / "b" as path segments
_WORD = re.compile(r"[a-z']+")
_PORT = "--remote-debugging-port"
_TOGGLES = ("://inspect/#remote-debugging", "://inspect#remote-debugging", "allow remote debugging")
_CDP_WORD = re.compile(r"(?<![a-z])cdp(?![a-z])")
_OWNED_BROWSER_CJK = ("日常浏览器",)  # the user's everyday browser
_CJK_NEGATION = ("不要", "禁止", "切勿", "不得", "避免", "不会")  # do not, forbidden, never, must not, avoid, will not
_AUTO_CONNECT = ("--auto-connect", "--autoconnect")
_DEVTOOLS_PORT_FILE = "devtoolsactiveport"
_USER_DATA_FLAG = ("--user-data-dir", "user-data-dir=")
_USER_DATA_NAMES = ("userdatadir", "user_data_dir")
_PERSISTENT = ("launchpersistentcontext", "launch_persistent_context", "persistent context", "persistent_context")
_COPY_CALLS = ("copytree(", "cp_r(", "copy_tree(", "fse.copy(")
_RECURSIVE_COPY_CALLS = ("cpsync(", "fs.cp(", "fs.promises.cp(")
_COPY_COMMANDS = frozenset({"cp", "rsync"})
_ROBOCOPY_RECURSIVE = frozenset({"/e", "/mir"})
_IDENTITY_PHRASES = ("logged-in", "logged in", "signed-in", "signed in", "existing session", "existing login",
                     "already-running chrome", "already running chrome", "do not launch your own browser",
                     "don't launch your own browser", "do not launch a new browser", "don't launch a new browser", "日常浏览器")
_IDENTITY_OWNED = re.compile(
    r"\b(?:your|the user's)\s+(?:existing|running|real|everyday|actual|regular|normal|daily|personal)\s+"
    r"(?:google\s+)?(?:chrome|chromium|browser|edge|brave)\b")
_IDENTITY_ATTACH = re.compile(r"\battach(?:es|ing)?\s+to\s+(?:the\s+)?existing\s+(?:google\s+)?(?:chrome|edge|brave)\b")
_SELF_MANAGED = ("launches its own", "its own browser", "fresh profile", "temporary profile", "temp profile", "mkdtemp")
_DETECTION = frozenset({"detect", "detects", "detected", "detecting", "detection", "detector", "blocklist", "blocked",
                        "blocking", "deny", "denylist", "denied", "forbidden", "indicator", "indicators", "ioc", "iocs",
                        "regex", "regexp", "pattern", "patterns"})
_CAUTION = frozenset({"attacker", "attackers", "malicious", "malware", "abuse", "abused", "abuses", "threat", "threats",
                      "never", "avoid", "warning"})
_REGEX_CUES = ("re.compile", "new regexp", "(?:")
_NEAR_ROOT = 3  # lines around a profile path read for detection wording
_NEAR_LAUNCH = 3
_NEAR_COPY = 12
_NEAR_USER_DATA = 5
_MAX_ARGS = 400  # characters of a call read for its arguments
_MAX_CALLS = 200  # call sites of one function looked at
_NAME = r"[a-z_$][\w$]*"
_DEF_PATTERNS = (
    re.compile(rf"\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*({_NAME})\s*\(([^)]*)\)"),
    re.compile(rf"\s*(?:export\s+)?(?:const|let|var)\s+({_NAME})\s*=\s*(?:async\s*)?(?:\(([^)]*)\)|({_NAME}))\s*=>"),
    re.compile(rf"\s*(?:async\s+)?def\s+({_NAME})\s*\(([^)]*)\)"),
)
_ASSIGN = re.compile(rf"\s*(?:(?:const|let|var)\s+)?({_NAME})\s*=\s*(?:await\s+)?({_NAME}(?:\.{_NAME})*)\s*\(")
_CALL_EXPR = re.compile(rf"(?:await\s+)?({_NAME}(?:\.{_NAME})*)\s*\(")
_CALL_SITE = re.compile(rf"(?<![\w$.])({_NAME})\s*\(")
_IDENT = re.compile(_NAME)


def _normal(line: str) -> str:
    # `\\` in a string literal is one separator, as is a lone `\`
    low = line.lower().replace("’", "'").replace("\\\\", "/").replace("\\", "/")
    return _JOIN.sub("/", low)


def _roots_in(low: str) -> frozenset[str]:
    found = set()
    for root in _ROOTS:
        start = low.find(root)
        while start != -1:
            end = start + len(root)
            before = low[start - 1] if start else " "
            after = low[end] if end < len(low) else " "
            if not (before.isalnum() or before in "_-") and not (after.isalnum() or after in "_-"):
                found.add(root)
                break
            start = low.find(root, start + 1)
    return frozenset(found)


def _words(low: str) -> frozenset[str]:
    return frozenset(_WORD.findall(low))


def _copies(low: str) -> bool:
    """A recursive copy on this line (the `fs.cp` family also needs `recursive` nearby, checked by the caller)."""
    if any(call in low for call in _COPY_CALLS):
        return True
    tokens = low.split()
    recurse = "-recurse" in low  # once per line: a scan per `copy-item` token would be quadratic
    for index, token in enumerate(tokens):
        name = token.lstrip("\"'`(;&|$")
        following = tokens[index + 1:index + 7]
        if name in _COPY_COMMANDS:
            for flag in following:
                if not flag.startswith("-"):
                    break
                if flag in ("--recursive", "--archive") or (not flag.startswith("--") and any(c in "ra" for c in flag[1:])):
                    return True
        elif name == "robocopy" and any(flag in _ROBOCOPY_RECURSIVE for flag in following):
            return True
        elif name == "copy-item" and recurse:
            return True
    return False


def _calls_recursive_copy(low: str) -> bool:
    return any(call in low for call in _RECURSIVE_COPY_CALLS)


def _split_args(raw: str, open_paren: int) -> list[str]:
    """The top-level arguments of the call whose `(` is at `open_paren` (at most `_MAX_ARGS` characters are read)."""
    args, depth, quote, start = [], 0, "", open_paren + 1
    for pos in range(open_paren + 1, min(len(raw), open_paren + 1 + _MAX_ARGS)):
        char = raw[pos]
        if quote:
            quote = "" if char == quote else quote
        elif char in "\"'`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                args.append(raw[start:pos].strip())
                return args
            depth -= 1
        elif char == "," and depth == 0:
            args.append(raw[start:pos].strip())
            start = pos + 1
    return args


def _copy_source(raw: str) -> str:
    """The first argument of the recursive copy on this (lower-cased, raw) line, or an empty string."""
    found = [(raw.find(call), call) for call in _COPY_CALLS + _RECURSIVE_COPY_CALLS if call in raw]
    if found:
        pos, call = min(found)
        args = _split_args(raw, pos + len(call) - 1)
        return args[0] if args else ""
    tokens = raw.split()
    for index, token in enumerate(tokens):
        if token.lstrip("\"'`(;&|$") in _COPY_COMMANDS | {"robocopy", "copy-item"}:
            for following in tokens[index + 1:index + 7]:
                if not following.startswith("-"):
                    return following.strip("\"'`(){};$,")
            return ""
    return ""


class _Trace:
    """The functions of one script, indexed once: where each body is, and which of them return a default profile root."""

    def __init__(self, scan: _File) -> None:
        raw = [line.lower() for line in scan.lines]
        self.raw = raw
        self.names: list[str] = []
        self.params: list[list[str]] = []
        starts: list[int] = []
        ends: list[int] = []
        self.owner = [-1] * len(raw)
        stack: list[tuple[int, int]] = []  # (indent, def id)
        for index, line in enumerate(raw):
            found = self._definition(line) if ("function" in line or "def " in line or "=>" in line) else None
            if found is not None:
                indent = len(line) - len(line.lstrip())
                while stack and stack[-1][0] >= indent:
                    ends[stack.pop()[1]] = index
                self.names.append(found[0])
                self.params.append(found[1])
                starts.append(index)
                ends.append(len(raw))
                stack.append((indent, len(self.names) - 1))
            self.owner[index] = stack[-1][1] if stack else -1
        self.starts = frozenset(starts)
        rooted = [0]  # prefix count of the lines that name a root
        for index in range(len(raw)):
            rooted.append(rooted[-1] + (1 if scan.roots(index) else 0))
        self.root_funcs = frozenset(self.names[i] for i in range(len(self.names)) if rooted[ends[i]] - rooted[starts[i]])
        self.root_vars: set[str] = set()
        if self.root_funcs:
            for line in raw:
                if "=" in line:
                    match = _ASSIGN.match(line)
                    if match and match.group(2) in self.root_funcs:
                        self.root_vars.add(match.group(1))
        self._calls: dict[str, list[tuple[int, int]]] | None = None
        self._scan = scan

    @staticmethod
    def _definition(line: str) -> tuple[str, list[str]] | None:
        for pattern in _DEF_PATTERNS:
            match = pattern.match(line)
            if match:
                params = match.group(2) if match.group(2) is not None else (match.group(3) or "") if pattern.groups >= 3 else ""
                names = []
                for param in params.split(","):
                    found = _IDENT.search(param.strip().lstrip("*."))
                    names.append(found.group(0) if found else "")
                return match.group(1), names
        return None

    def _is_root(self, expr: str, line: int | None = None) -> bool:
        """The argument is a variable assigned from a root function, a call of one, or (on a root-naming line) names a root."""
        if _IDENT.fullmatch(expr):
            return expr in self.root_vars
        call = _CALL_EXPR.match(expr)
        if call and call.group(1) in self.root_funcs:
            return True
        return line is not None and bool(self._scan.roots(line)) and bool(_roots_in(_normal(expr)))

    def _call_sites(self) -> dict[str, list[tuple[int, int]]]:
        if self._calls is None:
            known = set(self.names)
            self._calls = {}
            for index, line in enumerate(self.raw):
                if index in self.starts or "(" not in line:
                    continue
                for match in _CALL_SITE.finditer(line):
                    if match.group(1) in known:
                        sites = self._calls.setdefault(match.group(1), [])
                        if len(sites) < _MAX_CALLS:
                            sites.append((index, match.end() - 1))
        return self._calls

    def copies_root(self, index: int) -> bool:
        """The copy on this line takes its source from a root: returned by a function, or passed in by a caller."""
        source = _copy_source(self.raw[index])
        if not source:
            return False
        if self._is_root(source):
            return True
        owner = self.owner[index]
        if owner < 0 or source not in self.params[owner]:
            return False
        position = self.params[owner].index(source)
        for line, paren in self._call_sites().get(self.names[owner], ()):
            args = _split_args(self.raw[line], paren)
            if position < len(args) and self._is_root(args[position], line):
                return True
        return False


class _File:
    """One scanned file: its lines normalised once, and the per-line judgements computed on demand."""

    def __init__(self, source: TextFile, skill_intent: bool, gate: bool, self_managed: bool) -> None:
        self.source = source
        self.lines = source.lines
        self.low = [_normal(line) for line in self.lines]
        self.gate = gate
        self.self_managed = self_managed
        self.intent = skill_intent or _has_identity_intent(" ".join(source.text.lower().replace("’", "'").split()))
        self._words: dict[int, frozenset[str]] = {}
        self._roots: dict[int, frozenset[str]] = {}
        self._trace: _Trace | None = None
        self._heading_quiet = self._headings() if source.path.lower().endswith(".md") else [False] * len(self.lines)

    def words(self, index: int) -> frozenset[str]:
        if index not in self._words:
            self._words[index] = _words(self.low[index])
        return self._words[index]

    def _headings(self) -> list[bool]:
        quiet = False
        result = []
        for index, line in enumerate(self.lines):
            if line.lstrip().startswith("#"):
                quiet = bool(self.words(index) & (_DETECTION | _CAUTION))
            result.append(quiet)
        return result

    def quiet(self, index: int) -> bool:
        """The line only describes, lists or tests for what the rule looks for."""
        low = self.low[index]
        return (self._heading_quiet[index] or bool(self.words(index) & (_DETECTION | _CAUTION))
                or any(cue in low for cue in _REGEX_CUES)
                or ("|" in low and len(_roots_in(low)) > 1))

    def roots(self, index: int) -> frozenset[str]:
        """The default profile roots a line names, unless the line is a detection list entry."""
        if index not in self._roots:
            found = _roots_in(self.low[index])
            if found:
                lo, hi = max(0, index - _NEAR_ROOT), min(len(self.lines), index + _NEAR_ROOT + 1)
                if self.quiet(index) or any(self.words(i) & _DETECTION for i in range(lo, hi)):
                    found = frozenset()
            self._roots[index] = found
        return self._roots[index]

    def root_near(self, first: int, last: int) -> bool:
        return any(self.roots(i) for i in range(max(0, first), min(len(self.lines), last + 1)))

    def optional_attach(self, index: int) -> bool:
        return self.self_managed and any("optional" in w or "optionally" in w for i in range(max(0, index - 2), index + 1)
                                         for w in (self.words(i),))

    def default_launch(self, index: int) -> bool:
        lo, hi = max(0, index - _NEAR_LAUNCH), min(len(self.lines), index + _NEAR_LAUNCH + 1)
        near = self.low[lo:hi]
        if any("headless" in line for line in near) and any("localhost" in line or "127.0.0.1" in line for line in near):
            return False
        if any(flag in line for line in near for flag in _USER_DATA_FLAG + _USER_DATA_NAMES):
            return self.root_near(lo, hi - 1)
        return True

    def attach_steps(self) -> Iterator[int]:
        has_root = self.root_near(0, len(self.lines) - 1)
        for index, low in enumerate(self.low):
            if any(toggle in low for toggle in _TOGGLES):
                hit = True
            elif _DEVTOOLS_PORT_FILE in low:
                hit = has_root
            elif _PORT in low:
                hit = self.default_launch(index)
            elif "chrome-devtools" in low and any(flag in low for flag in _AUTO_CONNECT):
                hit = self.default_launch(index)
            elif _CDP_WORD.search(low) and any(name in low for name in _OWNED_BROWSER_CJK) and not any(
                    word in low for word in _CJK_NEGATION):
                hit = True
            else:
                continue
            if hit and not self.quiet(index) and not self.optional_attach(index):
                yield index

    def copies_traced_root(self, index: int) -> bool:
        """One hop, for scripts only: the copy's source arrives from a function that returns a root, or as its parameter."""
        if self.source.path.lower().endswith(".md"):
            return False
        if self._trace is None:
            self._trace = _Trace(self)
        return self._trace.copies_root(index)

    def clone_steps(self) -> Iterator[int]:
        if not self.gate:
            return
        for index, low in enumerate(self.low):
            if self.quiet(index):
                continue
            if _copies(low) or (_calls_recursive_copy(low) and any(
                    "recursive" in self.low[i] for i in range(max(0, index - 2), min(len(self.low), index + 3)))):
                if self.root_near(index - _NEAR_COPY, index + _NEAR_COPY) or self.copies_traced_root(index):
                    yield index
            elif any(name in low for name in _USER_DATA_NAMES + ("launchpersistentcontext", "launch_persistent_context")):
                if self.roots(index) or self.root_near(index - _NEAR_USER_DATA, index - 1):
                    yield index
            elif any(flag in low for flag in _USER_DATA_FLAG) and self.roots(index):
                yield index


def _has_identity_intent(text: str) -> bool:
    return (any(phrase in text for phrase in _IDENTITY_PHRASES) or _IDENTITY_OWNED.search(text) is not None
            or _IDENTITY_ATTACH.search(text) is not None)


def _finding(path: str, line: int, matched: str) -> Finding:
    return Finding(RULE_ID, SEVERITY, TITLE, Location(path, line), excerpt(matched), fingerprint(RULE_ID, path, matched), MALICIOUS)


def detect(package: Package) -> Iterator[Finding]:
    files = [f for f in package.text_files if f.path.lower().endswith(_SUFFIXES)]
    if not files:
        return
    lowered = [f.text.lower() for f in files]
    gate = any(_PORT in text or any(name in text for name in _PERSISTENT) for text in lowered)
    self_managed = any(phrase in text for text in lowered for phrase in _SELF_MANAGED)
    skill_intent = any(_has_identity_intent(" ".join(text.replace("’", "'").split()))
                       for f, text in zip(files, lowered, strict=True) if f.path.lower().rsplit("/", 1)[-1] == "skill.md")
    for source in files:
        scan = _File(source, skill_intent, gate, self_managed)
        steps = list(scan.clone_steps())
        if scan.intent:
            steps.extend(scan.attach_steps())
        if steps:
            line = min(steps)
            yield _finding(source.path, line + 1, source.lines[line])
