"""SW-SKL-033: skill drives the user's own signed-in browser over a remote-debugging port.

Read over the Markdown files and the scripts (`.js`, `.mjs`, `.ts`, `.py`, `.ps1`, `.sh`) of a skill package. Two paths:

* attach: text that turns remote debugging on in the user's running browser (`chrome://inspect/#remote-debugging`,
  "Allow remote debugging"), code that reads `DevToolsActivePort` next to a default browser profile directory, or a launch
  with `--remote-debugging-port` that names no profile of its own (`--profile-directory`, `Default` included, names a
  profile inside the user data directory: it is the user's own only when no dedicated `--user-data-dir` is given). It fires only when the same file, or the skill's
  SKILL.md, says the point is to reuse the user's identity ("your existing Chrome", "already logged in", ...);
* clone: a default profile root (Chrome, Edge or Brave under the user's home) used as the source of a recursive copy, or as
  the user data directory, in a skill that also launches with a debugging port or a persistent context.

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
_TOGGLES = ("chrome://inspect/#remote-debugging", "allow remote debugging")
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
                     "don't launch your own browser", "do not launch a new browser", "don't launch a new browser")
_IDENTITY_OWNED = re.compile(
    r"\b(?:your|the user's)\s+(?:existing|running|real|everyday|actual|regular|normal|daily|personal)\s+"
    r"(?:google\s+)?(?:chrome|chromium|browser|edge|brave)\b")
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
            else:
                continue
            if hit and not self.quiet(index) and not self.optional_attach(index):
                yield index

    def clone_steps(self) -> Iterator[int]:
        if not self.gate:
            return
        for index, low in enumerate(self.low):
            if self.quiet(index):
                continue
            if _copies(low) or (_calls_recursive_copy(low) and any(
                    "recursive" in self.low[i] for i in range(max(0, index - 2), min(len(self.low), index + 3)))):
                if self.root_near(index - _NEAR_COPY, index + _NEAR_COPY):
                    yield index
            elif any(name in low for name in _USER_DATA_NAMES + ("launchpersistentcontext", "launch_persistent_context")):
                if self.roots(index) or self.root_near(index - _NEAR_USER_DATA, index - 1):
                    yield index
            elif any(flag in low for flag in _USER_DATA_FLAG) and self.roots(index):
                yield index


def _has_identity_intent(text: str) -> bool:
    return any(phrase in text for phrase in _IDENTITY_PHRASES) or _IDENTITY_OWNED.search(text) is not None


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
