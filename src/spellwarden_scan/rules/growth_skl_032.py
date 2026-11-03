"""SW-SKL-032: instructions lure the user into running a password-protected download or a pasted script.

Three lures are read over the Markdown files of a skill package (SKILL.md, references, fenced blocks):

* an archive lure: within one line or a short run of up to three consecutive lines, a link to an archive or an
  executable, an extraction password written right next to a short literal, and a verb that runs the download;
* a paste-site lure: a URL on a snippet or paste host within three lines of a copy or paste instruction and a
  terminal word;
* an encoded one-liner: `echo '<base64>' | base64 -d | bash` whose decoded text pipes a remote fetch to a shell. SW-SKL-004
  reports the same line on purpose: it names the decode-and-run, this rule the lure around it.

Each lure is reported once, at its first line. A section whose heading names indicators or IOCs lists lures rather
than being one, and is skipped; no other word silences a lure. Only lines within one window of an http(s) URL or a paste
host are analysed. Everything is a plain string scan or an anchored, unambiguous pattern, so a long line is read in linear
time. The module is registered by the rule set, not here."""
from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator

from spellwarden_scan.evidence import excerpt, fingerprint
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.package import CodeBlock, Package, TextFile

RULE_ID = "SW-SKL-032"
TITLE = "Instructions lure the user into running a password-protected download or a pasted script"
SEVERITY = "critical"
OWASP = ("ASI04", "ASI09")
NIST = ("SR-3", "SI-3")
MALICIOUS = True

_WINDOW = 3  # a lure is one line or up to this many consecutive lines
_ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar", ".exe", ".msi", ".dmg", ".pkg")
_RELEASE_DOWNLOAD = "/releases/download/"
_PASTE_HOSTS = ("glot.io", "pastebin.com", "rentry.co", "paste.ee", "hastebin.com", "justpaste.it", "controlc.com")
_RUN_VERBS = frozenset({"run", "runs", "running", "execute", "executes", "executing", "open", "opens", "launch", "launches",
                        "install", "installs", "installing"})
_PASTE_VERBS = frozenset({"copy", "copies", "copied", "paste", "pasted", "pasting"})
_TERMINAL_WORDS = frozenset({"terminal", "powershell", "cmd"})
# Only a heading that names indicators or IOCs makes its section a list of lures rather than a lure (Fable review F1):
# words such as detect or block cost an author nothing to add to a real lure, so they never silence one.
_INDICATOR_WORDS = frozenset({"indicator", "indicators", "ioc", "iocs"})
_NOT_A_PASSWORD = frozenset({"ok", "yes", "no", "none", "true", "false", "fail", "failed", "pass", "passed", "n/a", "na"})
_EXTRACT_LEAD_INS = ("extract using ", "extract with ", "unzip using ", "unzip with ", "unpack using ", "unpack with ",
                     "extract it using ", "extract it with ")
_LITERAL_MAX = 32
_LITERAL_PREFIX = "*`\"'("
_SPLIT_URL = re.compile(r"[\s()\[\]<>\"'`]+")
_WORDS = re.compile(r"[a-z]+")
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]+")
_TOKEN_SPLIT = re.compile(r"[\s'\"`;|&()<>]+")
_CANDIDATE_MIN = 16
_CANDIDATE_MAX = 1 << 16
_CANDIDATES_PER_COMMAND = 16


def _words(text: str) -> frozenset[str]:
    return frozenset(_WORDS.findall(text.lower()))


def _url_tokens(line: str) -> Iterator[str]:
    for token in _SPLIT_URL.split(line):
        if token:
            yield token


def _has_archive_link(line: str) -> bool:
    for token in _url_tokens(line):
        low = token.lower()
        if not low.startswith(("http://", "https://")):
            continue
        path = low.split("#", 1)[0].split("?", 1)[0].rstrip(".,;:!*")
        if path.endswith(_ARCHIVE_SUFFIXES) or _RELEASE_DOWNLOAD in path:
            return True
    return False


def _paste_host(token: str) -> bool:
    low = token.lower()
    if "://" in low:
        low = low.split("://", 1)[1]
    host, slash, _path = low.partition("/")
    if not slash:
        return False
    host = host.rsplit("@", 1)[-1].split(":", 1)[0]
    return any(host == known or host.endswith("." + known) for known in _PASTE_HOSTS)


def _has_paste_link(line: str) -> bool:
    return any(_paste_host(token) for token in _url_tokens(line))


def _literal_span(low: str, start: int) -> tuple[str, int]:
    """`(literal, stop)`: the short literal at `start` (after spaces and quote marks), or "", and where its raw text
    ends."""
    end = len(low)
    while start < end and low[start] in " \t":
        start += 1
    while start < end and low[start] in _LITERAL_PREFIX:
        start += 1
    stop = start
    limit = min(end, start + _LITERAL_MAX + 1)
    while stop < limit and not low[stop].isspace():
        stop += 1
    literal = low[start:stop].rstrip("*`\"'),.;")
    if not literal or len(literal) > _LITERAL_MAX or "://" in literal or literal in _NOT_A_PASSWORD:
        return "", stop
    return literal, stop


def _literal_after(low: str, start: int) -> str:
    """The short literal at `start` (after spaces and quote marks), or "" when there is none."""
    return _literal_span(low, start)[0]


# An extraction password written without the word "pass": `(extract using: <word>)`. The literal must close the
# parenthesis, clause or line, and must not be an archive tool's name (`Extract with: 7-Zip` names a tool).
_EXTRACT_KEYS = ("extract using", "extract with", "extract it using", "extract it with", "unzip using", "unzip with",
                 "unpack using", "unpack with")
_ARCHIVE_TOOLS = frozenset({"7-zip", "7zip", "7z", "winrar", "rar", "unrar", "unzip", "zip", "tar", "bsdtar", "gzip",
                            "gunzip", "peazip", "bandizip", "winzip", "keka", "ark"})


def _bare_extract_password(low: str) -> bool:
    content_end = len(low.rstrip(" \t*_"))
    for key in _EXTRACT_KEYS:
        index = low.find(key)
        while index != -1:
            before = low[index - 1] if index else " "
            sign = index + len(key)
            while sign < len(low) and low[sign] in " \t":
                sign += 1
            if not (before.isalnum()) and sign < len(low) and low[sign] in ":=":
                literal, stop = _literal_span(low, sign + 1)
                if literal and literal not in _ARCHIVE_TOOLS and (stop >= content_end or low[stop - 1] in "),;."):
                    return True
            index = low.find(key, index + len(key))
    return False


def _has_password(line: str) -> bool:
    """`pass:`/`password:`, `extract using pass` or `extract using:` right before a short literal. `--pass`, `--password-file`, `bypass`
    and `passed` are other words; a bare `PASS`/`FAIL` verdict has no colon and no literal after it."""
    low = line.lower()
    index = low.find("pass")
    while index != -1:
        end = index + 4
        before = low[index - 1] if index else " "
        if not (before.isalnum() or before in "-_"):
            if low.startswith("word", end):
                end += 4
            after = low[end] if end < len(low) else " "
            if not (after.isalnum() or after in "-_"):
                lead = low[max(0, index - 20):index]
                sign = end
                while sign < len(low) and low[sign] in " \t":
                    sign += 1
                if sign < len(low) and low[sign] in ":=" and _literal_after(low, sign + 1):
                    return True
                if lead.endswith(_EXTRACT_LEAD_INS) and after in " \t" and _literal_after(low, end):
                    return True
        index = low.find("pass", index + 4)
    return _bare_extract_password(low)


class _Features:
    """What one line contributes to a window: computed once per line, so windows cost nothing."""

    __slots__ = ("archive", "password", "run", "paste_link", "paste_verb", "terminal")

    def __init__(self, line: str | None) -> None:
        if line is None:  # a line no lure window can reach: it contributes nothing
            self.archive = self.password = self.run = self.paste_link = self.paste_verb = self.terminal = False
            return
        words = _words(line)
        self.archive = _has_archive_link(line)
        self.password = _has_password(line)
        self.run = bool(words & _RUN_VERBS)
        self.paste_link = _has_paste_link(line)
        self.paste_verb = bool(words & _PASTE_VERBS)
        self.terminal = bool(words & _TERMINAL_WORDS)


def _anchor(line: str) -> bool:
    """A line that may hold an archive link (it needs an http(s) URL) or a paste link (it needs a paste host)."""
    low = line.lower()
    return "://" in low or any(host in low for host in _PASTE_HOSTS)


def _met(window: list[_Features], needs: tuple[tuple[str, ...], ...]) -> bool:
    return all(any(getattr(item, name) for item in window for name in group) for group in needs)


def _windows(features: list[_Features], headings: list[bool], needs: tuple[tuple[str, ...], ...], touch: tuple[str, ...]
             ) -> Iterator[tuple[int, int]]:
    """`(first index, size)` of each lure: the smallest window, at most `_WINDOW` lines, in which every group of `needs`
    is met by some line, that starts on a line that itself contributes (one of `touch`) and where neither the window nor
    its heading is an indicator list. A reported window is consumed."""
    index = 0
    count = len(features)
    while index < count:
        first = features[index]
        if not any(getattr(first, name) for name in touch):
            index += 1
            continue
        for size in range(1, _WINDOW + 1):
            window = features[index:index + size]
            if len(window) < size:
                break
            if _met(window, needs):
                if size > 1 and _met(window[1:], needs):
                    break  # the lure starts on a later line: that start reports it
                if not headings[index]:
                    yield index, size
                    index += size - 1
                break
        index += 1


def _lure_windows(lines: tuple[str, ...]) -> Iterator[tuple[int, int]]:
    # Every lure window holds an archive or paste link, so only lines within one window of a link are analysed; the
    # others contribute nothing (most lines of a large package), which keeps the rule cheap.
    near = [False] * len(lines)
    for index, line in enumerate(lines):
        if _anchor(line):
            for at in range(max(0, index - _WINDOW + 1), min(len(lines), index + _WINDOW)):
                near[at] = True
    features = [_Features(line if near[index] else None) for index, line in enumerate(lines)]
    # The heading in force at each line names indicators or IOCs: the section lists lures, it is not one.
    headings: list[bool] = []
    indicator_heading = False
    for line in lines:
        if line.lstrip().startswith("#"):
            indicator_heading = bool(_words(line) & _INDICATOR_WORDS)
        headings.append(indicator_heading)
    archive = _windows(features, headings, (("archive",), ("password",), ("run",)), ("archive", "password", "run"))
    paste = _windows(features, headings, (("paste_link",), ("paste_verb",), ("terminal",)),
                     ("paste_link", "paste_verb", "terminal"))
    yield from archive
    yield from paste


def _base64_candidates(command: str) -> Iterator[bytes]:
    taken = 0
    for token in _TOKEN_SPLIT.split(command):
        if not _CANDIDATE_MIN <= len(token) <= _CANDIDATE_MAX or not _BASE64_TOKEN.fullmatch(token):
            continue
        taken += 1
        if taken > _CANDIDATES_PER_COMMAND:
            return
        padded = token + "=" * (-len(token) % 4)
        try:
            yield base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
        except (binascii.Error, ValueError):
            continue


def _encoded_one_liners(package: Package) -> Iterator[tuple[str, int, str]]:
    # Imported here: rules/skill.py imports this module when the rule is registered, so a top-level import would cycle.
    from spellwarden_scan.rules.skill import decodes_and_runs, logical_commands, pipes_remote_to_shell

    fenced = {(block.path, block.first_line + offset) for block in package.code_blocks for offset in range(len(block.lines))}
    for unit in (*package.instructions(), *package.code_blocks):
        prose = isinstance(unit, TextFile)
        commands = (entry for entry in logical_commands(unit) if not (prose and (entry[0], entry[1]) in fenced))
        for path, number, command in decodes_and_runs(commands):
            for decoded in _base64_candidates(command):
                text = decoded.decode("utf-8", errors="replace")
                shell = CodeBlock(path, "sh", text, number)
                if any(True for _ in pipes_remote_to_shell(logical_commands(shell))):
                    yield path, number, command
                    break


def _finding(path: str, line: int, matched: str) -> Finding:
    return Finding(RULE_ID, SEVERITY, TITLE, Location(path, line), excerpt(matched), fingerprint(RULE_ID, path, matched), MALICIOUS)


def detect(package: Package) -> Iterator[Finding]:
    reported: set[tuple[str, int]] = set()
    for file in package.instructions():
        found = sorted(_lure_windows(file.lines))
        for index, size in found:
            if (file.path, index + 1) in reported:
                continue
            reported.add((file.path, index + 1))
            yield _finding(file.path, index + 1, "\n".join(file.lines[index:index + size]))
    for path, number, command in _encoded_one_liners(package):
        if (path, number) in reported:
            continue
        reported.add((path, number))
        yield _finding(path, number, command)
