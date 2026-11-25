"""SW-SKL-038: writes to an agent's memory or instruction files.

Read over every text file of a skill package, and of an instruction file when the scan kind is `instructions`, one logical
command at a time (`skill.logical_commands`: a line that ends in a backslash is joined to the next) and one sentence at a time
(a sentence ends at `.`, `!` or `?` followed by white space). A sentence fires when all of these hold:

* it names a memory or instruction file (`patterns.AGENT_MEMORY_PATHS`: `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`,
  the rule folders, a `MEMORY.md` and the memory folder of a Claude project);
* it holds a persisting write: SW-SKL-005's verbs (`>>`, `tee`, `sed -i`, `write_text`, "append to",
  "update", ...) or `save`, `store`, `persist`, `insert`, `record`, `remember` and the bare `add`, `append`, `write`, `put` ("Add \"...\" to `CLAUDE.md`");
* the words the write puts into the file hold a standing directive (`always`, `never`, `from now on`, `going forward`, `in
  every future session`, `permanently`, `every time`, `whenever`, `do not tell`, `without asking`, `silently`). The words
  put into the file are: every quoted text of the sentence; the part of the sentence after `that`, `saying` or a colon that
  follows the verb; the body of `echo` and `printf`; the lines of a heredoc that follows; and the lines of a fenced block that
  follows a sentence ending in a colon. A directive word that says when the write happens ("Always update `CLAUDE.md` when you
  add a command", "Whenever you change the API, update `AGENTS.md`") is not among them.

It is quiet when the sentence has a prohibition before the verb ("Never edit `AGENTS.md`"); when the same text file has
approval language anywhere ("ask the user", "approval", "confirm", "with the user's permission", "--dry-run", ...), read outside
the words the file's writes put into the memory file and not counting a negated one ("without asking the user", "never ask for
permission", "skip confirmation", "auto-approve"; two negations cancel); and in a
file written for people (README, INSTALL, CONTRIBUTING, CHANGELOG and anything below `docs/`), which tells a person what to add
to their own file and which an agent does not load as instructions. A heredoc or fenced block longer than `_BODY_LINES` lines
is not read to its end: the sentence that opens it fires, and its evidence says so first, before the line it quotes, so a long
line cannot cut the notice off (the limits rule: content left unread never looks like a pass). The bodies are judged from one
pass over the file's lines (`_Following`), never by reading them again for each write. The rule has no cap of its own: `run_rules` keeps at most `max_per_rule` findings and counts the rest.
Each finding is at the line of the logical command, once per line, and quotes that line. Every line of every text file is read
through `unit.lines`, so the scan's time limit applies to the rule. The module is registered by the rule set, not here."""
from __future__ import annotations

import bisect
import functools
import re
from collections.abc import Iterator

from spellwarden_scan.evidence import bounded_evidence, fingerprint
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.package import Package
from spellwarden_scan.rules import patterns as P

RULE_ID = "SW-SKL-038"
TITLE = "Writes to an agent's memory or instruction files"
SEVERITY = "medium"
OWASP = ("ASI06", "MCP10")
NIST = ("SI-7",)
ATLAS = ("AML.T0080.000",)
OWASP_AST = ("AST03",)
MALICIOUS = False

_I = re.IGNORECASE
_BODY_LINES = 200

_SENTENCE = re.compile(r"(?<=[.!?])\s+")
# Quoted text, which is content and never a verb or a prohibition: "...", the same in curly double quotes, and '...' that is not an apostrophe.
_QUOTED = re.compile("\"[^\"\\n]*\"|\u201c[^\u201d\\n]*\u201d|(?<!\\w)'[^'\\n]*'(?!\\w)")
_EXTRA_VERBS = re.compile(r"\b(?:save|store|persist|insert|record|remember|add|append|write|put)\b", _I)
_PROHIBITION = re.compile(
    r"\b(?:never|do not|don['\u2019]t|must not|mustn['\u2019]t|should not|shouldn['\u2019]t|cannot|can['\u2019]t|not to|avoid|refuse to)\b", _I)
_DIRECTIVE = re.compile(
    r"\b(?:always|never|from now on|going forward|in every (?:future |later |new )?(?:session|conversation|task)s?|permanent(?:ly)?|"
    r"every time|whenever|(?:do not|don['\u2019]t) (?:tell|mention|ask)|without (?:asking|telling)|silently)\b", _I)
_INTRODUCER = re.compile(r"\bthat\b|\bsaying\b|:(?=\s|$)|\b(?:with|using) the (?:text|lines?|rules?|instructions?|notes?)\b", _I)
_ECHO = re.compile(r"\b(?:echo|printf)\b([^|>]*)", _I)
_HEREDOC = re.compile(r"<<-?\s*(?:'([^'\n]+)'|\"([^\"\n]+)\"|([A-Za-z_]\w*))")
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
_APPROVAL = re.compile(
    r"\bask(?:s|ing)? (?:the |your |their )?user\b|\bapprov(?:e|es|ed|al)\b|\bconfirm|\bask(?:s|ing)? for (?:their |the user's |your )?permission\b|"
    r"\bwith (?:the user's|your|their) permission\b|\bpropos(?:e|es|ed|al)\b|\bsuggest\w*\b[^.\n]{0,60}\bchanges?\b|"
    r"\bshow(?:s|ing)? the user\b|\bshow the diff\b|\bonly if the user\b|\bon request\b|"
    r"\bif the user (?:asks|wants|requests)\b|--dry-run", _I)
# A word that turns the approval language after it into its opposite: "without asking the user", "never ask for permission",
# "skip confirmation", "auto-approve". Two of them cancel ("never write without approval" is a gate), so the approval words
# count when an even number of these stand before them in the same clause.
_NEGATOR = re.compile(r"\b(?:never|without|not|no|cannot|skip\w*|bypass\w*|avoid\w*)\b|n['\u2019]t\b|\bauto-", _I)
_CLAUSE_END = ".!?;:,\n"
_CLAUSE_REACH = 80
_HUMAN_FACING = re.compile(r"(?:^|/)(?:readme|install|installation|contributing|changelog)[^/]*$|(?:^|/)docs/", _I)


@functools.cache
def _verb_matchers() -> tuple:
    """SW-SKL-005's write verbs, one matcher each, and the persisting verbs of this rule, loaded on first use: `rules.skill`
    imports this module."""
    from spellwarden_scan.rules.skill import _WRITE_VERB

    return (*_WRITE_VERB.matchers, _EXTRA_VERBS)


def _verb_at(sentence: str) -> int | None:
    """The offset of the first persisting write in the sentence, or None."""
    starts = [match.start() for matcher in _verb_matchers() if (match := matcher.search(sentence)) is not None]
    return min(starts) if starts else None


def _blanked(sentence: str) -> str:
    """The sentence with every quoted text and the body of `echo` or `printf` replaced by spaces of their length, so that a
    prohibition word inside the text a command writes is not read as a prohibition, and offsets stay the sentence's own."""
    text = _QUOTED.sub(lambda match: " " * len(match.group(0)), sentence)
    return _ECHO.sub(lambda match: match.group(0)[:match.start(1) - match.start()] + " " * len(match.group(1)), text)


def _content(sentence: str, outside: str, verb_at: int) -> str:
    """The words the sentence puts into the file: its quoted texts, the part after an introducer that follows the verb, and
    the body of `echo` or `printf`."""
    parts = [match.group(0)[1:-1] for match in _QUOTED.finditer(sentence)]
    introducer = _INTRODUCER.search(outside, verb_at)
    if introducer is not None:
        parts.append(sentence[introducer.end():])
    echo = _ECHO.search(sentence)
    if echo is not None:
        parts.append(sentence[echo.start(1):echo.end(1)])
    return " ".join(parts)


def _without_content(sentence: str, outside: str, verb_at: int) -> str:
    """The sentence without the words it puts into the file (those `_content` reads): the text after the introducer, the quoted
    texts and the body of `echo` or `printf`. What is left can still hold a step that asks a person."""
    introducer = _INTRODUCER.search(outside, verb_at)
    text = sentence if introducer is None else sentence[:introducer.end()]
    text = _QUOTED.sub(" ", text)
    return _ECHO.sub(lambda match: match.group(0)[:match.start(1) - match.start()], text)


def _asks_a_person(text: str) -> bool:
    """Whether the text holds approval language that is not negated (`_NEGATOR`): "ask the user" counts, "without asking the user"
    and "never ask for permission" do not, and "never write without approval" does. Only the 80 characters of the clause before a
    match are read, so a long line without a clause end is read in linear time."""
    for match in _APPROVAL.finditer(text):
        start = max(0, match.start() - _CLAUSE_REACH)
        cut = max(text.rfind(char, start, match.start()) for char in _CLAUSE_END)
        if len(_NEGATOR.findall(text, max(cut + 1, start), match.start())) % 2 == 0:
            return True
    return False


def _opens_body(sentence: str) -> tuple[str, str | None] | None:
    """How a sentence that writes to a memory file hands over its content on the lines that follow: `("heredoc", delimiter)`,
    `("fence", None)` for a sentence ending in a colon, or None."""
    heredoc = _HEREDOC.search(sentence)
    if heredoc is not None:
        return "heredoc", next(group for group in heredoc.groups() if group)
    if sentence.rstrip().endswith(":"):
        return "fence", None
    return None


class _Following:
    """The lines of one text file, read once on first use, for the bodies that writes hand over: for each line, the next line
    that holds a standing directive; the lines of each stripped text (where a heredoc ends); and the lines that hold only
    backticks or only tildes (where a fenced block may end). A body is then judged without reading its lines again, so a file
    of many writes that open bodies over the same lines is still read in linear time."""

    def __init__(self, lines: tuple[str, ...]) -> None:
        texts = list(lines)  # one pass through `Lines`, so the scan's time limit applies
        self.count = len(texts)
        self.directive = [self.count] * (self.count + 1)
        self.stripped: dict[str, list[int]] = {}
        self.fences: dict[str, list[tuple[int, int]]] = {"`": [], "~": []}
        for index, line in enumerate(texts):
            text = line.strip()
            self.stripped.setdefault(text, []).append(index)
            if len(text) >= 3 and text[0] in self.fences and not text.strip(text[0]):
                self.fences[text[0]].append((index, len(text)))
        for index in range(self.count - 1, -1, -1):
            self.directive[index] = index if _DIRECTIVE.search(texts[index]) else self.directive[index + 1]

    def next_stripped(self, text: str, start: int) -> int:
        """The least index from `start` of a line whose stripped text is `text`, or the number of lines."""
        indices = self.stripped.get(text, [])
        at = bisect.bisect_left(indices, start)
        return indices[at] if at < len(indices) else self.count

    def next_fence(self, char: str, length: int, start: int, stop: int) -> int:
        """The least index in `[start, stop)` of a line of only `char` at least `length` long, or `stop`."""
        entries = self.fences[char]
        at = bisect.bisect_left(entries, (start, 0))
        while at < len(entries) and entries[at][0] < stop:
            if entries[at][1] >= length:
                return entries[at][0]
            at += 1
        return stop


def _body_has_directive(lines: tuple[str, ...], following: _Following, start: int, kind: str,
                        delimiter: str | None) -> tuple[bool, bool, int]:
    """`(directive found, cut, end)` for the lines after index `start` that are the body of a heredoc (up to its delimiter line) or of
    a fenced block (the next non-blank line must open a fence; the body runs to its closing fence). At most `_BODY_LINES` lines
    are read; `cut` is true when that stopped the read before the end of the body; `end` is the index where the body, as far as it was
    read, ends (`start` when no body follows). The body's lines are not read here: `following` knows where the next directive and
    the end of the body are."""
    index = start
    fence = None
    if kind == "fence":
        while index < len(lines) and not lines[index].strip():
            index += 1
        opener = _FENCE.match(lines[index]) if index < len(lines) else None
        if opener is None:
            return False, False, start
        fence = opener.group(1)
        index += 1
    stop = min(index + _BODY_LINES, following.count)
    end = (following.next_stripped(delimiter, index) if kind == "heredoc"
           else following.next_fence(fence[0], len(fence), index, stop))
    if following.directive[index] < min(end, stop):
        return True, False, min(end, stop)
    if end < stop:
        return False, False, end
    return False, index + _BODY_LINES <= following.count, stop


def detect(package: Package) -> Iterator[Finding]:
    # Imported here, not at the top: rules/skill.py imports this module to register it (import cycle).
    from spellwarden_scan.rules.skill import logical_commands

    for unit in package.text_files:
        if _HUMAN_FACING.search(unit.path):
            continue
        following: _Following | None = None
        items = list(logical_commands(unit))
        lines = unit.lines
        findings: list[Finding] = []
        rewritten: dict[int, str] = {}  # line index -> the command that starts there, without the content its writes put in the file
        covered: list[tuple[int, int]] = []  # line index ranges that are the content of a write, or the rest of a command
        for index, (path, number, command) in enumerate(items):
            if P.AGENT_MEMORY_PATHS.search(command) is None:
                continue
            after = (items[index + 1][1] if index + 1 < len(items) else len(lines) + 1) - 1  # the index of the next line
            sentences = _SENTENCE.split(command)
            parts = list(sentences)
            fired = False
            for position, sentence in enumerate(sentences):
                if P.AGENT_MEMORY_PATHS.search(sentence) is None:
                    continue
                outside = _blanked(sentence)
                verb_at = _verb_at(sentence)
                if verb_at is None:
                    continue
                prohibition = _PROHIBITION.search(outside)
                if prohibition is not None and prohibition.start() < verb_at:
                    continue
                fires = _DIRECTIVE.search(_content(sentence, outside, verb_at)) is not None
                shown = command
                body_end = after
                opens = _opens_body(sentence)
                if opens is not None:
                    if following is None:
                        following = _Following(lines)
                    found, cut, body_end = _body_has_directive(lines, following, after, *opens)
                    if not fires:
                        fires = found
                        if cut:
                            fires = True
                            shown = f"[the text it writes is longer than {_BODY_LINES} lines and was not read to its end] {command}"
                if not fires:
                    continue
                parts[position] = _without_content(sentence, outside, verb_at)
                covered.append((after, body_end))
                if not fired:
                    findings.append(Finding(RULE_ID, SEVERITY, TITLE, Location(path, number), bounded_evidence(shown),
                                            fingerprint(RULE_ID, path, command), MALICIOUS))
                    fired = True
            if fired:
                rewritten[number - 1] = " ".join(parts)
                covered.append((number, after))
        if not findings:
            continue
        # The approval gate reads the file as it is, less the words the writes put into the file: an instruction to push "without
        # asking the user" is the directive the rule is after, and it must not silence the rule.
        texts = list(lines)
        for line, text in rewritten.items():
            texts[line] = text
        depth = [0] * (len(texts) + 1)
        for first, last in covered:
            depth[first] += 1
            depth[min(last, len(texts))] -= 1
        running = 0
        for line in range(len(texts)):
            running += depth[line]
            if running > 0:
                texts[line] = ""
        if not _asks_a_person("\n".join(texts)):
            yield from findings
