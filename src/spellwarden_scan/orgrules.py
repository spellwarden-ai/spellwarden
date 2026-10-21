"""Org rules (Phase C spec 5.2): plain JSON rule specs that an organisation promotes from a manual finding, validated
and compiled here into `Rule`s that `RuleSet.with_rules` accepts. The Spellwarden pattern language (5.2.2) is a small
subset of regular expressions with a hand-written tokenizer, so the accepted language is the same on every Python
version; a pattern compiles to one Python pattern per `.*`-separated part plus one PCRE string for exports.

Bounded time. Python's `re` has no timeout and backtracks, so the grammar refuses the shapes whose cost grows with
the text faster than linearly (plan decision P-ORG-1, which tightens 5.2.2): no quantified or nested groups, no
backreferences or lookaround, at most one unbounded repeat per part, no part that starts with an unbounded repeat,
and no repeat next to an item that can match the same characters (`a+a`, `\\s*\\s`, `.{0,100}x`). Long units are
read in windows of 4096 characters that start every 3584 characters."""
from __future__ import annotations

import re
import types
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import date

from spellwarden_scan.evidence import bounded_evidence, fingerprint
from spellwarden_scan.glob import glob_match
from spellwarden_scan.model import SEVERITY_RANK, Finding, Location
from spellwarden_scan.package import CodeBlock, Package
from spellwarden_scan.rules import ALLOWED_NIST, ALLOWED_OWASP, Rule
from spellwarden_scan.rules.skill import logical_commands
from spellwarden_scan.text import valid_line

ORG_RULE_ID_RE = re.compile(r"^SW-ORG-(?!000)\d{3}$")
PATTERN_LIMITS = types.MappingProxyType({
    "max_length": 300, "max_parts": 4, "max_groups": 4, "max_alternatives": 16, "max_class_members": 64,
    "max_repeat": 100, "window": 4096, "overlap": 512,
})
WINDOW = PATTERN_LIMITS["window"]
WINDOW_STEP = PATTERN_LIMITS["window"] - PATTERN_LIMITS["overlap"]
ERROR_CODES = ("bad_id", "bad_title", "bad_severity", "bad_area", "bad_mapping", "bad_target", "bad_detection",
               "bad_glob", "pattern_too_long", "pattern_syntax", "pattern_too_complex", "bad_predicate", "bad_values",
               "unknown_key")

_METAS = frozenset("\\.[](){}|*+?^$")
_CLASS_ESCAPES = frozenset("sSdDwW")
_LITERAL_ESCAPES = _METAS | {"/", "-"}
_QUANTIFIER_START = frozenset("*+?{")
_BOUNDED = re.compile(r"\{(\d{1,3})(?:,(\d{1,3}))?\}")
# Characters tried against every item when two items are compared (see `_overlaps`): all of Latin-1, the characters
# whose case folds to ASCII (Kelvin sign, long s, dotted and dotless i, sharp s), and samples of Unicode digits,
# spaces and letters that `\d`, `\s` and `\w` match.
_EXTRA_SAMPLES = "".join(map(chr, (
    0x212A, 0x017F, 0x0130, 0x0131, 0x1E9E, 0x0660, 0x0669, 0x06F0, 0x0966, 0xFF10, 0xFF19, 0x1680,
    0x2000, 0x2003, 0x2007, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0x0410, 0x044F, 0x03B1, 0x05D0,
    0x0627, 0x4E00, 0x9FFF, 0xAC00, 0x3042, 0x0E01, 0xFB01, 0x1D7CE,
)))


class OrgRuleError(ValueError):
    """A rule spec the engine refuses: `code` from `ERROR_CODES`, `message` one sentence for the person writing it."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _syntax(message: str) -> OrgRuleError:
    return OrgRuleError("pattern_syntax", message)


def _complex(message: str) -> OrgRuleError:
    return OrgRuleError("pattern_too_complex", message)


@dataclass(frozen=True)
class CompiledPattern:
    """A validated pattern. `parts` are searched one after the other (`Then`, `rules/patterns.py`); `pcre` is the
    one-string form for exports (the parts joined by `.*`, `(?i)` unless case-sensitive); `anchored_end` tells the
    window loop that only the window ending at the end of the unit can match."""

    source: str
    case_sensitive: bool
    parts: tuple[re.Pattern[str], ...]
    pcre: str
    anchored_end: bool = False


@dataclass
class _Atom:
    regex: str          # the canonical regex of one character: a literal, `.`, an escape or a bracket class
    position: int       # 1-based character position in the pattern, for messages
    low: int
    high: int | None    # None: unbounded (`*`, `+`)
    ranges: tuple[tuple[str, str], ...] = ()
    literals: str = ""

    @property
    def variable(self) -> bool:
        return self.low != self.high

    def emit(self) -> str:
        if self.low == 1 and self.high == 1:
            return self.regex
        if self.high is None:
            return self.regex + ("*" if self.low == 0 else "+")
        if self.low == 0 and self.high == 1:
            return self.regex + "?"
        if self.low == self.high:
            return f"{self.regex}{{{self.low}}}"
        return f"{self.regex}{{{self.low},{self.high}}}"


@dataclass
class _Boundary:
    position: int

    def emit(self) -> str:
        return "\\b"


@dataclass
class _Group:
    alternatives: list[list]
    optional: bool
    position: int

    def emit(self) -> str:
        body = "|".join("".join(item.emit() for item in alternative) for alternative in self.alternatives)
        return f"(?:{body})" + ("?" if self.optional else "")


class _Parser:
    def __init__(self, text: str, offset: int) -> None:
        self.text = text
        self.offset = offset    # characters of the pattern before `text` (a leading `^`)
        self.index = 0

    def position(self) -> int:
        return self.offset + self.index + 1

    def peek(self, ahead: int = 0) -> str | None:
        index = self.index + ahead
        return self.text[index] if index < len(self.text) else None

    def parts(self) -> list[list]:
        parts: list[list] = [[]]
        while self.index < len(self.text):
            char = self.text[self.index]
            if char == "." and self.peek(1) == "*":
                if self.peek(2) in ("?", "+"):
                    raise _syntax(f"The pattern has a lazy or possessive quantifier at character {self.position() + 2}. "
                                  "Write .* without ? or + after it.")
                self.index += 2
                parts.append([])
                continue
            if char == "(":
                parts[-1].append(self.group())
                continue
            if char == ")":
                raise _syntax(f"The pattern closes a group at character {self.position()} that was never opened. "
                              "Write \\) for a literal parenthesis.")
            if char == "|":
                raise _syntax(f"The pattern has | outside a group at character {self.position()}. "
                              "Put the alternatives in a group, such as (a|b).")
            parts[-1].append(self.item(in_group=False))
        return parts

    def group(self) -> _Group:
        start = self.position()
        self.index += 1
        if self.peek() == "?":
            raise _syntax(f"The pattern has (? at character {start}. Lookahead, lookbehind, flags and named groups "
                          "are not part of the pattern language.")
        alternatives: list[list] = [[]]
        while True:
            char = self.peek()
            if char is None:
                raise _syntax(f"The group opened at character {start} is never closed. Add ) or write \\( for a "
                              "literal parenthesis.")
            if char == ")":
                self.index += 1
                break
            if char == "(":
                raise _syntax(f"The pattern nests a group at character {self.position()}. Groups cannot hold groups.")
            if char == "|":
                self.index += 1
                alternatives.append([])
                continue
            if char == "." and self.peek(1) == "*":
                raise _complex(f"The group at character {start} holds .* at character {self.position()}. "
                               "Use {m,n} inside groups.")
            alternatives[-1].append(self.item(in_group=True))
        if any(not alternative for alternative in alternatives):
            raise _syntax(f"The group at character {start} has an empty alternative. Write each alternative, "
                          "or follow the group with ? to make it optional.")
        if len(alternatives) > PATTERN_LIMITS["max_alternatives"]:
            raise _complex(f"The group at character {start} has {len(alternatives)} alternatives. "
                           f"Write at most {PATTERN_LIMITS['max_alternatives']}.")
        optional = False
        char = self.peek()
        if char == "?":
            self.index += 1
            optional = True
            if self.peek() in ("?", "+"):
                raise _syntax(f"The pattern has a lazy or possessive quantifier at character {self.position()}. "
                              "Remove it.")
        elif char is not None and char in _QUANTIFIER_START:
            raise _syntax(f"The pattern has a quantifier on a group at character {self.position()}. "
                          "Quantify one character or class instead.")
        return _Group(alternatives, optional, start)

    def item(self, *, in_group: bool):
        start = self.position()
        char = self.text[self.index]
        if char in _QUANTIFIER_START:
            raise _syntax(f"The pattern has a quantifier with nothing to repeat at character {start}. "
                          "Write \\" + char + " for the literal character.")
        if char in ("^", "$"):
            raise _syntax(f"The pattern has {char} at character {start}. Write ^ only as the first character and $ only "
                          f"as the last, or \\{char} for the literal character.")
        if char in ("]", "}"):
            raise _syntax(f"The pattern has {char} at character {start} without its opening bracket. "
                          f"Write \\{char} for the literal character.")
        if char == "\\" and self.peek(1) == "b":
            self.index += 2
            if self.peek() is not None and self.peek() in _QUANTIFIER_START:
                raise _syntax(f"The pattern repeats \\b at character {self.position()}. A word boundary cannot be repeated.")
            return _Boundary(start)
        atom = self.atom()
        atom.position = start
        self.quantifier(atom, in_group=in_group)
        return atom

    def atom(self) -> _Atom:
        char = self.text[self.index]
        if char == ".":
            self.index += 1
            return _Atom(".", 0, 1, 1)
        if char == "[":
            return self.bracket()
        if char == "\\":
            escaped = self.peek(1)
            if escaped is None:
                raise _syntax(f"The pattern ends with a lone backslash at character {self.position()}. Write \\\\ for "
                              "a literal backslash.")
            self.index += 2
            if escaped in _CLASS_ESCAPES:
                return _Atom("\\" + escaped, 0, 1, 1)
            if escaped in _LITERAL_ESCAPES:
                return _Atom(re.escape(escaped), 0, 1, 1, literals=escaped)
            raise _syntax(f"The pattern has the escape \\{escaped} at character {self.position() - 2}. Only \\s \\S \\d \\D "
                          "\\w \\W \\b and escaped special characters are allowed.")
        self.index += 1
        return _Atom(re.escape(char), 0, 1, 1, literals=char)

    def bracket(self) -> _Atom:
        start = self.position()
        self.index += 1
        negated = self.peek() == "^"
        if negated:
            self.index += 1
        members: list[str] = []
        ranges: list[tuple[str, str]] = []
        literals: list[str] = []
        first = True
        while True:
            char = self.peek()
            if char is None:
                raise _syntax(f"The class opened at character {start} is never closed. Add ] or write \\[ for a "
                              "literal bracket.")
            if char == "]":
                if not members:
                    raise _syntax(f"The class at character {start} is empty. Write at least one member.")
                self.index += 1
                break
            if char == "[":
                raise _syntax(f"The class at character {start} holds [ at character {self.position()}. Classes do not "
                              "nest and [:name:] classes are not allowed; write \\[ for a literal bracket.")
            if char == "-" and not first and self.peek(1) != "]":
                raise _syntax(f"The class at character {start} has - at character {self.position()} outside a range. "
                              "Write \\- for a literal hyphen.")
            member, literal = self.class_member()
            if literal is not None and self.peek() == "-" and self.peek(1) not in ("]", None):
                range_at = self.position()
                self.index += 1
                end, end_literal = self.class_member()
                if end_literal is None:
                    raise _syntax(f"The range at character {range_at} ends in a class escape. A range joins two characters.")
                if literal > end_literal:
                    raise _syntax(f"The range at character {range_at} starts after it ends. Write the lower character first.")
                members.append(f"{member}-{end}")
                ranges.append((literal, end_literal))
            else:
                if literal is None and self.peek() == "-" and self.peek(1) not in ("]", None):
                    raise _syntax(f"The range at character {self.position()} starts with a class escape. A range joins "
                                  "two characters.")
                members.append(member)
                if literal is not None:
                    literals.append(literal)
            first = False
        if len(members) > PATTERN_LIMITS["max_class_members"]:
            raise _complex(f"The class at character {start} has {len(members)} members. "
                           f"Write at most {PATTERN_LIMITS['max_class_members']}.")
        regex = "[" + ("^" if negated else "") + "".join(members) + "]"
        return _Atom(regex, 0, 1, 1, ranges=tuple(ranges), literals="".join(literals))

    def class_member(self) -> tuple[str, str | None]:
        """`(regex text, the literal character or None for a class escape)`."""
        char = self.text[self.index]
        if char == "\\":
            escaped = self.peek(1)
            if escaped is None:
                raise _syntax(f"The pattern ends with a lone backslash at character {self.position()}.")
            self.index += 2
            if escaped in _CLASS_ESCAPES:
                return "\\" + escaped, None
            if escaped in _LITERAL_ESCAPES:
                return re.escape(escaped), escaped
            raise _syntax(f"The pattern has the escape \\{escaped} at character {self.position() - 2}. Only \\s \\S \\d \\D "
                          "\\w \\W and escaped special characters are allowed in a class.")
        self.index += 1
        return re.escape(char), char

    def quantifier(self, atom: _Atom, *, in_group: bool) -> None:
        char = self.peek()
        if char is None or char not in _QUANTIFIER_START:
            return
        at = self.position()
        if char == "{":
            match = _BOUNDED.match(self.text, self.index)
            if match is None:
                raise _syntax(f"The pattern has {{ at character {at} that is not {{m}} or {{m,n}}. Write \\{{ for the literal "
                              "character; {m,} is not allowed.")
            low = int(match.group(1))
            high = int(match.group(2)) if match.group(2) is not None else low
            if low > high:
                raise _syntax(f"The quantifier at character {at} has its minimum above its maximum. Write {{m,n}} with m "
                              "at most n.")
            if high == 0:
                raise _syntax(f"The quantifier at character {at} repeats zero times. Remove it.")
            if high > PATTERN_LIMITS["max_repeat"]:
                raise _complex(f"The quantifier at character {at} repeats up to {high} times. "
                               f"Write at most {PATTERN_LIMITS['max_repeat']}.")
            self.index = match.end()
            atom.low, atom.high = low, high
        else:
            self.index += 1
            atom.low, atom.high = {"*": (0, None), "+": (1, None), "?": (0, 1)}[char]
            if atom.high is None and in_group:
                raise _complex(f"The group around character {at} holds an unbounded repeat (* or +). Use {{m,n}} inside "
                               "groups.")
        if self.peek() is not None and self.peek() in "?+*{":
            raise _syntax(f"The pattern has a lazy, possessive or repeated quantifier at character {self.position()}. "
                          "Write one quantifier.")


def _flow(items: list) -> tuple[bool, set[int], set[int], set[tuple[int, int]], list[_Atom]]:
    """Glushkov positions of a sequence: `(nullable, first, last, follow, atoms)`, positions being indexes into
    `atoms`. `follow` holds `(a, b)` when atom `b` can match right after atom `a`; `\\b` is transparent."""
    atoms: list[_Atom] = []

    def walk(sequence: list) -> tuple[bool, set[int], set[int], set[tuple[int, int]]]:
        nullable, first, last, follow = True, set(), set(), set()
        for item in sequence:
            if isinstance(item, _Boundary):
                continue
            if isinstance(item, _Atom):
                atoms.append(item)
                index = len(atoms) - 1
                i_null, i_first, i_last, i_follow = item.low == 0, {index}, {index}, set()
                if item.high is None or item.high > 1:
                    i_follow.add((index, index))
            else:
                i_null, i_first, i_last, i_follow = item.optional, set(), set(), set()
                for alternative in item.alternatives:
                    a_null, a_first, a_last, a_follow = walk(alternative)
                    i_null = i_null or a_null
                    i_first |= a_first
                    i_last |= a_last
                    i_follow |= a_follow
            follow |= i_follow | {(a, b) for a in last for b in i_first}
            if nullable:
                first |= i_first
            last = (last | i_last) if i_null else set(i_last)
            nullable = nullable and i_null
        return nullable, first, last, follow

    nullable, first, last, follow = walk(items)
    return nullable, first, last, follow, atoms


def _samples(atoms: list[_Atom]) -> str:
    chars = {chr(code) for code in range(256)} | set(_EXTRA_SAMPLES)
    for atom in atoms:
        for char in atom.literals:
            chars.update((char, char.upper(), char.lower(), char.casefold()))
        for low, high in atom.ranges:
            step = max(1, (ord(high) - ord(low)) // 64)
            chars.update(chr(code) for code in range(ord(low), ord(high) + 1, step))
            chars.add(high)
    return "".join(sorted(char for char in chars if len(char) == 1))


def _check_cost(items: list, flags: int) -> None:
    """The bounded-time rules of plan decision P-ORG-1 for one part."""
    _nullable, first, _last, follow, atoms = _flow(items)
    unbounded = [atom for atom in atoms if atom.high is None]
    if len(unbounded) > 1:
        raise _complex(f"The part with characters {unbounded[0].position} and {unbounded[1].position} has two unbounded "
                       "repeats (* or +). Split it with .* or bound one with {m,n}.")
    for index in first:
        if atoms[index].high is None:
            raise _complex(f"A part starts with an unbounded repeat at character {atoms[index].position}. Start it with "
                           "a fixed character.")
    samples = _samples(atoms)
    matched: dict[int, frozenset[str]] = {}

    def chars_of(index: int) -> frozenset[str]:
        if index not in matched:
            regex = re.compile(atoms[index].regex, flags)
            matched[index] = frozenset(char for char in samples if regex.fullmatch(char))
        return matched[index]

    for a, b in sorted(follow):
        if a == b or not (atoms[a].variable or atoms[b].variable):
            continue
        if chars_of(a) & chars_of(b):
            repeat, other = (atoms[a], atoms[b]) if atoms[a].variable else (atoms[b], atoms[a])
            raise _complex(f"The repeat at character {repeat.position} can match the same characters as the item at "
                           f"character {other.position} next to it. Put a character between them that neither matches.")


def compile_pattern(pattern: object, *, case_sensitive: bool = False) -> CompiledPattern:
    """Validates `pattern` against the grammar of spec 5.2.2 (as tightened by P-ORG-1) and compiles it; raises
    `OrgRuleError` with `pattern_too_long`, `pattern_syntax` or `pattern_too_complex`."""
    if not isinstance(pattern, str):
        raise _syntax("The pattern must be text.")
    if not pattern:
        raise _syntax("The pattern is empty. Write at least one character.")
    if len(pattern) > PATTERN_LIMITS["max_length"]:
        raise OrgRuleError("pattern_too_long", f"The pattern has {len(pattern)} characters. "
                                               f"Write at most {PATTERN_LIMITS['max_length']}.")
    anchored_start = pattern.startswith("^")
    body = pattern[1:] if anchored_start else pattern
    # `$` ends the pattern as an anchor unless it is escaped: an even number of backslashes before it.
    anchored_end = body.endswith("$") and (len(body[:-1]) - len(body[:-1].rstrip("\\"))) % 2 == 0
    if anchored_end:
        body = body[:-1]
    parts = _Parser(body, 1 if anchored_start else 0).parts()
    if len(parts) > PATTERN_LIMITS["max_parts"]:
        raise _complex(f"The pattern has {len(parts)} parts separated by .*. Write at most {PATTERN_LIMITS['max_parts']}.")
    if any(not [item for item in part if not isinstance(item, _Boundary)] for part in parts):
        raise _syntax("The pattern starts or ends with .*, holds .*.*, or has a part that is only an anchor or \\b. "
                      "Remove the empty part.")
    flags = 0 if case_sensitive else re.IGNORECASE
    for part in parts:
        groups = sum(1 for item in part if isinstance(item, _Group))
        if groups > PATTERN_LIMITS["max_groups"]:
            raise _complex(f"A part of the pattern has {groups} groups. Write at most {PATTERN_LIMITS['max_groups']} "
                           "between two .* gaps.")
        _check_cost(part, flags)
    texts = ["".join(item.emit() for item in part) for part in parts]
    if anchored_start:
        texts[0] = "^" + texts[0]
    if anchored_end:
        texts[-1] = texts[-1] + "$"
    compiled = tuple(re.compile(text, flags) for text in texts)
    pcre = ("" if case_sensitive else "(?i)") + ".*".join(texts)
    return CompiledPattern(source=pattern, case_sensitive=case_sensitive, parts=compiled, pcre=pcre,
                           anchored_end=anchored_end)


def unit_windows(text: str) -> Iterator[tuple[int, int]]:
    """`(start, end)` of the windows a unit is read in (spec 5.2.2): the whole unit when it has at most 4096
    characters, else windows of 4096 characters starting every 3584 (512 of overlap), the last one ending at the end."""
    if len(text) <= WINDOW:
        yield 0, len(text)
        return
    start = 0
    while True:
        end = min(start + WINDOW, len(text))
        yield start, end
        if end == len(text):
            return
        start += WINDOW_STEP


def pattern_search(compiled: CompiledPattern, text: str) -> bool:
    """`Then`-style: part 1 found, part 2 after the end of part 1's match, and so on, inside one window. Windows are
    ranges of `text` (`pos` and `endpos`), so `^` matches only at the start of the unit and `\\b` sees the character
    before a window; `$` is tried only in the window that ends at the end of the unit."""
    length = len(text)
    for start, end in unit_windows(text):
        if compiled.anchored_end and end != length:
            continue
        position = start
        for part in compiled.parts:
            match = part.search(text, position, end)
            if match is None:
                break
            position = match.end()
        else:
            return True
    return False


# --- Org rule specs (spec 5.2.1, 5.2.3) and their detection ------------------------------------------------

AREAS = ("skill", "mcp")
TARGETS = ("claude-code-hooks", "kong")
SPEC_KEYS = ("id", "title", "severity", "area", "owasp", "nist", "targets", "malicious", "detection")
PATTERN_KEYS = ("kind", "files", "in", "pattern", "case_sensitive")
PROBE_PREDICATES = ("auth_mode_in", "transport_in", "deprecated_feature_any", "spec_version_below",
                    "endpoint_host_in", "endpoint_host_not_in", "tool_name_matches", "tool_description_matches")
PATTERN_PREDICATES = ("tool_name_matches", "tool_description_matches")
AUTH_MODES = ("none", "static-key", "oauth-dcr", "oauth-cimd", "xaa", "unknown")
TRANSPORTS = ("streamable-http", "sse", "stdio", "unknown")
DEPRECATED_FEATURES = ("sse", "initialize_only", "sessions", "roots", "sampling", "logging", "dcr")
_VALUE_LISTS = {"auth_mode_in": (AUTH_MODES, 6), "transport_in": (TRANSPORTS, 4),
                "deprecated_feature_any": (DEPRECATED_FEATURES, 7)}
MAX_HOSTS = 50
MAX_GLOB = 200
MAX_GLOB_SEGMENTS = 16
MAX_MAPPINGS = 5
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"^(?:\*\.)?{_LABEL}(?:\.{_LABEL})*$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _fail(code: str, message: str) -> OrgRuleError:
    return OrgRuleError(code, message)


def _string_list(value: object, *, code: str, what: str, limit: int, allowed: tuple[str, ...] | None) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _fail(code, f"{what} must be a list of text values.")
    if len(set(value)) != len(value):
        raise _fail(code, f"{what} lists a value twice. List each value once.")
    if len(value) > limit:
        raise _fail(code, f"{what} lists {len(value)} values. List at most {limit}.")
    if allowed is not None:
        for item in value:
            if item not in allowed:
                raise _fail(code, f"{what} holds {item!r}, which is not one of {', '.join(allowed)}.")
    return value


def _check_glob(files: object) -> str:
    if not isinstance(files, str) or not 1 <= len(files) <= MAX_GLOB:
        raise _fail("bad_glob", f"The files pattern must be text of 1 to {MAX_GLOB} characters.")
    if files.startswith("/") or "\\" in files or "\x00" in files:
        raise _fail("bad_glob", "The files pattern must be a relative path with / between folders, such as **/*.sh.")
    segments = files.split("/")
    if len(segments) > MAX_GLOB_SEGMENTS:
        raise _fail("bad_glob", f"The files pattern has {len(segments)} segments. Write at most {MAX_GLOB_SEGMENTS}.")
    if any(segment in ("", ".", "..") for segment in segments):
        raise _fail("bad_glob", "The files pattern holds an empty, . or .. segment. Write a path inside the skill.")
    return files


def _check_hosts(values: list[str]) -> None:
    for host in values:
        if len(host) > 253 or _HOST.match(host) is None:
            raise _fail("bad_values", f"The host {host!r} is not a lower-case host name such as mcp.example.com or "
                                      "*.example.com.")


def _check_detection(detection: object, area: str) -> dict:
    if not isinstance(detection, dict):
        raise _fail("bad_detection", "The detection must be an object with a kind.")
    kind = detection.get("kind")
    if area == "skill":
        if kind != "pattern":
            raise _fail("bad_detection", "A skill rule detects with a file pattern: set kind to pattern.")
        for key in detection:
            if key not in PATTERN_KEYS:
                raise _fail("unknown_key", f"The detection has the unknown key {key!r}.")
        if "pattern" not in detection:
            raise _fail("bad_detection", "A pattern rule needs a pattern.")
        _check_glob(detection.get("files", "**"))
        if detection.get("in", "lines") not in ("lines", "commands"):
            raise _fail("bad_detection", "Read either lines or commands.")
        case_sensitive = detection.get("case_sensitive", False)
        if not isinstance(case_sensitive, bool):
            raise _fail("bad_detection", "Set case_sensitive to true or false.")
        compile_pattern(detection["pattern"], case_sensitive=case_sensitive)
        return detection
    if kind != "probe":
        raise _fail("bad_detection", "A server rule detects with a probe check: set kind to probe.")
    predicate = detection.get("predicate")
    if predicate not in PROBE_PREDICATES:
        raise _fail("bad_predicate", f"The check {predicate!r} is not one of {', '.join(PROBE_PREDICATES)}.")
    if predicate in PATTERN_PREDICATES:
        allowed_keys = ("kind", "predicate", "pattern", "case_sensitive")
    else:
        allowed_keys = ("kind", "predicate", "values")
    for key in detection:
        if key not in allowed_keys:
            raise _fail("unknown_key", f"The detection has the unknown key {key!r} for the check {predicate}.")
    if predicate in PATTERN_PREDICATES:
        if "pattern" not in detection:
            raise _fail("bad_detection", f"The check {predicate} needs a pattern.")
        case_sensitive = detection.get("case_sensitive", False)
        if not isinstance(case_sensitive, bool):
            raise _fail("bad_detection", "Set case_sensitive to true or false.")
        compile_pattern(detection["pattern"], case_sensitive=case_sensitive)
        return detection
    if "values" not in detection:
        raise _fail("bad_values", f"The check {predicate} needs values.")
    values = detection["values"]
    if predicate in _VALUE_LISTS:
        allowed, limit = _VALUE_LISTS[predicate]
        _string_list(values, code="bad_values", what="The value list", limit=limit, allowed=allowed)
    elif predicate == "spec_version_below":
        if not (isinstance(values, list) and len(values) == 1 and isinstance(values[0], str)
                and _DATE.match(values[0]) and _real_date(values[0])):
            raise _fail("bad_values", "The check spec_version_below takes one date written YYYY-MM-DD.")
    else:
        _string_list(values, code="bad_values", what="The host list", limit=MAX_HOSTS, allowed=None)
        _check_hosts(values)
    if not values:
        raise _fail("bad_values", f"The check {predicate} needs at least one value.")
    return detection


def _real_date(text: str) -> bool:
    try:
        date.fromisoformat(text)
    except ValueError:
        return False
    return True


def validate_org_rule(spec: object) -> None:
    """Spec 5.2.1: raises `OrgRuleError` for the first problem found, in the order of the field table."""
    if not isinstance(spec, dict):
        raise _fail("unknown_key", "An org rule is an object with the keys " + ", ".join(SPEC_KEYS) + ".")
    for key in spec:
        if key not in SPEC_KEYS:
            raise _fail("unknown_key", f"The rule has the unknown key {key!r}.")
    rule_id = spec.get("id")
    if not isinstance(rule_id, str) or ORG_RULE_ID_RE.match(rule_id) is None:
        raise _fail("bad_id", "The rule id must be SW-ORG- followed by three digits from 001 to 999.")
    if not valid_line(spec.get("title"), 120):
        raise _fail("bad_title", "The title must be 1 to 120 characters on one line, without control characters.")
    severity = spec.get("severity")
    if severity not in SEVERITY_RANK:
        raise _fail("bad_severity", "The severity must be critical, high, medium or low.")
    area = spec.get("area")
    if area not in AREAS:
        raise _fail("bad_area", "The area must be skill or mcp.")
    _string_list(spec.get("owasp", []), code="bad_mapping", what="The OWASP mapping", limit=MAX_MAPPINGS,
                 allowed=ALLOWED_OWASP)
    _string_list(spec.get("nist", []), code="bad_mapping", what="The NIST mapping", limit=MAX_MAPPINGS,
                 allowed=ALLOWED_NIST)
    targets = _string_list(spec.get("targets", []), code="bad_target", what="The target list", limit=len(TARGETS),
                           allowed=TARGETS)
    malicious = spec.get("malicious", False)
    if not isinstance(malicious, bool):
        raise _fail("bad_severity", "Set malicious to true or false.")
    if malicious and severity != "critical":
        raise _fail("bad_severity", "Only a critical rule can be marked malicious.")
    if "detection" not in spec:
        raise _fail("bad_detection", "The rule needs a detection.")
    detection = _check_detection(spec["detection"], area)
    if targets and area == "mcp":
        raise _fail("bad_target", "A server check has no export target.")
    if "claude-code-hooks" in targets and detection.get("in", "lines") != "commands":
        raise _fail("bad_target", "Claude Code hooks check shell commands, so the rule must read commands.")


@dataclass(frozen=True)
class OrgRuleBudget:
    """The org-rule time budget of a scan (spec 5.2.2): `clock` is the caller's (the engine reads no clock of its own)."""

    clock: Callable[[], float]
    seconds: float


class BudgetMeter:
    """One per scan call. `tick()` is read before each unit an org rule evaluates: True while fewer than `seconds` have
    passed since the first tick, then False for the rest of the scan. Without a budget it is always True."""

    def __init__(self, budget: OrgRuleBudget | None) -> None:
        self.budget = budget
        self.started: float | None = None
        self.stopped = False
        self.incomplete: set[str] = set()

    def tick(self) -> bool:
        if self.budget is None:
            return True
        if self.stopped:
            return False
        now = self.budget.clock()
        if self.started is None:
            self.started = now
        elif now - self.started >= self.budget.seconds:
            self.stopped = True
            return False
        return True


def _without_bom(text: str, first: bool) -> str:
    return text[1:] if first and text.startswith("\U0000feff") else text


class OrgRuleDetector:
    """The `detect` of a compiled org rule: callable like every rule's `detect`, and `evaluate(subject, meter)` for
    the scan functions, which reads one unit per `meter.tick()` and records the rule in `meter.incomplete` when the
    budget stops it before the last unit."""

    def __init__(self, spec: dict) -> None:
        self.spec = spec
        self.rule_id: str = spec["id"]
        self.severity: str = spec["severity"]
        self.title: str = spec["title"].strip()
        self.malicious: bool = bool(spec.get("malicious", False))
        detection = spec["detection"]
        self.kind: str = detection["kind"]
        self.files: str = detection.get("files", "**")
        self.read: str = detection.get("in", "lines")
        self.predicate: str | None = detection.get("predicate")
        self.values: tuple[str, ...] = tuple(detection.get("values", ()))
        self.pattern = (compile_pattern(detection["pattern"], case_sensitive=detection.get("case_sensitive", False))
                        if "pattern" in detection else None)

    def __call__(self, subject) -> Iterator[Finding]:
        return self.evaluate(subject, BudgetMeter(None))

    def evaluate(self, subject, meter: BudgetMeter) -> Iterator[Finding]:
        units = self._package_units(subject) if self.kind == "pattern" else self._probe_units(subject)
        for unit in units:
            if not meter.tick():
                meter.incomplete.add(self.rule_id)
                return
            finding = unit()
            if finding is not None:
                yield finding

    # Each unit is a thunk returning the finding or None, so the meter is read before the unit's work.

    def _selected(self, package: Package, path: str) -> bool:
        prefix = f"{package.root}/" if package.root else ""
        relative = path[len(prefix):] if prefix and path.startswith(prefix) else path
        return glob_match(relative, self.files)

    def _package_units(self, package: Package) -> Iterator[Callable[[], Finding | None]]:
        if self.read == "lines":
            for unit in package.text_files:
                if not self._selected(package, unit.path):
                    continue
                for number, line in enumerate(unit.lines, start=1):
                    yield self._line_unit(unit.path, number, _without_bom(line, number == 1))
            return
        for unit in package.scripts():
            if not self._selected(package, unit.path):
                continue
            for path, number, command in logical_commands(unit):
                yield self._line_unit(path, number, _without_bom(command, number == 1 and not isinstance(unit, CodeBlock)))

    def _line_unit(self, path: str, number: int, text: str) -> Callable[[], Finding | None]:
        def run() -> Finding | None:
            if self.pattern is None or not pattern_search(self.pattern, text):
                return None
            return Finding(self.rule_id, self.severity, self.title, Location(path, number), bounded_evidence(text),
                           fingerprint(self.rule_id, path, text), self.malicious)
        return run

    def _probe_units(self, probe) -> Iterator[Callable[[], Finding | None]]:
        if self.predicate in PATTERN_PREDICATES:
            for tool in probe.tools:
                yield self._tool_unit(tool)
            return
        yield lambda: self._server_finding(probe)

    def _tool_unit(self, tool) -> Callable[[], Finding | None]:
        def run() -> Finding | None:
            from spellwarden_scan.probe import text_of

            text = tool.name if self.predicate == "tool_name_matches" else text_of(tool.description)
            if self.pattern is None or not isinstance(text, str) or not pattern_search(self.pattern, text):
                return None
            return self._finding(f"tool:{tool.name}", text)
        return run

    def _server_finding(self, probe) -> Finding | None:
        from spellwarden_scan.probe import classify

        spec_version, transport, auth_mode, deprecated = classify(probe)
        if self.predicate == "transport_in":
            return self._finding(None, f"transport {transport}", probe) if transport in self.values else None
        if probe.endpoint is None:
            return None  # a stdio server sees transport_in and the tool checks only (spec 5.2.3)
        if self.predicate == "auth_mode_in":
            return self._finding(None, f"auth mode {auth_mode}", probe) if auth_mode in self.values else None
        if self.predicate == "deprecated_feature_any":
            used = [name for name in deprecated if name in self.values]
            return self._finding(None, "deprecated features: " + ", ".join(used), probe) if used else None
        if self.predicate == "spec_version_below":
            if spec_version is None:
                return self._finding(None, "spec version unknown", probe)
            return self._finding(None, f"spec version {spec_version}", probe) if spec_version < self.values[0] else None
        host = endpoint_host(probe.endpoint)
        listed = host is not None and any(host_matches(host, entry) for entry in self.values)
        if self.predicate == "endpoint_host_in":
            return self._finding(None, f"endpoint host {host}", probe) if listed else None
        return None if listed else self._finding(None, f"endpoint host {host or 'unknown'}", probe)

    def _finding(self, path: str | None, evidence: str, probe=None) -> Finding:
        from spellwarden_scan.rules.mcp import _where

        location = path if path is not None else _where(probe)
        return Finding(self.rule_id, self.severity, self.title, Location(location, None), bounded_evidence(evidence),
                       fingerprint(self.rule_id, location, evidence), self.malicious)


def endpoint_host(endpoint: str | None) -> str | None:
    """The lower-case host of an endpoint URL without port, brackets or a trailing dot; None when it has none."""
    from spellwarden_scan.rules.mcp import _origin

    origin = _origin(endpoint)
    if origin is None:
        return None
    authority = origin.split("://", 1)[1]
    if authority.startswith("["):
        return authority[1:authority.index("]")]
    return authority.rsplit(":", 1)[0].rstrip(".") if ":" in authority else authority.rstrip(".")


def host_matches(host: str, entry: str) -> bool:
    """`mcp.example.com` matches itself only; `*.example.com` matches every subdomain and not `example.com`."""
    if entry.startswith("*."):
        return host.endswith(entry[1:]) and host != entry[2:]
    return host == entry


def compile_org_rule(spec: object) -> Rule:
    """Validates `spec` and returns its `Rule`, built without `make_rule` (which keeps refusing `SW-ORG` ids)."""
    validate_org_rule(spec)
    assert isinstance(spec, dict)
    owasp = tuple(spec.get("owasp", ()))
    return Rule(
        id=spec["id"], title=spec["title"].strip(), severity_default=spec["severity"], area=spec["area"],
        owasp_agentic=tuple(i for i in owasp if i.startswith("ASI")),
        owasp_mcp=tuple(i for i in owasp if i.startswith("MCP")), nist=tuple(spec.get("nist", ())),
        targets=tuple(spec.get("targets", ())), malicious_indicator=bool(spec.get("malicious", False)),
        detect=OrgRuleDetector(spec),
    )


def is_org_rule(rule: Rule) -> bool:
    return isinstance(rule.detect, OrgRuleDetector)


__all__ = ["AREAS", "AUTH_MODES", "DEPRECATED_FEATURES", "ERROR_CODES", "ORG_RULE_ID_RE", "PATTERN_LIMITS",
           "PROBE_PREDICATES", "TARGETS", "TRANSPORTS", "BudgetMeter", "CompiledPattern", "OrgRuleBudget",
           "OrgRuleDetector", "OrgRuleError", "compile_org_rule", "compile_pattern", "endpoint_host", "host_matches",
           "is_org_rule", "pattern_search", "unit_windows", "validate_org_rule"]
