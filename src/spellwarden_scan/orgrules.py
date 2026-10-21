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
from collections.abc import Iterator
from dataclasses import dataclass

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


__all__ = ["ERROR_CODES", "ORG_RULE_ID_RE", "PATTERN_LIMITS", "CompiledPattern", "OrgRuleError", "compile_pattern",
           "pattern_search", "unit_windows"]
