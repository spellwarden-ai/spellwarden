"""The bounded JSON reader shared by `agentconfig` and `a2a` (O4 spec 5.1). Pure and total: it raises `Refused` with a
document error code and nothing else.

It is a small recursive-descent reader that records the 1-based line of every key and array item from the token it
parsed, refuses a key repeated in one object (`duplicate_key`: readers disagree on which duplicate wins), refuses a lone
surrogate (it cannot be encoded, hashed or printed) and stops at `max_depth` nested containers.

Two modes. Lenient (the default, what every configuration file is read with since 1.0.0) accepts JSONC: line and block
comments, trailing commas and a leading byte-order mark that it strips. Strict (agent cards, which A2A clients parse with
strict JSON parsers) refuses all three: a comment or a trailing comma is `not_json`, a byte-order mark is `bom`."""
from __future__ import annotations

import bisect
import re
from json.decoder import scanstring
from typing import Any

MAX_DOCUMENT_BYTES = 2**20
DEFAULT_MAX_DEPTH = 32

_LINE_END = re.compile(r"\r\n|\r|\n")
_COMMENT_END = re.compile(r"[\r\n]")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_SURROGATE = re.compile("[\ud800-\udfff]")
_LITERALS = (("true", True), ("false", False), ("null", None))
_BOM = b"\xef\xbb\xbf"


class Refused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Obj(dict):
    """A JSON object with the line of each key (`lines`) and of its opening brace (`line`)."""

    __slots__ = ("line", "lines")


class Arr(list):
    """A JSON array with the line of each item (`lines`) and of its opening bracket (`line`)."""

    __slots__ = ("line", "lines")


class Reader:
    def __init__(self, text: str, *, strict: bool = False, max_depth: int = DEFAULT_MAX_DEPTH) -> None:
        self.text = text
        self.pos = 0
        self.strict = strict
        self.max_depth = max_depth
        self.ends = [match.start() for match in _LINE_END.finditer(text)]

    def line(self, pos: int) -> int:
        return bisect.bisect_left(self.ends, pos) + 1

    def skip(self) -> None:
        text, pos, size = self.text, self.pos, len(self.text)
        while pos < size:
            char = text[pos]
            if char in " \t\r\n":
                pos += 1
            elif self.strict:
                break
            elif text.startswith("//", pos):
                end = _COMMENT_END.search(text, pos)
                pos = size if end is None else end.start()
            elif text.startswith("/*", pos):
                end = text.find("*/", pos + 2)
                if end < 0:
                    raise Refused("not_json")
                pos = end + 2
            else:
                break
        self.pos = pos

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def value(self, depth: int) -> Any:
        self.skip()
        char = self.peek()
        if char == "{":
            return self.obj(depth + 1)
        if char == "[":
            return self.arr(depth + 1)
        if char == '"':
            return self.string()
        number = _NUMBER.match(self.text, self.pos)
        if number:
            self.pos = number.end()
            token = number.group(0)
            try:
                return float(token) if any(mark in token for mark in ".eE") else int(token)
            except ValueError:  # an integer over the interpreter's digit limit
                raise Refused("not_json") from None
        for word, literal in _LITERALS:
            if self.text.startswith(word, self.pos):
                self.pos += len(word)
                return literal
        raise Refused("not_json")

    def string(self) -> str:
        try:
            text, end = scanstring(self.text, self.pos + 1, True)
        except ValueError:
            raise Refused("not_json") from None
        if _SURROGATE.search(text):  # a lone surrogate cannot be encoded, hashed or printed
            raise Refused("not_json")
        self.pos = end
        return text

    def obj(self, depth: int) -> Obj:
        if depth > self.max_depth:
            raise Refused("too_deep")
        result = Obj()
        result.line, result.lines = self.line(self.pos), {}
        self.pos += 1
        self.skip()
        if self.peek() == "}":
            self.pos += 1
            return result
        while True:
            self.skip()
            if self.peek() != '"':
                raise Refused("not_json")
            key_line = self.line(self.pos)
            key = self.string()
            if key in result:
                raise Refused("duplicate_key")
            self.skip()
            if self.peek() != ":":
                raise Refused("not_json")
            self.pos += 1
            result[key] = self.value(depth)
            result.lines[key] = key_line
            self.skip()
            char = self.peek()
            if char == "}":
                self.pos += 1
                return result
            if char != ",":
                raise Refused("not_json")
            self.pos += 1
            self.skip()
            if not self.strict and self.peek() == "}":  # a trailing comma (lenient mode only)
                self.pos += 1
                return result

    def arr(self, depth: int) -> Arr:
        if depth > self.max_depth:
            raise Refused("too_deep")
        result = Arr()
        result.line, result.lines = self.line(self.pos), []
        self.pos += 1
        self.skip()
        if self.peek() == "]":
            self.pos += 1
            return result
        while True:
            self.skip()
            result.lines.append(self.line(self.pos))
            result.append(self.value(depth))
            self.skip()
            char = self.peek()
            if char == "]":
                self.pos += 1
                return result
            if char != ",":
                raise Refused("not_json")
            self.pos += 1
            self.skip()
            if not self.strict and self.peek() == "]":  # a trailing comma (lenient mode only)
                self.pos += 1
                return result


def load_json(content: bytes, *, strict: bool = False, max_depth: int = DEFAULT_MAX_DEPTH,
              max_bytes: int = MAX_DOCUMENT_BYTES) -> Any:
    """The parsed document. Raises `Refused` with `too_large`, `bom` (strict only), `not_utf8`, `not_json`,
    `duplicate_key` or `too_deep`; the caller decides what else a document must be (an object, for instance)."""
    if len(content) > max_bytes:
        raise Refused("too_large")
    if content.startswith(_BOM):
        if strict:
            raise Refused("bom")
        content = content[3:]
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("not_utf8") from None
    reader = Reader(text, strict=strict, max_depth=max_depth)
    value = reader.value(0)
    reader.skip()
    if reader.pos != len(text):
        raise Refused("not_json")
    return value
