"""A Python copy of the semantics of the Zuplo guard (`exports/zuplo_guard.py`, Zuplo export spec 4.4), as
`guard_template.py` is a copy of the engine's matchers: the same decisions, written again in Python so that a vector
that the two disagree on fails a test. `decide(vector, sets)` gives the outcome of one vector of
`fixtures/zuplo_vectors.json`: `{"outcome": "pass"}` or `{"outcome": "block", "rule_ids": [...], "reason": ..., "id": ...}`.

Three switches choose how much of the guard is on. `strip_invisible` removes the characters of the scanner's `visible`;
`nfkc` normalises to NFKC (with the dotted-i mapping); `js` reads a pattern as JavaScript reads it (ASCII `\\d \\w \\b`,
JavaScript's `\\s`, a `.` that stops at U+2028 and U+2029). Claim G1 runs everything on; claim G2 runs with all three off,
which is the engine's own reading, and compares with `orgrules.pattern_search`. Lengths, windows and slices count UTF-16
code units: a text is turned into a string of code units (an astral character is two surrogate characters) first."""
from __future__ import annotations

import base64
import json
import re
import struct
import unicodedata

from spellwarden_scan.rules.skill import visible

WINDOW = 4096
WINDOW_STEP = 3584
MAX_DEPTH = 64
MAX_EVENTS = 10000
MAX_STRINGS = 200000
TEXT_MIME = ("application/json", "application/xml", "application/yaml", "application/x-yaml", "image/svg+xml")
NEWLINE = re.compile(r"\r\n|\r|\n")
JS_SPACE = "\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
WORD = "A-Za-z0-9_"
BOUNDARY = f"(?:(?<=[{WORD}])(?![{WORD}])|(?<![{WORD}])(?=[{WORD}]))"


class Stop(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def units(text: str) -> str:
    """The text as a string of UTF-16 code units: one character per unit, an astral character as two surrogates."""
    raw = text.encode("utf-16-le", "surrogatepass")
    return "".join(map(chr, struct.unpack(f"<{len(raw) // 2}H", raw)))


def normalise(text: str, *, strip_invisible: bool = True, nfkc: bool = True) -> str:
    if strip_invisible:
        text = visible(text)
    if nfkc:
        # Spec 4.4 step 7 and P16: NFKC first, then U+0130 and U+0131 (NFKC keeps U+0130 and composes `I` + U+0307 into it).
        text = unicodedata.normalize("NFKC", text).replace("\u0130", "I").replace("\u0131", "i")
    return text


def js_regex(source: str) -> str:
    """A part written for JavaScript as a Python pattern that reads the classes the way JavaScript does."""
    out: list[str] = []
    in_class = False
    index = 0
    while index < len(source):
        char = source[index]
        if char == "\\":
            escaped = source[index + 1]
            index += 2
            table = {"d": ("0-9", "[0-9]"), "w": (WORD, f"[{WORD}]"), "s": (JS_SPACE, f"[{JS_SPACE}]")}
            if escaped in table:
                out.append(table[escaped][0] if in_class else table[escaped][1])
            elif escaped in "DWS":
                if in_class:
                    raise ValueError("a negated class escape inside a class is not supported by the reference")
                out.append("[^" + table[escaped.lower()][0] + "]")
            elif escaped == "b" and not in_class:
                out.append(BOUNDARY)
            else:
                out.append("\\" + escaped)
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
            out.append(char)
            index += 1
            if source[index:index + 1] == "^":
                out.append("^")
                index += 1
            continue
        elif char == ".":
            out.append("[^\\n\\r\\u2028\\u2029]")
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


class Check:
    def __init__(self, entry: dict, *, js: bool) -> None:
        self.rule_id = entry["rule_id"]
        self.title = entry["title"]
        flags = re.IGNORECASE if entry["flags"] == "i" else 0
        self.parts = [re.compile(js_regex(part) if js else part, flags) for part in entry["parts"]]
        self.anchored_end = entry["anchored_end"]


def search_unit(check: Check, unit: str) -> bool:
    """The engine's `pattern_search` over one unit (windows of `pos` and `endpos`), on code units."""
    length = len(unit)
    windows = [(0, length)]
    if length > WINDOW:
        windows, start = [], 0
        while True:
            end = min(start + WINDOW, length)
            windows.append((start, end))
            if end == length:
                break
            start += WINDOW_STEP
    for start, end in windows:
        if check.anchored_end and end != length:
            continue
        position, found = start, True
        for part in check.parts:
            match = part.search(unit, position, end)
            if match is None:
                found = False
                break
            position = match.end()
        if found:
            return True
    return False


def hits(strings: list[str], checks: list[Check], *, strip_invisible: bool = True, nfkc: bool = True) -> list[Check]:
    found: set[int] = set()
    for raw in strings:
        lines = NEWLINE.split(units(normalise(raw, strip_invisible=strip_invisible, nfkc=nfkc)))
        if lines and lines[-1] == "":
            lines.pop()
        for unit in lines:
            for index, check in enumerate(checks):
                if index not in found and search_unit(check, unit):
                    found.add(index)
    return [checks[index] for index in sorted(found)]


# --- options -----------------------------------------------------------------------------------------------------

def valid_options(options: object) -> bool:
    if not isinstance(options, dict) or set(options) != {"spellwarden", "maxBodyBytes", "onTooLarge", "checks", "deployChecks"}:
        return False
    if not isinstance(options["spellwarden"], dict) or options["spellwarden"].get("format") != 1:
        return False
    limit = options["maxBodyBytes"]
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 16_777_216:
        return False
    if options["onTooLarge"] not in ("block", "allow"):
        return False
    deploy = options["deployChecks"]
    if not isinstance(deploy, dict) or any(key != "SW-GW-003" or not isinstance(value, bool) for key, value in deploy.items()):
        return False
    if not isinstance(options["checks"], list):
        return False
    for check in options["checks"]:
        if not isinstance(check, dict) or set(check) != {"rule_id", "title", "parts", "flags", "anchored_end"}:
            return False
        if not isinstance(check["rule_id"], str) or not isinstance(check["title"], str) or not isinstance(check["anchored_end"], bool):
            return False
        if check["flags"] not in ("i", ""):
            return False
        parts = check["parts"]
        if not isinstance(parts, list) or not 1 <= len(parts) <= 4 or any(not isinstance(part, str) for part in parts):
            return False
        try:
            for part in parts:
                re.compile(js_regex(part))
        except (re.error, ValueError, IndexError):
            return False
    return True


# --- reading -----------------------------------------------------------------------------------------------------

def parse_json(text: str):
    def refuse(_name: str):
        raise ValueError("not JSON")

    try:
        return json.loads(text, parse_constant=refuse)
    except RecursionError:
        raise Stop("too_deep") from None
    except ValueError:
        raise Stop("not_json") from None


def messages_of(value) -> list[dict]:
    if isinstance(value, list):
        if any(not isinstance(item, dict) for item in value):
            raise Stop("not_mcp")
        return value
    if not isinstance(value, dict):
        raise Stop("not_mcp")
    return [value]


def is_answer(message: dict) -> bool:
    return "result" in message or "error" in message


def is_server_request(message: dict) -> bool:
    return "method" in message and message.get("id") is not None and not is_answer(message)


def utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise Stop("not_json") from None


def data_field(line: str) -> str | None:
    """The value of a `data` field line (one leading space dropped), None for a comment or any other field."""
    name, _, value = line.partition(":")
    if line.startswith(":") or name != "data":
        return None
    return value[1:] if value.startswith(" ") else value


def split_events(data: bytes, *, done: bool) -> list[str]:
    """The text of every complete event of `data` in order (a leading byte-order mark skipped): the `data` fields joined by
    LF, comments and other fields ignored, an event without data skipped. A CR at the very end waits unless `done`; at the
    end of the stream the last line and the event it belongs to count even without a terminator."""
    events: list[str] = []
    pending: list[str] = []
    start = 3 if data[:3] == b"\xef\xbb\xbf" else 0
    at = start
    while at < len(data):
        byte = data[at]
        if byte not in (0x0A, 0x0D):
            at += 1
            continue
        if byte == 0x0D and at + 1 == len(data) and not done:
            return events
        following = at + 2 if byte == 0x0D and data[at + 1:at + 2] == b"\n" else at + 1
        if at == start:
            if "\n".join(pending) != "":
                events.append("\n".join(pending))
            pending = []
        else:
            value = data_field(utf8(data[start:at]))
            if value is not None:
                pending.append(value)
        start = at = following
    if done:
        if start < len(data):
            value = data_field(utf8(data[start:]))
            if value is not None:
                pending.append(value)
        if "\n".join(pending) != "":
            events.append("\n".join(pending))
    return events


def forgiving_base64(text: str) -> bytes:
    """`atob`: ASCII whitespace dropped, up to two `=` of a padded length dropped, the standard alphabet only."""
    text = re.sub(r"[ \t\n\f\r]", "", text)
    if len(text) % 4 == 0:
        text = re.sub(r"==?$", "", text)
    if len(text) % 4 == 1 or re.search(r"[^A-Za-z0-9+/]", text):
        raise ValueError("not base64")
    return base64.b64decode(text + "=" * (-len(text) % 4))


def textual(mime: str) -> bool:
    kind = mime.split(";")[0].strip().lower()
    return kind.startswith("text/") or kind in TEXT_MIME


def collect(value, depth: int, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
        if len(out) > MAX_STRINGS:
            raise Stop("too_many_strings")
        return
    if not isinstance(value, (dict, list)):
        return
    if depth > MAX_DEPTH:
        raise Stop("too_deep")
    if isinstance(value, list):
        for item in value:
            collect(item, depth + 1, out)
        return
    media = value.get("type") in ("image", "audio")
    for key, item in value.items():
        out.append(key)
        if len(out) > MAX_STRINGS:
            raise Stop("too_many_strings")
        if key == "data" and media:
            continue
        if key == "blob" and isinstance(item, str):
            mime = value.get("mimeType")
            if isinstance(mime, str) and not textual(mime):
                continue
            try:
                text = forgiving_base64(item).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                raise Stop("not_text") from None
            out.append(text)
            if len(out) > MAX_STRINGS:
                raise Stop("too_many_strings")
            continue
        collect(item, depth + 1, out)


def expand(vector: dict) -> bytes:
    if "body_expand" in vector:
        spec = vector["body_expand"]
        return (spec.get("prefix", "") + spec["repeat"] * spec["times"] + spec.get("suffix", "")).encode("utf-8")
    if "body_b64" in vector:
        return base64.b64decode(vector["body_b64"])
    return vector.get("body", "").encode("utf-8")


def resolve_options(vector: dict, sets: dict) -> object:
    """The options of a vector: the full set of its check set, then `options` laid over it and the keys of `drop` removed;
    a vector whose `raw_options` is present uses that value as it is."""
    if "raw_options" in vector:
        return vector["raw_options"]
    options = {"spellwarden": {"format": 1}, "maxBodyBytes": 1048576, "onTooLarge": "block", "checks": sets[vector["checks"]],
               "deployChecks": {}}
    options.update(vector.get("options", {}))
    for key in vector.get("drop", []):
        options.pop(key, None)
    return options


def identifier(messages: list[dict]):
    answer = next((message for message in messages if is_answer(message)), None)
    found = None if answer is None else answer.get("id")
    return found if found is None or (isinstance(found, (str, int, float)) and not isinstance(found, bool)) else None


def decide(vector: dict, sets: dict, *, strip_invisible: bool = True, nfkc: bool = True, js: bool = True) -> dict:
    options = resolve_options(vector, sets)
    state: list[dict] = []
    try:
        if not valid_options(options):
            raise Stop("bad_options")
        checks = [Check(entry, js=js) for entry in options["checks"]]
        return check_response(vector, options, checks, state, strip_invisible=strip_invisible, nfkc=nfkc)
    except Stop as stop:
        return {"outcome": "block", "rule_ids": [], "reason": stop.reason, "id": identifier(state)}


def check_response(vector: dict, options: dict, checks: list[Check], state: list[dict], *, strip_invisible: bool, nfkc: bool) -> dict:
    status = vector.get("status", 200)
    media = vector.get("media", "application/json")
    success = 200 <= status < 300
    data = expand(vector)
    limit, allow = options["maxBodyBytes"], options["onTooLarge"] == "allow"
    if status in (202, 204) or vector.get("no_body") or (not success and media != "application/json"):
        return {"outcome": "pass"}
    encoding = (vector.get("encoding") or "").strip().lower()
    if encoding not in ("", "identity", "gzip", "br"):
        raise Stop("encoded")
    events = success and media == "text/event-stream"
    if events and vector.get("method", "POST") != "POST":
        raise Stop("not_post")
    declared = vector.get("content_length")
    if declared is not None and declared > limit:
        if not allow:
            raise Stop("too_large")
        return {"outcome": "pass"}
    if success and not events and media != "application/json":
        if len(data) == 0:
            return {"outcome": "pass"}
        raise Stop("not_mcp")
    size = vector.get("chunk_size") or max(len(data), 1)
    chunks = [data[at:at + size] for at in range(0, len(data), size)]
    if events:
        read = 0
        for number, chunk in enumerate(chunks):
            if read + len(chunk) > limit:
                if not allow:
                    raise Stop("too_large")
                return {"outcome": "pass"}
            read += len(chunk)
            state.clear()
            if answered(data[:read], state, done=number == len(chunks) - 1):
                break
    else:
        if len(data) > limit:
            if not allow:
                raise Stop("too_large")
            return {"outcome": "pass"}
        if len(data) == 0:
            return {"outcome": "pass"}
        state.extend(messages_of(parse_json(utf8(data))))
    strings: list[str] = []
    for message in state:
        for key in ("result", "error", "params"):
            if key in message:
                collect(message[key], 1, strings)
    found = hits(strings, checks, strip_invisible=strip_invisible, nfkc=nfkc)
    if not found:
        return {"outcome": "pass"}
    ids = list(dict.fromkeys(item.rule_id for item in found))
    return {"outcome": "block", "rule_ids": ids, "reason": "matched", "id": identifier(state)}


def answered(data: bytes, state: list[dict], *, done: bool) -> bool:
    """Reads the complete events of `data` in order into `state`; True when one of them answers the request. Raises the
    guard's stops (`not_json`, `not_mcp`, `server_request`, `too_many_events`)."""
    for count, text in enumerate(split_events(data, done=done), start=1):
        if count > MAX_EVENTS:
            raise Stop("too_many_events")
        found = messages_of(parse_json(text))
        for message in found:
            if is_answer(message):
                state.extend(found)
                return True
            if is_server_request(message):
                raise Stop("server_request")
        state.extend(found)
    return False
