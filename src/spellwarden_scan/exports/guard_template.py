"""The source of `spellwarden_guard.py` (spec 5.5.1), as one string the hooks export fills in. The engine opens no
file (invariant 1), so the guard's source lives here as text; `hooks.guard_script` replaces the four placeholders
`__PACK_NAME__`, `__PACK_VERSION__`, `__MODE__` and `__CHECKS__` with Python literals in one pass. The guard is
standard-library Python 3.8 or newer (`json`, `re`, `sys`, `os`, `stat`, `datetime`), never opens the network and
never blocks a tool call on its own failure (decision D28). Its matchers (`Then`, `Within`, `Piped`, the logical
command join, the window loop) are copies of the engine's `rules/patterns.py`, `rules/skill.logical_commands`,
`orgrules.unit_windows` and `orgrules.pattern_search`; the shared vectors of claim E7 hold them equal."""

TEMPLATE = r'''#!/usr/bin/env python3
"""Spellwarden guard for Claude Code hooks, generated from a Spellwarden policy pack.

Run as `python3 -I spellwarden_guard.py pre` (PreToolUse) or `... post` (PostToolUse). Standard library only,
Python 3.8 or newer. It never opens the network. Unreadable or unexpected input exits 0 with one line on standard
error, so the normal permission flow applies: the guard never blocks a tool call on its own failure.
"""
import datetime
import json
import os
import re
import stat
import sys

PACK_NAME = __PACK_NAME__
PACK_VERSION = __PACK_VERSION__
MODE = __MODE__
CHECKS = json.loads(__CHECKS__)

MAX_INPUT = 1024 * 1024
WINDOW = 4096
WINDOW_STEP = 3584
LOG_NAME = "spellwarden-activity.jsonl"
LOG_ROTATE_AT = 5 * 1024 * 1024
CONTINUES = ("|", "&&", "||")
NEWLINE = re.compile(r"\r\n|\r|\n")
REQUIRED_FIELDS = {"Bash": ("command",), "PowerShell": ("command",), "Read": ("file_path",), "Glob": ("pattern",)}
PATH_FIELDS = {"Read": ("file_path",), "Grep": ("path",), "Glob": ("pattern", "path")}
COMMAND_TOOLS = ("Bash", "PowerShell")


class Unexpected(Exception):
    """Input the guard cannot judge: it says so on standard error and lets the tool call proceed."""


class Then(object):
    """Each part searched after the end of the previous one (the engine's `patterns.Then`)."""

    def __init__(self, parts, flags):
        self.parts = [re.compile(part, flags) for part in parts]

    def search(self, text, pos=0):
        match = None
        for part in self.parts:
            match = part.search(text, pos)
            if match is None:
                return None
            pos = match.end()
        return match


class Within(object):
    """`inner` between the end of each `opener` and the next `close` character (the engine's `patterns.Within`)."""

    def __init__(self, opener, inner, close, flags):
        self.opener = re.compile(opener, flags)
        self.inner = re.compile(inner, flags)
        self.close = close

    def search(self, text, pos=0):
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


class Piped(object):
    """A segment holding `source` followed by a segment that starts with `sink` (the engine's `patterns.Piped`)."""

    def __init__(self, source, sink, flags):
        self.source = re.compile(source, flags)
        self.sink = re.compile(sink, flags)

    def search(self, text, pos=0):
        segments = text[pos:].split("|")
        for index in range(len(segments) - 1):
            if self.source.search(segments[index]):
                match = self.sink.match(segments[index + 1])
                if match:
                    return match
        return None


def matcher(spec):
    flags = re.IGNORECASE if spec.get("i") else 0
    if "re" in spec:
        return re.compile(spec["re"], flags)
    if "then" in spec:
        return Then(spec["then"], flags)
    if "piped" in spec:
        return Piped(spec["piped"][0], spec["piped"][1], flags)
    if "within" in spec:
        return Within(spec["within"][0], spec["within"][1], spec["within"][2], flags)
    raise Unexpected("unknown matcher in CHECKS")


def split_lines(text):
    lines = NEWLINE.split(text)
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def logical_commands(text):
    """One shell command per item, joined as the engine joins a script: at a trailing backslash, and at a line
    ending in `|`, `&&` or `||`."""
    pending = []
    for line in split_lines(text):
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            pending.append(stripped[:-1])
            continue
        if stripped.endswith(CONTINUES):
            pending.append(stripped)
            continue
        pending.append(line)
        yield " ".join(pending)
        pending = []
    if pending:
        yield " ".join(pending)


def spans(length):
    """The engine's `orgrules.unit_windows`: the whole unit when it has at most 4096 characters, else windows of
    4096 characters starting every 3584 characters, the last one ending at the end."""
    if length <= WINDOW:
        yield 0, length
        return
    start = 0
    while True:
        yield start, min(start + WINDOW, length)
        if start + WINDOW >= length:
            return
        start += WINDOW_STEP


def windowed(parts, text, anchored_end):
    """The engine's `orgrules.pattern_search`: every part searched in the unit between `pos` and the window's end, so
    `^` matches only at the unit's real start; a pattern ending in `$` is tried only in the window ending at the end."""
    length = len(text)
    for start, end in spans(length):
        if anchored_end and end != length:
            continue
        pos = start
        found = True
        for part in parts:
            match = part.search(text, pos, end)
            if match is None:
                found = False
                break
            pos = match.end()
        if found:
            return True
    return False


class Check(object):
    def __init__(self, entry):
        self.rule_id = entry["rule_id"]
        self.title = entry["title"]
        self.decision = entry["decision"]
        self.tools = entry["tools"]
        self.kind = entry["kind"]
        self.matchers = [matcher(spec) for spec in entry.get("any", [])]
        flags = re.IGNORECASE if entry.get("i") else 0
        self.parts = [re.compile(part, flags) for part in entry.get("parts", [])]
        self.anchored_end = bool(entry.get("anchored_end"))
        self.verbs = entry.get("verbs", [])

    def applies(self, tool_name):
        if tool_name in self.tools:
            return True
        return "mcp__*" in self.tools and tool_name.startswith("mcp__")

    def any_match(self, text):
        for one in self.matchers:
            if one.search(text):
                return True
        return False

    def hit(self, tool_name, tool_input):
        if self.kind == "mcp_verb":
            return mcp_verb(tool_name, self.verbs)
        if tool_name in COMMAND_TOOLS:
            for command in logical_commands(field(tool_name, tool_input, "command")):
                if self.kind == "then" and windowed(self.parts, command, self.anchored_end):
                    return True
                if self.kind in ("commands", "any_path") and self.any_match(command):
                    return True
            return False
        if self.kind == "any_path":
            for name in PATH_FIELDS.get(tool_name, ()):
                value = field(tool_name, tool_input, name)
                if value and (self.any_match(value) or self.any_match(value.replace("\\", "/"))):
                    return True
        return False


def field(tool_name, tool_input, name):
    """A string field of `tool_input`: absent is "" unless the tool requires it; any other type is unexpected."""
    if name not in tool_input:
        if name in REQUIRED_FIELDS.get(tool_name, ()):
            raise Unexpected("tool_input has no " + name)
        return ""
    value = tool_input[name]
    if not isinstance(value, str):
        raise Unexpected("tool_input." + name + " is not a string")
    return value


def mcp_verb(tool_name, verbs):
    """`mcp__<server>__<tool>` whose tool part starts with a verb or holds it as a `_`- or `-`-separated word."""
    rest = tool_name[len("mcp__"):]
    if "__" not in rest:
        return False
    tool = rest.split("__", 1)[1].lower()
    words = [word for word in re.split(r"[_-]+", tool) if word]
    for verb in verbs:
        if tool.startswith(verb) or verb in words:
            return True
    return False


def read_event():
    data = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise Unexpected("hook input larger than 1 MiB")
    try:
        event = json.loads(data.decode("utf-8"))
    except ValueError:
        raise Unexpected("hook input is not JSON")
    if not isinstance(event, dict):
        raise Unexpected("hook input is not a JSON object")
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str):
        raise Unexpected("tool_name is not a string")
    tool_input = event.get("tool_input", {})
    if not isinstance(tool_input, dict):
        raise Unexpected("tool_input is not an object")
    return event, tool_name, tool_input


def pre():
    event, tool_name, tool_input = read_event()
    for tool_check in [Check(entry) for entry in CHECKS]:
        if tool_check.applies(tool_name) and tool_check.hit(tool_name, tool_input):
            reason = "Spellwarden %s: %s (pack %s %s)." % (tool_check.rule_id, tool_check.title, PACK_NAME, PACK_VERSION)
            output = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": tool_check.decision,
                                             "permissionDecisionReason": reason}}
            sys.stdout.write(json.dumps(output) + "\n")
            return


def log_directory():
    if MODE == "project":
        root = os.environ.get("CLAUDE_PROJECT_DIR")
        if not root:
            raise Unexpected("CLAUDE_PROJECT_DIR is not set")
        return os.path.join(root, ".claude")
    home = os.path.expanduser("~")
    if home == "~":
        raise Unexpected("no home directory")
    return os.path.join(home, ".claude")


def regular_or_absent(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return True
    return stat.S_ISREG(info.st_mode)


def post():
    event, tool_name, _tool_input = read_event()
    session_id = event.get("session_id")
    if not isinstance(session_id, str):
        session_id = None
    directory = log_directory()
    if not os.path.isdir(directory):
        raise Unexpected("no log directory " + directory)
    path = os.path.join(directory, LOG_NAME)
    if not regular_or_absent(path):
        raise Unexpected("the activity log is not a regular file")
    try:
        if os.lstat(path).st_size >= LOG_ROTATE_AT:
            os.replace(path, path + ".1")
    except FileNotFoundError:
        pass
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_BINARY", "O_CLOEXEC"):
        flags |= getattr(os, name, 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise Unexpected("the activity log is not a regular file")
        at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = {"at": at, "session_id": session_id, "tool_name": tool_name, "hook": "PostToolUse"}
        os.write(descriptor, (json.dumps(line, sort_keys=True) + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)


def main(argv):
    phase = argv[1] if len(argv) > 1 else ""
    try:
        if phase == "pre":
            pre()
        elif phase == "post":
            post()
        else:
            raise Unexpected("run with pre or post")
    except Unexpected as problem:
        sys.stderr.write("spellwarden_guard: " + str(problem) + "; the tool call proceeds.\n")
    except Exception as problem:  # never block on the guard's own failure (decision D28)
        sys.stderr.write("spellwarden_guard: " + type(problem).__name__ + "; the tool call proceeds.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''
