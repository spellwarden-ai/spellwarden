"""The source of `spellwarden_gateway_guard.py` (1.15.0), the interceptor the Docker MCP Gateway export installs, as one string
`docker_gateway.guard_script` fills in. The engine opens no file, so the guard's source lives here as text; the placeholders
`__PACK__`, `__VERSION__`, `__VERBS__`, `__PATTERNS__` and `__INVISIBLE__` are replaced in one pass with ASCII Python literals
(`ascii()`). The guard is standard-library Python 3.8 or newer, run by the gateway as `python3 -I <guard> before`
or `... after` (`--interceptor=before:exec:...`), reads one JSON object on stdin and fails closed: what it cannot read is
answered with an error result, never let through (phase 3 batch 2b spec, D29).

The interceptor contract is the one Docker documents only in `examples/interceptors/README.md` of Docker MCP Gateway v0.44.3
and implements in `pkg/interceptors/interceptors.go`: `before` gets the `tools/call` request and `after` the `CallToolResult` as
JSON on stdin; a JSON object on stdout replaces the call or the result (the gateway unmarshals it as a `CallToolResult`); nothing
on stdout lets it go on; an interceptor that fails fails the call. Run at v0.44.3, the request is the Go value as marshalled,
`{"Session": {}, "Params": {"name": ..., "arguments": ...}, "Extra": null}`, not the `params` the README reads (the vendored
captures in `tests/fixtures/gateways/docker-v0.44.3/`), and with `--transport=streaming` the gateway cannot marshal the request
at all, so a `before` interceptor fails every tool call: the export runs the gateway with `--transport=sse` or stdio."""

TEMPLATE = r'''#!/usr/bin/env python3
"""Spellwarden guard for Docker MCP Gateway interceptors (checked against v0.44.3), generated from a Spellwarden policy pack.

Run as `python3 -I spellwarden_gateway_guard.py before` (a tool call) or `... after` (its result). Standard library only,
Python 3.8 or newer, no network. Input it cannot read is answered with an error result (fail closed).
"""
import json
import re
import sys
import unicodedata

PACK = __PACK__
VERSION = __VERSION__
VERBS = __VERBS__
PATTERNS = [(rule_id, re.compile(source, re.IGNORECASE)) for rule_id, source in __PATTERNS__]
INVISIBLE = re.compile(__INVISIBLE__)
MAX_INPUT = 1024 * 1024
NAME_SHOWN = 200


def shown(name):
    """A tool name as it may appear in a message: printable ASCII, other characters as `?`, at most 200 characters."""
    return "".join(char if " " <= char <= "~" else "?" for char in name)[:NAME_SHOWN]


def error_result(text):
    return {"content": [{"type": "text", "text": text}], "isError": True}


def decide(text, rule_id, name):
    """The error result that replaces a call or a result, and the one line the guard writes on standard error."""
    sys.stdout.write(json.dumps(error_result(text)) + "\n")
    sys.stderr.write("spellwarden: blocked " + rule_id + " " + shown(name) + "\n")


def destructive(name):
    """SW-GW-006: the name starts with a verb or holds it as a `_`- or `-`-separated word (the hooks export's `mcp_verb`)."""
    lowered = name.lower()
    words = [word for word in re.split(r"[_-]+", lowered) if word]
    return any(lowered.startswith(verb) or verb in words for verb in VERBS)


def visible(text):
    """`text` as an agent reads it: invisible and format characters removed, NFKC, whitespace collapsed."""
    text = INVISIBLE.sub("", text)
    text = "".join(char for char in text if unicodedata.category(char) != "Cf")
    return " ".join(unicodedata.normalize("NFKC", text).split())


def strings(value, found):
    """Every string inside a JSON value, keys included."""
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for key, inner in value.items():
            found.append(key)
            strings(inner, found)
    elif isinstance(value, list):
        for inner in value:
            strings(inner, found)
    return found


def result_texts(result):
    """The text content and the strings of `structuredContent` of a `CallToolResult`."""
    texts = []
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                texts.append(item["text"])
    strings(result.get("structuredContent"), texts)
    return texts


def read_message():
    data = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError("the input is larger than 1 MiB")
    message = json.loads(data.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("the input is not a JSON object")
    return message


def blocked_unreadable(reason):
    decide("Spellwarden policy " + PACK + " " + VERSION + " blocked this tool call: the guard could not read it (" + reason
           + ").", "unreadable", "-")


def before(message):
    # v0.44.3 writes the Go request as it is, `{"Session": {}, "Params": {"name": ..., "arguments": ...}, "Extra": null}`; the
    # examples README reads `.params`. Either key is read.
    params = message.get("Params", message.get("params"))
    name = params.get("name") if isinstance(params, dict) else None
    if not isinstance(name, str):
        blocked_unreadable("the request names no tool")
        return
    if destructive(name):
        decide("Spellwarden policy " + PACK + " " + VERSION + " blocked the tool " + shown(name) + ": SW-GW-006 asks a person "
               "to approve destructive tools, and this gateway cannot ask.", "SW-GW-006", name)


def after(message):
    text = "\n".join(visible(part) for part in result_texts(message))
    for rule_id, pattern in PATTERNS:
        if pattern.search(text):
            decide("Spellwarden policy " + PACK + " " + VERSION + " replaced a tool result: " + rule_id + " found "
                   "instructions aimed at the model in it.", rule_id, "-")
            return


def main(argv):
    phase = argv[1] if len(argv) == 2 else ""
    if phase not in ("before", "after"):
        sys.stderr.write("spellwarden: usage: spellwarden_gateway_guard.py before|after\n")
        return 2
    try:
        message = read_message()
    except (ValueError, RecursionError) as exc:  # a JSON or UTF-8 decoding error is a ValueError too
        blocked_unreadable(str(exc) if str(exc).startswith("the input ") else "the input is not JSON")
        return 0
    (before if phase == "before" else after)(message)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''

__all__ = ["TEMPLATE"]
