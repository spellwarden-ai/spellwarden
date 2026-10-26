"""RFC 8785 JSON Canonicalization Scheme over the values `_json.load_json` produces (O4 spec 5.5).

`jcs_canonicalize(value)` returns the canonical UTF-8 bytes: object members sorted by the UTF-16 code units of their
names, no whitespace, strings escaped as RFC 8785 3.2.2.2 says, numbers written by the ECMAScript `Number.prototype.toString`
algorithm (RFC 8785 3.2.2.3). Two departures from the RFC, both refusals (`JcsError("number")`): a non-finite number and an
integer above 2**53 in magnitude. A signer whose parser reads integers as doubles signs a rounded value
(`9007199254740993` signs as `9007199254740992`); the scanner keeps the exact integer and refuses rather than guess.

Not to be confused with `canonical.canonical_sha256` (the package hash) or `packs.canonical_json` (the pack hash's sorted
`json.dumps`): neither is RFC 8785."""
from __future__ import annotations

import math
from typing import Any

MAX_INTEGER = 2**53

_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


class JcsError(ValueError):
    """`args[0]` is `number` (outside what the scanner canonicalises), `string` (not encodable) or `type`."""


def _string(text: str) -> str:
    out = ['"']
    for char in text:
        short = _SHORT.get(char)
        if short is not None:
            out.append(short)
        elif char < " ":
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _float(value: float) -> str:
    """ECMAScript `Number::toString` for a finite double (RFC 8785 3.2.2.3), from Python's shortest round-trip `repr`."""
    if value == 0:
        return "0"  # also -0
    sign = "-" if value < 0 else ""
    mantissa, _, exponent = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    everything = whole + fraction
    point = len(whole) + (int(exponent) if exponent else 0)
    stripped = everything.lstrip("0")
    point -= len(everything) - len(stripped)
    digits = stripped.rstrip("0")
    k, n = len(digits), point
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * -n + digits
    else:
        lead = digits[0] + ("." + digits[1:] if k > 1 else "")
        body = f"{lead}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"
    return sign + body


def _write(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, int):
        if abs(value) > MAX_INTEGER:
            raise JcsError("number")
        out.append(str(value))
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise JcsError("number")
        out.append(_float(value))
    elif isinstance(value, dict):
        out.append("{")
        for index, key in enumerate(sorted(value, key=lambda name: name.encode("utf-16-be", "surrogatepass"))):
            if index:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _write(value[key], out)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _write(item, out)
        out.append("]")
    else:
        raise JcsError("type")


def jcs_canonicalize(value: Any) -> bytes:
    out: list[str] = []
    _write(value, out)
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError:
        raise JcsError("string") from None
