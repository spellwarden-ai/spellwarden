"""Evidence excerpts, credential masking, fingerprints (spec 5.10)."""
from __future__ import annotations

import hashlib
import re
import unicodedata

from spellwarden_scan.rules.patterns import ASSIGNED_SECRET, ASSIGNED_VALUE, CREDENTIAL_PATTERNS, PLACEHOLDER_VALUE

EVIDENCE_MAX = 300
# Spec 5.10: a run of 20 or more characters of `[A-Za-z0-9_\-+/=]` that does not continue an earlier run; `=` is part of
# the run wherever it sits, so `token=abcd1234abcd1234` is one run and is masked whole (a short secret after `=` never leaks).
_MIXED_RUN = re.compile(r"(?<![A-Za-z0-9_\-+/=])[A-Za-z0-9_\-+/=]{20,}")
_SCHEME = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]+")  # any length: the scheme word is the tell (spec 5.10)
# `scheme://user:password@host`: the password, whatever its shape, before the last `@` of the authority (spec 5.10)
_URL_PASSWORD = re.compile(r"(://[^/\s@:]*:)(?!\*\*\*@)[^/\s]+@")
# Any other userinfo of a URL, token-only included (`git+https://tok@github.com/x`) and the backslash forms the
# password rule above does not read (`http:\\u:p@h`): from the scheme's `:` and its run of `/` or `\` to the `@`,
# masked whole as `<scheme>://***@`. A `user:***@` the password rule already wrote is left as it is. Bounded and
# anchored at a scheme's start, so a long line reads in linear time (test_linear_time).
_URL_USERINFO = re.compile(r"(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{0,31}):[/\\]{0,8}([^/\\@\s]{1,256})@")
_HAS_LETTER = re.compile(r"[A-Za-z]")
_HAS_DIGIT = re.compile(r"[0-9]")


def _mask_match(match: re.Match) -> str:
    text = match.group(0)
    if text.endswith("***"):
        return text
    return text[:4] + "***"


def _mask_run(match: re.Match) -> str:
    text = match.group(0)
    if text.endswith("***") or not (_HAS_LETTER.search(text) and _HAS_DIGIT.search(text)):
        return text
    return text[:4] + "***"


def _mask_assigned(match: re.Match) -> str:
    """A quoted secret assignment keeps its name and quotes; the value becomes its first four characters and `***`."""
    whole, value = match.group(0), match.group(2)
    start = match.start(2) - match.start(0)
    return whole[:start] + value[:4] + "***" + whole[start + len(value):]


def _mask_userinfo(match: re.Match) -> str:
    if match.group(2).endswith(":***"):  # the password rule's own output keeps its user name
        return match.group(0)
    return match.group(1) + "://***@"


def _mask_value(match: re.Match) -> str:
    """Any value assigned to a secret-like name, quoted or not and of any length, becomes `***` (a short or
    letters-only password is still a password); a placeholder such as `$TOKEN` or `<your-key>` stays readable."""
    value = match.group(3)
    quote = value[:3] if value[:3] in ('"""', "'''") else value[:1] if value[:1] in ("'", '"') else ""
    closed = bool(quote) and len(value) >= 2 * len(quote) and value.endswith(quote)
    inner = value[len(quote):len(value) - len(quote)] if closed else value[len(quote):]
    if inner in ("", "***") or PLACEHOLDER_VALUE.fullmatch(inner):  # only this function's own output counts as masked
        return match.group(0)
    # A quoted value is masked to its closing quote; one never closed, to the end of the line.
    return match.group(1) + match.group(2) + quote + "***" + (quote if closed else "")


def mask_credentials(text: str) -> str:
    """Every SW-SKL-011 pattern and every 20+ character mixed run becomes its
    first four characters and `***`; `Bearer` and `Basic` tokens are masked
    after the scheme word; whatever is left after a secret-like name and `=`
    or `:` becomes `***`. Idempotent."""
    masked = _SCHEME.sub(lambda m: m.group(1) + " ***", text)
    masked = ASSIGNED_SECRET.sub(_mask_assigned, masked)
    for pattern in CREDENTIAL_PATTERNS:
        masked = pattern.sub(_mask_match, masked)
    masked = _MIXED_RUN.sub(_mask_run, masked)
    masked = _URL_PASSWORD.sub(r"\1***@", masked)
    masked = _URL_USERINFO.sub(_mask_userinfo, masked)
    return ASSIGNED_VALUE.sub(_mask_value, masked)


def bounded_evidence(text: str) -> str:
    """The one way evidence is made (spec 5.10): collapsed to single spaces, masked, and at most
    `EVIDENCE_MAX` characters in all (cut to 297 and `...` appended). Every finding's evidence,
    custom text included, goes through it."""
    collapsed = " ".join(str(text).split())
    masked = mask_credentials(collapsed)
    if len(masked) > EVIDENCE_MAX:
        return masked[:EVIDENCE_MAX - 3] + "..."
    return masked


def excerpt(line: str) -> str:
    """The matched line as evidence: `bounded_evidence` of the line."""
    return bounded_evidence(line)


def fingerprint(rule_id: str, path: str, matched: str) -> str:
    """sha256 hex of `rule_id NUL path NUL matched` (spec 5.2): triage carry-over keys on it.
    `matched` is always the original matched text, never masked evidence, so two different
    credentials on otherwise identical lines never share a fingerprint."""
    return hashlib.sha256(f"{rule_id}\x00{path}\x00{matched}".encode()).hexdigest()


def code_point_names(text: str) -> str:
    """`U+200B ZERO WIDTH SPACE, ...` for the distinct hidden characters of `text` (SW-SKL-002)."""
    seen: list[str] = []
    for char in text:
        if unicodedata.category(char) not in ("Cf", "Cc", "Co", "Cn", "Zl", "Zp", "Mn") and char not in "\ufeff\u115f\u3164":
            continue
        label = f"U+{ord(char):04X} {unicodedata.name(char, 'UNNAMED')}"
        if label not in seen:
            seen.append(label)
    return ", ".join(seen)
