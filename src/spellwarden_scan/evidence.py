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
# One shell word: unquoted characters, and `"..."` (backslash escapes) or `'...'` segments that may hold spaces; a quote
# never closed runs to the end of the line. Possessive throughout, so a word is read once (Python 3.11+).
_SHELL_WORD = r"""(?:[^\s"']++|"(?:[^"\\\n]|\\.)*+"?|'[^'\n]*+'?)++"""
# A credential given as a command option (r0:F2, r1:F2): `-u user:pass`, `-uuser:pass`, a short-option cluster that ends
# in `u` (`-fsu user:pass`), `--user`, `--proxy-user` (and `-U`) keep the user name and mask the password to the end of
# its shell word; `--password`, `--http-password` and `--proxy-password` mask their whole word. A short option never
# starts inside a longer word or option (`--user-agent`, `sudo -u www-data` carry no `user:pass` and stay).
_USER_OPTION = re.compile(
    r"""(?<![\w-])(?:(?P<user>-(?:[A-Za-z]*[uU][ \t]+|[uU])|--(?:proxy-)?user(?:[ \t]+|=))"""
    r"""|(?P<password>--(?:http-|proxy-)?password(?:[ \t]+|=)))(?P<word>""" + _SHELL_WORD + ")")
# mysql's `-p<password>` (attached, no space) is masked only inside a mysql, mysqldump or mariadb command, up to the
# command's end (`|`, `;`, `&` or the end of the line outside quotes): elsewhere `-p` is too generic.
_MYSQL_COMMAND = re.compile(
    r"""(?<![\w.-])(?:mysql|mysqldump|mariadb)(?![\w.-])(?P<rest>(?:[ \t]++|[^\s"'|;&]++|"(?:[^"\\\n]|\\.)*+"?|'[^'\n]*+'?)*+)""")
_ATTACHED_P = re.compile(r"""(?<![\w-])-p(?P<word>""" + _SHELL_WORD + ")")
# A header that carries a credential (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`): the value is
# masked to the closing quote of its opening quote (the one after the `:`, else the one before the header name, as in
# `-H "Authorization: x"`) or, unquoted, to the end of the line. Only a known scheme word of an authorization header
# stays (Digest and AWS4 parameters after it are masked too); a cookie keeps no word. Idempotent.
_AUTH_HEADER = re.compile(
    r"""(?<![A-Za-z0-9_-])(?:(?P<auth>(?:proxy-)?authorization)|(?:set-)?cookie)["']?[ \t]*:[ \t]*(?P<quote>["']?)""", re.I)
_AUTH_SCHEME = re.compile(r"(?:bearer|basic|token|negotiate|digest|ntlm|aws4-hmac-sha256)[ \t]+", re.I)
_HEADER_VALUE = {'"': re.compile(r"""(?:[^"\\\n]|\\.)*+"""), "'": re.compile(r"[^'\n]*+"), "": re.compile(r"[^\n]*+")}
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


def _closes(word: str, start: int, quote: str) -> bool:
    """Whether the `quote` open at `word[start]` closes later in the word (a backslash escapes inside `"`)."""
    index = start
    while index < len(word):
        if quote == '"' and word[index] == "\\":
            index += 2
            continue
        if word[index] == quote:
            return True
        index += 1
    return False


def _mask_word(word: str, keep_user: bool) -> str:
    """The shell word with its secret masked: after the first `:` when `keep_user` (`user:***`, quotes and all; a word
    with no `:` names a user only and stays), otherwise whole. A quote open where the mask starts keeps its closing
    quote, so `'bob:pw two'` reads `'bob:***'`. Idempotent: the output masks to itself."""
    quote, index, split = "", 0, 0
    if keep_user:
        while index < len(word):
            char = word[index]
            if quote == '"' and char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
            elif not quote and char in "\"'":
                quote = char
            elif char == ":":
                break
            index += 1
        if index >= len(word):
            return word
        split = index + 1
    elif word[:1] in ("'", '"'):
        quote, split = word[0], 1
    return word[:split] + "***" + (quote if quote and _closes(word, split, quote) else "")


def _mask_user_option(match: re.Match) -> str:
    """`-u user:pass` keeps the option and the user name; `--password pass` keeps the option; the secret becomes `***`."""
    keep_user = match.group("user") is not None
    return match.group("user" if keep_user else "password") + _mask_word(match.group("word"), keep_user)


def _mask_mysql_command(match: re.Match) -> str:
    rest = _ATTACHED_P.sub(lambda m: "-p" + _mask_word(m.group("word"), keep_user=False), match.group("rest"))
    return match.group(0)[:match.start("rest") - match.start(0)] + rest


def _mask_auth_headers(text: str) -> str:
    """`Authorization: Token x` keeps the header name and a known scheme word; the rest of the value becomes `***`.
    One pass, each value read once, so a long line stays linear."""
    out: list[str] = []
    position = 0
    while (match := _AUTH_HEADER.search(text, position)) is not None:
        before = text[match.start() - 1] if match.start() else ""
        quote = match.group("quote") or (before if before in ("'", '"') else "")
        start = match.end()
        end = _HEADER_VALUE[quote].match(text, start).end()
        value = text[start:end]
        scheme = _AUTH_SCHEME.match(value) if match.group("auth") else None
        keep = scheme.end() if scheme else 0
        out.append(text[position:start] + value[:keep] + ("***" if value[keep:] else ""))
        position = end
    out.append(text[position:])
    return "".join(out)


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
    after the scheme word; the password of `-u user:pass` (`--user`, `--proxy-user`, a cluster
    such as `-fsu`), of `--password` and of mysql's `-p` to the end of its shell word (r1:F2),
    and the value of an Authorization, Proxy-Authorization or Cookie header are
    masked to its closing quote, keeping only a known scheme word (r0:F2); whatever is left after a secret-like name and `=`
    or `:` becomes `***`. Idempotent."""
    masked = _SCHEME.sub(lambda m: m.group(1) + " ***", text)
    masked = _mask_auth_headers(masked)
    masked = _USER_OPTION.sub(_mask_user_option, masked)
    masked = _MYSQL_COMMAND.sub(_mask_mysql_command, masked)
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
