"""The 17 skill rules of spec 5.3. Each `detect(package)` is a generator of
`Finding`s: one per matching line (or per file for SW-SKL-010), the evidence
the matched line (masked), the fingerprint `rule_id NUL path NUL line`."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Iterable, Iterator

from spellwarden_scan.evidence import bounded_evidence, code_point_names, excerpt, fingerprint
from spellwarden_scan.frontmatter import FrontmatterError, parse_frontmatter
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.package import SCRIPT_EXTENSIONS, CodeBlock, Package, TextFile
from spellwarden_scan.rules import Rule, make_rule
from spellwarden_scan.rules import patterns as P

_I = re.IGNORECASE


def _finding(rule_id: str, severity: str, title: str, path: str, line: int | None, matched: str, *,
             malicious: bool = False, evidence: str | None = None) -> Finding:
    """`matched` is the original matched text: the fingerprint is computed from it (spec 5.2).
    The evidence is `excerpt(matched)`, or the custom `evidence`, and in both cases goes through
    `bounded_evidence` (masked, collapsed, at most 300 characters; spec 5.10)."""
    shown = excerpt(matched) if evidence is None else bounded_evidence(evidence)
    return Finding(rule_id, severity, title, Location(path, line), shown, fingerprint(rule_id, path, matched), malicious)


def _numbered(unit: TextFile | CodeBlock) -> Iterator[tuple[str, int, str]]:
    """`(path, line number, line)` of a text file or of a fenced block (numbered in its file)."""
    if isinstance(unit, CodeBlock):
        for offset, line in enumerate(unit.lines):
            yield unit.path, unit.first_line + offset, line
    else:
        for number, line in enumerate(unit.lines, start=1):
            yield unit.path, number, line


_CONTINUES = ("|", "&&", "||")


def _is_script(unit: TextFile | CodeBlock) -> bool:
    return isinstance(unit, CodeBlock) or unit.path.lower().endswith(SCRIPT_EXTENSIONS)


def logical_commands(unit: TextFile | CodeBlock) -> Iterator[tuple[str, int, str]]:
    """One shell command per item, `(path, first line, command text)`: a line with a trailing backslash is joined
    to the next, and in a script or a fenced code block so is a line ending in `|`, `&&` or `||` (the shell reads
    on). Markdown prose is joined at backslashes only (a table row ends in `|`). The one normalisation step of the
    skill rules and the hook rules (spec 5.4): a hook command is passed as `CodeBlock(path, "sh", command, line)`,
    so it is joined exactly like the same text in a script."""
    pending: list[str] = []
    start = 0
    path = unit.path
    operators = _is_script(unit)
    for path, number, line in _numbered(unit):
        if not pending:
            start = number
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            pending.append(stripped[:-1])
            continue
        if operators and stripped.endswith(_CONTINUES):
            pending.append(stripped)
            continue
        pending.append(line)
        yield path, start, " ".join(pending)
        pending = []
    if pending:
        yield path, start, " ".join(pending)


def _lines_matching(units, pattern: re.Pattern, rule_id: str, severity: str, title: str, *, malicious: bool = False):
    for path, number, line in (entry for unit in units for entry in _numbered(unit)):
        if pattern.search(line):
            yield _finding(rule_id, severity, title, path, number, line, malicious=malicious)


# --- SW-SKL-001 ------------------------------------------------------------------------------

def _skl_001(package: Package) -> Iterator[Finding]:
    for unit in package.instructions():
        for path, number, line in _numbered(unit):
            seen = visible(line)
            if any(p.search(seen) for p in P.INJECTION):
                yield _finding("SW-SKL-001", "high", TITLES["SW-SKL-001"], path, number, line)


# --- SW-SKL-002 ------------------------------------------------------------------------------

# Spec 5.3, plus the characters that hide text the same way: the combining grapheme joiner, the Hangul fillers, the
# Mongolian vowel separator, the line and paragraph separators, the interlinear annotation marks, the tag block
# U+E0000 to U+E007F ("ASCII smuggling") and the variation selectors supplement U+E0100 to U+E01EF (bytes hidden
# behind an emoji); a basic variation selector U+FE00 to U+FE0F when two or more follow each other, or one follows a
# character that takes none (`_stray_selectors`: emoji and symbols take one, U+FE0F after an emoji is ordinary).
# The soft hyphen is not flagged (ordinary in text copied from a word processor); `_visible` drops it before matching.
_HIDDEN = re.compile("[\u034f\u115f\u180b-\u180f\u200b-\u200f\u2028\u2029\u2060-\u2064\u202a-\u202e\u2066-\u2069\u3164\ufeff\uffa0"
                     "\ufff9-\ufffb\U000e0000-\U000e007f\U000e0100-\U000e01ef]|[\ufe00-\ufe0f]{2,}")
_SELECTOR = re.compile("[\ufe00-\ufe0f]")
_KEYCAP_BASES = frozenset("0123456789#*")
_KEYCAP = "\u20e3"
# Emoji bases outside the symbol categories (emoji-variation-sequences.txt): ℹ (Ll), ‼ ⁉ 〽 (Po), 〰 (Pd).
_EMOJI_BASES = frozenset("\u2139\u203c\u2049\u3030\u303d")
_ZWJ = "\u200d"


def _emoji_base(char: str) -> bool:
    """An emoji base: an `So` or `Sm` symbol (❤, ↔, ◻), one of `_EMOJI_BASES`, or a character of the emoji
    blocks U+1F000 to U+1FAFF; never a currency or modifier symbol and nothing above those blocks (tags, selectors)."""
    if not char:
        return False
    return unicodedata.category(char) in ("So", "Sm") or char in _EMOJI_BASES or "\U0001f000" <= char <= "\U0001faff"


def _ideograph(char: str) -> bool:
    return "\u3400" <= char <= "\u9fff" or "\uf900" <= char <= "\ufaff"


def hidden_characters(text: str) -> list[str]:
    """Every hidden character of a line: `_HIDDEN`, every other format character (`Cf`) but the soft hyphen, and the
    stray variation selectors; a joiner inside an emoji sequence is not one."""
    if text.isascii():
        return []
    joined = _without_emoji_joiners(text)
    found = _HIDDEN.findall(joined)
    found += [char for char in joined if unicodedata.category(char) == "Cf" and char != "\u00ad" and not _HIDDEN.fullmatch(char)]
    if "\ufe00" <= max(text):
        found += _stray_selectors(text)
    return found


def _without_emoji_joiners(line: str) -> str:
    """A zero-width joiner inside an emoji sequence (an emoji, optionally its selector or modifier, the joiner,
    the next emoji: 👨\u200d💻, 🏳\ufe0f\u200d🌈) is how those emoji are written; only a joiner elsewhere is hidden text."""
    if _ZWJ not in line:
        return line
    kept: list[str] = []
    for index, char in enumerate(line):
        if char == _ZWJ:
            before = line[index - 1] if index else ""
            if before in ("\ufe0f",) or "\U0001f3fb" <= before <= "\U0001f3ff":  # a selector or a skin-tone modifier
                before = line[index - 2] if index > 1 else ""
            after = line[index + 1] if index + 1 < len(line) else ""
            if _emoji_base(before) and _emoji_base(after):
                continue
        kept.append(char)
    return "".join(kept)


def _stray_selectors(line: str) -> list[str]:
    """Single basic variation selectors that no standard sequence explains. U+FE0E and U+FE0F (text and emoji
    presentation) are ordinary after an emoji or other `So` symbol, or after a keycap base that a U+20E3 follows;
    U+FE00 to U+FE0D only after a CJK ideograph (the ideographic variants). Anywhere else a selector only hides
    data; the selector opening a line has no base and counts too."""
    stray: list[str] = []
    for match in _SELECTOR.finditer(line):
        start, selector = match.start(), match.group(0)
        base = line[start - 1] if start else ""
        if "\ufe00" <= base <= "\ufe0f":
            continue  # part of a run, which `_HIDDEN` reports
        if selector in "\ufe0e\ufe0f":
            keycap = base in _KEYCAP_BASES and line[start + 1:start + 2] == _KEYCAP
            if _emoji_base(base) or keycap:
                continue
        elif base and _ideograph(base):
            continue
        stray.append(selector)
    return stray
# Every format character and the soft hyphen, removed before the injection phrases are matched (SW-SKL-001,
# SW-MCP-011): `ig\u00adnore previous instructions` reads as the phrase to an agent.
_INVISIBLE = re.compile("[\u00ad\u034f\u115f\u180b-\u180f\u200b-\u200f\u2060-\u2064\u202a-\u202e\u2066-\u2069\u3164\ufeff\uffa0\ufe00-\ufe0f"
                        "\ufff9-\ufffb\U000e0000-\U000e007f\U000e0100-\U000e01ef]")


def visible(text: str) -> str:
    """`text` without the characters `_INVISIBLE` names and without every other format character (`Cf`: U+061C,
    U+1BCA0 and the rest), as an agent reads it."""
    text = _INVISIBLE.sub("", text)
    if text.isascii():
        return text
    return "".join(char for char in text if unicodedata.category(char) != "Cf")


def _skl_002(package: Package) -> Iterator[Finding]:
    for unit in package.text_files:
        for number, line in enumerate(unit.lines, start=1):
            text = line[1:] if number == 1 and line.startswith("\ufeff") else line
            hidden = hidden_characters(text)
            if hidden:
                names = code_point_names("".join(hidden))
                yield _finding("SW-SKL-002", "high", TITLES["SW-SKL-002"], unit.path, number, names, evidence=names)


# --- SW-SKL-003 ------------------------------------------------------------------------------

# Every gap of an unbounded `.*` or `[^x]*` is a `P.Then`, `P.Within` or `P.Piped` (linear on any line; the regex
# form backtracks quadratically on a line that repeats the first half). The matched text is never used.
_SKIP = P.AnyOf(re.compile(
    r"(skip (the |any |all )?(approval|approvals|confirmation|confirmations|permission|permissions|review)|"
    r"--dangerously-skip-permissions|bypassPermissions|(disable|remove|turn off|delete) (the |all |any )?hooks?\b|"
    r"(allow|permit) (all|every) tools?\b|"
    r"defaultMode\"?\s*:\s*\"?(bypassPermissions|dontAsk))", _I),
    P.Within(r"\"permissions\"\s*:\s*\{", r"\"allow\"\s*:\s*\[\s*\"\*\"", "}"))


def _skl_003(package: Package) -> Iterator[Finding]:
    yield from _lines_matching(package.text_files, _SKIP, "SW-SKL-003", "high", TITLES["SW-SKL-003"])


# --- SW-SKL-004 ------------------------------------------------------------------------------

_DECODER = re.compile(r"(base64 (-d|--decode|-D)\b|b64decode\(|atob\(|openssl enc -d|xxd -r|gunzip -c|\bzcat\b)", _I)
_EXECUTOR = re.compile(
    r"(\| *(sudo +)?(sh|bash|zsh|python[0-9.]*|node|perl|ruby)\b|\beval\(|\bexec\(|subprocess|os\.system|child_process|"
    r"new Function\(|\bsh -c\b)", _I)


def decodes_and_runs(commands: Iterable[tuple[str, int, str]]) -> Iterator[tuple[str, int, str]]:
    """The SW-SKL-004 test over `logical_commands` output: a decoder and an executor in one command."""
    for path, number, text in commands:
        if _DECODER.search(text) and _EXECUTOR.search(text):
            yield path, number, text


def _skl_004(package: Package) -> Iterator[Finding]:
    for unit in package.scripts():
        # `... | base64 -d \` then `| sh`: one command
        for path, number, line in decodes_and_runs(logical_commands(unit)):
            yield _finding("SW-SKL-004", "critical", TITLES["SW-SKL-004"], path, number, line, malicious=True)


# --- SW-SKL-005 ------------------------------------------------------------------------------

_WRITE_VERB = P.AnyOf(re.compile(
    r"(>>?|\btee\b|sed -i|\bcp\b|\bmv\b|write_text|writeFile|"
    r"\b(edit|add to|append to|modify|update|write to|replace)\b (the |your )?)", _I),
    P.Within(r"open\(", r"[\"'][wa][\"']", ")"), P.Then(r"\bjq\b", r">"))
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


def _skl_005(package: Package) -> Iterator[Finding]:
    for unit in package.text_files:
        for number, line in enumerate(unit.lines, start=1):
            for sentence in _SENTENCE.split(line):
                if P.AGENT_CONFIG_PATHS.search(sentence) and _WRITE_VERB.search(sentence):
                    yield _finding("SW-SKL-005", "high", TITLES["SW-SKL-005"], unit.path, number, line)
                    break


# --- SW-SKL-006 ------------------------------------------------------------------------------

_DESTRUCTIVE = P.AnyOf(re.compile(
    r"(\brm -[a-z]*r[a-z]*f\b|\brm -[a-z]*f[a-z]*r\b|git reset --hard|git clean -[a-z]*f|"
    r"\bdrop (table|database|schema)\b|\btruncate table\b|kubectl delete|terraform destroy|"
    r"gsutil (rm|rb) -r|\bmkfs\b|\bdd if=|\bshred\b|chmod -R 777|:\(\)\{ :\|:& \};:)", _I),
    P.Then(r"git push ", r"(--force|-f)\b"), P.Then(r"aws s3 (rm|rb) ", r"(--recursive|--force)"),
    P.Then(r"\baz ", r" delete\b"))
_CONFIRMED = re.compile(r"(confirm|\bask\b|approval|approve|only if the user|after the user|prompt the user|--dry-run)", _I)


def _skl_006(package: Package) -> Iterator[Finding]:
    for unit in package.scripts():
        entries = list(logical_commands(unit))
        for index, (path, number, line) in enumerate(entries):
            if not _DESTRUCTIVE.search(line):
                continue
            window = [entry[2] for entry in entries[max(0, index - 3):index + 1]]
            if any(_CONFIRMED.search(text) for text in window):
                continue
            yield _finding("SW-SKL-006", "medium", TITLES["SW-SKL-006"], path, number, line)


# --- SW-SKL-007 ------------------------------------------------------------------------------

_PIPED = P.AnyOf(
    P.Piped(r"(curl|wget|fetch|Invoke-WebRequest|iwr)\b",
            r"\s*(sudo\s+)?(sh|bash|zsh|ksh|python[0-9.]*|node|perl|ruby|pwsh|powershell|iex)\b"),
    re.compile(r"((sh|bash|zsh) -c [\"']?\$\((curl|wget)|(sh|bash|zsh) <\((curl|wget))", _I),
    P.Then(r"iex ?\(", r"(iwr|Invoke-WebRequest|DownloadString)"))


def pipes_remote_to_shell(commands: Iterable[tuple[str, int, str]]) -> Iterator[tuple[str, int, str]]:
    """The SW-SKL-007 test over `logical_commands` output: remote content piped to an interpreter."""
    for path, number, text in commands:
        if _PIPED.search(text):
            yield path, number, text


def _skl_007(package: Package) -> Iterator[Finding]:
    # A fenced block is read as a script (joined at `|`, `&&` and `||`); the prose of its Markdown file skips the
    # block's lines, so a command is reported once, at its first line, by whichever view holds it.
    fenced: set[tuple[str, int]] = {(block.path, block.first_line + offset)
                                    for block in package.code_blocks for offset in range(len(block.lines))}
    for unit in (*package.text_files, *package.code_blocks):
        prose = not isinstance(unit, CodeBlock)
        # `curl ... |` then `sh` on the next line is one pipe
        commands = (entry for entry in logical_commands(unit) if not (prose and (entry[0], entry[1]) in fenced))
        for path, number, line in pipes_remote_to_shell(commands):
            yield _finding("SW-SKL-007", "high", TITLES["SW-SKL-007"], path, number, line)


# --- SW-SKL-008 ------------------------------------------------------------------------------

_SEND = P.AnyOf(
    re.compile(r"(\bnc\b|\bncat\b|\bnetcat\b|requests\.(post|put)\(|axios\.(post|put)\()", _I),
    P.Then(r"curl ", r"(-d|--data|--data-binary|-F|--form|-T|--upload-file)\b"), P.Then(r"wget ", r"--post-(data|file)"),
    P.Then(r"fetch\(", r"method:\s*[\"'](POST|PUT)"), P.Then(r"\bscp ", r" [^ @]+@"), P.Then(r"\brsync ", r" [^ @]+@"),
    P.Then(r"Invoke-RestMethod ", r"-Method (Post|Put)"))


def sends_file_contents(commands: Iterable[tuple[str, int, str]]) -> Iterator[tuple[str, int, str]]:
    """The SW-SKL-008 test over `logical_commands` output: a secret path and a sending command in one command."""
    for path, number, text in commands:
        if P.SECRET_PATHS.search(text) and _SEND.search(text):
            yield path, number, text


def skl_008_lines(package: Package) -> set[tuple[str, int]]:
    """`(path, line)` of every SW-SKL-008 match, shared with SW-SKL-012."""
    hits: set[tuple[str, int]] = set()
    for unit in package.text_files:
        for path, number, _text in sends_file_contents(logical_commands(unit)):
            hits.add((path, number))
    return hits


def _skl_008(package: Package) -> Iterator[Finding]:
    for unit in package.text_files:
        for path, number, text in sends_file_contents(logical_commands(unit)):
            yield _finding("SW-SKL-008", "critical", TITLES["SW-SKL-008"], path, number, text, malicious=True)


# --- SW-SKL-009 ------------------------------------------------------------------------------

_PIP = re.compile(r"\b(pip3?|uv pip|pipx) install\b(.*)", _I)
_NPM = re.compile(r"\b(npm (install|i|add)|yarn add|pnpm add)\b(.*)", _I)
_NPX = re.compile(r"\bnpx\s+(.*)", _I)
_GO = P.Then(r"\bgo install\b", r"@latest\b")
_CARGO = re.compile(r"\bcargo install\b(.*)", _I)
_GEM = re.compile(r"\bgem install\b(.*)", _I)
_BREW = re.compile(r"\bbrew install\b", _I)
_APT = re.compile(r"\bapt(-get)? install\b(.*)", _I)
_PIP_SKIP_NEXT = {"-r", "--requirement", "-e", "--editable", "-c", "--constraint", "-i", "--index-url", "-t", "--target"}


def _args(text: str) -> list[str]:
    return [token for token in text.split() if token not in ("&&", "||", ";", "|")]


def _is_path_or_url(token: str) -> bool:
    return token.startswith((".", "/", "~")) or "://" in token or token.startswith("git+") or token.endswith((".tgz", ".whl", ".tar.gz"))


def _unpinned_pip(rest: str) -> bool:
    tokens = _args(rest)
    skip = False
    for token in tokens:
        if skip:
            skip = False
            continue
        if token in _PIP_SKIP_NEXT:
            skip = True
            continue
        if token.startswith("-") or _is_path_or_url(token):
            continue
        if "==" not in token and "===" not in token and "@" not in token:
            return True
    return False


def _unpinned_npm(rest: str) -> bool:
    found_package = False
    for token in _args(rest):
        if token.startswith("-") or _is_path_or_url(token):
            continue
        if "/" in token and not token.startswith("@"):
            continue
        found_package = True
        name = token[1:] if token.startswith("@") else token
        if "@" not in name:
            return True
    return found_package and False


def _unpinned_npx(rest: str) -> bool:
    for token in _args(rest):
        if token.startswith("-"):
            continue
        name = token[1:] if token.startswith("@") else token
        return "@" not in name
    return False


def _skl_009(package: Package) -> Iterator[Finding]:
    for unit in package.scripts():
        for path, number, line in logical_commands(unit):
            fires = False
            if (m := _PIP.search(line)) and _unpinned_pip(m.group(2)):
                fires = True
            elif (m := _NPM.search(line)) and _unpinned_npm(m.group(3)):
                fires = True
            elif (m := _NPX.search(line)) and _unpinned_npx(m.group(1)):
                fires = True
            elif _GO.search(line):
                fires = True
            elif (m := _CARGO.search(line)) and "--version" not in m.group(1) and _args(m.group(1)):
                fires = True
            elif (m := _GEM.search(line)) and " -v" not in m.group(1) and "--version" not in m.group(1) and _args(m.group(1)):
                fires = True
            elif _BREW.search(line):
                fires = True
            elif (m := _APT.search(line)) and any("=" not in t for t in _args(m.group(2)) if not t.startswith("-")):
                fires = True
            if fires:
                yield _finding("SW-SKL-009", "medium", TITLES["SW-SKL-009"], path, number, line)


# --- SW-SKL-010 ------------------------------------------------------------------------------

_BINARY_EXTENSIONS = (".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".pyc", ".pyo", ".class", ".jar", ".war", ".wasm",
                      ".apk", ".msi", ".deb", ".rpm", ".pkg", ".dmg", ".com", ".scr", ".sys", ".drv", ".elf")
_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def _skl_010(package: Package) -> Iterator[Finding]:
    seen: set[str] = set()
    for binary in package.binary_files:
        if binary.path.lower().endswith(_BINARY_EXTENSIONS) or binary.head.startswith(_MAGIC):
            seen.add(binary.path)
    for text in package.text_files:
        if text.path.lower().endswith(_BINARY_EXTENSIONS) or text.head.startswith(_MAGIC):
            seen.add(text.path)
    seen.update(package.executable_paths)
    for path in sorted(seen):
        yield _finding("SW-SKL-010", "medium", TITLES["SW-SKL-010"], path, None, path, evidence=path)


# --- SW-SKL-011 ------------------------------------------------------------------------------

def has_credential(line: str) -> bool:
    if any(p.search(line) for p in P.CREDENTIAL_PATTERNS):
        return True
    match = P.ASSIGNED_SECRET.search(line)
    return bool(match) and P.PLACEHOLDER.search(match.group(2)) is None


def _skl_011(package: Package) -> Iterator[Finding]:
    for unit in package.text_files:
        for number, line in enumerate(unit.lines, start=1):
            if has_credential(line):
                # The fingerprint comes from the original line; `_finding` masks the evidence itself.
                yield _finding("SW-SKL-011", "critical", TITLES["SW-SKL-011"], unit.path, number, line)


# --- SW-SKL-012 ------------------------------------------------------------------------------

_READ_CONTEXT = re.compile(r"(\bcat\b|\bread\b|open\(|\bsource\b|Get-Content|\bload\b|read the|look in|use the credentials in)", _I)
_PURPOSE = re.compile(r"(because|so that|in order to|needed to|required for|to authenticate|to sign|\bwhy\b)", _I)


def _skl_012(package: Package) -> Iterator[Finding]:
    exfiltrated = skl_008_lines(package)
    for unit in package.text_files:
        lines = unit.lines
        for number, line in enumerate(lines, start=1):
            if (unit.path, number) in exfiltrated:
                continue
            if not (P.SECRET_PATHS.search(line) or P.MORE_SECRET_PATHS.search(line)) or not _READ_CONTEXT.search(line):
                continue
            window = lines[max(0, number - 3):number]
            if any(_PURPOSE.search(text) for text in window):
                continue
            yield _finding("SW-SKL-012", "medium", TITLES["SW-SKL-012"], unit.path, number, line)


# --- SW-SKL-013 ------------------------------------------------------------------------------

# The authority up to `/`, `?`, `#` or whitespace. A browser (WHATWG) also ends it at `\\`, curl (RFC 3986) does not:
# both readings are checked, so `https://github.com\\@bit.ly/` is the shortener for curl and is flagged.
# A browser also accepts `https:host`, `https:/\\host` and a percent-encoded host; quotes, backticks, brackets and
# list punctuation around a URL in code or Markdown end the authority.
_URL_AUTHORITY = re.compile(r"https?:[/\\]*([^/\s?#\"'`<>(){},;]+)", _I)
_DOC_RANGES = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"),
               ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("2001:db8::/32"))


_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")


def _percent_decoded(text: str) -> str:
    """`%2E` and the like decoded as a browser decodes a host (UTF-8 when the bytes form it)."""
    if "%" not in text:
        return text
    raw = _PERCENT.sub(lambda m: chr(int(m.group(1), 16)), text)
    try:
        return raw.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return raw


def _host_of(authority: str) -> str:
    """The host a client connects to: userinfo dropped (`https://github.com@203.0.113.9/` goes to the
    IP), the port dropped, IPv6 brackets removed, a trailing dot removed (`bit.ly.` is `bit.ly`)."""
    # UTS 46 folding as a browser applies it: full-width digits and dots (NFKC), the ideographic and halfwidth
    # full stops, case. `ｂｉｔ．ｌｙ` and `１２７。０。０。１` are the hosts they look like.
    host = _percent_decoded(authority.rsplit("@", 1)[-1])
    host = unicodedata.normalize("NFKC", host).replace("\u3002", ".").replace("\uff61", ".").lower()
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end > 0 else host[1:]
    return host.split(":", 1)[0].rstrip(".")


def _legacy_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """`inet_aton` forms that curl and browsers resolve: one to four parts, each decimal, octal (leading `0`)
    or hex (`0x`), the last part filling the remaining bytes (`127.1`, `2130706433`, `0x7f.0.0.1`)."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values: list[int] = []
    for part in parts:
        if part[:2].lower() == "0x":
            digits, base = part[2:], 16
        elif len(part) > 1 and part.startswith("0"):
            digits, base = part[1:], 8
        else:
            digits, base = part, 10
        allowed = "0123456789abcdefABCDEF" if base == 16 else "0123456789"[:base]
        if not digits or len(digits) > 12 or not all(c in allowed for c in digits):
            return None
        values.append(int(digits, base))
    *head, last = values
    if any(value > 255 for value in head) or last >= 256 ** (5 - len(values)):
        return None
    number = 0
    for value in head:
        number = number * 256 + value
    return ipaddress.IPv4Address((number << (8 * (5 - len(values)))) + last)


def _suspicious_host(authority: str) -> bool:
    bare = _host_of(authority)
    try:
        address = ipaddress.ip_address(bare)
    except ValueError:
        address = _legacy_ipv4(bare)
    if address is None:
        name = bare.lower()
        return name[4:] in P.SHORTENERS if name.startswith("www.") else name in P.SHORTENERS
    # Loopback and the documentation ranges are examples; a link-local address is not: `169.254.169.254` is the
    # cloud metadata endpoint, the classic place a skill steals instance credentials from.
    if address.is_loopback or address.is_unspecified:  # `0.0.0.0:8000` is a local server in docs, like loopback
        return False
    return not any(address in network for network in _DOC_RANGES)


def _skl_013(package: Package) -> Iterator[Finding]:
    for unit in package.text_files:
        for number, line in enumerate(unit.lines, start=1):
            if any(_suspicious_host(m.group(1)) or _suspicious_host(m.group(1).split("\\", 1)[0])
                   for m in _URL_AUTHORITY.finditer(line)):
                yield _finding("SW-SKL-013", "medium", TITLES["SW-SKL-013"], unit.path, number, line)


# --- SW-SKL-014 ------------------------------------------------------------------------------

_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{200,}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){100,}")
_X_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}")
_FROM_CHAR_CODE = re.compile(r"String\.fromCharCode\(")
# Ten `chr(...)` calls joined by `+`: one whitespace run between them, never two adjacent `\s*` (they backtrack).
_CHR_JOIN = re.compile(r"(?:chr\([^()]*\)\s*(?:\+\s*)?){10,}")  # `[^()]`: an unclosed `chr(` stops at the next `(`
_EVAL_NONLITERAL = re.compile(r"\b(eval|exec)\(\s*(?![\"'])[^)]")
_COMPILE_EXEC = P.Then(r"compile\(", r"exec\(", flags=0)


def _char_codes(line: str) -> bool:
    """`String.fromCharCode(...)` with ten or more arguments; each call's argument list is read once."""
    reached = -1
    for call in _FROM_CHAR_CODE.finditer(line):
        if call.start() < reached:
            continue
        end = line.find(")", call.end())
        if end < 0:
            return False
        if len(line[call.end():end].split(",")) >= 10:
            return True
        reached = end
    return False


def _skl_014(package: Package) -> Iterator[Finding]:
    for unit in package.scripts():
        for path, number, line in _numbered(unit):
            comment = line.lstrip().startswith(("#", "//"))
            fires = (not comment and (_B64_RUN.search(line) or _HEX_RUN.search(line))) or _X_ESCAPES.search(line) \
                or _char_codes(line) \
                or _CHR_JOIN.search(line) or _EVAL_NONLITERAL.search(line) or _COMPILE_EXEC.search(line)
            if fires:
                yield _finding("SW-SKL-014", "medium", TITLES["SW-SKL-014"], path, number, line)


# --- SW-SKL-015 and SW-SKL-031 --------------------------------------------------------------------

def _skill_md(package: Package) -> str:
    prefix = f"{package.root}/" if package.root else ""
    return f"{prefix}SKILL.md"


def _skl_015(package: Package) -> Iterator[Finding]:
    meta = package.metadata
    if meta.frontmatter_ok:
        return
    path = _skill_md(package)
    line = None if package.file_at(path) is None else 1
    text = "; ".join(meta.problems)
    yield _finding("SW-SKL-015", "low", TITLES["SW-SKL-015"], path, line, text, evidence=text)


_UNPARSED = ("SKILL.md is missing", "frontmatter is")


def _skl_031(package: Package) -> Iterator[Finding]:
    """Spec 5.3: not raised only when SW-SKL-015 fired for a missing or unparsable frontmatter; a parsed
    frontmatter with a bad name or description still reports its missing license and version."""
    meta = package.metadata
    if any(problem.startswith(_UNPARSED) for problem in meta.problems):
        return
    missing = [name for name in ("license", "version") if name not in meta.present]
    if missing:
        text = "missing " + ", ".join(missing)
        yield _finding("SW-SKL-031", "low", TITLES["SW-SKL-031"], _skill_md(package), 1, text, evidence=text)


# --- SW-SKL-019 ------------------------------------------------------------------------------

_FETCH_MARKER = re.compile(
    r"(\bWebFetch\b|\bweb_fetch\b|\b(fetch|read|load|download|get) (the )?(page|contents?|url|document|text) (of |from |at )?https?://|"
    r"requests\.get\(|urlopen\(|curl -s[a-zA-Z]* https?://|Invoke-WebRequest)", _I)
_REDIRECTED = re.compile(r"(\s-o\s|\s>\s?)")
_NEARBY_ALLOW = re.compile(r"(only from|allowlist)", _I)
_ALLOWLIST_KEYS = ("allowed-hosts", "allowed_hosts", "allowed-domains", "allowed_domains")


def _allowlist_declared(package: Package) -> bool:
    text_file = package.file_at(_skill_md(package))
    if text_file is None:
        return False
    try:
        mapping, _ = parse_frontmatter(text_file.text)
    except FrontmatterError:
        return False
    for key in _ALLOWLIST_KEYS:
        value = mapping.get(key)
        if isinstance(value, (list, tuple)) and value:
            return True
    tools = mapping.get("allowed-tools")
    return isinstance(tools, str) and "WebFetch(domain:" in tools


def _skl_019(package: Package) -> Iterator[Finding]:
    if _allowlist_declared(package):
        return
    for unit in package.text_files:
        lines = unit.lines
        for number, line in enumerate(lines, start=1):
            match = _FETCH_MARKER.search(line)
            if not match:
                continue
            if match.group(0).lower().startswith("curl") and _REDIRECTED.search(line):
                continue
            nearby = lines[max(0, number - 3):number + 2]
            if any(_NEARBY_ALLOW.search(text) for text in nearby):
                continue
            yield _finding("SW-SKL-019", "medium", TITLES["SW-SKL-019"], unit.path, number, line)


# --- the table ----------------------------------------------------------------------------------

TITLES = {
    "SW-SKL-001": "Prompt-injection phrases in skill instructions",
    "SW-SKL-002": "Hidden text: zero-width or bidirectional control characters",
    "SW-SKL-003": "Instructions to skip approvals or disable hooks",
    "SW-SKL-004": "Encoded payload decoded and executed",
    "SW-SKL-005": "Writes to agent configuration",
    "SW-SKL-006": "Destructive command without a confirmation step",
    "SW-SKL-007": "Remote script piped to a shell",
    "SW-SKL-008": "Sends local file contents to an external host",
    "SW-SKL-009": "Unpinned dependency install",
    "SW-SKL-010": "Bundled binary or executable file",
    "SW-SKL-011": "Hard-coded credential in the package",
    "SW-SKL-012": "Reads a credential file path without stating purpose",
    "SW-SKL-013": "Network calls to raw IP addresses or URL shorteners",
    "SW-SKL-014": "Obfuscated script code",
    "SW-SKL-015": "Frontmatter missing or invalid (name, description)",
    "SW-SKL-019": "Fetches external URL content into context without an allowlist",
    "SW-SKL-031": "Missing license and version metadata",
}

RULES: tuple[Rule, ...] = (
    make_rule("SW-SKL-001", TITLES["SW-SKL-001"], "high", "skill", owasp=("ASI01",), nist=("SI-10",), detect=_skl_001, targets=("claude-code-hooks",)),
    make_rule("SW-SKL-002", TITLES["SW-SKL-002"], "high", "skill", owasp=("ASI01",), nist=("SI-10",), detect=_skl_002),
    make_rule("SW-SKL-003", TITLES["SW-SKL-003"], "high", "skill", owasp=("ASI10",), nist=("AC-6",), detect=_skl_003),
    make_rule("SW-SKL-004", TITLES["SW-SKL-004"], "critical", "skill", owasp=("ASI04",), nist=("SR-3",), detect=_skl_004, malicious=True, targets=("claude-code-hooks",)),
    make_rule("SW-SKL-005", TITLES["SW-SKL-005"], "high", "skill", owasp=("ASI10",), nist=("AC-6",), detect=_skl_005, targets=("claude-code-hooks",)),
    make_rule("SW-SKL-006", TITLES["SW-SKL-006"], "medium", "skill", owasp=("ASI10",), nist=("AC-6",), detect=_skl_006, targets=("claude-code-hooks",)),
    make_rule("SW-SKL-007", TITLES["SW-SKL-007"], "high", "skill", owasp=("ASI04",), nist=("SR-3",), detect=_skl_007, targets=("claude-code-hooks", "kong")),
    make_rule("SW-SKL-008", TITLES["SW-SKL-008"], "critical", "skill", owasp=("ASI10",), nist=("SC-7",), detect=_skl_008, malicious=True, targets=("claude-code-hooks", "kong")),
    make_rule("SW-SKL-009", TITLES["SW-SKL-009"], "medium", "skill", owasp=("ASI04",), nist=("SR-3",), detect=_skl_009),
    make_rule("SW-SKL-010", TITLES["SW-SKL-010"], "medium", "skill", owasp=("ASI04",), nist=("SR-3",), detect=_skl_010),
    make_rule("SW-SKL-011", TITLES["SW-SKL-011"], "critical", "skill", owasp=("MCP01",), nist=("IA-5",), detect=_skl_011),
    make_rule("SW-SKL-012", TITLES["SW-SKL-012"], "medium", "skill", owasp=("ASI04",), nist=("IA-5",), detect=_skl_012),
    make_rule("SW-SKL-013", TITLES["SW-SKL-013"], "medium", "skill", owasp=("ASI10",), nist=("SC-7",), detect=_skl_013, targets=("kong",)),
    make_rule("SW-SKL-014", TITLES["SW-SKL-014"], "medium", "skill", owasp=("ASI04",), nist=("SR-3",), detect=_skl_014),
    make_rule("SW-SKL-015", TITLES["SW-SKL-015"], "low", "skill", owasp=("ASI04",), nist=("SR-3",), detect=_skl_015, targets=("registry",)),
    make_rule("SW-SKL-019", TITLES["SW-SKL-019"], "medium", "skill", owasp=("ASI01", "MCP10"), nist=("SI-10",), detect=_skl_019, targets=("kong",)),
    make_rule("SW-SKL-031", TITLES["SW-SKL-031"], "low", "skill", owasp=("ASI04",), nist=("SR-3",), detect=_skl_031, targets=("registry",)),
)
