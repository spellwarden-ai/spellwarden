"""The 17 skill rules of spec 5.3. Each `detect(package)` is a generator of
`Finding`s: one per matching line (or per file for SW-SKL-010), the evidence
the matched line (masked), the fingerprint `rule_id NUL path NUL line`."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

from spellwarden_scan.evidence import bounded_evidence, code_point_names, excerpt, fingerprint
from spellwarden_scan.frontmatter import FrontmatterError, parse_frontmatter
from spellwarden_scan.model import Finding, Location
from spellwarden_scan.package import CodeBlock, Package, TextFile
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


def _logical_lines(unit: TextFile | CodeBlock) -> Iterator[tuple[str, int, str]]:
    """Lines with a trailing backslash joined to the next (one shell command), numbered by their first line."""
    pending: list[str] = []
    start = 0
    path = unit.path
    for path, number, line in _numbered(unit):
        if not pending:
            start = number
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            pending.append(stripped[:-1])
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
            if any(p.search(line) for p in P.INJECTION):
                yield _finding("SW-SKL-001", "high", TITLES["SW-SKL-001"], path, number, line)


# --- SW-SKL-002 ------------------------------------------------------------------------------

_HIDDEN = re.compile("[\u200b-\u200f\u2060-\u2064\u202a-\u202e\u2066-\u2069\ufeff]")


def _skl_002(package: Package) -> Iterator[Finding]:
    for unit in package.text_files:
        for number, line in enumerate(unit.lines, start=1):
            text = line[1:] if number == 1 and line.startswith("\ufeff") else line
            hidden = _HIDDEN.findall(text)
            if hidden:
                names = code_point_names("".join(hidden))
                yield _finding("SW-SKL-002", "high", TITLES["SW-SKL-002"], unit.path, number, names, evidence=names)


# --- SW-SKL-003 ------------------------------------------------------------------------------

_SKIP = re.compile(
    r"(skip (the |any |all )?(approval|approvals|confirmation|confirmations|permission|permissions|review)|"
    r"--dangerously-skip-permissions|bypassPermissions|(disable|remove|turn off|delete) (the |all |any )?hooks?\b|"
    r"(allow|permit) (all|every) tools?\b|\"permissions\"\s*:\s*\{[^}]*\"allow\"\s*:\s*\[\s*\"\*\"|"
    r"defaultMode\"?\s*:\s*\"?(bypassPermissions|dontAsk))", _I)


def _skl_003(package: Package) -> Iterator[Finding]:
    yield from _lines_matching(package.text_files, _SKIP, "SW-SKL-003", "high", TITLES["SW-SKL-003"])


# --- SW-SKL-004 ------------------------------------------------------------------------------

_DECODER = re.compile(r"(base64 (-d|--decode|-D)\b|b64decode\(|atob\(|openssl enc -d|xxd -r|gunzip -c|\bzcat\b)", _I)
_EXECUTOR = re.compile(
    r"(\| *(sudo +)?(sh|bash|zsh|python[0-9.]*|node|perl|ruby)\b|\beval\(|\bexec\(|subprocess|os\.system|child_process|"
    r"new Function\(|\bsh -c\b)", _I)


def _skl_004(package: Package) -> Iterator[Finding]:
    for unit in package.scripts():
        for path, number, line in _numbered(unit):
            if _DECODER.search(line) and _EXECUTOR.search(line):
                yield _finding("SW-SKL-004", "critical", TITLES["SW-SKL-004"], path, number, line, malicious=True)


# --- SW-SKL-005 ------------------------------------------------------------------------------

_WRITE_VERB = re.compile(
    r"(>>?|\btee\b|sed -i|\bcp\b|\bmv\b|write_text|writeFile|open\([^)]*[\"'][wa][\"']|\bjq\b.*>|"
    r"\b(edit|add to|append to|modify|update|write to|replace)\b (the |your )?)", _I)
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


def _skl_005(package: Package) -> Iterator[Finding]:
    for unit in package.text_files:
        for number, line in enumerate(unit.lines, start=1):
            for sentence in _SENTENCE.split(line):
                if P.AGENT_CONFIG_PATHS.search(sentence) and _WRITE_VERB.search(sentence):
                    yield _finding("SW-SKL-005", "high", TITLES["SW-SKL-005"], unit.path, number, line)
                    break


# --- SW-SKL-006 ------------------------------------------------------------------------------

_DESTRUCTIVE = re.compile(
    r"(\brm -[a-z]*r[a-z]*f\b|\brm -[a-z]*f[a-z]*r\b|git push .*(--force|-f)\b|git reset --hard|git clean -[a-z]*f|"
    r"\bdrop (table|database|schema)\b|\btruncate table\b|kubectl delete|terraform destroy|aws s3 (rm|rb) .*(--recursive|--force)|"
    r"gsutil (rm|rb) -r|\baz .* delete\b|\bmkfs\b|\bdd if=|\bshred\b|chmod -R 777|:\(\)\{ :\|:& \};:)", _I)
_CONFIRMED = re.compile(r"(confirm|\bask\b|approval|approve|only if the user|after the user|prompt the user|--dry-run)", _I)


def _skl_006(package: Package) -> Iterator[Finding]:
    for unit in package.scripts():
        entries = list(_numbered(unit))
        for index, (path, number, line) in enumerate(entries):
            if not _DESTRUCTIVE.search(line):
                continue
            window = [entry[2] for entry in entries[max(0, index - 3):index + 1]]
            if any(_CONFIRMED.search(text) for text in window):
                continue
            yield _finding("SW-SKL-006", "medium", TITLES["SW-SKL-006"], path, number, line)


# --- SW-SKL-007 ------------------------------------------------------------------------------

_PIPED = re.compile(
    r"((curl|wget|fetch|Invoke-WebRequest|iwr)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|ksh|python[0-9.]*|node|perl|ruby|pwsh|powershell|iex)\b|"
    r"(sh|bash|zsh) -c [\"']?\$\((curl|wget)|(sh|bash|zsh) <\((curl|wget)|iex ?\(.*(iwr|Invoke-WebRequest|DownloadString))", _I)


def _skl_007(package: Package) -> Iterator[Finding]:
    yield from _lines_matching(package.text_files, _PIPED, "SW-SKL-007", "high", TITLES["SW-SKL-007"])


# --- SW-SKL-008 ------------------------------------------------------------------------------

_SEND = re.compile(
    r"(curl .*(-d|--data|--data-binary|-F|--form|-T|--upload-file)\b|wget .*--post-(data|file)|\bnc\b|\bncat\b|\bnetcat\b|"
    r"requests\.(post|put)\(|fetch\(.*method:\s*[\"'](POST|PUT)|axios\.(post|put)\(|\bscp .* [^ ]+@|\brsync .* [^ ]+@|"
    r"Invoke-RestMethod .*-Method (Post|Put))", _I)


def skl_008_lines(package: Package) -> set[tuple[str, int]]:
    """`(path, line)` of every SW-SKL-008 match, shared with SW-SKL-012."""
    hits: set[tuple[str, int]] = set()
    for unit in package.text_files:
        for path, number, text in _logical_lines(unit):
            if P.SECRET_PATHS.search(text) and _SEND.search(text):
                hits.add((path, number))
    return hits


def _skl_008(package: Package) -> Iterator[Finding]:
    for unit in package.text_files:
        for path, number, text in _logical_lines(unit):
            if P.SECRET_PATHS.search(text) and _SEND.search(text):
                yield _finding("SW-SKL-008", "critical", TITLES["SW-SKL-008"], path, number, text, malicious=True)


# --- SW-SKL-009 ------------------------------------------------------------------------------

_PIP = re.compile(r"\b(pip3?|uv pip|pipx) install\b(.*)", _I)
_NPM = re.compile(r"\b(npm (install|i|add)|yarn add|pnpm add)\b(.*)", _I)
_NPX = re.compile(r"\bnpx\s+(.*)", _I)
_GO = re.compile(r"\bgo install\b.*@latest\b", _I)
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
        for path, number, line in _numbered(unit):
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

def _has_credential(line: str) -> bool:
    if any(p.search(line) for p in P.CREDENTIAL_PATTERNS):
        return True
    match = P.ASSIGNED_SECRET.search(line)
    return bool(match) and P.PLACEHOLDER.search(match.group(2)) is None


def _skl_011(package: Package) -> Iterator[Finding]:
    for unit in package.text_files:
        for number, line in enumerate(unit.lines, start=1):
            if _has_credential(line):
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

_URL_HOST = re.compile(r"https?://(\[[^\]/\s]+\]|[^/\s:?#]+)", _I)
_DOC_RANGES = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"),
               ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("2001:db8::/32"))


def _suspicious_host(host: str) -> bool:
    bare = host[1:-1] if host.startswith("[") else host
    try:
        address = ipaddress.ip_address(bare)
    except ValueError:
        name = bare.lower()
        return name[4:] in P.SHORTENERS if name.startswith("www.") else name in P.SHORTENERS
    if address.is_loopback or address.is_link_local:
        return False
    return not any(address in network for network in _DOC_RANGES)


def _skl_013(package: Package) -> Iterator[Finding]:
    for unit in package.text_files:
        for number, line in enumerate(unit.lines, start=1):
            if any(_suspicious_host(m.group(1)) for m in _URL_HOST.finditer(line)):
                yield _finding("SW-SKL-013", "medium", TITLES["SW-SKL-013"], unit.path, number, line)


# --- SW-SKL-014 ------------------------------------------------------------------------------

_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{200,}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){100,}")
_X_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}")
_FROM_CHAR_CODE = re.compile(r"String\.fromCharCode\(([^)]*)\)")
_CHR_JOIN = re.compile(r"(?:chr\([^)]*\)\s*\+?\s*){10,}")
_EVAL_NONLITERAL = re.compile(r"\b(eval|exec)\(\s*(?![\"'])[^)]")
_COMPILE_EXEC = re.compile(r"compile\(.*exec\(")


def _skl_014(package: Package) -> Iterator[Finding]:
    for unit in package.scripts():
        for path, number, line in _numbered(unit):
            comment = line.lstrip().startswith(("#", "//"))
            fires = (not comment and (_B64_RUN.search(line) or _HEX_RUN.search(line))) or _X_ESCAPES.search(line) \
                or any(len(m.group(1).split(",")) >= 10 for m in _FROM_CHAR_CODE.finditer(line)) \
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


def _skl_031(package: Package) -> Iterator[Finding]:
    meta = package.metadata
    if not meta.frontmatter_ok:
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
