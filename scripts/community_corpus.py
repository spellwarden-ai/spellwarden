#!/usr/bin/env python3
"""The community corpus (docs/specs/2026-11-25-community-reports.md, section 6): the one reader of the format of
`fixtures/community/`. Three programs use it: the tests, `scripts/add_community_case.py` and the rule benchmark. Standard library
only; no network and no engine import. Every function returns data or a list of one-line problems. A problem names the case, the
path and the check, never the text of a sample."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import date
from pathlib import Path
from typing import NamedTuple

CORPUS_FORMAT = 1
CASE_ID = re.compile(r"^COM-[0-9]{4}$")
KINDS = ("miss", "false_positive")
OUTCOMES = ("open", "fixed")
AREAS = ("skill", "config", "a2a")  # the areas of rules that a scan of files, with no probe and no connected mode, can raise
RECORD_MEMBERS = frozenset({"id", "kind", "rule", "kept_hosts", "reported_against", "outcome", "fixed_in", "credit", "date",
                            "issue"})
TOP_FILES = ("README.md", "RETIRED.json")
MAX_FILES = 20
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 256 * 1024
MAX_PATH = 200
MAX_CREDIT = 80
# r0:F4: a credit is printed in the CHANGELOG and the release thread, so it holds letters, digits, spaces and . , ' - only:
# no mention, link, URL, markup or HTML can reach either
CREDIT_CHARACTERS = frozenset(" .,'-")


# a name shaped like a host (`www.evil.com`, `evil.com`): GitHub's Markdown turns it into a link, so it is refused too; initials
# (`J.R.R. Tolkien`, `A.B. Smith`) have no last part of two letters or more after a dot and pass
_CREDIT_HOST = re.compile(r"(?i)(?:\bwww\.|[^\W_]\.[^\W\d_]{2,}\b)")


def credit_is_plain(value: str) -> bool:
    return bool(value) and all((character.isalnum() and character != "_") or character in CREDIT_CHARACTERS
                               for character in value) and _CREDIT_HOST.search(value) is None
TEST_SET_MIN_BYTES = 200
_SCANNER_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_RULES_VERSION = re.compile(r"^[0-9]{4}\.[0-9]{2}\.[0-9]+$")
_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
_RESERVED_NAME = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$", re.I)
_WINDOWS_BAD = re.compile(r'[<>:"|?*\x00-\x1f]')
_DRIVE = re.compile(r"^[A-Za-z]:")
RESERVED_SUFFIXES = (".example", ".invalid", ".test", ".localhost")
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
RESERVED_NETWORKS = tuple(ipaddress.ip_network(text) for text in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8", "::1/128", "2001:db8::/32"))
# What a host looks like in a URL (`scheme://[user@]host`) and after the `@` of an e-mail address. The host is the longest run of
# host characters, so that a closing backtick, a pipe or a brace after it does not hide it; a placeholder such as `${HOST}` has
# none.
# r1:F3: a host may hold letters of any script (`ébay.com`); the search text has JSON's `\/` read as `/` first (`live_hosts`)
_URL_HOST = re.compile(r"\b[A-Za-z][A-Za-z0-9+.\-]{1,19}://(?:[A-Za-z0-9._~%!$+,=:\-]*@)?"
                       r"(\[[0-9A-Fa-f:.]+\]|(?:[^\W_]|[.\-])+)")
_MAIL_HOST = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@((?:[^\W_]|-)+(?:\.(?:[^\W_]|-)+)+)")
# a host name with a letter outside ASCII: a live host unless reserved, where `_HOST` (ASCII) would read it as no host at all
_UNICODE_HOST = re.compile(r"^[^\W_](?:(?:[^\W_]|[.-])*[^\W_])?$")
# The credential shapes of tests/conftest.py `credential()`, apart from its `password = "..."` shape. Every open-ended length is
# bounded, so that a 64 KiB file of one repeated prefix cannot make a search quadratic.
CREDENTIAL_SHAPES = (
    ("an AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("a GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})")),
    ("a Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,255}")),
    ("an Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,255}")),
    ("an OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,255}")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,255}")),
    ("a GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}")),
    ("a JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,4096}\.eyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{10,4096}")),
    ("a PEM private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("a Spellwarden key or token", re.compile(r"\bsw[kct]_[A-Za-z0-9_-]{40,255}")),
)


class CorpusError(Exception):
    """The corpus on disk cannot be read: its message holds the one-line problems, joined by `; `."""


class Case(NamedTuple):
    id: str
    record: dict
    files: dict[str, bytes]


def version_tuple(text: str) -> tuple[int, ...]:
    """`1.23.0` as `(1, 23, 0)`: versions are compared as integers, never as text."""
    return tuple(int(part) for part in text.split("."))


def dump_record(record: dict) -> str:
    """The canonical text of `record.json`: UTF-8, sorted keys, two-space indent, a final newline."""
    return json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def shown(path: str) -> str:
    """A path as it is shown in a problem: ASCII only and short, because a reporter chose it."""
    return ascii(path)[:80]


# --- the layout on disk ---------------------------------------------------------------------------------------------------

def _case_layout(directory: Path) -> list[str]:
    problems = []
    names = sorted(entry.name for entry in directory.iterdir())
    for extra in [name for name in names if name not in ("record.json", "files")]:
        problems.append(f"{directory.name}: extra member {shown(extra)}")
    record = directory / "record.json"
    if "record.json" not in names:
        problems.append(f"{directory.name}: record.json is missing")
    elif record.is_symlink() or not record.is_file():
        problems.append(f"{directory.name}: record.json is not a regular file")
    files = directory / "files"
    if "files" not in names:
        problems.append(f"{directory.name}: files/ is missing")
    elif files.is_symlink() or not files.is_dir():
        problems.append(f"{directory.name}: files is not a directory")
    else:
        found = list(files.rglob("*"))
        if any(entry.is_symlink() for entry in found):
            problems.append(f"{directory.name}: files/ holds a link")
        if not any(entry.is_file() and not entry.is_symlink() for entry in found):
            problems.append(f"{directory.name}: files/ holds no file")
    return problems


def layout_problems(root: Path) -> list[str]:
    """What is wrong with the shape of the corpus directory: a stray file, a directory that is not a case, a case without
    `record.json` or `files/`, an extra member, a link. A missing directory has no problem (there is no corpus)."""
    root = Path(root)
    if not root.is_dir():
        return []
    problems = []
    for entry in sorted(root.iterdir(), key=lambda path: path.name):
        if entry.is_symlink():
            problems.append(f"{shown(entry.name)}: a link is not allowed in the corpus")
        elif entry.is_file():
            if entry.name not in TOP_FILES:
                problems.append(f"{shown(entry.name)}: not a case, and the only files allowed here are README.md and "
                                "RETIRED.json")
        elif not CASE_ID.match(entry.name):
            problems.append(f"{shown(entry.name)}: a directory that is not a case id (COM- and four digits)")
        else:
            problems += _case_layout(entry)
    return problems


def load_cases(root: Path) -> list[Case]:
    """Every case of the corpus, ascending by id. A missing directory is an empty corpus. Raises `CorpusError` when the layout is
    wrong or a record is not UTF-8 JSON in its canonical form (`dump_record`)."""
    root = Path(root)
    problems = layout_problems(root)
    if problems:
        raise CorpusError("; ".join(problems))
    cases = []
    entries = list(root.iterdir()) if root.is_dir() else []
    directories = sorted((entry for entry in entries if entry.is_dir()), key=lambda path: path.name)
    for directory in directories:
        try:
            text = (directory / "record.json").read_bytes().decode("utf-8")
            record = json.loads(text)
        except ValueError:
            raise CorpusError(f"{directory.name}: record.json is not UTF-8 JSON") from None
        if text != dump_record(record):
            raise CorpusError(f"{directory.name}: record.json is not in the canonical form (sorted keys, two-space indent, "
                              "a final newline)")
        base = directory / "files"
        files = {path.relative_to(base).as_posix(): path.read_bytes() for path in sorted(base.rglob("*")) if path.is_file()}
        cases.append(Case(directory.name, record, files))
    return cases


def retired_ids(root: Path) -> list[str]:
    """The ids in `RETIRED.json` (cases removed on a reporter's request); none when the file is absent. Raises `CorpusError` when
    the file is not a JSON array of case ids."""
    path = Path(root) / "RETIRED.json"
    if not path.is_file():
        return []
    try:
        value = json.loads(path.read_bytes().decode("utf-8"))
    except ValueError:
        raise CorpusError("RETIRED.json is not UTF-8 JSON") from None
    if not isinstance(value, list) or not all(isinstance(item, str) and CASE_ID.match(item) for item in value):
        raise CorpusError("RETIRED.json must be an array of case ids (COM- and four digits)")
    return value


def next_id(root: Path) -> str:
    """The id after the highest in the directory and in `RETIRED.json`: an id is never reused."""
    root = Path(root)
    numbers = [int(entry.name[4:]) for entry in root.iterdir() if entry.is_dir() and CASE_ID.match(entry.name)] \
        if root.is_dir() else []
    numbers += [int(item[4:]) for item in retired_ids(root)]
    return f"COM-{max(numbers, default=0) + 1:04d}"


# --- the record -----------------------------------------------------------------------------------------------------------

def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def host_problem(host: object) -> str | None:
    """Why `host` is not a bare host name (no scheme, port, path or upper case), or None."""
    if not isinstance(host, str) or _HOST.match(host) is None:
        return "is not a bare lower-case host name (no scheme, port or path)"
    return None


def record_problems(record: object, *, directory_name: str | None = None, rule_areas: dict[str, str] | None = None,
                    current_version: str | None = None) -> list[str]:
    """What is wrong with one record (6.2, 6.5). `directory_name` is the name of the case's directory (the id must equal it),
    `rule_areas` maps every rule id of the baseline to its area (the rule must exist, in an area of `AREAS`) and
    `current_version` is the scanner's version, which a `fixed_in` must not exceed; each check is skipped when its argument is
    None."""
    if not isinstance(record, dict):
        return [f"{directory_name or 'a record'}: the record must be a JSON object"]
    where = directory_name or str(record.get("id"))[:20]
    problems = []
    for member in sorted(set(record) - RECORD_MEMBERS):
        problems.append(f"{where}: unknown member {shown(str(member))}")
    for member in sorted(RECORD_MEMBERS - set(record)):
        problems.append(f"{where}: member {member} is missing")
    if problems:
        return problems
    if not isinstance(record["id"], str) or not CASE_ID.match(record["id"]):
        problems.append(f"{where}: id must be COM- and four digits")
    elif directory_name is not None and record["id"] != directory_name:
        problems.append(f"{where}: id {record['id']} is not the name of the directory")
    if record["kind"] not in KINDS:
        problems.append(f"{where}: kind must be miss or false_positive")
    rule = record["rule"]
    if rule_areas is not None:
        if rule not in rule_areas:
            problems.append(f"{where}: rule {shown(str(rule))} is not a rule of the baseline")
        elif rule_areas[rule] not in AREAS:
            problems.append(f"{where}: rule {rule} is of the area {rule_areas[rule]}, which a scan of files cannot raise "
                            f"(a case takes a rule of the areas {', '.join(AREAS)})")
    elif not isinstance(rule, str):
        problems.append(f"{where}: rule must be a rule id")
    hosts = record["kept_hosts"]
    if not isinstance(hosts, list):
        problems.append(f"{where}: kept_hosts must be an array")
    else:
        for host in hosts:
            reason = host_problem(host)
            if reason is not None:
                problems.append(f"{where}: kept_hosts entry {shown(str(host))} {reason}")
        if all(isinstance(host, str) for host in hosts) and hosts != sorted(set(hosts)):
            problems.append(f"{where}: kept_hosts must be sorted and hold no host twice")
    against = record["reported_against"]
    scanner = None
    if not isinstance(against, dict) or set(against) != {"scanner", "rules"}:
        problems.append(f"{where}: reported_against must hold exactly scanner and rules")
    else:
        if not isinstance(against["scanner"], str) or not _SCANNER_VERSION.match(against["scanner"]):
            problems.append(f"{where}: reported_against.scanner must be X.Y.Z")
        else:
            scanner = against["scanner"]
        if not isinstance(against["rules"], str) or not _RULES_VERSION.match(against["rules"]):
            problems.append(f"{where}: reported_against.rules must be YYYY.MM.N")
    outcome, fixed_in = record["outcome"], record["fixed_in"]
    if outcome not in OUTCOMES:
        problems.append(f"{where}: outcome must be open or fixed")
    elif outcome == "open":
        if fixed_in is not None:
            problems.append(f"{where}: fixed_in must be null while the outcome is open")
    elif not isinstance(fixed_in, str) or not _SCANNER_VERSION.match(fixed_in):
        problems.append(f"{where}: fixed_in must be X.Y.Z when the outcome is fixed")
    else:
        if scanner is not None and version_tuple(fixed_in) < version_tuple(scanner):
            problems.append(f"{where}: fixed_in {fixed_in} is before the version reported against, {scanner}")
        if current_version is not None and version_tuple(fixed_in) > version_tuple(current_version):
            problems.append(f"{where}: fixed_in {fixed_in} is after this version, {current_version}")
    credit = record["credit"]
    if credit is not None:
        if not isinstance(credit, str) or not credit or credit != credit.strip() or len(credit) > MAX_CREDIT \
                or re.search(r"[\x00-\x1f\x7f]", credit):
            problems.append(f"{where}: credit must be null or one trimmed line of at most {MAX_CREDIT} characters")
        elif not credit_is_plain(credit):
            problems.append(f"{where}: credit must hold only letters, digits, spaces and . , ' -, and no host name")
    day = record["date"]
    try:
        valid = isinstance(day, str) and _DATE.match(day) is not None and date.fromisoformat(day).isoformat() == day
    except ValueError:
        valid = False
    if not valid:
        problems.append(f"{where}: date must be YYYY-MM-DD")
    if record["issue"] is not None and not _is_count(record["issue"]):
        problems.append(f"{where}: issue must be null or the number of an issue")
    return problems


def changelog_line(record: dict) -> str:
    """The line that the CHANGELOG section of `fixed_in` holds for a fixed case (6.6); the credit is named exactly when the record
    has one."""
    kind = "missed detection" if record["kind"] == "miss" else "false positive"
    credit = f", reported by {record['credit']}" if record["credit"] is not None else ""
    return f"Community report {record['id']} ({record['rule']}, {kind}){credit}."


def retired_problems(root: Path, cases: list[Case]) -> list[str]:
    """Ids must be unique, and none may be in `RETIRED.json` (6.1, C-3)."""
    problems = []
    seen: set[str] = set()
    for case in cases:
        if case.id in seen:
            problems.append(f"{case.id}: the id is used twice")
        seen.add(case.id)
    try:
        retired = retired_ids(root)
    except CorpusError as error:
        return [*problems, str(error)]
    for item in retired:
        if item in seen:
            problems.append(f"{item}: a retired id is used by a case")
    if len(set(retired)) != len(retired):
        problems.append("RETIRED.json lists an id twice")
    return problems


# --- the sample -----------------------------------------------------------------------------------------------------------

def path_problems(path: str) -> list[str]:
    """Why `path` cannot be a file of a sample on every system the checks run on (6.4), including Windows."""
    problems = []
    label = shown(path)
    segments = path.split("/")
    if not path:
        return [f"{label}: the path is empty"]
    if len(path) > MAX_PATH:
        problems.append(f"{label}: the path is longer than {MAX_PATH} characters")
    if "\\" in path:
        problems.append(f"{label}: the path holds a backslash")
    if path.startswith("/") or _DRIVE.match(path):
        problems.append(f"{label}: the path is not relative")
    if "" in segments and not path.startswith("/"):
        problems.append(f"{label}: the path has an empty segment")
    for segment in segments:
        if segment in (".", ".."):
            problems.append(f"{label}: the path has a segment {segment}")
        elif segment and (segment.endswith((".", " "))):
            problems.append(f"{label}: a segment of the path ends in a dot or a space")
        if segment and _RESERVED_NAME.match(segment.split(".", 1)[0]):
            problems.append(f"{label}: a segment of the path is a reserved Windows name")
        if segment and _WINDOWS_BAD.search(segment):
            problems.append(f"{label}: a segment of the path holds a character that Windows does not allow")
    if segments[0].lower() == ".git":
        problems.append(f"{label}: the path is under .git")
    return problems


def _host_is_reserved(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        return any(address in network for network in RESERVED_NETWORKS if network.version == address.version)
    return host == "localhost" or host in RESERVED_DOMAINS or host.endswith(RESERVED_SUFFIXES) \
        or any(host.endswith("." + domain) for domain in RESERVED_DOMAINS)


def live_hosts(text: str, kept_hosts: tuple[str, ...] | list[str] = ()) -> list[str]:
    """The hosts of the URLs and the e-mail addresses of `text` that are neither reserved nor in `kept_hosts`, sorted and unique.
    A host that is not a name or an address (a placeholder such as `${HOST}`) is not a host."""
    kept = {host.lower() for host in kept_hosts}
    found = set()
    text = text.replace("\\/", "/")   # r1:F3: JSON may write `https:\/\/host\/path`
    for match in [*_URL_HOST.finditer(text), *_MAIL_HOST.finditer(text)]:
        host = match.group(1).rstrip(".,;:").lower()
        bare = host.strip("[]")
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            if _HOST.match(host) is None and (host.isascii() or _UNICODE_HOST.match(host) is None):
                continue
        if host not in kept and not _host_is_reserved(host):
            found.add(host)
    return sorted(found)


def sample_problems(files: dict[str, bytes], kept_hosts: tuple[str, ...] | list[str] = ()) -> list[str]:
    """The hygiene checks of 6.4 on the files of one sample: paths, sizes, UTF-8 text, hosts and credential shapes. A problem
    names the path and the check and never quotes the sample."""
    problems = []
    if not files:
        return ["the sample has no file"]
    if len(files) > MAX_FILES:
        problems.append(f"the sample has {len(files)} files and at most {MAX_FILES} are accepted")
    total = sum(len(data) for data in files.values())
    if total > MAX_TOTAL_BYTES:
        problems.append(f"the sample is {total} bytes in all and at most {MAX_TOTAL_BYTES} are accepted")
    lowered: dict[str, str] = {}
    for path in sorted(files):
        problems += path_problems(path)
        if path.lower() in lowered:
            problems.append(f"{shown(path)}: the path equals {shown(lowered[path.lower()])} when case is ignored")
        lowered[path.lower()] = path
    for path in sorted(files):
        if any(other.lower().startswith(path.lower() + "/") for other in files):
            problems.append(f"{shown(path)}: the path is a file and also a directory of another path")
    for path in sorted(files):
        data = files[path]
        if len(data) > MAX_FILE_BYTES:
            problems.append(f"{shown(path)}: the file is {len(data)} bytes and at most {MAX_FILE_BYTES} are accepted")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{shown(path)}: the file is not UTF-8 text (a binary sample is not accepted)")
            continue
        if "\x00" in text:
            problems.append(f"{shown(path)}: the file holds a NUL byte (a binary sample is not accepted)")
        for host in live_hosts(text, kept_hosts):
            problems.append(f"{shown(path)}: a URL or an e-mail address names the host {shown(host)}, which is not reserved "
                            "(use example.com, a name under .example, .invalid or .test, or an address of 192.0.2.0/24)")
        for label, pattern in CREDENTIAL_SHAPES:
            if pattern.search(text):
                problems.append(f"{shown(path)}: the text has the shape of {label}")
    return problems


def files_digest(files: dict[str, bytes]) -> str:
    """sha256 over the sorted paths and the sha256 of each file's bytes: two samples are equal when this is equal."""
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.encode("utf-8") + b"\0" + hashlib.sha256(files[path]).digest())
    return digest.hexdigest()


def corpus_sha256(cases: list[Case]) -> str:
    """sha256 over the cases ascending by id: each id, the canonical text of its record and the digest of its files."""
    digest = hashlib.sha256()
    for case in sorted(cases, key=lambda value: value.id):
        digest.update(case.id.encode("ascii") + b"\0" + dump_record(case.record).encode("utf-8") + b"\0"
                      + files_digest(case.files).encode("ascii") + b"\0")
    return digest.hexdigest()


def manifest_duplicates(files: dict[str, bytes], manifest_path: Path) -> list[str]:
    """The files of the sample that equal, byte for byte, a file of an item of a set whose role is `test` in the benchmark's
    manifest (only files of `TEST_SET_MIN_BYTES` or more are compared). The manifest holds hashes and sizes and no text, so this
    opens no test-set sample; a problem names the sample's path and nothing of the set. Raises `CorpusError` when the manifest
    cannot be read."""
    try:
        manifest = json.loads(Path(manifest_path).read_bytes().decode("utf-8"))
        test_sets = {name for name, value in manifest["sets"].items() if value["role"] == "test"}
        hashes = {file["sha256"] for item in manifest["items"] if item["set"] in test_sets for root in item["roots"]
                  for file in root["files"] if file["bytes"] >= TEST_SET_MIN_BYTES}
    except (OSError, ValueError, KeyError, TypeError):
        raise CorpusError(f"{Path(manifest_path).name} cannot be read as the benchmark's manifest") from None
    return [f"{shown(path)}: the file equals a file of a set that the benchmark keeps as a test set"
            for path, data in sorted(files.items())
            if len(data) >= TEST_SET_MIN_BYTES and hashlib.sha256(data).hexdigest() in hashes]


# --- the text of an issue form ---------------------------------------------------------------------------------------------

_HEADING = re.compile(r"^### (.+?)\s*$")
_FENCE_OPEN = re.compile(r"^(`{3,})[^`]*$")
_NO_RESPONSE = "_No response_"


def _answer(lines: list[str]) -> str:
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]
    if lines == [_NO_RESPONSE]:
        return ""
    opened = _FENCE_OPEN.match(lines[0]) if lines else None
    if opened and len(lines) >= 2 and re.fullmatch(f"`{{{len(opened.group(1))},}}[ \t]*", lines[-1]):
        return "\n".join(lines[1:-1])
    return "\n".join(lines)


def parse_issue_body(text: str) -> dict[str, str]:
    """The answers of an issue made from a form, by the label of each field: GitHub renders `### <label>` and the answer under
    it. A `render: text` answer is the content of its fenced block, taken line by line between the first fence line and its close
    (the fence may be longer than three characters); `_No response_` is an empty answer; line endings are read as LF. A heading
    inside a fenced block is text. A label that appears twice keeps its last answer. `parse_form_body` is the strict reading the
    add script uses, with the labels of one form."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    sections: dict[str, list[str]] = {}
    current: str | None = None
    fence: str | None = None
    for line in lines:
        if fence is None:
            heading = _HEADING.match(line)
            if heading:
                current = heading.group(1)
                sections[current] = []
                continue
            opened = _FENCE_OPEN.match(line)
            if opened:
                fence = opened.group(1)
        elif re.fullmatch(f"`{{{len(fence)},}}[ \t]*", line):
            fence = None
        if current is not None:
            sections[current].append(line)
    return {label: _answer(body) for label, body in sections.items()}


def form_headings(text: str) -> list[str]:
    """The text of every `### ` heading line of `text`, in order."""
    return [heading.group(1) for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            if (heading := _HEADING.match(line))]


def parse_form_body(text: str, labels: list[str] | tuple[str, ...]) -> dict[str, str]:
    """The answers of an issue made from one form whose fields have `labels`, in the form's order (r1:F1, r1:F2). Only a
    `### <label>` line of that list starts a field, so a sample's own blocks and other headings are its text; the answer is the
    text between its first and its last line (`_answer`). Raises `CorpusError` when one of the labels heads more than one line,
    since the sample then holds a line that GitHub's rendering cannot be told apart from (it would cut the sample short), or when
    the fields are out of the form's order."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    starts = [(index, heading.group(1)) for index, line in enumerate(lines)
              if (heading := _HEADING.match(line)) and heading.group(1) in labels]
    found = [label for _index, label in starts]
    for label in labels:
        if found.count(label) > 1:
            raise CorpusError(f"the body holds the heading ### {label} more than once; ask the reporter to rename that heading "
                              f"in the sample")
    positions = [labels.index(label) for label in found]
    if positions != sorted(positions):
        raise CorpusError("the fields of the body are not in the order of the form")
    ends = [index for index, _label in starts[1:]] + [len(lines)]
    return {label: _answer(lines[index + 1:end]) for (index, label), end in zip(starts, ends, strict=True)}


def file_bytes(content: str) -> bytes:
    """The bytes of one sample file from its text in an issue: LF endings, trailing blank lines dropped, one final newline;
    empty text is an empty file."""
    text = "\n".join(content.replace("\r\n", "\n").replace("\r", "\n").split("\n")).rstrip("\n")
    return (text + "\n").encode("utf-8") if text.strip() else b""


_MARKER = re.compile(r"^=== (.+?) ===$")


def split_files(text: str) -> tuple[dict[str, str], list[str]]:
    """The answer of the form's `more` field as `({path: text}, problems)`: each file starts with a line that is exactly
    `=== path ===`. Text before the first marker and a path used twice are problems."""
    files: dict[str, list[str]] = {}
    problems = []
    current: str | None = None
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        marker = _MARKER.match(line)
        if marker:
            current = marker.group(1)
            if current in files:
                problems.append(f"{shown(current)}: the path is given twice in the other files")
            files[current] = []
        elif current is not None:
            files[current].append(line)
        elif line.strip():
            problems.append("the other files start with text before the first line `=== path ===`")
            break
    return {path: "\n".join(lines) for path, lines in files.items()}, problems
