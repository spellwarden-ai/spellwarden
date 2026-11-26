"""The rule benchmark (Rule benchmark, section 9): one command that fetches every sample of the benchmark's fixed public sets
from its source at a pinned commit, checks every byte against `benchmarks/manifest.json`, runs the installed scanner's skill
rules over each skill in memory and prints the table. Rules only: no model is called.

    python benchmarks/rule_benchmark.py run [--cache DIR] [--offline] [--expect-version X] [--verify FILE] ...

Run it from the repository root with the Python that has the scanner installed (`uv run --locked` in a checkout, or a
virtual environment with `spellwarden==X.Y.Z` and `benchmarks/requirements.txt`). Python puts this file's directory first on
`sys.path`, so `import spellwarden_scan` is the installed scanner. No sample is printed, logged or written to disk as a file:
the cache holds the source objects as fetched (compressed archives, hash-named files) outside the repository, and every
message names ids, paths, URLs and hashes only. `benchmarks/README.md` says what is measured and how."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import inspect
import io
import json
import math
import os
import re
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from spellwarden_scan import RULES_VERSION, SEVERITY_RANK, RuleSet, scan_skill_package
from spellwarden_scan import __version__ as SCANNER_VERSION
from spellwarden_scan.frontmatter import FrontmatterLimit
from spellwarden_scan.identity import is_skill_file, nested_skill_roots, package_files, package_sha256

try:
    from spellwarden_scan import normalise as NORMALISE
    from spellwarden_scan.package import TextLimit
except ImportError:  # a scanner before 1.22.0: no normalised reading and no read limit error (P6-4 spec 6.2.2)
    NORMALISE = None

    class TextLimit(Exception):
        """Never raised: the installed scanner predates 1.22.0."""

REPOSITORY = Path(__file__).resolve().parents[1]
BENCHMARKS = REPOSITORY / "benchmarks"


def _load_disguise():
    """`disguise.py` beside this file, loaded by its path (P6-4 spec 6.1.1): the tests load this script by its path, where
    `benchmarks/` is not on `sys.path`, so a plain `import disguise` would fail there."""
    spec = importlib.util.spec_from_file_location("spellwarden_benchmark_disguise", Path(__file__).with_name("disguise.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DISGUISE = _load_disguise()


def _load_measured_sets():
    """`measured_sets.py` beside this file, loaded by its path as `disguise.py` is (P6-9 spec 8.6): the record of the rules that
    are measured on a set of their own, its validator and the release check."""
    path = Path(__file__).with_name("measured_sets.py")
    spec = importlib.util.spec_from_file_location("spellwarden_benchmark_measured_sets", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MEASURED_SETS = _load_measured_sets()


def _load_community():
    """`scripts/community_corpus.py`, the one reader of `fixtures/community/`, loaded by its path (community reports spec 8.3):
    the tests load this script by its path too, so a plain import would fail."""
    spec = importlib.util.spec_from_file_location("spellwarden_community_corpus", REPOSITORY / "scripts" / "community_corpus.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["spellwarden_community_corpus"] = module
    spec.loader.exec_module(module)
    return module


COMMUNITY = _load_community()
COMMUNITY_DIR = REPOSITORY / "fixtures" / "community"
USER_AGENT = "spellwarden-rule-benchmark/1 (+https://github.com/spellwarden-ai/spellwarden)"
TIMEOUT_SECONDS = 60
PARALLEL_REQUESTS = 8
RETRY_DELAYS = (2, 4)
MAX_REDIRECTS = 5
TOKEN_HOSTS = ("raw.githubusercontent.com",)
LABELS = ("malicious", "benign")
ROLES = ("test", "tuning")
KINDS = ("tar.gz", "parquet")
PER_ITEM = "per-item"
MAX_ROOTS = 20
MAX_FILES = 300
MAX_FILE_BYTES = 2_000_000
MAX_ROOT_BYTES = 5_000_000
MAX_PER_ITEM_ITEMS = 20
MAX_STRING = 400
_NAME = re.compile(r"[A-Za-z0-9._-]{1,60}")
_ITEM_ID = re.compile(r"[A-Za-z0-9._-]{1,100}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_RAW_URL = re.compile(r"https://raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/\S+")
TOP_MEMBERS = {"manifest", "name", "built", "sources", "sets", "items", "excluded"}
SOURCE_MEMBERS = {"url", "sha256", "bytes", "kind", "title", "licence"}
SET_MEMBERS = {"title", "role", "strata", "report"}
STRATUM_MEMBERS = {"label", "title"}
ITEM_MEMBERS = {"id", "set", "stratum", "ref", "licence", "roots"}
ROOT_MEMBERS = {"package_sha256", "files"}
FILE_MEMBERS = {"path", "sha256", "bytes", "from"}
EXCLUDED_MEMBERS = {"id", "set", "stratum", "reason", "date"}
FROM_FORMS = ({"source", "member"}, {"source", "row"}, {"url"})


class BenchmarkError(Exception):
    """An error that stops the command with exit 2. `code` is the error name the one-line message starts with."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code

    def line(self) -> str:
        return f"{self.code}: {self}"


class ManifestError(BenchmarkError):
    def __init__(self, message: str) -> None:
        super().__init__("manifest_invalid", message)


class FetchFailed(BenchmarkError):
    """`status` is the HTTP status of the answer that failed, or None for a network error, a wrong size or a wrong hash."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__("fetch_failed", message)
        self.status = status


# --- the manifest (Rule benchmark, 10.1) ------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Manifest:
    document: dict
    sha256: str
    sources: dict
    sets: dict
    items: list
    excluded: list


def manifest_sha256(document: object) -> str:
    """The sha256 of the canonical JSON of the parsed manifest, so a checkout with CRLF line endings gives the same value."""
    text = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, inner in value.items():
            yield key
            yield from _strings(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _strings(inner)


def _members(value: object, allowed: set[str], required: set[str], where: str) -> dict:
    if not isinstance(value, dict):
        raise ManifestError(f"{where} is not an object")
    extra = sorted(set(value) - allowed)
    if extra:
        raise ManifestError(f"{where} has a member the manifest does not allow: {extra[0]}")
    missing = sorted(required - set(value))
    if missing:
        raise ManifestError(f"{where} lacks the member {missing[0]}")
    return value


def _count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def valid_path(path: object) -> bool:
    """A relative POSIX path: no leading slash or backslash, no `..`, `.` or empty part, no backslash, no NUL, at most 400 bytes
    in UTF-8."""
    if not isinstance(path, str) or not path or path.startswith(("/", "\\")) or "\\" in path or "\0" in path:
        return False
    try:
        size = len(path.encode("utf-8"))
    except UnicodeEncodeError:
        return False
    return size <= MAX_STRING and all(part not in ("", ".", "..") for part in path.split("/"))


def check_source(source_id: str, source: object) -> None:
    where = f"source {source_id}"
    if not isinstance(source_id, str) or not _NAME.fullmatch(source_id):
        raise ManifestError(f"{where}: the id must be 1 to 60 letters, digits, dots, underscores or hyphens")
    _members(source, SOURCE_MEMBERS, {"url", "sha256", "bytes", "kind", "title"}, where)
    if not isinstance(source["url"], str) or not source["url"].startswith("https://"):
        raise ManifestError(f"{where}: the url must start with https://")
    if not isinstance(source["sha256"], str) or not _SHA256.fullmatch(source["sha256"]):
        raise ManifestError(f"{where}: sha256 must be 64 lower-case hex characters")
    if not _count(source["bytes"]) or source["bytes"] <= 0:
        raise ManifestError(f"{where}: bytes must be a positive whole number")
    if source["kind"] not in KINDS:
        raise ManifestError(f"{where}: kind must be tar.gz or parquet")
    if not isinstance(source["title"], str) or not source["title"]:
        raise ManifestError(f"{where}: the title is missing")
    if "licence" in source and not isinstance(source["licence"], str):
        raise ManifestError(f"{where}: licence must be text")


def check_set(set_id: str, value: object) -> None:
    where = f"set {set_id}"
    if not isinstance(set_id, str) or not _NAME.fullmatch(set_id):
        raise ManifestError(f"{where}: the id must be 1 to 60 letters, digits, dots, underscores or hyphens")
    _members(value, SET_MEMBERS, {"title", "role", "strata"}, where)
    if not isinstance(value["title"], str) or not value["title"]:
        raise ManifestError(f"{where}: the title is missing")
    if value["role"] not in ROLES:
        raise ManifestError(f"{where}: role must be test or tuning")
    if "report" in value and value["report"] != PER_ITEM:
        raise ManifestError(f"{where}: report may only be per-item")
    if not isinstance(value["strata"], dict) or not value["strata"]:
        raise ManifestError(f"{where}: strata must be a non-empty object")
    for stratum_id, stratum in value["strata"].items():
        here = f"{where}, stratum {stratum_id}"
        if not isinstance(stratum_id, str) or not _NAME.fullmatch(stratum_id):
            raise ManifestError(f"{here}: the id must be 1 to 60 letters, digits, dots, underscores or hyphens")
        _members(stratum, STRATUM_MEMBERS, STRATUM_MEMBERS, here)
        if stratum["label"] not in LABELS:
            raise ManifestError(f"{here}: label must be malicious or benign")
        if not isinstance(stratum["title"], str) or not stratum["title"]:
            raise ManifestError(f"{here}: the title is missing")
        if value.get("report") == PER_ITEM and stratum["label"] != "malicious":
            raise ManifestError(f"{here}: every stratum of a per-item set has the label malicious")


def _check_from(where: str, path: str, origin: object, sources: Mapping[str, dict]) -> None:
    if not isinstance(origin, dict) or set(origin) not in FROM_FORMS:
        raise ManifestError(f"{where}: from must be exactly one of source and member, source and row, or url")
    if "url" in origin:
        if not isinstance(origin["url"], str) or not _RAW_URL.fullmatch(origin["url"]):
            raise ManifestError(f"{where}: url must be a raw.githubusercontent.com URL at a 40-hex commit")
        return
    source = sources.get(origin["source"]) if isinstance(origin["source"], str) else None
    if source is None:
        raise ManifestError(f"{where}: the source {origin['source']} is not in sources")
    if "member" in origin:
        if source["kind"] != "tar.gz" or not isinstance(origin["member"], str) or not origin["member"]:
            raise ManifestError(f"{where}: a member is a non-empty name in a tar.gz source")
    else:
        if source["kind"] != "parquet" or not isinstance(origin["row"], str) or not origin["row"]:
            raise ManifestError(f"{where}: a row is a non-empty id in a parquet source")
        if path != "SKILL.md":
            raise ManifestError(f"{where}: a parquet row is always SKILL.md")


def check_item(item: object, sources: Mapping[str, dict], sets: Mapping[str, dict]) -> None:
    """Checks one item record (10.1.1, 10.1.2) against checked sources and sets; raises `ManifestError` naming the item."""
    if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not _ITEM_ID.fullmatch(item["id"]):
        raise ManifestError("an item has no id of 1 to 100 letters, digits, dots, underscores or hyphens")
    where = f"item {item['id']}"
    _members(item, ITEM_MEMBERS, {"id", "set", "stratum", "roots"}, where)
    long = next((text for text in _strings(item) if len(text) > MAX_STRING), None)
    if long is not None:
        raise ManifestError(f"{where}: a string is longer than {MAX_STRING} characters")
    if item["set"] not in sets or item["stratum"] not in sets[item["set"]]["strata"]:
        raise ManifestError(f"{where}: the set or the stratum is not in sets")
    for name in ("ref", "licence"):
        if name in item and not isinstance(item[name], str):
            raise ManifestError(f"{where}: {name} must be text")
    roots = item["roots"]
    if not isinstance(roots, list) or not 1 <= len(roots) <= MAX_ROOTS:
        raise ManifestError(f"{where}: an item has 1 to {MAX_ROOTS} roots")
    seen_roots: set[str] = set()
    for number, root in enumerate(roots, start=1):
        here = f"{where}, root {number}"
        _members(root, ROOT_MEMBERS, ROOT_MEMBERS, here)
        if not isinstance(root["package_sha256"], str) or not _SHA256.fullmatch(root["package_sha256"]):
            raise ManifestError(f"{here}: package_sha256 must be 64 lower-case hex characters")
        if root["package_sha256"] in seen_roots:
            raise ManifestError(f"{where}: one root hash appears twice")
        seen_roots.add(root["package_sha256"])
        files = root["files"]
        if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
            raise ManifestError(f"{here}: a root has 1 to {MAX_FILES} files")
        paths: set[str] = set()
        total = 0
        for entry in files:
            _members(entry, FILE_MEMBERS, FILE_MEMBERS, f"{here}, a file")
            if not valid_path(entry["path"]):
                raise ManifestError(f"{here}: a file path is not a safe relative POSIX path")
            spot = f"{here}, file {entry['path']}"
            if entry["path"] in paths:
                raise ManifestError(f"{spot}: the path appears twice")
            paths.add(entry["path"])
            if not isinstance(entry["sha256"], str) or not _SHA256.fullmatch(entry["sha256"]):
                raise ManifestError(f"{spot}: sha256 must be 64 lower-case hex characters")
            if not _count(entry["bytes"]) or not 0 <= entry["bytes"] <= MAX_FILE_BYTES:
                raise ManifestError(f"{spot}: bytes must be a whole number from 0 to {MAX_FILE_BYTES}")
            total += entry["bytes"]
            _check_from(spot, entry["path"], entry["from"], sources)
        if total > MAX_ROOT_BYTES:
            raise ManifestError(f"{here}: the files hold more than {MAX_ROOT_BYTES} bytes")
        if "SKILL.md" not in paths:
            raise ManifestError(f"{here}: no file has the path SKILL.md")


def check_manifest(document: object) -> Manifest:
    """The manifest, checked (10.1.1, 10.1.2); raises `ManifestError` naming the first problem."""
    top = _members(document, TOP_MEMBERS, {"manifest", "sources", "sets", "items", "excluded"}, "the manifest")
    if top["manifest"] != 1 or isinstance(top["manifest"], bool):
        raise ManifestError("the manifest must have \"manifest\": 1")
    if not isinstance(top["sources"], dict) or not isinstance(top["sets"], dict) or not isinstance(top["items"], list):
        raise ManifestError("sources and sets must be objects and items a list")
    if not isinstance(top["excluded"], list):
        raise ManifestError("excluded must be a list")
    for name in ("name", "built"):
        if name in top and not isinstance(top[name], str):
            raise ManifestError(f"{name} must be text")
    long = next((text for text in _strings(document) if len(text) > MAX_STRING), None)
    if long is not None:
        raise ManifestError(f"a string of the manifest is longer than {MAX_STRING} characters")
    for source_id, source in top["sources"].items():
        check_source(source_id, source)
    for set_id, value in top["sets"].items():
        check_set(set_id, value)
    seen: set[str] = set()
    sets_of_hash: dict[str, set[str]] = {}
    lists: dict[str, set[tuple[str, ...]]] = {}
    per_set: dict[str, int] = {}
    for item in top["items"]:
        check_item(item, top["sources"], top["sets"])
        if item["id"] in seen:
            raise ManifestError(f"item {item['id']}: the id appears twice")
        seen.add(item["id"])
        hashes = tuple(root["package_sha256"] for root in item["roots"])
        for value in hashes:
            sets_of_hash.setdefault(value, set()).add(item["set"])
        if hashes in lists.setdefault(item["set"], set()):
            raise ManifestError(f"item {item['id']}: another item of set {item['set']} has the same list of root hashes")
        lists[item["set"]].add(hashes)
        per_set[item["set"]] = per_set.get(item["set"], 0) + 1
    for value, owners in sorted(sets_of_hash.items()):
        if len(owners) > 1:
            names = ", ".join(sorted(owners))
            raise ManifestError(f"the package hash {value} appears in items of two sets ({names})")
    for set_id, value in top["sets"].items():
        if value.get("report") == PER_ITEM and not 1 <= per_set.get(set_id, 0) <= MAX_PER_ITEM_ITEMS:
            raise ManifestError(f"set {set_id}: a per-item set has 1 to {MAX_PER_ITEM_ITEMS} items")
    for record in top["excluded"]:
        _members(record, EXCLUDED_MEMBERS, EXCLUDED_MEMBERS, "an excluded record")
        where = f"excluded {record['id']}"
        if not isinstance(record["id"], str) or not _ITEM_ID.fullmatch(record["id"]) or record["id"] in seen:
            raise ManifestError(f"{where}: the id is malformed or is also an item")
        if record["set"] not in top["sets"] or record["stratum"] not in top["sets"][record["set"]]["strata"]:
            raise ManifestError(f"{where}: the set or the stratum is not in sets")
        if not isinstance(record["reason"], str) or not record["reason"]:
            raise ManifestError(f"{where}: the reason is missing")
        if not isinstance(record["date"], str) or not _DATE.fullmatch(record["date"]):
            raise ManifestError(f"{where}: the date must be YYYY-MM-DD")
    items = sorted(top["items"], key=lambda item: item["id"])
    return Manifest(document, manifest_sha256(document), top["sources"], top["sets"], items, top["excluded"])


def load_manifest(path: Path) -> Manifest:
    """The manifest file, checked. A missing file is `manifest_missing` (10.1.5); anything else wrong is `ManifestError`."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise BenchmarkError("manifest_missing",
                             f"{path} does not exist; it is written by benchmarks/build_manifest.py") from None
    except OSError as exc:
        raise ManifestError(f"{path} cannot be read: {type(exc).__name__}") from None
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ManifestError(f"{path} is not UTF-8 JSON") from None
    return check_manifest(document)


def sample_hash(files: Mapping[str, bytes]) -> str:
    """The engine's package hash of one skill root, as `scripts/measure_analyzer.py` computes it: the identity each root of the
    manifest is pinned by."""
    return package_sha256(package_files(files, "", nested_skill_roots(files, "")).files)


# --- the cache (10.3.4) ------------------------------------------------------------------------------------------------------

class Cache:
    """A content-addressed store: `objects/<sha256>`, as fetched. `get` hashes what it reads again; `put` refuses data whose hash
    differs and writes through a temporary file and `os.replace`."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.objects = directory / "objects"

    def get(self, sha256: str) -> bytes | None:
        try:
            data = (self.objects / sha256).read_bytes()
        except OSError:
            return None
        return data if hashlib.sha256(data).hexdigest() == sha256 else None

    def put(self, sha256: str, data: bytes) -> None:
        if hashlib.sha256(data).hexdigest() != sha256:
            raise ValueError("the data does not have the sha256 it is stored under")
        self.objects.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=self.objects, prefix=".part-")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
            os.replace(temporary, self.objects / sha256)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise


def inside_repository(path: Path) -> bool:
    resolved = path.resolve()
    return resolved == REPOSITORY or REPOSITORY in resolved.parents


def cache_directory(option: Path | None, environ: Mapping[str, str], *, windows: bool) -> Path:
    """`--cache`, else SPELLWARDEN_BENCHMARK_CACHE, else the per-user cache directory (10.3.4). A directory inside the repository
    checkout is the error `cache_in_repository`."""
    if option is not None:
        chosen = option
    elif environ.get("SPELLWARDEN_BENCHMARK_CACHE"):
        chosen = Path(environ.get("SPELLWARDEN_BENCHMARK_CACHE"))
    elif windows and environ.get("LOCALAPPDATA"):
        chosen = Path(environ.get("LOCALAPPDATA")) / "spellwarden" / "benchmark-cache"
    elif environ.get("XDG_CACHE_HOME"):
        chosen = Path(environ.get("XDG_CACHE_HOME")) / "spellwarden" / "benchmark-cache"
    else:
        chosen = Path.home() / ".cache" / "spellwarden" / "benchmark-cache"
    if inside_repository(chosen):
        raise BenchmarkError("cache_in_repository",
                             f"the cache {chosen} is inside the repository checkout; choose a directory outside it")
    return chosen.resolve()


# --- fetching (10.3) ---------------------------------------------------------------------------------------------------------

class Answer(NamedTuple):
    """One HTTP answer: the status, the Location of a redirect (or None) and at most `limit` bytes of the body."""
    status: int
    location: str | None
    body: bytes


Opener = Callable[[str, Mapping[str, str], float, int], Answer]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002 (the signature urllib calls)
        return None


_URLLIB = urllib.request.build_opener(_NoRedirect)


def urllib_opener(url: str, headers: Mapping[str, str], timeout: float, limit: int) -> Answer:
    """One GET without following redirects: `download` follows them itself, so it can check each hop."""
    request = urllib.request.Request(url, headers=dict(headers))
    try:
        with _URLLIB.open(request, timeout=timeout) as response:
            return Answer(response.status, None, response.read(limit))
    except urllib.error.HTTPError as error:
        location = error.headers.get("Location") if 300 <= error.code < 400 else None
        error.close()
        return Answer(error.code, location, b"")


class _TryAgain(Exception):
    pass


def _one_pass(url: str, limit: int, *, opener: Opener, token: str | None, token_hosts: tuple[str, ...]) -> bytes:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        if not current.startswith("https://"):
            raise FetchFailed(f"{url}: a redirect leads to a URL that is not https")
        headers = {"User-Agent": USER_AGENT}
        if token and urllib.parse.urlsplit(current).hostname in token_hosts:
            headers["Authorization"] = f"Bearer {token}"
        try:
            answer = opener(current, headers, TIMEOUT_SECONDS, limit + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise _TryAgain(type(exc).__name__) from None
        if answer.status in (301, 302, 303, 307, 308) and answer.location:
            current = urllib.parse.urljoin(current, answer.location)
            continue
        if answer.status == 429 or answer.status >= 500:
            raise _TryAgain(f"HTTP {answer.status}")
        if answer.status != 200:
            raise FetchFailed(f"{url}: HTTP {answer.status}", answer.status)
        return answer.body
    raise FetchFailed(f"{url}: more than {MAX_REDIRECTS} redirects")


def download(url: str, limit: int, *, opener: Opener, token: str | None = None,
             token_hosts: tuple[str, ...] = TOKEN_HOSTS, sleep: Callable[[float], None] = time.sleep) -> bytes:
    """At most `limit + 1` bytes of `url` (10.3.2): https only, redirects followed only to https URLs, a connection error, a
    timeout, HTTP 429 or a 5xx answer tried again twice after 2 and 4 seconds, any other 4xx a `FetchFailed` at once. The token
    goes to `token_hosts` only, and is dropped when a redirect leaves them."""
    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            return _one_pass(url, limit, opener=opener, token=token, token_hosts=token_hosts)
        except _TryAgain as exc:
            if attempt == len(RETRY_DELAYS):
                raise FetchFailed(f"{url}: {exc} after {attempt + 1} tries") from None
            sleep(RETRY_DELAYS[attempt])
    raise AssertionError("not reached")


def fetch_object(url: str, sha256: str, size: int, cache: Cache, *, opener: Opener, token: str | None = None,
                 sleep: Callable[[float], None] = time.sleep) -> bytes:
    """One object by its recorded size and hash: from the cache when it is there, else downloaded, checked and put in the
    cache. A body of another length or hash is refused and never cached."""
    cached = cache.get(sha256)
    if cached is not None:
        return cached
    data = download(url, size, opener=opener, token=token, sleep=sleep)
    if len(data) != size:
        longer = "longer" if len(data) > size else "shorter"
        raise FetchFailed(f"{url}: the body is {longer} than the {size} bytes the manifest says")
    actual = hashlib.sha256(data).hexdigest()
    if actual != sha256:
        raise FetchFailed(f"{url}: sha256 {actual}, the manifest says {sha256}")
    cache.put(sha256, data)
    return data


class Need(NamedTuple):
    what: str
    url: str
    sha256: str
    size: int


class FetchReport(NamedTuple):
    needed: int
    fetched: int


def needed_objects(manifest: Manifest) -> list[Need]:
    """Every source object the items use and every file fetched by URL, once per sha256, in a stable order."""
    needs: dict[str, Need] = {}
    used: set[str] = set()
    for item in manifest.items:
        for root in item["roots"]:
            for entry in root["files"]:
                origin = entry["from"]
                if "url" in origin:
                    needs.setdefault(entry["sha256"], Need(f"item {item['id']}, file {entry['path']}", origin["url"],
                                                           entry["sha256"], entry["bytes"]))
                else:
                    used.add(origin["source"])
    for source_id in sorted(used):
        source = manifest.sources[source_id]
        needs.setdefault(source["sha256"], Need(f"source {source_id}", source["url"], source["sha256"], source["bytes"]))
    return sorted(needs.values(), key=lambda need: (not need.what.startswith("source "), need.what))


def fetch(manifest: Manifest, cache: Cache, *, opener: Opener, offline: bool, token: str | None,
          sleep: Callable[[float], None] = time.sleep) -> FetchReport:
    """Gets every object the manifest needs and the cache lacks (10.3.1), 8 at a time. With `offline` nothing is fetched and a
    missing object is the error `object_missing`."""
    needs = needed_objects(manifest)
    missing = [need for need in needs if cache.get(need.sha256) is None]
    if offline and missing:
        raise BenchmarkError("object_missing",
                             f"{missing[0].what} is not in the cache {cache.directory} and --offline fetches nothing")
    with ThreadPoolExecutor(max_workers=PARALLEL_REQUESTS, thread_name_prefix="fetch") as pool:
        futures = [pool.submit(fetch_object, need.url, need.sha256, need.size, cache, opener=opener, token=token, sleep=sleep)
                   for need in missing]
        errors = []
        for need, future in zip(missing, futures, strict=True):
            try:
                future.result()
            except FetchFailed as exc:
                errors.append(FetchFailed(f"{need.what}: {exc}", exc.status))
    if errors:
        raise errors[0]
    return FetchReport(len(needs), len(missing))


# --- rebuilding and verifying a skill (10.4) -------------------------------------------------------------------------------

PYARROW_FIX = "pip install --require-hashes -r benchmarks/requirements.txt"


class Objects:
    """The verified source objects a run reads, each opened once: the members of a tar.gz source that the manifest lists, the
    rows of a parquet source, and url files from the cache. Nothing is extracted to disk."""

    def __init__(self, manifest: Manifest, cache: Cache) -> None:
        self._manifest = manifest
        self._cache = cache
        self._members: dict[str, dict[str, bytes]] = {}
        self._rows: dict[str, dict[str, list[tuple[object, object]]]] = {}
        self._wanted: dict[str, set[str]] = {}
        for item in manifest.items:
            for root in item["roots"]:
                for entry in root["files"]:
                    if "member" in entry["from"]:
                        self._wanted.setdefault(entry["from"]["source"], set()).add(entry["from"]["member"])

    def _object(self, source_id: str) -> bytes:
        source = self._manifest.sources[source_id]
        data = self._cache.get(source["sha256"])
        if data is None:
            raise BenchmarkError("object_missing", f"source {source_id} is not in the cache {self._cache.directory}")
        return data

    def member(self, source_id: str, name: str, item_id: str) -> bytes:
        if source_id not in self._members:
            found: dict[str, bytes] = {}
            wanted = self._wanted.get(source_id, set())
            with tarfile.open(fileobj=io.BytesIO(self._object(source_id)), mode="r:gz") as archive:
                for info in archive:
                    if info.name not in wanted:
                        continue
                    if info.isreg():
                        handle = archive.extractfile(info)
                        found[info.name] = handle.read() if handle is not None else b""
                    else:
                        found.pop(info.name, None)
            self._members[source_id] = found
        data = self._members[source_id].get(name)
        if data is None:
            raise BenchmarkError("sample_changed", f"item {item_id}: the member {name} of source {source_id} is missing or not a "
                                                   "regular file")
        return data

    def row(self, source_id: str, row_id: str, item_id: str) -> bytes:
        if source_id not in self._rows:
            try:
                import pyarrow.parquet as parquet
            except ImportError:
                raise BenchmarkError("pyarrow_missing", f"reading source {source_id} needs pyarrow: {PYARROW_FIX}") from None
            table = parquet.read_table(io.BytesIO(self._object(source_id)),
                                       columns=["benchmark_id", "skill_text", "text_available"])
            rows: dict[str, list[tuple[object, object]]] = {}
            for key, text, available in zip(table.column("benchmark_id").to_pylist(), table.column("skill_text").to_pylist(),
                                            table.column("text_available").to_pylist(), strict=True):
                rows.setdefault(str(key), []).append((text, available))
            self._rows[source_id] = rows
        found = self._rows[source_id].get(row_id, [])
        if len(found) != 1:
            raise BenchmarkError("sample_changed", f"item {item_id}: source {source_id} holds the row {row_id} "
                                                   f"{len(found)} times, not once")
        text, available = found[0]
        if available is not True or not isinstance(text, str):
            raise BenchmarkError("sample_changed", f"item {item_id}: the row {row_id} of source {source_id} has no text "
                                                   "available")
        return text.encode("utf-8")

    def url_file(self, entry: dict, item_id: str) -> bytes:
        data = self._cache.get(entry["sha256"])
        if data is None:
            raise BenchmarkError("object_missing", f"item {item_id}, file {entry['path']} is not in the cache "
                                                   f"{self._cache.directory}")
        return data


def rebuild(item: dict, objects: Objects) -> list[dict[str, bytes]]:
    """One `{path: bytes}` per skill root of the item, from verified objects, checked file by file and root by root (10.4.2).
    A difference is the error `sample_changed`, naming the item, the file or root and both hashes, never content."""
    roots = []
    for number, root in enumerate(item["roots"], start=1):
        files: dict[str, bytes] = {}
        for entry in root["files"]:
            origin = entry["from"]
            if "member" in origin:
                data = objects.member(origin["source"], origin["member"], item["id"])
            elif "row" in origin:
                data = objects.row(origin["source"], origin["row"], item["id"])
            else:
                data = objects.url_file(entry, item["id"])
            actual = hashlib.sha256(data).hexdigest()
            if len(data) != entry["bytes"] or actual != entry["sha256"]:
                raise BenchmarkError("sample_changed", f"item {item['id']}, file {entry['path']}: sha256 {actual} "
                                                       f"({len(data)} bytes), the manifest says {entry['sha256']} "
                                                       f"({entry['bytes']} bytes)")
            files[entry["path"]] = data
        actual = sample_hash(files)
        if actual != root["package_sha256"]:
            raise BenchmarkError("sample_changed", f"item {item['id']}, root {number}: package hash {actual}, the manifest says "
                                                   f"{root['package_sha256']}")
        roots.append(files)
    return roots


# --- scanning (10.5) ---------------------------------------------------------------------------------------------------------

LINES = ("medium", "high")
LINE_RANK = {line: SEVERITY_RANK[line] for line in LINES}
NONE = "none"
SCAN_CAP = 1_000_000


# The rules that report a disguise itself whatever the content (P6-4 spec 6.1.7, 6.2.4): a hidden character, a decode-and-run
# line, obfuscated script code. SW-SKL-032 is not one: its decoding branch reports what the decoded text does.
DISGUISE_RULES = ("SW-SKL-002", "SW-SKL-004", "SW-SKL-014")


class ItemResult(NamedTuple):
    """One item's result: `unread` is the reason it was not read whole (None when it was), `worst` its worst severity over
    every rule (`none` without a finding), `rules` the worst severity per rule that found something and `other` (1.22.0) the
    worst severity over the rules that are not `DISGUISE_RULES`."""
    unread: str | None
    worst: str
    rules: dict[str, str]
    other: str = "none"


class RootReading(NamedTuple):
    """One scan of one root: the reason it was not read whole (or None), the worst severity per rule and, for the check that
    normalisation removes nothing (P6-4 spec 6.2.3), `(rule id, path, line, fingerprint)` of every finding."""
    unread: str | None
    rules: dict[str, str]
    keys: frozenset


def worse(first: str, second: str) -> str:
    """The worse of two severities, `none` being better than any."""
    if first == NONE:
        return second
    if second == NONE:
        return first
    return first if SEVERITY_RANK[first] <= SEVERITY_RANK[second] else second


def at_or_above(severity: str, line: str) -> bool:
    return severity != NONE and SEVERITY_RANK[severity] <= LINE_RANK[line]


def normalises(function: Callable) -> bool:
    """Whether the installed `scan_skill_package` takes the keyword `normalise` (1.22.0, P6-4 spec 6.2.2)."""
    parameters = inspect.signature(function).parameters
    return "normalise" in parameters or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values())


def read_root(files: Mapping[str, bytes], rules: RuleSet, normalise: object = None) -> RootReading:
    """One scan of one root (10.5.1, 10.5.2): `normalise` is passed to the scanner unless it is None (the scanner's default).
    Any exception is unread content, never a clean skill, and no message quotes text."""
    options = {} if normalise is None else {"normalise": normalise}
    try:
        result = scan_skill_package(files, rules, root="", nested_roots=nested_skill_roots(files, ""),
                                    max_findings=SCAN_CAP, max_per_rule=SCAN_CAP, **options)
    except FrontmatterLimit:
        return RootReading("frontmatter_limit", {}, frozenset())
    except TextLimit:
        return RootReading("text_limit", {}, frozenset())
    except Exception as exc:  # any scanner failure is unread content, never a clean skill
        return RootReading(f"scanner_error:{type(exc).__name__}", {}, frozenset())
    if result.truncated > 0:
        return RootReading("findings_truncated", {}, frozenset())
    found: dict[str, str] = {}
    for finding in result.findings:
        found[finding.rule_id] = worse(found.get(finding.rule_id, NONE), finding.severity)
    keys = frozenset((f.rule_id, f.location.path, f.location.line, f.fingerprint) for f in result.findings)
    return RootReading(None, found, keys)


def scan_root(files: Mapping[str, bytes], rules: RuleSet) -> tuple[str | None, dict[str, str]]:
    """The reason one root was not read whole (or None) and the worst severity per rule of its findings, with the scanner's
    default reading (10.5.1, 10.5.2)."""
    reading = read_root(files, rules)
    return reading.unread, reading.rules


def fold_roots(readings: list[RootReading]) -> ItemResult:
    """Folds the readings of one item's roots (10.5.3): any unread root makes the whole item unread (the first such root's
    reason); otherwise each rule's worst severity is the worst over the roots."""
    merged: dict[str, str] = {}
    for reading in readings:
        if reading.unread is not None:
            return ItemResult(reading.unread, NONE, {})
        for rule_id, severity in reading.rules.items():
            merged[rule_id] = worse(merged.get(rule_id, NONE), severity)
    overall = other = NONE
    for rule_id, severity in merged.items():
        overall = worse(overall, severity)
        if rule_id not in DISGUISE_RULES:
            other = worse(other, severity)
    return ItemResult(None, overall, merged, other)


def scan_item(roots: list[dict[str, bytes]], rules: RuleSet) -> ItemResult:
    """One item with the scanner's default reading (10.5.3)."""
    return fold_roots([read_root(files, rules) for files in roots])


class BothReadings(NamedTuple):
    """One item read as written (`normalise=False`) and normalised (the scanner's default), and per rule the findings the
    normalised reading adds over all roots read whole both ways."""
    written: ItemResult
    normalised: ItemResult
    added: dict[str, int]


def scan_both(roots: list[dict[str, bytes]], rules: RuleSet, item_id: str, normalise: object = True) -> BothReadings:
    """Each root as written and with `normalise` (P6-4 spec 6.2.1); a scanner without the keyword gives one reading for both
    (6.2.2). A finding of the reading as written that the normalised reading lacks stops the run (6.2.3,
    `normalisation_removed`), naming the item and the rule, never text."""
    both = normalises(scan_skill_package)
    written: list[RootReading] = []
    normalised: list[RootReading] = []
    added: dict[str, int] = {}
    for files in roots:
        plain = read_root(files, rules, False if both else None)
        other = read_root(files, rules, normalise) if both else plain
        if plain.unread is None and other.unread is None:
            lost = sorted(plain.keys - other.keys, key=lambda key: (key[0], key[1], key[2] or 0, key[3]))
            if lost:
                raise BenchmarkError("normalisation_removed", f"item {item_id}: the normalised reading lacks a finding of "
                                                              f"{lost[0][0]} that the text as written gives")
            for key in other.keys - plain.keys:
                added[key[0]] = added.get(key[0], 0) + 1
        written.append(plain)
        normalised.append(other)
    return BothReadings(fold_roots(written), fold_roots(normalised), added)


class VariantReadings(NamedTuple):
    """One technique on one item: `changed` is False when the variant of every root equals the root (nothing more was
    scanned); `readings` is None when the generator failed (the variant is not read whole)."""
    changed: bool
    readings: BothReadings | None


def scan_variant(roots: list[dict[str, bytes]], rules: RuleSet, item_id: str, technique: str,
                 normalise: object = True) -> VariantReadings:
    """The variant of each root under `technique`, scanned both ways when any root changed (P6-4 spec 6.2.1). The variant
    lives in memory only and is dropped here; an exception from the generator is unread content, and no message quotes text."""
    try:
        variants = [DISGUISE.variant(files, technique, key=f"{item_id}/{number}") for number, files in enumerate(roots, start=1)]
    except Exception:  # the generator failed: the variant is not read whole, the run goes on
        return VariantReadings(True, None)
    if all(variant == files for variant, files in zip(variants, roots, strict=True)):
        return VariantReadings(False, None)
    return VariantReadings(True, scan_both(variants, rules, item_id, normalise))


# --- counting (10.6) and the entry (10.7) ------------------------------------------------------------------------------------

def count_stratum(title: str, label: str, results: list[tuple[str, ItemResult]], rule_ids: list[str], *,
                  per_item: bool) -> dict:
    """The counts of one stratum from its items' results, in id order."""
    stratum: dict = {"title": title, "label": label, "items": len(results), "unread": {},
                     "found": {line: 0 for line in LINES},
                     "rules": {rule_id: {line: 0 for line in LINES} for rule_id in rule_ids}}
    if label == "malicious":
        stratum["missed"] = {}
    if per_item:
        stratum["outcomes"] = {}
    for item_id, result in results:
        if result.unread is not None:
            stratum["unread"][item_id] = result.unread
            continue
        for line in LINES:
            stratum["found"][line] += at_or_above(result.worst, line)
            for rule_id in rule_ids:
                stratum["rules"][rule_id][line] += at_or_above(result.rules.get(rule_id, NONE), line)
        if label == "malicious" and not at_or_above(result.worst, "high"):
            stratum["missed"][item_id] = result.worst
        if per_item:
            stratum["outcomes"][item_id] = result.worst
    return stratum


def _found_block() -> dict:
    return {"found": {line: 0 for line in LINES}, "found_other": {line: 0 for line in LINES}}


def _add_found(block: dict, result: ItemResult) -> None:
    for line in LINES:
        block["found"][line] += at_or_above(result.worst, line)
        block["found_other"][line] += at_or_above(result.other, line)


def _technique_block() -> dict:
    return {"changed": 0, "unread": 0, "plain_as_written": _found_block(), "plain_normalised": _found_block(),
            "disguised_as_written": _found_block(), "disguised_normalised": _found_block()}


def count_technique(block: dict, plain: BothReadings, variant: VariantReadings) -> None:
    """Adds one malicious item to a technique's counts for its set (P6-4 spec 6.2.4): nothing when the technique did not change
    it; `changed`, and `unread` when its variant was not read whole in either reading; otherwise the four detections."""
    if not variant.changed:
        return
    block["changed"] += 1
    readings = variant.readings
    if readings is None or readings.written.unread is not None or readings.normalised.unread is not None:
        block["unread"] += 1
        return
    _add_found(block["plain_as_written"], plain.written)
    _add_found(block["plain_normalised"], plain.normalised)
    _add_found(block["disguised_as_written"], readings.written)
    _add_found(block["disguised_normalised"], readings.normalised)


def count_plain(results: list[ItemResult], rule_ids: list[str]) -> dict:
    """The reading as written of one label of one set (P6-4 spec 6.2.5 `plain_as_written`): items read whole, found at each line
    and per rule."""
    read = [result for result in results if result.unread is None]
    return {"read": len(read), "found": {line: sum(at_or_above(r.worst, line) for r in read) for line in LINES},
            "rules": {rule_id: {line: sum(at_or_above(r.rules.get(rule_id, NONE), line) for r in read) for line in LINES}
                      for rule_id in rule_ids}}


def count_added(added: dict[str, dict[str, int]], plain: BothReadings) -> None:
    """Adds one harmless item's added findings to its set's counts per rule: the findings, and the item once per rule."""
    for rule_id, count in plain.added.items():
        entry = added.setdefault(rule_id, {"findings": 0, "skills": 0})
        entry["findings"] += count
        entry["skills"] += 1


# --- the community corpus (community reports spec 8) -------------------------------------------------------------------------

COMMUNITY_RESULTS = ("holds", "fails", "not_read_whole", "open", "not_measured")


def one_skill_package(files: Mapping[str, bytes]) -> bool:
    """Whether the files of a case are one skill package the benchmark reads as one root: `SKILL.md` at the root and no other file
    that `identity.is_skill_file` takes for a skill file (a nested skill, a case variant under `skills/<name>/`)."""
    return "SKILL.md" in files and not [path for path in files if path != "SKILL.md" and is_skill_file(path)]


def community_cases(directory: Path, rules: RuleSet) -> list:
    """The cases of the corpus in `directory`, every record checked. A corpus that cannot be read stops the run with
    `community_invalid` and exit 2: a skipped case would look like a pass. The message names the case and the problem, never a
    sample."""
    try:
        cases = COMMUNITY.load_cases(directory)
    except COMMUNITY.CorpusError as error:
        raise BenchmarkError("community_invalid", str(error)) from None
    areas = {rule.id: rule.area for rule in rules}
    problems = [problem for case in cases
                for problem in COMMUNITY.record_problems(case.record, directory_name=case.id, rule_areas=areas)]
    if problems:
        raise BenchmarkError("community_invalid", "; ".join(problems[:10]))
    return cases


def community_result(case: object, rules: RuleSet, skill_rules: frozenset[str]) -> str:
    """The `result` of one case (8.2): `open` while the rule change is not released; `not_measured` for a rule that is not a skill
    rule or files that are not one skill package; `not_read_whole` when the scanner could not read the skill whole; else `holds`
    when a miss's rule is among the findings or a false positive's is not, and `fails` otherwise. The scan is `read_root` of the
    files as the root, the scanner's default reading."""
    record = case.record
    if record["outcome"] == "open":
        return "open"
    if record["rule"] not in skill_rules or not one_skill_package(case.files):
        return "not_measured"
    reading = read_root(case.files, rules)
    if reading.unread is not None:
        return "not_read_whole"
    return "holds" if (record["rule"] in reading.rules) == (record["kind"] == "miss") else "fails"


def measure_community(rules: RuleSet, directory: Path) -> dict | None:
    """The member `community` of an entry (8.2), or None when the corpus holds no case (the member is then absent and the entry is
    what it was before the corpus existed). The files are only read, in memory."""
    cases = community_cases(directory, rules)
    if not cases:
        return None
    skill_rules = frozenset(rule.id for rule in rules.by_area("skill"))
    return {"corpus": COMMUNITY.CORPUS_FORMAT, "corpus_sha256": COMMUNITY.corpus_sha256(cases),
            "cases": {case.id: {"kind": case.record["kind"], "rule": case.record["rule"], "outcome": case.record["outcome"],
                                "fixed_in": case.record["fixed_in"], "result": community_result(case, rules, skill_rules)}
                      for case in cases}}


def community_counts(block: dict) -> dict[str, int]:
    """How many cases of a `community` member have each result (8.4)."""
    return {result: sum(1 for case in block["cases"].values() if case["result"] == result) for result in COMMUNITY_RESULTS}


def measure(manifest: Manifest, cache: Cache, *, progress: Callable[[str], None] | None = None,
            community: Path | None = None) -> dict:
    """The measured part of the entry (10.6, 10.7): every item rebuilt, verified and scanned as written and normalised, and
    every changed variant of a malicious item read whole both ways scanned both ways (P6-4 spec 6.2), or an error that stops the
    run. `community` is the directory of the community corpus (default `COMMUNITY_DIR`), measured into the member `community`."""
    rules = RuleSet.baseline()
    skill_rules = sorted(rules.by_area("skill"), key=lambda rule: rule.id)
    rule_ids = [rule.id for rule in skill_rules]
    objects = Objects(manifest, cache)
    results: dict[tuple[str, str], list[tuple[str, ItemResult]]] = {}
    written: dict[tuple[str, str], list[ItemResult]] = {}
    techniques = {technique: {set_id: _technique_block() for set_id, value in sorted(manifest.sets.items())
                              if any(s["label"] == "malicious" for s in value["strata"].values())}
                  for technique in DISGUISE.TECHNIQUE_IDS}
    added: dict[str, dict] = {set_id: {} for set_id, value in sorted(manifest.sets.items())
                              if any(s["label"] == "benign" for s in value["strata"].values())}
    for number, item in enumerate(manifest.items, start=1):
        roots = rebuild(item, objects)
        plain = scan_both(roots, rules, item["id"])
        label = manifest.sets[item["set"]]["strata"][item["stratum"]]["label"]
        results.setdefault((item["set"], item["stratum"]), []).append((item["id"], plain.normalised))
        written.setdefault((item["set"], label), []).append(plain.written)
        read_both = plain.written.unread is None and plain.normalised.unread is None
        if label == "benign" and read_both:
            count_added(added[item["set"]], plain)
        if label == "malicious" and read_both:
            for technique in DISGUISE.TECHNIQUE_IDS:
                count_technique(techniques[technique][item["set"]], plain,
                                scan_variant(roots, rules, item["id"], technique))
        if progress is not None and number % 250 == 0:
            progress(f"measured {number} of {len(manifest.items)} items")
    sets: dict = {}
    for set_id in sorted(manifest.sets):
        value = manifest.sets[set_id]
        per_item = value.get("report") == PER_ITEM
        block: dict = {"title": value["title"], "role": value["role"], "strata": {}}
        if per_item:
            block["report"] = PER_ITEM
        for stratum_id in sorted(value["strata"]):
            stratum = value["strata"][stratum_id]
            block["strata"][stratum_id] = count_stratum(stratum["title"], stratum["label"],
                                                        results.get((set_id, stratum_id), []), rule_ids, per_item=per_item)
        sets[set_id] = block
    normalising = normalises(scan_skill_package) and NORMALISE is not None
    plain_as_written = {set_id: {label: count_plain(written.get((set_id, label), []), rule_ids)
                                 for label in LABELS if any(s["label"] == label for s in value["strata"].values())}
                        for set_id, value in sorted(manifest.sets.items())}
    disguise = {"generator": {"version": DISGUISE.GENERATOR_VERSION, "seed": DISGUISE.SEED,
                              "techniques": list(DISGUISE.TECHNIQUE_IDS)},
                "steps": list(NORMALISE.STEPS) if normalising else [],
                "rules_normalised": sorted(NORMALISE.RULES) if normalising else [],
                "plain_as_written": plain_as_written, "techniques": techniques, "added_on_harmless": added}
    entry = {"version": SCANNER_VERSION, "rules_version": RULES_VERSION, "manifest_sha256": manifest.sha256,
             "lines": list(LINES), "rules_measured": {rule.id: rule.severity_default for rule in skill_rules},
             "rules_not_measured": sorted(rule.id for rule in rules if rule.area != "skill"), "sets": sets,
             "disguise": disguise}
    block = measure_community(rules, COMMUNITY_DIR if community is None else community)
    if block is not None:
        entry["community"] = block  # absent for an empty corpus, so an earlier release's entry is what it was
    return entry


# --- rates (10.6) ------------------------------------------------------------------------------------------------------------

WILSON_Z = 1.959963984540054


def wilson(found: int, total: int) -> tuple[float, float]:
    """The 95% Wilson score interval of `found` in `total` ((0.0, 1.0) when `total` is 0), as `measure_analyzer.wilson`."""
    if total == 0:
        return 0.0, 1.0
    share = found / total
    centre = share + WILSON_Z * WILSON_Z / (2 * total)
    margin = WILSON_Z * math.sqrt(share * (1 - share) / total + WILSON_Z * WILSON_Z / (4 * total * total))
    denominator = 1 + WILSON_Z * WILSON_Z / total
    return max(0.0, (centre - margin) / denominator), min(1.0, (centre + margin) / denominator)


def percent(value: float) -> str:
    """A share as a percentage with one decimal: `floor(v * 1000 + 0.5) / 10`, the landing page's rule too."""
    return f"{math.floor(value * 1000 + 0.5) / 10:.1f}"


def three_decimals(value: float) -> str:
    return f"{math.floor(value * 1000 + 0.5) / 1000:.3f}"


def macro_f1(tp: int, fn: int, fp: int, tn: int) -> float:
    """The mean of the F1 of the malicious class, 2TP/(2TP+FP+FN), and of the benign class, 2TN/(2TN+FN+FP); 0 for a zero
    denominator."""
    malicious = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0
    benign = 2 * tn / (2 * tn + fn + fp) if 2 * tn + fn + fp else 0.0
    return (malicious + benign) / 2


class Total(NamedTuple):
    items: int
    unread: int
    read: int
    found: dict[str, int]
    rules: dict[str, dict[str, int]]


def totals(set_block: dict, label: str) -> Total | None:
    """The sum over a set's strata of one label (None when the set has no stratum of that label)."""
    strata = [stratum for stratum in set_block["strata"].values() if stratum["label"] == label]
    if not strata:
        return None
    items = sum(stratum["items"] for stratum in strata)
    unread = sum(len(stratum["unread"]) for stratum in strata)
    found = {line: sum(stratum["found"][line] for stratum in strata) for line in LINES}
    rule_ids = sorted({rule_id for stratum in strata for rule_id in stratum["rules"]})
    rules = {rule_id: {line: sum(stratum["rules"].get(rule_id, {}).get(line, 0) for stratum in strata) for line in LINES}
             for rule_id in rule_ids}
    return Total(items, unread, items - unread, found, rules)


def stratum_read(stratum: dict) -> int:
    return stratum["items"] - len(stratum["unread"])


def rate_text(found: int, read: int) -> str:
    """`36.0% (302 of 839; 32.8% to 39.3%)`, or `no skill read whole` when nothing was read."""
    if read == 0:
        return "no skill read whole"
    low, high = wilson(found, read)
    return f"{percent(found / read)}% ({found} of {read}; {percent(low)}% to {percent(high)}%)"


def set_macro_f1(set_block: dict, line: str) -> float | None:
    malicious, benign = totals(set_block, "malicious"), totals(set_block, "benign")
    if malicious is None or benign is None:
        return None
    tp, fp = malicious.found[line], benign.found[line]
    return macro_f1(tp, malicious.read - tp, fp, benign.read - fp)


# --- the history file (10.7) -----------------------------------------------------------------------------------------------

ABOUT = ("The rule benchmark's history: one entry per release, written by `python benchmarks/rule_benchmark.py run --record`; "
         "benchmarks/README.md says what it measures.")
NOTE_MAX = 200
_VERSION = re.compile(r"\d+\.\d+\.\d+")
ENTRY_MEMBERS = {"version", "rules_version", "released", "note", "manifest_sha256", "lines", "rules_measured",
                 "rules_not_measured", "sets"}
# 1.22.0 (P6-4 spec 6.2.5, 6.4.1): the disguised samples, required from this version on and absent from earlier entries
DISGUISE_FROM = "1.22.0"
DISGUISE_MEMBERS = {"generator", "steps", "rules_normalised", "plain_as_written", "techniques", "added_on_harmless"}
GENERATOR_MEMBERS = {"version", "seed", "techniques"}


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _leaves(value: object):
    if isinstance(value, dict):
        for inner in value.values():
            yield from _leaves(inner)
    else:
        yield value


def check_disguise(value: object, version: str) -> None:
    """The member `disguise` of one entry (P6-4 spec 6.4.1): exactly its six members, the generator's three, the steps and rules
    as lists of text, and every count a whole number of 0 or more. Raises `BenchmarkError` `results_invalid`."""
    where = f"the disguise member of the entry for {version}"
    if not isinstance(value, dict) or set(value) != DISGUISE_MEMBERS:
        raise BenchmarkError("results_invalid", f"{where} must have exactly the members {', '.join(sorted(DISGUISE_MEMBERS))}")
    generator = value["generator"]
    if not isinstance(generator, dict) or set(generator) != GENERATOR_MEMBERS or not _count(generator["version"]) \
            or not isinstance(generator["seed"], str) or not isinstance(generator["techniques"], list) \
            or not all(isinstance(name, str) for name in generator["techniques"]):
        raise BenchmarkError("results_invalid", f"{where}: generator must be exactly version (a whole number), seed (text) and "
                                                "techniques (a list of text)")
    for name in ("steps", "rules_normalised"):
        if not isinstance(value[name], list) or not all(isinstance(item, str) for item in value[name]):
            raise BenchmarkError("results_invalid", f"{where}: {name} must be a list of text")
    for name in ("plain_as_written", "techniques", "added_on_harmless"):
        if not isinstance(value[name], dict):
            raise BenchmarkError("results_invalid", f"{where}: {name} must be an object")
        if not all(_count(leaf) and leaf >= 0 for leaf in _leaves(value[name])):
            raise BenchmarkError("results_invalid", f"{where}: every count of {name} must be a whole number of 0 or more")


COMMUNITY_MEMBERS = {"corpus", "corpus_sha256", "cases"}
COMMUNITY_CASE_MEMBERS = {"kind", "rule", "outcome", "fixed_in", "result"}
_CASE_ID = re.compile(r"COM-[0-9]{4}")
_RULE_ID = re.compile(r"SW-(?:SKL|MCP|CFG|REG|A2A)-[0-9]{3}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def check_community(value: object, version: str) -> None:
    """The member `community` of one entry (community reports spec 8.3): exactly `corpus` (the format, a whole number),
    `corpus_sha256` (64 hex) and `cases` (at least one case by id); each case exactly `kind`, `rule`, `outcome`, `fixed_in` and
    `result`, with the enums of the corpus, `fixed_in` a version exactly when the outcome is `fixed`, and the result `open`
    exactly when the outcome is. Raises `BenchmarkError` `results_invalid`."""
    where = f"the community member of the entry for {version}"
    if not isinstance(value, dict) or set(value) != COMMUNITY_MEMBERS:
        raise BenchmarkError("results_invalid", f"{where} must have exactly the members {', '.join(sorted(COMMUNITY_MEMBERS))}")
    if not _count(value["corpus"]) or value["corpus"] < 1:
        raise BenchmarkError("results_invalid", f"{where}: corpus must be a whole number of 1 or more")
    if not isinstance(value["corpus_sha256"], str) or not _HEX64.fullmatch(value["corpus_sha256"]):
        raise BenchmarkError("results_invalid", f"{where}: corpus_sha256 must be 64 lower-case hex digits")
    cases = value["cases"]
    if not isinstance(cases, dict) or not cases:
        raise BenchmarkError("results_invalid", f"{where}: cases must be an object with at least one case")
    for case_id, case in cases.items():
        if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id):
            raise BenchmarkError("results_invalid", f"{where}: a case id must be COM- and four digits")
        if not isinstance(case, dict) or set(case) != COMMUNITY_CASE_MEMBERS:
            raise BenchmarkError("results_invalid", f"{where}: {case_id} must have exactly the members "
                                                    f"{', '.join(sorted(COMMUNITY_CASE_MEMBERS))}")
        problems = []
        if case["kind"] not in COMMUNITY.KINDS:
            problems.append("kind must be miss or false_positive")
        if not isinstance(case["rule"], str) or not _RULE_ID.fullmatch(case["rule"]):
            problems.append("rule must be a rule id")
        if case["outcome"] not in COMMUNITY.OUTCOMES:
            problems.append("outcome must be open or fixed")
        elif case["outcome"] == "open" and case["fixed_in"] is not None:
            problems.append("fixed_in must be null while the outcome is open")
        elif case["outcome"] == "fixed" and (not isinstance(case["fixed_in"], str) or not _VERSION.fullmatch(case["fixed_in"])):
            problems.append("fixed_in must be X.Y.Z when the outcome is fixed")
        if case["result"] not in COMMUNITY_RESULTS:
            problems.append(f"result must be one of {', '.join(COMMUNITY_RESULTS)}")
        elif (case["result"] == "open") != (case["outcome"] == "open"):
            problems.append("the result is open exactly when the outcome is")
        if problems:
            raise BenchmarkError("results_invalid", f"{where}: {case_id}: {'; '.join(problems)}")


def check_results(document: object) -> dict:
    """The history document, checked: `{"results": 1, "about": text, "entries": [...]}`, entries ascending by version, at most one
    per version, each with the members of 10.7, from 1.22.0 on also `disguise` (P6-4 spec 6.4.1), and `community` when the corpus
    held a case (community reports spec 8.2, optional, so every earlier entry stays valid). Raises `BenchmarkError`
    `results_invalid` naming the first problem."""
    if not isinstance(document, dict) or document.get("results") != 1 or not isinstance(document.get("entries"), list) \
            or not isinstance(document.get("about"), str) or set(document) != {"results", "about", "entries"}:
        raise BenchmarkError("results_invalid", 'the history must be {"results": 1, "about": "...", "entries": [...]}')
    previous: str | None = None
    for entry in document["entries"]:
        if not isinstance(entry, dict) or not ENTRY_MEMBERS <= set(entry) \
                or set(entry) - ENTRY_MEMBERS - {"disguise", "community"}:
            raise BenchmarkError("results_invalid", f"an entry must have exactly the members {', '.join(sorted(ENTRY_MEMBERS))}, "
                                                    f"disguise from {DISGUISE_FROM} on, and community when the corpus has a case")
        version = entry["version"]
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise BenchmarkError("results_invalid", "an entry's version must be X.Y.Z")
        if "disguise" in entry:
            check_disguise(entry["disguise"], version)
        elif version_key(version) >= version_key(DISGUISE_FROM):
            raise BenchmarkError("results_invalid", f"the entry for {version} lacks the member disguise")
        if "community" in entry:
            check_community(entry["community"], version)
        if previous is not None and version_key(version) <= version_key(previous):
            raise BenchmarkError("results_invalid", f"the entry for {version} comes after {previous}: entries ascend by version")
        if not isinstance(entry["released"], str) or not _DATE.fullmatch(entry["released"]):
            raise BenchmarkError("results_invalid", f"the entry for {version} has no release date")
        if not isinstance(entry["note"], str) or len(entry["note"]) > NOTE_MAX:
            raise BenchmarkError("results_invalid", f"the note of {version} must be text of at most {NOTE_MAX} characters")
        previous = version
    return document


def dump_results(document: dict) -> str:
    return json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def load_results(path: Path) -> dict:
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise BenchmarkError("results_invalid", f"{path} cannot be read as UTF-8") from None
    try:
        document = json.loads(text)
    except ValueError:
        raise BenchmarkError("results_invalid", f"{path} is not JSON") from None
    return check_results(document)


def entry_for(results: dict, version: str) -> dict | None:
    return next((entry for entry in results["entries"] if entry["version"] == version), None)


def measured_part(entry: dict) -> dict:
    """The entry without `released` and `note`: what `--verify` and `check-history` compare."""
    return {key: value for key, value in entry.items() if key not in ("released", "note")}


def differences(recorded: object, computed: object, limit: int = 10) -> list[str]:
    """The first differences between two JSON values, each `<key> / <key> / ...: recorded <a>, computed <b>`, so a difference in
    a stratum reads `sets / <set> / strata / <stratum> / <field> / <line>`."""
    found: list[str] = []

    def walk(left: object, right: object, path: list[str]) -> None:
        if len(found) >= limit:
            return
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                if key not in left or key not in right:
                    found.append(f"{' / '.join([*path, key])}: recorded {json.dumps(left.get(key))}, computed "
                                 f"{json.dumps(right.get(key))}")
                else:
                    walk(left[key], right[key], [*path, key])
        elif left != right:
            found.append(f"{' / '.join(path) or 'the entry'}: recorded {json.dumps(left)}, computed {json.dumps(right)}")

    walk(recorded, computed, [])
    return found[:limit]


# --- the CHANGELOG rule (10.10) ---------------------------------------------------------------------------------------------

LINE_TEXT = {"medium": "medium or above", "high": "high or above"}
FIRST_TABLE = "Rule benchmark: first published table, see benchmarks/RESULTS.md."
# 1.22.0 (P6-4 spec 6.4.4): the CHANGELOG lines of the disguised samples
FIRST_DISGUISE_TABLE = "Rule benchmark: first table of disguised samples, see benchmarks/RESULTS.md."
NO_HARMLESS_ADDED = "Rule benchmark: normalisation adds no finding on harmless skills."
HARMLESS_ADDED = ("Rule benchmark: normalisation adds these findings on harmless skills, which the rules as written do not "
                  "report:")


def _rule_rows(previous: Total, current: Total, rule_ids: list[str], line: str) -> list[tuple[str, int, int]]:
    rows = [("all rules", previous.found[line], current.found[line])]
    rows += [(rule_id, previous.rules.get(rule_id, {}).get(line, 0), current.rules.get(rule_id, {}).get(line, 0))
             for rule_id in rule_ids]
    return rows


def worse_rates(previous: dict, current: dict) -> list[str]:
    """One line per rate that got worse from `previous` to `current` (10.10): per set (strata summed), for the whole rule set
    and for each rule both entries measured, at each line, a detection rate that went down or a false-positive rate that went
    up (exact fractions), and more items not read whole. A per-item set is compared skill by skill and with counts only."""
    rule_ids = sorted(set(previous["rules_measured"]) & set(current["rules_measured"]))
    lines: list[str] = []
    for set_id, block in current["sets"].items():
        before = previous["sets"].get(set_id)
        if before is None:
            continue
        title = block["title"]
        per_item = block.get("report") == PER_ITEM
        for line in LINES:
            for label, word in (("malicious", "detection"), ("benign", "false positives")):
                old, new = totals(before, label), totals(block, label)
                if old is None or new is None or old.read == 0 or new.read == 0:
                    continue
                for name, old_found, new_found in _rule_rows(old, new, rule_ids, line):
                    old_scaled, new_scaled = old_found * new.read, new_found * old.read
                    if not (new_scaled < old_scaled if label == "malicious" else new_scaled > old_scaled):
                        continue
                    counts = f"{old_found} of {old.read} to {new_found} of {new.read}"
                    if per_item:
                        lines.append(f"- {title}, {name}, {LINE_TEXT[line]}: {word} {counts}")
                    else:
                        lines.append(f"- {title}, {name}, {LINE_TEXT[line]}: {word} {percent(old_found / old.read)}% to "
                                     f"{percent(new_found / new.read)}% ({counts})")
            if per_item:
                for stratum_id, stratum in block["strata"].items():
                    old_outcomes = before["strata"].get(stratum_id, {}).get("outcomes", {})
                    for item_id in sorted(set(old_outcomes) & set(stratum.get("outcomes", {}))):
                        if at_or_above(old_outcomes[item_id], line) and not at_or_above(stratum["outcomes"][item_id], line):
                            lines.append(f"- {title}, {item_id}, {LINE_TEXT[line]}: found to not found")
        old_unread = sum(len(stratum["unread"]) for stratum in before["strata"].values())
        new_unread = sum(len(stratum["unread"]) for stratum in block["strata"].values())
        if new_unread > old_unread:
            lines.append(f"- {title}, items not read whole: {old_unread} to {new_unread}")
    return lines + worse_disguised(previous, current)


def technique_titles() -> dict[str, str]:
    return dict(DISGUISE.TECHNIQUES)


def disguise_read(block: dict) -> int:
    """The denominator of every rate of a technique in a set (P6-4 spec 6.2.4): items changed and read whole."""
    return block["changed"] - block["unread"]


def worse_disguised(previous: dict, current: dict) -> list[str]:
    """P6-4 spec 6.4.3: per technique and set both entries measured, at each line, a line when the disguised normalised
    detection went down and a second when its detection without the disguise rules went down (exact fractions). Nothing when
    either entry has no `disguise`."""
    if "disguise" not in previous or "disguise" not in current:
        return []
    titles = technique_titles()
    lines: list[str] = []
    for technique, by_set in current["disguise"]["techniques"].items():
        for set_id, block in by_set.items():
            before = previous["disguise"]["techniques"].get(technique, {}).get(set_id)
            if before is None or set_id not in current["sets"]:
                continue
            title = current["sets"][set_id]["title"]
            per_item = current["sets"][set_id].get("report") == PER_ITEM
            old_read, new_read = disguise_read(before), disguise_read(block)
            if old_read == 0 or new_read == 0:
                continue
            for line in LINES:
                for member, word in (("found", "detection"), ("found_other", "detection without the disguise rules")):
                    old_found = before["disguised_normalised"][member][line]
                    new_found = block["disguised_normalised"][member][line]
                    if new_found * old_read >= old_found * new_read:
                        continue
                    counts = f"{old_found} of {old_read} to {new_found} of {new_read}"
                    head = f"- {title}, disguised: {titles.get(technique, technique)}, {LINE_TEXT[line]}: {word}"
                    lines.append(f"{head} {counts}" if per_item else
                                 f"{head} {percent(old_found / old_read)}% to {percent(new_found / new_read)}% ({counts})")
    return lines


def harmless_lines(entry: dict) -> list[str]:
    """`- <set title>, <rule>: N findings in M skills` for each set with a harmless stratum, test sets first, and each rule with
    an added finding (P6-4 spec 6.4.4)."""
    added = entry["disguise"]["added_on_harmless"]
    return [f"- {block['title']}, {rule_id}: {counts['findings']} findings in {counts['skills']} skills"
            for set_id, block in ordered_sets(entry) for rule_id, counts in sorted(added.get(set_id, {}).items())]


def changelog_lines(results: dict) -> list[str]:
    """The lines the newest entry's CHANGELOG section must hold (10.10); none without an entry."""
    entries = results["entries"]
    if not entries:
        return []
    if len(entries) == 1:
        return [FIRST_TABLE, *disguise_changelog_lines(None, entries[0])]
    previous, current = entries[-2], entries[-1]
    worse_lines = worse_rates(previous, current)
    if worse_lines:
        required = [f"Rule benchmark: these rates got worse than in {previous['version']}:", *worse_lines]
    else:
        required = [f"Rule benchmark: no rate got worse than in {previous['version']}."]
    if current["manifest_sha256"] != previous["manifest_sha256"]:
        required.append(f"Rule benchmark: the sets changed since {previous['version']}; benchmarks/README.md lists what was "
                        "left out.")
    return required + disguise_changelog_lines(previous, current)


def disguise_changelog_lines(previous: dict | None, current: dict) -> list[str]:
    """P6-4 spec 6.4.4: with `disguise` in the newest entry, the first-table sentence when the entry before has none, then the
    harmless findings normalisation adds, as one sentence or as a sentence and its list."""
    if "disguise" not in current:
        return []
    required = [FIRST_DISGUISE_TABLE] if previous is None or "disguise" not in previous else []
    listed = harmless_lines(current)
    return required + ([HARMLESS_ADDED, *listed] if listed else [NO_HARMLESS_ADDED])


def changelog_section(text: str, version: str) -> str | None:
    """The body under `## <version>` (any date suffix) up to the next `## ` heading, as `scripts/release_manifest.py` reads it;
    None without such a heading."""
    match = re.search(rf"^## {re.escape(version)}\b.*?\n(.*?)(?=^## |\Z)", text.replace("\r\n", "\n"), re.M | re.S)
    return None if match is None else match.group(1)


def released_date(text: str, version: str) -> str | None:
    """The date of the heading `## <version> (<YYYY-MM-DD>)`, or None."""
    match = re.search(rf"^## {re.escape(version)} \((\d{{4}}-\d{{2}}-\d{{2}})\)[ \t]*$", text.replace("\r\n", "\n"), re.M)
    return None if match is None else match.group(1)


def check_changelog(results: dict, text: str) -> list[str]:
    """What the newest entry's CHANGELOG section lacks (10.10): every required line, and the worse lines right under their
    heading, in order. Empty when the history has no entry."""
    required = changelog_lines(results)
    if not required:
        return []
    version = results["entries"][-1]["version"]
    section = changelog_section(text, version)
    if section is None:
        return [f"CHANGELOG.md has no section for {version}"]
    # A sentence may sit inside a paragraph that the file wraps at its usual width, so sentences are matched with whitespace
    # joined (review r0:F2). Each list is matched line by line: each `- ` line stands on a line of its own, unwrapped, in order,
    # right after the sentence that introduces it (1.22.0, P6-4 spec 6.4.5: every sentence ending in `:` has its own list).
    have = [line.rstrip() for line in section.splitlines()]
    flat = " ".join(section.split())
    problems = []
    groups: list[tuple[str, list[str]]] = []
    for line in required:
        if line.startswith("- ") and groups:
            groups[-1][1].append(line)
        else:
            groups.append((line, []))
    for line, items in groups:
        sentence = " ".join(line.split())
        if sentence not in flat:
            problems.append(f"the CHANGELOG section of {version} lacks the sentence: {line}")
        elif line.endswith(":"):
            starts = [i for i in range(len(have) - len(items) + 1) if have[i:i + len(items)] == items]
            listed = " | ".join(items)
            first = " ".join(items[0].split()) if items else ""
            right_under = bool(items) and flat.find(f"{sentence} {first}") != -1
            if not starts or not right_under:
                problems.append(f"the CHANGELOG section of {version} must list under that sentence, one line each, "
                                f"in order: {listed}")
    return problems


def check_history(previous: dict, current: dict) -> list[str]:
    """Earlier entries are unchanged (10.9): every entry of `previous` is in `current` with the same measured part, `released`
    and `note`, and `current` adds entries only above the newest of `previous`."""
    old = {entry["version"]: entry for entry in previous["entries"]}
    new = {entry["version"]: entry for entry in current["entries"]}
    problems = []
    for version, entry in old.items():
        if version not in new:
            problems.append(f"the entry for {version} that the last release published is missing")
        elif measured_part(new[version]) != measured_part(entry):
            problems.append(f"the measured part of the entry for {version} changed: {differences(entry, new[version])[0]}")
        elif (new[version]["released"], new[version]["note"]) != (entry["released"], entry["note"]):
            problems.append(f"the release date or the note of the entry for {version} changed")
    if old:
        newest = max(old, key=version_key)
        for version in new:
            if version not in old and version_key(version) <= version_key(newest):
                problems.append(f"the entry for {version} is new but not above {newest}, the newest the last release published")
    return problems


# --- output (10.8) -----------------------------------------------------------------------------------------------------------

TUNING_SENTENCE = "Tuning set: rules may be tuned on it, so its rates can look better than those of a test set."
NO_TABLE = "No release has published a table yet. The first one ships with the next release."
GENERATED = ("<!-- Generated by `python benchmarks/rule_benchmark.py render` from benchmarks/results.json. Do not edit it by "
             "hand: change results.json and run render again. -->")
README_START, README_END = "<!-- benchmark:start -->", "<!-- benchmark:end -->"
BELOW = "below this line"
LABEL_TEXT = {"malicious": "malicious", "benign": "harmless"}
RATE_WORD = {"malicious": "detection", "benign": "false positives"}
DISGUISE_RULES_SENTENCE = ("The disguise rules are SW-SKL-002, SW-SKL-004 and SW-SKL-014: they report a hidden character or a "
                           "decode-and-run line whatever the content.")
README_DISGUISE_HEAD = "Disguised samples, medium or above, rules on the text as written and after normalisation:"
README_DISGUISE_RULES = ("SW-SKL-002, SW-SKL-004 and SW-SKL-014 report the disguise itself (a hidden character, a decode-and-run "
                         "line), so a row can be high as written while the other rules no longer see the content: "
                         "[benchmarks/RESULTS.md](benchmarks/RESULTS.md) shows every row without those three rules, as written "
                         "and normalised.")


def harmless_sentence(entry: dict, set_id: str) -> str:
    """P6-4 spec 6.3.1: what normalisation adds on a set's harmless skills, each rule with its own counts, never a sum of skills
    over rules."""
    parts = added_parts(entry["disguise"]["added_on_harmless"].get(set_id, {}))
    if not parts:
        return "Normalisation adds no finding on harmless skills."
    return "Normalisation adds these findings on harmless skills: " + "; ".join(parts) + "."


def set_techniques(entry: dict, set_id: str) -> list[tuple[str, dict]]:
    """`(technique, counts)` of one set in the generator's order, empty for an entry without `disguise` or a set without a
    malicious stratum."""
    if "disguise" not in entry:
        return []
    return [(technique, by_set[set_id]) for technique, by_set in entry["disguise"]["techniques"].items() if set_id in by_set]


def _count_or_rate(found: int, read: int, per_item: bool) -> str:
    return f"{found} of {read}" if per_item else rate_text(found, read)


def ordered_sets(entry: dict) -> list[tuple[str, dict]]:
    """Test sets first, then tuning sets, each by id."""
    return sorted(entry["sets"].items(), key=lambda pair: (pair[1]["role"] != "test", pair[0]))


def below(entry: dict, rule_id: str, line: str) -> bool:
    return SEVERITY_RANK[entry["rules_measured"][rule_id]] > LINE_RANK[line]


def not_measured_text(entry: dict) -> str:
    names = entry["rules_not_measured"]
    prefixes = ", ".join(sorted({name.rsplit("-", 1)[0] for name in names}))
    return f"{len(names)} rules judge other kinds of content and are not measured here: {prefixes}"


def _short(found: int, read: int, per_item: bool) -> str:
    if per_item:
        return f"{found} of {read}"
    if read == 0:
        return "no skill read whole"
    return f"{percent(found / read)}% ({found} of {read})"


def _found_text(found: int, read: int, per_item: bool) -> str:
    if per_item or read == 0:
        return f"found {found} of {read}"
    low, high = wilson(found, read)
    return f"found {found} of {read}, {percent(found / read)}% ({percent(low)}% to {percent(high)}%)"


def _outcome(stratum: dict, item_id: str, line: str) -> str:
    if item_id in stratum["unread"]:
        return "not read whole"
    return "found" if at_or_above(stratum["outcomes"][item_id], line) else "not found"


def _per_item_ids(block: dict) -> list[tuple[str, dict]]:
    return sorted(((item_id, stratum) for stratum in block["strata"].values()
                   for item_id in [*stratum["unread"], *stratum.get("outcomes", {})]), key=lambda pair: pair[0])


def _missed(block: dict) -> tuple[int, int]:
    missed = [severity for stratum in block["strata"].values() for severity in stratum.get("missed", {}).values()]
    return sum(1 for severity in missed if not at_or_above(severity, "medium")), len(missed)


def render_text(entry: dict, *, ids_at: str) -> str:
    """The terminal table of one entry (10.8.1). `ids_at` says where the ids of missed items are."""
    out = [f"Spellwarden rule benchmark: scanner {entry['version']}, rules {entry['rules_version']}, manifest "
           f"{entry['manifest_sha256']}; rules only, no model.", ""]
    for set_id, block in ordered_sets(entry):
        per_item = block.get("report") == PER_ITEM
        out.append(f"{block['title']} ({block['role']}{', shown skill by skill' if per_item else ''})")
        if block["role"] == "tuning":
            out.append(TUNING_SENTENCE)
        if per_item:
            for item_id, stratum in _per_item_ids(block):
                if item_id in stratum["unread"]:
                    out.append(f"  {item_id}: not read whole ({stratum['unread'][item_id]})")
                else:
                    out.append(f"  {item_id}: " + "; ".join(f"{LINE_TEXT[line]}: {_outcome(stratum, item_id, line)}"
                                                           for line in LINES))
        else:
            for stratum_id, stratum in sorted(block["strata"].items()):
                read = stratum_read(stratum)
                rates = "; ".join(f"{LINE_TEXT[line]}: {_found_text(stratum['found'][line], read, False)}" for line in LINES)
                out.append(f"  {stratum['title']} [{stratum_id}], {LABEL_TEXT[stratum['label']]}: {stratum['items']} skills, "
                           f"{len(stratum['unread'])} not read whole; {rates}")
        for label in LABELS:
            total = totals(block, label)
            if total is not None:
                out.append(f"  all {LABEL_TEXT[label]}: {total.items} skills, {total.unread} not read whole; "
                           + "; ".join(f"{LINE_TEXT[line]}: {_found_text(total.found[line], total.read, per_item)}"
                                       for line in LINES))
        if not per_item and set_macro_f1(block, "medium") is not None:
            scores = "; ".join(f"{LINE_TEXT[line]} {three_decimals(set_macro_f1(block, line))}" for line in LINES)
            out.append(f"  macro-F1: {scores}")
        out.append("  rules:")
        for rule_id, severity in sorted(entry["rules_measured"].items()):
            cells = []
            for line in LINES:
                if below(entry, rule_id, line):
                    cells.append(f"{LINE_TEXT[line]}: {BELOW}")
                    continue
                parts = []
                for label in LABELS:
                    total = totals(block, label)
                    if total is not None:
                        parts.append(f"{RATE_WORD[label]} {_short(total.rules[rule_id][line], total.read, per_item)}")
                cells.append(f"{LINE_TEXT[line]}: " + ", ".join(parts))
            out.append(f"    {rule_id} ({severity}): " + "; ".join(cells))
        out += _disguise_text(entry, set_id)
        if not per_item and totals(block, "malicious") is not None:
            at_medium, at_high = _missed(block)
            out.append(f"  missed malicious skills: {at_medium} at medium or above, {at_high} at high or above; their ids are in "
                       f"{ids_at}")
        out.append("")
    out += _community_text(entry)
    out.append(not_measured_text(entry))
    return "\n".join(out) + "\n"


COMMUNITY_TITLE = "Community corpus (reported by people outside the project)"
COMMUNITY_NOT_A_SET = ("This is not a test set and not a tuning set: it holds the samples that people reported, and the rules "
                       "were changed for them, so a count here shows that those fixes hold, never how well the rules work. It "
                       "has no rate and no interval.")
COMMUNITY_READ = ("It is measured from the files of this repository's `fixtures/community/`, which the benchmark only reads in "
                  "memory.")
COMMUNITY_SETS_UNCHANGED = "The fixed sets above are unchanged by it."
COMMUNITY_WORDS = (("holds", "holds"), ("fails", "fails"), ("not_read_whole", "not read whole"), ("open", "open"),
                   ("not_measured", "not measured here"))


def _community_text(entry: dict) -> list[str]:
    """The four lines of the terminal table for the corpus (8.3): none when the entry has no `community` member."""
    block = entry.get("community")
    if block is None:
        return []
    counts = community_counts(block)
    failing = sorted(case_id for case_id, case in block["cases"].items() if case["result"] == "fails")
    return [COMMUNITY_TITLE, "  not a test set and not a tuning set: no rate and no interval",
            f"  {len(block['cases'])} cases: " + ", ".join(f"{counts[result]} {word}" for result, word in COMMUNITY_WORDS),
            "  failing cases: " + (", ".join(failing) if failing else "none"), ""]


def _community_markdown(entry: dict) -> list[str]:
    """The section of RESULTS.md for the corpus (8.4): counts, a table of cases and the three standing sentences."""
    block = entry.get("community")
    if block is None:
        return []
    counts = community_counts(block)
    shown = ". ".join(f"{word.capitalize()}: {counts[result]}" for result, word in COMMUNITY_WORDS)
    out = ["", f"### {COMMUNITY_TITLE}", "", f"Cases: {len(block['cases'])}. {shown}.",
           "", "| Case | Kind | Rule | Outcome | Fixed in | Result |", "|---|---|---|---|---|---|"]
    for case_id, case in sorted(block["cases"].items()):
        kind = "miss" if case["kind"] == "miss" else "false positive"
        out.append(f"| `{case_id}` | {kind} | `{case['rule']}` | {case['outcome']} | {case['fixed_in'] or 'not yet'} | "
                   f"{dict(COMMUNITY_WORDS)[case['result']]} |")
    return out + ["", COMMUNITY_NOT_A_SET, "", COMMUNITY_READ, "", COMMUNITY_SETS_UNCHANGED]


def _disguise_text(entry: dict, set_id: str) -> list[str]:
    """P6-4 spec 6.3.4: the disguised samples of one set in the terminal, as counts."""
    techniques = set_techniques(entry, set_id)
    if not techniques:
        return []
    titles = technique_titles()
    out = ["  disguised samples:"]
    for technique, block in techniques:
        cells = []
        for line in LINES:
            parts = [f"{block[name]['found'][line]} {word}" for name, word in (
                ("plain_as_written", "plain as written"), ("plain_normalised", "plain normalised"),
                ("disguised_as_written", "disguised as written"), ("disguised_normalised", "disguised normalised"))]
            parts += [f"{block[name]['found_other'][line]} {word} without the disguise rules" for name, word in (
                ("disguised_as_written", "disguised as written"), ("disguised_normalised", "disguised normalised"))]
            cells.append(f"{LINE_TEXT[line]}: " + ", ".join(parts))
        out.append(f"    {titles.get(technique, technique)}: {block['changed']} changed, {block['unread']} not read whole, "
                   f"{disguise_read(block)} read; " + "; ".join(cells))
    if set_id in entry["disguise"]["added_on_harmless"]:
        parts = added_parts(entry["disguise"]["added_on_harmless"][set_id])
        out.append("  normalisation on harmless skills: " + ("; ".join(parts) or "no finding added"))
    return out


def _ids(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "none"


def _entry_markdown(entry: dict) -> list[str]:
    out = [f"## Scanner {entry['version']}", "",
           f"Rules version {entry['rules_version']}, released {entry['released']}. Manifest `{entry['manifest_sha256']}`."]
    if entry["note"]:
        out += ["", f"Note: {entry['note']}"]
    for set_id, block in ordered_sets(entry):
        per_item = block.get("report") == PER_ITEM
        out += ["", f"### {block['title']} ({block['role']}{', shown skill by skill' if per_item else ''})", ""]
        if block["role"] == "tuning":
            out += [TUNING_SENTENCE, ""]
        if per_item:
            out += ["| Skill | Medium or above | High or above |", "|---|---|---|"]
            out += [f"| `{item_id}` | " + " | ".join(_outcome(stratum, item_id, line) for line in LINES) + " |"
                    for item_id, stratum in _per_item_ids(block)]
        else:
            out += ["| Stratum | Label | Skills | Not read whole | Medium or above | High or above |",
                    "|---|---|---|---|---|---|"]
            for _stratum_id, stratum in sorted(block["strata"].items()):
                read = stratum_read(stratum)
                rates = " | ".join(rate_text(stratum["found"][line], read) for line in LINES)
                out.append(f"| {stratum['title']} | {LABEL_TEXT[stratum['label']]} | {stratum['items']} | "
                           f"{len(stratum['unread'])} | {rates} |")
            for label in LABELS:
                total = totals(block, label)
                if total is not None:
                    out.append(f"| All {LABEL_TEXT[label]} | {LABEL_TEXT[label]} | {total.items} | {total.unread} | "
                               + " | ".join(rate_text(total.found[line], total.read) for line in LINES) + " |")
            if set_macro_f1(block, "medium") is not None:
                out += ["", "Macro-F1: " + ", ".join(f"{LINE_TEXT[line]} {three_decimals(set_macro_f1(block, line))}"
                                                    for line in LINES) + "."]
        labels = [label for label in LABELS if totals(block, label) is not None]
        header = ["Rule", "Severity"] + [f"{RATE_WORD[label].capitalize()}, {LINE_TEXT[line]}"
                                         for line in LINES for label in labels]
        out += ["", "| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
        for rule_id, severity in sorted(entry["rules_measured"].items()):
            cells = []
            for line in LINES:
                for label in labels:
                    total = totals(block, label)
                    shown = _short(total.rules[rule_id][line], total.read, per_item)
                    cells.append(BELOW if below(entry, rule_id, line) else shown)
            out.append(f"| `{rule_id}` | {severity} | " + " | ".join(cells) + " |")
        if not per_item and "malicious" in labels:
            missed = {item_id: severity for stratum in block["strata"].values()
                      for item_id, severity in stratum.get("missed", {}).items()}
            at_medium = sorted(item_id for item_id, severity in missed.items() if not at_or_above(severity, "medium"))
            out += ["", f"Malicious skills missed at medium or above: {_ids(at_medium)}.", "",
                    f"Malicious skills missed at high or above: {_ids(sorted(missed))}."]
        unread = sorted((item_id, reason) for stratum in block["strata"].values()
                        for item_id, reason in stratum["unread"].items())
        out += ["", "Skills not read whole: " + (", ".join(f"`{item_id}` ({reason})" for item_id, reason in unread)
                                                 if unread else "none") + "."]
        out += _disguise_markdown(entry, set_id, block)
    out += _community_markdown(entry)
    out += ["", f"{not_measured_text(entry)}."]
    return out


TECHNIQUE_HEADER = ["Technique", "Skills changed", "Not read whole", "Line", "Plain, as written", "Plain, normalised",
                    "Disguised, as written", "Disguised, normalised", "Disguised, as written, without the disguise rules",
                    "Disguised, normalised, without the disguise rules"]


def _disguise_markdown(entry: dict, set_id: str, block: dict) -> list[str]:
    """P6-4 spec 6.3.1: the subsection "Disguised samples" of one set of the newest entry."""
    techniques = set_techniques(entry, set_id)
    if not techniques:
        return []
    per_item = block.get("report") == PER_ITEM
    disguise = entry["disguise"]
    out = ["", "#### Disguised samples", "", "Plain samples, as written and normalised:", "",
           "| Skills | Line | As written | Normalised |", "|---|---|---|---|"]
    for label in LABELS:
        total = totals(block, label)
        written = disguise["plain_as_written"].get(set_id, {}).get(label)
        if total is None or written is None:
            continue
        for line in LINES:
            as_written = _count_or_rate(written["found"][line], written["read"], per_item)
            out.append(f"| {LABEL_TEXT[label]} | {LINE_TEXT[line]} | {as_written} | "
                       f"{_count_or_rate(total.found[line], total.read, per_item)} |")
    titles = technique_titles()
    out += ["", "| " + " | ".join(TECHNIQUE_HEADER) + " |", "|" + "---|" * len(TECHNIQUE_HEADER)]
    for technique, counts in techniques:
        read = disguise_read(counts)
        for line in LINES:
            cells = [_count_or_rate(counts[name]["found"][line], read, per_item) for name in (
                "plain_as_written", "plain_normalised", "disguised_as_written", "disguised_normalised")]
            cells += [_count_or_rate(counts[name]["found_other"][line], read, per_item)
                      for name in ("disguised_as_written", "disguised_normalised")]
            out.append(f"| {titles.get(technique, technique)} | {counts['changed']} | {counts['unread']} | {LINE_TEXT[line]} | "
                       + " | ".join(cells) + " |")
    out += ["", DISGUISE_RULES_SENTENCE]
    if set_id in disguise["added_on_harmless"]:
        out += ["", harmless_sentence(entry, set_id)]
    steps = ", ".join(disguise["steps"]) or "none"
    generator = disguise["generator"]
    out += ["", f"Normalisation steps: {steps}; generator version {generator['version']}, seed `{generator['seed']}`."]
    return out


def _history_markdown(entries: list[dict]) -> list[str]:
    header = ["Set and line"]
    for index, entry in enumerate(entries):
        changed = index > 0 and entry["manifest_sha256"] != entries[index - 1]["manifest_sha256"]
        header.append(entry["version"] + (" (sets changed)" if changed else ""))
    out = ["## Release by release", "", "| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    newest = entries[-1]
    for set_id, block in ordered_sets(newest):
        per_item = block.get("report") == PER_ITEM
        for line in LINES:
            for label in LABELS:
                if totals(block, label) is None:
                    continue
                cells = []
                for entry in entries:
                    other = entry["sets"].get(set_id)
                    total = totals(other, label) if other is not None else None
                    if total is None:
                        cells.append("not in this release")
                    elif per_item:
                        cells.append(f"found {total.found[line]} of {total.read}")
                    else:
                        cells.append(_short(total.found[line], total.read, False))
                name = "found" if per_item else RATE_WORD[label]
                out.append(f"| {block['title']}, {name}, {LINE_TEXT[line]} | " + " | ".join(cells) + " |")
    titles = technique_titles()
    for set_id, block in ordered_sets(newest):
        per_item = block.get("report") == PER_ITEM
        for technique, _counts in set_techniques(newest, set_id):
            cells = []
            for entry in entries:
                counts = dict(set_techniques(entry, set_id)).get(technique)
                if counts is None:
                    cells.append("not in this release")
                    continue
                found, read = counts["disguised_normalised"]["found"]["medium"], disguise_read(counts)
                cells.append(f"found {found} of {read}" if per_item else _short(found, read, False))
            out.append(f"| {block['title']}, disguised: {titles.get(technique, technique)}, detection, medium or above | "
                       + " | ".join(cells) + " |")
    if any(entry["note"] for entry in entries):
        out.append("| Note | " + " | ".join(entry["note"] for entry in entries) + " |")
    return out


def render_markdown(results: dict) -> str:
    """`benchmarks/RESULTS.md` (10.8.2): the newest entry in full and the history table."""
    out = [GENERATED, "", "# Rule benchmark results", "",
           "What the scanner's skill rules find on fixed public sets of malicious and harmless skills, measured again for every "
           "release. Rules only: no model is called. What is measured, the sources and how to run it yourself are in "
           "[README.md](README.md).", ""]
    entries = results["entries"]
    if not entries:
        out.append(NO_TABLE)
        return "\n".join(out) + "\n"
    out += _entry_markdown(entries[-1]) + [""] + _history_markdown(entries)
    return "\n".join(out) + "\n"


def readme_block(results: dict) -> str:
    """The README block between the markers (10.8.3), ending with a newline."""
    entries = results["entries"]
    if not entries:
        return NO_TABLE + "\n"
    entry = entries[-1]
    out = ["| Set | Skills | Line | Detection | False positives | Not read whole |", "|---|---|---|---|---|---|"]
    sentences = []
    for _set_id, block in ordered_sets(entry):
        if block.get("report") == PER_ITEM:
            for line in LINES:
                groups: dict[str, list[str]] = {"found": [], "not found": [], "not read whole": []}
                for item_id, stratum in _per_item_ids(block):
                    groups[_outcome(stratum, item_id, line)].append(item_id)
                parts = [f"{name} " + ", ".join(f"`{item_id}`" for item_id in ids) for name, ids in groups.items() if ids]
                sentences.append(f"{block['title']}, {LINE_TEXT[line]}: " + "; ".join(parts) + ".")
            continue
        name = block["title"] + (" (tuning)" if block["role"] == "tuning" else "")
        items = sum(stratum["items"] for stratum in block["strata"].values())
        unread = sum(len(stratum["unread"]) for stratum in block["strata"].values())
        for index, line in enumerate(LINES):
            cells = []
            for label in LABELS:
                total = totals(block, label)
                cells.append("none in this set" if total is None else rate_text(total.found[line], total.read))
            first = f"{name} | {items}" if index == 0 else " | "
            out.append(f"| {first} | {LINE_TEXT[line]} | {cells[0]} | {cells[1]} | {unread} |")
    if sentences:
        out += [""] + sentences
    out += _disguise_readme(entry)
    out += ["", f"Scanner {entry['version']}, rules version {entry['rules_version']}, released {entry['released']}."]
    return "\n".join(out) + "\n"


def _disguise_readme(entry: dict) -> list[str]:
    """P6-4 spec 6.3.3: the disguised samples in the README block, medium or above; nothing for an entry without them."""
    if "disguise" not in entry:
        return []
    disguise = entry["disguise"]
    titles = technique_titles()
    shown = [(set_id, block) for set_id, block in ordered_sets(entry)
             if block.get("report") != PER_ITEM and set_techniques(entry, set_id)]
    names = [block["title"] + (" (tuning)" if block["role"] == "tuning" else "") for _set_id, block in shown]
    out = ["", README_DISGUISE_HEAD, "", "| Samples | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    cells = []
    for set_id, block in shown:
        written, total = disguise["plain_as_written"][set_id]["malicious"], totals(block, "malicious")
        cells.append(f"as written {_short(written['found']['medium'], written['read'], False)}, "
                     f"normalised {_short(total.found['medium'], total.read, False)}")
    out.append("| plain samples | " + " | ".join(cells) + " |")
    for technique in disguise["generator"]["techniques"]:
        cells = []
        for set_id, _block in shown:
            counts = disguise["techniques"][technique][set_id]
            read = disguise_read(counts)
            cells.append(f"as written {_short(counts['disguised_as_written']['found']['medium'], read, False)}, "
                         f"normalised {_short(counts['disguised_normalised']['found']['medium'], read, False)}")
        out.append(f"| {titles.get(technique, technique)} | " + " | ".join(cells) + " |")
    out += ["", README_DISGUISE_RULES]
    for set_id, block in ordered_sets(entry):
        if block.get("report") != PER_ITEM:
            continue
        parts = []
        for technique, counts in set_techniques(entry, set_id):
            read = disguise_read(counts)
            parts.append(f"{titles.get(technique, technique)} found {counts['disguised_as_written']['found']['medium']} of {read}"
                         f" as written, {counts['disguised_normalised']['found']['medium']} of {read} normalised")
        if parts:
            out += ["", f"{block['title']}, disguised, medium or above: " + "; ".join(parts) + "."]
    for set_id, block in ordered_sets(entry):
        if set_id in disguise["added_on_harmless"]:
            out += ["", f"{block['title']}: {harmless_sentence(entry, set_id)}"]
    return out


def with_readme_block(readme: str, block: str) -> str:
    """The README text with `block` between the markers; raises `BenchmarkError` `readme_markers` unless each marker is there
    once, the start first."""
    text = readme.replace("\r\n", "\n")
    start, end = README_START + "\n", README_END
    if text.count(start) != 1 or text.count(end) != 1 or text.index(start) > text.index(end):
        raise BenchmarkError("readme_markers", f"README.md must hold {README_START} and {README_END} once each, in that order")
    return text[:text.index(start) + len(start)] + block + text[text.index(end):]


# --- the command line (10.9, 10.11, 10.12) ---------------------------------------------------------------------------------

def _write_text(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))


def _read_text(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8").replace("\r\n", "\n")
    except (OSError, UnicodeDecodeError):
        raise BenchmarkError("usage", f"{path} cannot be read as UTF-8") from None


def _measure_from_sources(args: argparse.Namespace, environ: Mapping[str, str]) -> tuple[Manifest, Cache]:
    manifest = load_manifest(args.manifest)
    cache = Cache(cache_directory(args.cache, environ, windows=os.name == "nt"))
    report = fetch(manifest, cache, opener=urllib_opener, offline=args.offline, token=environ.get("GITHUB_TOKEN") or None)
    print(f"{report.needed} source objects, {report.fetched} fetched now, the rest from the cache {cache.directory}",
          file=sys.stderr)
    return manifest, cache


def command_fetch(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    args.offline = False
    _measure_from_sources(args, environ)
    return 0


def command_run(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    if args.expect_version is not None and args.expect_version != SCANNER_VERSION:
        raise BenchmarkError("wrong_version", f"the installed scanner is {SCANNER_VERSION}, not {args.expect_version}")
    if len(args.note) > NOTE_MAX or "\n" in args.note:
        raise BenchmarkError("usage", f"--note is one line of at most {NOTE_MAX} characters")
    released = released_date(_read_text(args.changelog), SCANNER_VERSION) if args.changelog.exists() else None
    history = None
    if args.record is not None:
        if released is None:
            raise BenchmarkError("usage", f"--record needs the heading '## {SCANNER_VERSION} (YYYY-MM-DD)' in {args.changelog}")
        history = load_results(args.record) if args.record.exists() else {"results": 1, "about": ABOUT, "entries": []}
        if history["entries"] and version_key(SCANNER_VERSION) < version_key(history["entries"][-1]["version"]):
            raise BenchmarkError("usage", f"the installed scanner {SCANNER_VERSION} is lower than the newest entry "
                                          f"{history['entries'][-1]['version']}")
    community_cases(COMMUNITY_DIR, RuleSet.baseline())  # an unreadable corpus stops the run before anything is fetched
    manifest, cache = _measure_from_sources(args, environ)
    measured = measure(manifest, cache, progress=lambda text: print(text, file=sys.stderr))
    entry = {**measured, "released": released, "note": args.note}
    ids_at = f"{args.entry_out if args.entry_out is not None else 'the file of --entry-out'} and, once recorded, " \
             "benchmarks/RESULTS.md"
    print(render_text(entry, ids_at=ids_at), end="")
    if args.entry_out is not None:
        _write_text(args.entry_out, json.dumps(entry, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    code = 0
    if args.verify is not None:
        recorded = entry_for(load_results(args.verify), SCANNER_VERSION)
        if recorded is None:
            print(f"no entry for {SCANNER_VERSION} in {args.verify}: run the benchmark and record it before tagging")
            code = 1
        else:
            found = differences(measured_part(recorded), measured)
            if found:
                print(f"differs from the entry recorded for {SCANNER_VERSION}:")
                for line in found:
                    print(f"  {line}")
                code = 1
            else:
                print(f"matches the entry recorded for {SCANNER_VERSION}")
    elif args.results.exists():
        recorded = entry_for(load_results(args.results), SCANNER_VERSION)
        if recorded is not None:
            same = not differences(measured_part(recorded), measured)
            print(f"{'matches' if same else 'differs from'} the entry recorded for {SCANNER_VERSION} in {args.results}")
    if history is not None:
        kept = [old for old in history["entries"] if old["version"] != SCANNER_VERSION]
        history["entries"] = sorted([*kept, entry], key=lambda value: version_key(value["version"]))
        _write_text(args.record, dump_results(check_results(history)))
        print(f"recorded the entry for {SCANNER_VERSION} in {args.record}; run render next")
    return code


def command_render(args: argparse.Namespace, _environ: Mapping[str, str]) -> int:
    results = load_results(args.results)
    markdown = render_markdown(results)
    readme = with_readme_block(_read_text(args.readme), readme_block(results))
    if args.check:
        stale = [str(path) for path, text in ((args.markdown, markdown), (args.readme, readme))
                 if not path.exists() or _read_text(path) != text]
        for path in stale:
            print(f"{path} is not what {args.results} gives: run python benchmarks/rule_benchmark.py render")
        return 1 if stale else 0
    if args.json_out is not None or args.markdown_out is not None:
        if _read_text(args.results) != dump_results(results):
            print(f"{args.results} is not in its canonical form: record entries with run --record")
            return 1
        if args.json_out is not None:
            _write_text(args.json_out, dump_results(results))
        if args.markdown_out is not None:
            _write_text(args.markdown_out, markdown)
        return 0
    _write_text(args.markdown, markdown)
    _write_text(args.readme, readme)
    return 0


def command_changelog_lines(args: argparse.Namespace, _environ: Mapping[str, str]) -> int:
    for line in changelog_lines(load_results(args.results)):
        print(line)
    return 0


def command_check_changelog(args: argparse.Namespace, _environ: Mapping[str, str]) -> int:
    problems = check_changelog(load_results(args.results), _read_text(args.changelog))
    for problem in problems:
        print(problem)
    return 1 if problems else 0


# --- choosing the normalisation steps on the tuning set (P6-4 spec 6.2.6, 6.6) ----------------------------------------------

def tuning_only(manifest: Manifest) -> Manifest:
    """The manifest cut to the sets whose role is `tuning` and their items: `fetch` and `Objects` built from it fetch and read no
    member, row or file of a test item, even in a source archive that holds both."""
    sets = {set_id: value for set_id, value in manifest.sets.items() if value["role"] == "tuning"}
    items = [item for item in manifest.items if item["set"] in sets]
    return Manifest(manifest.document, manifest.sha256, manifest.sources, sets, items, [])


def step_configurations(candidates: tuple[str, ...]) -> list[tuple[str, tuple[str, ...]]]:
    """No normalisation, each candidate alone, all candidates, and all candidates without each one (6.2.6)."""
    configurations = [("none", ())]
    configurations += [(f"only {step}", (step,)) for step in candidates]
    configurations.append(("all", tuple(candidates)))
    configurations += [(f"all without {step}", tuple(other for other in candidates if other != step)) for step in candidates]
    return configurations


def measure_steps(tuning: Manifest, cache: Cache, configurations: list[tuple[str, tuple[str, ...]]], *,
                  clock: Callable[[], float] = time.perf_counter) -> dict[str, dict]:
    """Per configuration, over the items of `tuning` only: the plain malicious items found and found without the disguise rules
    with that normalisation, each technique's counts, the findings it adds on harmless items per rule, and the seconds it took."""
    rules = RuleSet.baseline()
    objects = Objects(tuning, cache)
    tallies = {name: {"plain": _found_block(), "added": {}, "seconds": 0.0,
                      "techniques": {technique: _technique_block() for technique in DISGUISE.TECHNIQUE_IDS}}
               for name, _steps in configurations}
    for item in tuning.items:
        roots = rebuild(item, objects)
        label = tuning.sets[item["set"]]["strata"][item["stratum"]]["label"]
        for name, steps in configurations:
            tally = tallies[name]
            started = clock()
            plain = scan_both(roots, rules, item["id"], steps)
            if plain.written.unread is None and plain.normalised.unread is None:
                if label == "benign":
                    count_added(tally["added"], plain)
                else:
                    _add_found(tally["plain"], plain.normalised)
                    for technique in DISGUISE.TECHNIQUE_IDS:
                        count_technique(tally["techniques"][technique], plain,
                                        scan_variant(roots, rules, item["id"], technique, steps))
            tally["seconds"] += clock() - started
    return tallies


def _gain_counts(tally: dict) -> list[tuple[str, int]]:
    """The counts a step may raise (6.6.2): plain malicious found and found without the disguise rules, and each technique's
    normalised found and found without the disguise rules, at each line."""
    counts = []
    for line in LINES:
        counts += [(f"plain found {line}", tally["plain"]["found"][line]),
                   (f"plain found without the disguise rules {line}", tally["plain"]["found_other"][line])]
        for technique, block in tally["techniques"].items():
            normalised = block["disguised_normalised"]
            counts += [(f"{technique} found {line}", normalised["found"][line]),
                       (f"{technique} found without the disguise rules {line}", normalised["found_other"][line])]
    return counts


def step_decisions(tallies: dict[str, dict], candidates: tuple[str, ...]) -> list[str]:
    """For each candidate, all candidates against all candidates without it: the counts it raises (a gain of at least one item
    keeps it, 6.6.2) and the findings it adds on harmless items per rule (a kept step adds none, 6.6.3)."""
    out = []
    every = tallies["all"]
    for step in candidates:
        without = tallies[f"all without {step}"]
        pairs = zip(_gain_counts(every), _gain_counts(without), strict=True)
        gains = [name for (name, value), (_, other) in pairs if value > other]
        harmless = {rule_id: counts["findings"] - without["added"].get(rule_id, {}).get("findings", 0)
                    for rule_id, counts in sorted(every["added"].items())}
        harmless = {rule_id: count for rule_id, count in harmless.items() if count > 0}
        verdict = "leave out (no gain)" if not gains else "harmless findings to clear (6.6.3)" if harmless else "keep"
        added = ", ".join(f"{rule_id} {count}" for rule_id, count in harmless.items()) or "none"
        raised = ", ".join(gains) or "none"
        out.append(f"{step}: raises {len(gains)} counts ({raised}); adds on harmless skills: {added}; {verdict}")
    return out


def added_parts(added: dict) -> list[str]:
    """`<rule>: N findings in M skills` for each rule of an `added_on_harmless` block, in rule order."""
    return [f"{rule_id}: {counts['findings']} findings in {counts['skills']} skills" for rule_id, counts in sorted(added.items())]


def render_steps(tallies: dict[str, dict], candidates: tuple[str, ...]) -> list[str]:
    """The `steps` output: counts only, never text."""
    out = [f"Rule benchmark steps: scanner {SCANNER_VERSION}, tuning sets only; counts, never text."]
    for name, tally in tallies.items():
        plain = tally["plain"]
        out.append(f"{name} ({tally['seconds']:.1f} s): plain malicious found " + ", ".join(
            f"{line} {plain['found'][line]} ({plain['found_other'][line]} without the disguise rules)" for line in LINES))
        for technique, block in tally["techniques"].items():
            normalised = block["disguised_normalised"]
            found = ", ".join(f"{line} {normalised['found'][line]} ({normalised['found_other'][line]} without the disguise rules)"
                              for line in LINES)
            out.append(f"  {technique}: {block['changed']} changed, {block['unread']} not read whole; normalised found {found}")
        out.append(f"  added on harmless skills: {'; '.join(added_parts(tally['added'])) or 'none'}")
    if "all" in tallies:
        out += ["Decisions (spec 6.6.2, 6.6.3):", *(f"  {line}" for line in step_decisions(tallies, candidates))]
    return out


def command_steps(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    if NORMALISE is None or not hasattr(NORMALISE, "CANDIDATE_STEPS") or not normalises(scan_skill_package):
        raise BenchmarkError("usage", "steps needs a scanner whose scan_skill_package takes normalise as a collection of steps "
                                      "(1.22.0 or later)")
    tuning = tuning_only(load_manifest(args.manifest))
    if not tuning.items:
        raise BenchmarkError("usage", "the manifest has no item of a set whose role is tuning")
    cache = Cache(cache_directory(args.cache, environ, windows=os.name == "nt"))
    report = fetch(tuning, cache, opener=urllib_opener, offline=args.offline, token=environ.get("GITHUB_TOKEN") or None)
    print(f"{report.needed} source objects of the tuning sets, {report.fetched} fetched now, the rest from the cache "
          f"{cache.directory}", file=sys.stderr)
    candidates = tuple(NORMALISE.CANDIDATE_STEPS)
    for line in render_steps(measure_steps(tuning, cache, step_configurations(candidates)), candidates):
        print(line)
    return 0


def command_check_history(args: argparse.Namespace, _environ: Mapping[str, str]) -> int:
    problems = check_history(load_results(args.previous), load_results(args.results))
    for problem in problems:
        print(problem)
    return 1 if problems else 0


def command_check_measured(args: argparse.Namespace, _environ: Mapping[str, str]) -> int:
    """P6-9 spec 8.6: every record of `measured_sets.json` is valid and each registered rule that needs a measurement of its
    own has one. With `--release`, each of them is `measured` at the severity it is registered at and a `withdrawn` one is not
    registered. Exit 0 passed, 1 a problem (one line each), 2 a file that cannot be read."""
    try:
        document = MEASURED_SETS.load(args.records)
    except ValueError as error:
        raise BenchmarkError("measured_sets", str(error)) from None
    registered = {rule.id: rule.severity_default for rule in RuleSet.baseline()}
    problems = MEASURED_SETS.release_problems(document, registered, release=args.release)
    for problem in problems:
        print(problem)
    return 1 if problems else 0


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise BenchmarkError("usage", message)


def parser() -> argparse.ArgumentParser:
    main_parser = _Parser(prog="rule_benchmark.py", description="The rule benchmark: rules only, no model.")
    commands = main_parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    manifest = BENCHMARKS / "manifest.json"
    results = BENCHMARKS / "results.json"
    for name in ("fetch", "run"):
        sub = commands.add_parser(name)
        sub.add_argument("--manifest", type=Path, default=manifest)
        sub.add_argument("--cache", type=Path, default=None)
    run = commands.choices["run"]
    run.add_argument("--offline", action="store_true")
    run.add_argument("--expect-version", default=None)
    run.add_argument("--verify", type=Path, default=None)
    run.add_argument("--entry-out", type=Path, default=None)
    run.add_argument("--record", type=Path, default=None)
    run.add_argument("--note", default="")
    run.add_argument("--changelog", type=Path, default=REPOSITORY / "CHANGELOG.md")
    run.add_argument("--results", type=Path, default=results, help=argparse.SUPPRESS)
    render = commands.add_parser("render")
    render.add_argument("--results", type=Path, default=results)
    render.add_argument("--readme", type=Path, default=REPOSITORY / "README.md")
    render.add_argument("--markdown", type=Path, default=BENCHMARKS / "RESULTS.md")
    render.add_argument("--check", action="store_true")
    render.add_argument("--json-out", type=Path, default=None)
    render.add_argument("--markdown-out", type=Path, default=None)
    lines = commands.add_parser("changelog-lines")
    lines.add_argument("--results", type=Path, default=results)
    check = commands.add_parser("check-changelog")
    check.add_argument("--results", type=Path, default=results)
    check.add_argument("--changelog", type=Path, default=REPOSITORY / "CHANGELOG.md")
    history = commands.add_parser("check-history")
    history.add_argument("--previous", type=Path, required=True)
    history.add_argument("--results", type=Path, default=results)
    steps = commands.add_parser("steps")
    steps.add_argument("--manifest", type=Path, default=manifest)
    steps.add_argument("--cache", type=Path, default=None)
    steps.add_argument("--offline", action="store_true")
    measured = commands.add_parser("check-measured")
    measured.add_argument("--records", type=Path, default=BENCHMARKS / "measured_sets.json")
    measured.add_argument("--release", action="store_true")
    return main_parser


COMMANDS = {"fetch": command_fetch, "run": command_run, "render": command_render, "changelog-lines": command_changelog_lines,
            "check-changelog": command_check_changelog, "check-history": command_check_history, "steps": command_steps,
            "check-measured": command_check_measured}


def main(argv: list[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    """Exit 0 when the table was produced or a check passed, 1 when a check found a difference, 2 when nothing was measured
    (10.11). Every error is one line on stderr that starts with its name."""
    try:
        args = parser().parse_args(argv)
        return COMMANDS[args.command](args, os.environ if environ is None else environ)
    except BenchmarkError as exc:
        print(exc.line(), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
