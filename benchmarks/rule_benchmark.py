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
from spellwarden_scan.identity import nested_skill_roots, package_files, package_sha256

REPOSITORY = Path(__file__).resolve().parents[1]
BENCHMARKS = REPOSITORY / "benchmarks"
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


class ItemResult(NamedTuple):
    """One item's result: `unread` is the reason it was not read whole (None when it was), `worst` its worst severity over
    every rule (`none` without a finding) and `rules` the worst severity per rule that found something."""
    unread: str | None
    worst: str
    rules: dict[str, str]


def worse(first: str, second: str) -> str:
    """The worse of two severities, `none` being better than any."""
    if first == NONE:
        return second
    if second == NONE:
        return first
    return first if SEVERITY_RANK[first] <= SEVERITY_RANK[second] else second


def at_or_above(severity: str, line: str) -> bool:
    return severity != NONE and SEVERITY_RANK[severity] <= LINE_RANK[line]


def scan_root(files: Mapping[str, bytes], rules: RuleSet) -> tuple[str | None, dict[str, str]]:
    """The reason one root was not read whole (or None) and the worst severity per rule of its findings (10.5.1, 10.5.2)."""
    try:
        result = scan_skill_package(files, rules, root="", nested_roots=nested_skill_roots(files, ""),
                                    max_findings=SCAN_CAP, max_per_rule=SCAN_CAP)
    except FrontmatterLimit:
        return "frontmatter_limit", {}
    except Exception as exc:  # any scanner failure is unread content, never a clean skill
        return f"scanner_error:{type(exc).__name__}", {}
    if result.truncated > 0:
        return "findings_truncated", {}
    found: dict[str, str] = {}
    for finding in result.findings:
        found[finding.rule_id] = worse(found.get(finding.rule_id, NONE), finding.severity)
    return None, found


def scan_item(roots: list[dict[str, bytes]], rules: RuleSet) -> ItemResult:
    """Folds the roots of one item (10.5.3): any unread root makes the whole item unread (the first such root's reason);
    otherwise each rule's worst severity is the worst over the roots."""
    merged: dict[str, str] = {}
    for files in roots:
        reason, found = scan_root(files, rules)
        if reason is not None:
            return ItemResult(reason, NONE, {})
        for rule_id, severity in found.items():
            merged[rule_id] = worse(merged.get(rule_id, NONE), severity)
    overall = NONE
    for severity in merged.values():
        overall = worse(overall, severity)
    return ItemResult(None, overall, merged)


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


def measure(manifest: Manifest, cache: Cache, *, progress: Callable[[str], None] | None = None) -> dict:
    """The measured part of the entry (10.6, 10.7): every item rebuilt, verified and scanned, or an error that stops the run."""
    rules = RuleSet.baseline()
    skill_rules = sorted(rules.by_area("skill"), key=lambda rule: rule.id)
    rule_ids = [rule.id for rule in skill_rules]
    objects = Objects(manifest, cache)
    results: dict[tuple[str, str], list[tuple[str, ItemResult]]] = {}
    for number, item in enumerate(manifest.items, start=1):
        result = scan_item(rebuild(item, objects), rules)
        results.setdefault((item["set"], item["stratum"]), []).append((item["id"], result))
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
    return {"version": SCANNER_VERSION, "rules_version": RULES_VERSION, "manifest_sha256": manifest.sha256,
            "lines": list(LINES), "rules_measured": {rule.id: rule.severity_default for rule in skill_rules},
            "rules_not_measured": sorted(rule.id for rule in rules if rule.area != "skill"), "sets": sets}


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


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def check_results(document: object) -> dict:
    """The history document, checked: `{"results": 1, "about": text, "entries": [...]}`, entries ascending by version, at most one
    per version, each with the members of 10.7. Raises `BenchmarkError` `results_invalid` naming the first problem."""
    if not isinstance(document, dict) or document.get("results") != 1 or not isinstance(document.get("entries"), list) \
            or not isinstance(document.get("about"), str) or set(document) != {"results", "about", "entries"}:
        raise BenchmarkError("results_invalid", 'the history must be {"results": 1, "about": "...", "entries": [...]}')
    previous: str | None = None
    for entry in document["entries"]:
        if not isinstance(entry, dict) or set(entry) != ENTRY_MEMBERS:
            raise BenchmarkError("results_invalid", f"an entry must have exactly the members {', '.join(sorted(ENTRY_MEMBERS))}")
        version = entry["version"]
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise BenchmarkError("results_invalid", "an entry's version must be X.Y.Z")
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
    return lines


def changelog_lines(results: dict) -> list[str]:
    """The lines the newest entry's CHANGELOG section must hold (10.10); none without an entry."""
    entries = results["entries"]
    if not entries:
        return []
    if len(entries) == 1:
        return [FIRST_TABLE]
    previous, current = entries[-2], entries[-1]
    worse_lines = worse_rates(previous, current)
    if worse_lines:
        required = [f"Rule benchmark: these rates got worse than in {previous['version']}:", *worse_lines]
    else:
        required = [f"Rule benchmark: no rate got worse than in {previous['version']}."]
    if current["manifest_sha256"] != previous["manifest_sha256"]:
        required.append(f"Rule benchmark: the sets changed since {previous['version']}; benchmarks/README.md lists what was "
                        "left out.")
    return required


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
    # joined (review r0:F2). The list of worse rates is matched line by line: each `- ` line stands on a line of its own, unwrapped,
    # in order, after the sentence that introduces it.
    have = [line.rstrip() for line in section.splitlines()]
    flat = " ".join(section.split())
    problems = []
    worse_lines = [line for line in required if line.startswith("- ")]
    for line in required:
        if line.startswith("- "):
            continue
        sentence = " ".join(line.split())
        if sentence not in flat:
            problems.append(f"the CHANGELOG section of {version} lacks the sentence: {line}")
        elif line.endswith(":"):
            starts = [i for i in range(len(have) - len(worse_lines) + 1) if have[i:i + len(worse_lines)] == worse_lines]
            listed = " | ".join(worse_lines)
            first = " ".join(worse_lines[0].split()) if worse_lines else ""
            right_under = bool(worse_lines) and flat.find(f"{sentence} {first}") != -1
            if not starts or not right_under:
                problems.append(f"the CHANGELOG section of {version} must list under that sentence, one line each, in order: {listed}")
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
    for _set_id, block in ordered_sets(entry):
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
        if not per_item and totals(block, "malicious") is not None:
            at_medium, at_high = _missed(block)
            out.append(f"  missed malicious skills: {at_medium} at medium or above, {at_high} at high or above; their ids are in "
                       f"{ids_at}")
        out.append("")
    out.append(not_measured_text(entry))
    return "\n".join(out) + "\n"


def _ids(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "none"


def _entry_markdown(entry: dict) -> list[str]:
    out = [f"## Scanner {entry['version']}", "",
           f"Rules version {entry['rules_version']}, released {entry['released']}. Manifest `{entry['manifest_sha256']}`."]
    if entry["note"]:
        out += ["", f"Note: {entry['note']}"]
    for _set_id, block in ordered_sets(entry):
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
    out += ["", f"{not_measured_text(entry)}."]
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
    out += ["", f"Scanner {entry['version']}, rules version {entry['rules_version']}, released {entry['released']}."]
    return "\n".join(out) + "\n"


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


def command_check_history(args: argparse.Namespace, _environ: Mapping[str, str]) -> int:
    problems = check_history(load_results(args.previous), load_results(args.results))
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
    return main_parser


COMMANDS = {"fetch": command_fetch, "run": command_run, "render": command_render, "changelog-lines": command_changelog_lines,
            "check-changelog": command_check_changelog, "check-history": command_check_history}


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
