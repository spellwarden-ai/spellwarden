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

import hashlib
import http.client
import json
import os
import re
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
