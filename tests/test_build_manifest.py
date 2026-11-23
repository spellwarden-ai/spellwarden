"""Rule benchmark 10.2 and claim T-21: `benchmarks/build_manifest.py` rebuilds every frozen item from its source as the set was
built, checks it against the frozen engine hash and writes the public manifest, offline here: synthetic frozen manifests, and
tar.gz, parquet and zip objects built in memory behind a fake opener. Every sample is a tiny harmless skill. The script is not
in the wheel or the sdist, so this file skips when `benchmarks/` is absent."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from spellwarden_scan.identity import nested_skill_roots, package_files, package_sha256

ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = ROOT / "benchmarks"
if not (BENCHMARKS / "build_manifest.py").exists():
    pytest.skip("benchmarks/ is not in an sdist", allow_module_level=True)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rb = _load("rule_benchmark", BENCHMARKS / "rule_benchmark.py")
bm = _load("build_manifest", BENCHMARKS / "build_manifest.py")

MARKER = "UNIQUE-BUILDER-MARKER"
FRONT = "---\nname: bench-sample\ndescription: A small harmless sample for the builder tests.\nlicense: MIT\nversion: 1.0.0\n---\n"


def skill(word: str) -> bytes:
    return (FRONT + f"# Sample {word}\n\nSay hello to the user. {MARKER}\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def package_hash(files: dict[str, bytes]) -> str:
    return package_sha256(package_files(files, "", nested_skill_roots(files, "")).files)


def tar_gz(members: list[tuple[str, bytes]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 0
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def zip_archive(top: str, files: dict[str, bytes], *, links: tuple[str, ...] = ()) -> bytes:
    """A codeload-style zip: every path under one top folder, a directory entry first, and `links` as symbolic links."""
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr(zipfile.ZipInfo(f"{top}/"), b"")
        for path, data in files.items():
            archive.writestr(zipfile.ZipInfo(f"{top}/{path}", date_time=(2026, 1, 1, 0, 0, 0)), data)
        for path in links:
            info = zipfile.ZipInfo(f"{top}/{path}", date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, "SKILL.md")
    return raw.getvalue()


def parquet(rows: list[tuple[str, str, bool]]) -> bytes:
    import pyarrow as pa
    import pyarrow.parquet as pq

    sink = io.BytesIO()
    pq.write_table(pa.table({"benchmark_id": [row[0] for row in rows], "skill_text": [row[1] for row in rows],
                             "text_available": [row[2] for row in rows]}), sink)
    return sink.getvalue()


class FakeOpener:
    def __init__(self, answers: dict) -> None:
        self.answers = dict(answers)
        self.calls: list[str] = []

    def __call__(self, url: str, _headers, _timeout: float, limit: int):
        self.calls.append(url)
        value = self.answers.get(url)
        if value is None:
            return rb.Answer(404, None, b"")
        return rb.Answer(200, None, value[:limit])


# --- the rebuild rules -----------------------------------------------------------------------------------------------------------

def test_skill_roots_split_nested_skills_and_read_one_markdown_file_as_skill_md():
    names = ["SKILL.md", "run.sh", "inner/SKILL.md", "inner/tool.py", "docs/a.md"]
    assert bm.skill_roots(names) == [{"SKILL.md": "SKILL.md", "run.sh": "run.sh", "docs/a.md": "docs/a.md"},
                                     {"SKILL.md": "inner/SKILL.md", "tool.py": "inner/tool.py"}]
    assert bm.skill_roots(["notes.MD"]) == [{"SKILL.md": "notes.MD"}]
    assert bm.skill_roots(["notes.md", "other.txt"]) == []


def test_a_lower_case_skill_md_counts_only_when_no_skill_md_exists():
    assert bm.skill_roots(["pkg/skill.md", "pkg/run.sh"]) == [{"SKILL.md": "pkg/skill.md", "run.sh": "pkg/run.sh"}]
    assert bm.skill_roots(["SKILL.md", "pkg/skill.md"]) == [{"SKILL.md": "SKILL.md", "pkg/skill.md": "pkg/skill.md"}]
    assert bm.skill_roots(["a/Skill.md", "a/SKILL.MD"]) == [{"SKILL.md": "a/SKILL.MD"}]


def test_clean_drops_the_five_kinds_of_name_and_a_file_over_2000000_bytes():
    files = {"SKILL.md": b"x", ".DS_Store": b"x", "a/__pycache__/m.cpython-313.pyc": b"x", "b.pyc": b"x", ".git/config": b"x",
             "node_modules/p/index.js": b"x", "big.bin": b"x" * 2_000_001, "ok.bin": b"x" * 2_000_000}
    assert sorted(bm.clean(files)) == ["SKILL.md", "ok.bin"]


def test_package_members_take_the_base_or_what_is_under_it_and_skip_unsafe_names():
    members = [("packages/a/b", b"one"), ("packages/a/b/SKILL.md", b"two"), ("packages/a/bc/SKILL.md", b"no"),
               ("/packages/a/b/x", b"no"), ("packages/a/b/../x", b"no")]
    found = bm.package_members(members, "packages/a/b")
    assert found == {"b": ("packages/a/b", b"one"), "SKILL.md": ("packages/a/b/SKILL.md", b"two")}


def test_a_file_with_a_backslash_a_dot_part_or_a_long_path_is_left_out_and_the_hash_is_over_the_rest():
    members = [("p/x/SKILL.md", skill("a")), ("p/x/a\\b.txt", b"no"), ("p/x/./c.txt", b"no"), ("p/x/" + "d" * 401, b"no"),
               ("p/x/keep.txt", b"yes")]
    roots = bm.msb_roots(members, "p/x", "msb-src002")
    assert [[entry.path for entry in root] for root in roots] == [["SKILL.md", "keep.txt"]]
    assert rb.sample_hash({entry.path: entry.data for entry in roots[0]}) == package_hash({"SKILL.md": skill("a"), "keep.txt": b"yes"})
    assert roots[0][0].origin == {"source": "msb-src002", "member": "p/x/SKILL.md"}


def test_roots_are_matched_to_the_frozen_samples_by_hash_and_written_in_the_frozen_order():
    first = [bm.File("SKILL.md", skill("one"), {})]
    second = [bm.File("SKILL.md", skill("two"), {})]
    hashes = [package_hash({"SKILL.md": skill("two")}), package_hash({"SKILL.md": skill("one")})]
    assert bm.match_frozen([first, second], hashes) == [second, first]
    with pytest.raises(bm.Excluded):
        bm.match_frozen([first], [package_hash({"SKILL.md": skill("three")})])


# --- the whole build, offline ----------------------------------------------------------------------------------------------------

COMMIT = "c" * 40
TOP = "repo-" + COMMIT


class World:
    """Synthetic frozen manifests and sources: two SkillHarm packages (one of two skills, nested, frozen in reverse order), an
    ATR harmless text row, a held-out wild-liu package, a tuning wild-amos package, an ATR held-out item that is left out, a
    harmless public skill with a nested skill and a link, and a Trail of Bits archive of two skills."""

    def __init__(self) -> None:
        nested = {"SKILL.md": skill("top"), "inner/SKILL.md": skill("inner"), "inner/x.py": b"print(1)\n", "__pycache__/a.pyc": b"x"}
        self.archives = {
            "msb-src009": [("packages/h/one/" + path, data) for path, data in nested.items()]
                          + [("packages/h/two/SKILL.md", skill("two"))],
            "msb-src002": [("packages/smp_1/wild/SKILL.md", skill("wild")), ("packages/smp_1/wild/.DS_Store", b"x")],
            "msb-src005": [("artifacts/amos/skill.md", skill("amos"))],
            "msb-src004": [("packages/leak/SKILL.md", skill("leak"))],
            "msb-src011": [("artifacts/atr/SKILL.md", skill("atr"))],
            "msb-src012": [("artifacts/sfb/SKILL.md", skill("sfb"))],
        }
        self.rows = [("ASB04_000003", skill("text").decode(), True)]
        self.csv = "benchmark_id,source_id,package_relative_path,sanitized\n" \
                   "ASB04_000001,SRC009,packages/h/one,no\nASB04_000002,SRC009,packages/h/two,no\n" \
                   "ASB04_000010,SRC002,packages/smp_1/wild,yes\nASB04_000011,SRC005,artifacts/amos,no\n"
        self.repository = {"skills/hello/SKILL.md": skill("hello"), "skills/hello/my notes.txt": b"notes\n",
                           "skills/hello/sub/SKILL.md": skill("sub"), "README.md": b"# r\n"}
        self.tob = {"skills/alpha/SKILL.md": skill("alpha"), "skills/alpha/__pycache__/hidden.cpython-313.pyc": b"\x00pyc",
                    "skills/beta/SKILL.md": skill("beta"), "README.md": b"# tob\n"}
        self.frozen_order_reversed = True

    def objects(self) -> dict[str, bytes]:
        """Every pinned object by source id, and the package manifest under `csv`."""
        found = {source_id: tar_gz(members) for source_id, members in self.archives.items()}
        found["msb-primary"] = parquet(self.rows)
        found["csv"] = self.csv.encode()
        return found

    def install(self, monkeypatch) -> FakeOpener:
        """Points the builder's pinned objects at the synthetic ones and returns an opener that serves every URL."""
        objects = self.objects()
        answers = {}
        sources = {}
        for source_id, pinned in bm.SOURCES.items():
            url = f"https://example.org/{source_id}"
            sources[source_id] = pinned._replace(url=url, sha256=sha(objects[source_id]), size=len(objects[source_id]))
            answers[url] = objects[source_id]
        monkeypatch.setattr(bm, "SOURCES", sources)
        monkeypatch.setattr(bm, "PACKAGE_MANIFEST", bm.PACKAGE_MANIFEST._replace(
            url="https://example.org/package_manifest.csv", sha256=sha(objects["csv"]), size=len(objects["csv"])))
        answers["https://example.org/package_manifest.csv"] = objects["csv"]
        monkeypatch.setattr(bm, "TOB_SKILLS", 2)
        answers[f"https://codeload.github.com/owner/repo/zip/{COMMIT}"] = zip_archive(TOP, self.repository,
                                                                                     links=("skills/hello/link.md",))
        for path in ("SKILL.md", "my notes.txt"):
            answers[bm.raw_url("owner", "repo", COMMIT, f"skills/hello/{path}")] = self.repository[f"skills/hello/{path}"]
        answers["https://api.github.com/repos/owner/repo/license"] = json.dumps({"license": {"spdx_id": "MIT"}}).encode()
        tob_top = f"{bm.TOB_REPOSITORY}-{bm.TOB_COMMIT}"
        answers[f"https://codeload.github.com/{bm.TOB_OWNER}/{bm.TOB_REPOSITORY}/zip/{bm.TOB_COMMIT}"] = zip_archive(tob_top, self.tob)
        for path, data in self.tob.items():
            answers[bm.raw_url(bm.TOB_OWNER, bm.TOB_REPOSITORY, bm.TOB_COMMIT, path)] = data
        return FakeOpener(answers)

    def write_frozen(self, run_dir: Path) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        top = package_hash({"SKILL.md": skill("top")})
        inner = package_hash({"SKILL.md": skill("inner"), "x.py": b"print(1)\n"})
        test_entries = [
            {"id": "m-asb04-000001", "label": "malicious", "source": "SRC009", "source_ref": "ASB04_000001", "content": "package"},
            {"id": "m-asb04-000002", "label": "malicious", "source": "SRC009", "source_ref": "ASB04_000002", "content": "package"},
            {"id": "b-asb04-000003", "label": "benign", "source": "SRC011", "source_ref": "ASB04_000003", "content": "text"},
        ]
        test_samples = [
            {"id": "m-asb04-000001.r1", "unit": "m-asb04-000001", "package_sha256": inner if self.frozen_order_reversed else top},
            {"id": "m-asb04-000001.r2", "unit": "m-asb04-000001", "package_sha256": top if self.frozen_order_reversed else inner},
            {"id": "m-asb04-000002", "package_sha256": package_hash({"SKILL.md": skill("two")})},
            {"id": "b-asb04-000003", "package_sha256": package_hash({"SKILL.md": skill("text")})},
        ]
        own_entries = [
            {"id": "m-asb04-000010", "half": "held-out", "label": "malicious", "stratum": "wild-liu", "source": "SRC002",
             "source_ref": "ASB04_000010", "source_path": "packages/smp_1/wild"},
            {"id": "m-asb04-000011", "half": "tuning", "label": "malicious", "stratum": "wild-amos", "source": "SRC005",
             "source_ref": "ASB04_000011", "source_path": "artifacts/amos"},
            {"id": "b-wild-0000000001", "half": "held-out", "label": "benign", "stratum": "benign-wild", "source": "LIU-SAFE",
             "source_ref": "skillsmp.com:smp_1:hello", "source_path": f"https://github.com/owner/repo/tree/{COMMIT}/skills/hello"},
            {"id": "m-atr-0000000001", "half": "held-out", "label": "malicious", "stratum": "curated-atr", "source": "ATR",
             "source_ref": "atr-1", "source_path": ""},
        ]
        own_samples = [
            {"id": "m-asb04-000010", "package_sha256": package_hash({"SKILL.md": skill("wild")})},
            {"id": "m-asb04-000011", "package_sha256": package_hash({"SKILL.md": skill("amos")})},
            {"id": "b-wild-0000000001", "package_sha256": package_hash({"SKILL.md": skill("hello"), "my notes.txt": b"notes\n"})},
            {"id": "m-atr-0000000001", "package_sha256": package_hash({"SKILL.md": skill("atr-held")})},
        ]
        documents = {"manifest-msb-test-v1.json": {"entries": test_entries, "set": "msb-test-v1"},
                     "measure-manifest-msb-test-v1.json": {"manifest": 1, "samples": test_samples},
                     "manifest-v1.json": {"entries": own_entries, "set": "analyzer-v1"},
                     "measure-manifest-v1.json": {"manifest": 1, "samples": own_samples}}
        for name, document in documents.items():
            (run_dir / name).write_text(json.dumps(document), encoding="utf-8")


def _build(tmp_path: Path, monkeypatch, world: World | None = None, **kwargs) -> tuple[dict, FakeOpener]:
    world = world or World()
    opener = world.install(monkeypatch)
    world.write_frozen(tmp_path / "run")
    document = bm.build(tmp_path / "run", cache=rb.Cache(tmp_path / "cache"), opener=opener, token=kwargs.get("token"),
                        date="2026-11-24", say=lambda _line: None)
    return document, opener


def test_the_build_writes_every_item_with_files_pointers_and_hashes(tmp_path, monkeypatch):
    document, _ = _build(tmp_path, monkeypatch)
    items = {item["id"]: item for item in document["items"]}
    assert sorted(items) == ["b-asb04-000003", "b-wild-0000000001", "m-asb04-000001", "m-asb04-000002", "m-asb04-000010",
                             "m-asb04-000011", "m-tob-alpha", "m-tob-beta"]
    two = items["m-asb04-000001"]
    assert (two["set"], two["stratum"], two["ref"]) == ("msb-test", "skillharm", "ASB04_000001")
    assert [[entry["path"] for entry in root["files"]] for root in two["roots"]] == [["SKILL.md", "x.py"], ["SKILL.md"]]
    assert two["roots"][0]["files"][1]["from"] == {"source": "msb-src009", "member": "packages/h/one/inner/x.py"}
    text = items["b-asb04-000003"]
    assert text["stratum"] == "atr-benign" and text["roots"][0]["files"][0]["from"] == {"source": "msb-primary", "row": "ASB04_000003"}
    assert items["m-asb04-000011"]["roots"][0]["files"][0]["from"]["member"] == "artifacts/amos/skill.md"
    assert (items["m-asb04-000010"]["set"], items["m-asb04-000011"]["set"]) == ("held-out", "tuning")
    harmless = items["b-wild-0000000001"]
    assert harmless["licence"] == "MIT" and [entry["path"] for entry in harmless["roots"][0]["files"]] == ["SKILL.md", "my notes.txt"]
    assert harmless["roots"][0]["files"][1]["from"]["url"].endswith(f"/{COMMIT}/skills/hello/my%20notes.txt")
    assert "m-atr-0000000001" not in json.dumps(document)
    assert document["excluded"] == [] and set(document["sets"]) == {"held-out", "msb-test", "trailofbits", "tuning"}
    assert MARKER not in json.dumps(document)
    rb.check_manifest(document)


def test_the_trail_of_bits_skills_keep_every_file_and_the_set_is_per_item(tmp_path, monkeypatch):
    document, _ = _build(tmp_path, monkeypatch)
    alpha = next(item for item in document["items"] if item["id"] == "m-tob-alpha")
    paths = [entry["path"] for entry in alpha["roots"][0]["files"]]
    assert paths == ["SKILL.md", "__pycache__/hidden.cpython-313.pyc"]
    assert alpha["roots"][0]["package_sha256"] == package_hash({"SKILL.md": skill("alpha"),
                                                                "__pycache__/hidden.cpython-313.pyc": b"\x00pyc"})
    assert alpha["licence"] == "none" and alpha["set"] == "trailofbits" and alpha["stratum"] == "tob"
    assert document["sets"]["trailofbits"]["report"] == "per-item"


def test_the_output_is_the_same_on_a_second_run_and_unpinned_objects_never_enter_the_cache(tmp_path, monkeypatch):
    first, _ = _build(tmp_path, monkeypatch)
    second, opener = _build(tmp_path, monkeypatch)
    assert bm.manifest_text(first) == bm.manifest_text(second)
    pinned = {pinned.sha256 for pinned in bm.SOURCES.values()} | {bm.PACKAGE_MANIFEST.sha256}
    assert {path.name for path in (tmp_path / "cache" / "objects").iterdir()} <= pinned
    assert not [url for url in opener.calls if url.startswith("https://example.org/")], "the second run reads the cache"


def test_the_github_token_goes_to_the_three_github_hosts_only(tmp_path, monkeypatch):
    world = World()
    opener = world.install(monkeypatch)
    seen: list[tuple[str, dict]] = []

    def recording(url, headers, timeout, limit):
        seen.append((url, dict(headers)))
        return opener(url, headers, timeout, limit)

    world.write_frozen(tmp_path / "run")
    bm.build(tmp_path / "run", cache=rb.Cache(tmp_path / "cache"), opener=recording, token="secret", date="2026-11-24",
             say=lambda _line: None)
    for url, headers in seen:
        github = url.startswith(("https://api.github.com/", "https://codeload.github.com/", "https://raw.githubusercontent.com/"))
        assert ("Authorization" in headers) == github, url


def test_an_item_whose_rebuilt_hash_no_frozen_sample_has_is_excluded_with_its_set_stratum_and_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(bm, "MAX_EXCLUDED_SHARE", 1.0)
    world = World()
    world.archives["msb-src002"] = [("packages/smp_1/wild/SKILL.md", skill("changed"))]
    document, _ = _build(tmp_path, monkeypatch, world)
    assert document["excluded"] == [{"id": "m-asb04-000010", "set": "held-out", "stratum": "wild-liu", "date": "2026-11-24",
                                     "reason": "rebuilt 1 roots whose package hashes are not the frozen ones"}]
    assert "m-asb04-000010" not in {item["id"] for item in document["items"]}


def test_a_raw_file_that_differs_from_the_archive_excludes_the_harmless_skill(tmp_path, monkeypatch):
    monkeypatch.setattr(bm, "MAX_EXCLUDED_SHARE", 1.0)
    world = World()
    opener = world.install(monkeypatch)
    opener.answers[bm.raw_url("owner", "repo", COMMIT, "skills/hello/my notes.txt")] = b"other\n"
    world.write_frozen(tmp_path / "run")
    document = bm.build(tmp_path / "run", cache=rb.Cache(tmp_path / "cache"), opener=opener, token=None, date="2026-11-24",
                        say=lambda _line: None)
    assert [(record["id"], record["reason"]) for record in document["excluded"]] == [
        ("b-wild-0000000001", "the raw file my notes.txt differs from the archive's")]


def test_a_raw_file_that_cannot_be_fetched_is_excluded_with_a_short_reason_even_when_its_path_is_long(tmp_path, monkeypatch):
    # Review r0:F4: the reason gives the path and the HTTP status, never the URL, and is cut to a length the manifest's
    # 400-character limit accepts, so a long path cannot make the whole build fail.
    monkeypatch.setattr(bm, "MAX_EXCLUDED_SHARE", 1.0)
    world = World()
    opener = world.install(monkeypatch)
    del opener.answers[bm.raw_url("owner", "repo", COMMIT, "skills/hello/my notes.txt")]
    world.write_frozen(tmp_path / "run")
    document = bm.build(tmp_path / "run", cache=rb.Cache(tmp_path / "cache"), opener=opener, token=None, date="2026-11-24",
                        say=lambda _line: None)
    assert [(record["id"], record["reason"]) for record in document["excluded"]] == [
        ("b-wild-0000000001", "the raw file my notes.txt could not be fetched (HTTP 404)")]
    long_path = "/".join(["d" * 120] * 3) + ".txt"
    reason = bm.short_reason(f"the raw file {long_path} could not be fetched (HTTP 404)")
    assert len(reason) <= bm.REASON_MAX <= rb.MAX_STRING and reason.endswith("...")
    document["excluded"][0]["reason"] = reason
    rb.check_manifest(document)


def test_what_a_harmless_skill_leaves_out_does_not_count_towards_its_size(tmp_path, monkeypatch):
    # Three files over 2,000,000 bytes and a compiled file are left out, as when the skill was collected. With them the directory
    # holds more than 5,000,000 bytes; without them the skill is the frozen one, so it is written and not excluded.
    world = World()
    for number in range(3):
        world.repository[f"skills/hello/big{number}.bin"] = b"0" * 2_000_001
    world.repository["skills/hello/__pycache__/m.pyc"] = b"x"
    document, _ = _build(tmp_path, monkeypatch, world)
    harmless = next(item for item in document["items"] if item["id"] == "b-wild-0000000001")
    assert [entry["path"] for entry in harmless["roots"][0]["files"]] == ["SKILL.md", "my notes.txt"]
    assert document["excluded"] == []


def test_more_than_five_percent_of_a_stratum_excluded_exits_2_and_writes_nothing(tmp_path, monkeypatch, capsys):
    world = World()
    world.archives["msb-src002"] = [("packages/smp_1/wild/SKILL.md", skill("changed"))]
    opener = world.install(monkeypatch)
    world.write_frozen(tmp_path / "run")
    out = tmp_path / "manifest.json"
    code = bm.main(["--run-dir", str(tmp_path / "run"), "--out", str(out), "--cache", str(tmp_path / "cache"),
                    "--date", "2026-11-24"], environ={}, opener=opener)
    assert code == 2 and not out.exists()
    assert "held-out / wild-liu: 1 of 1 items excluded, more than 5%" in capsys.readouterr().err


def test_a_trail_of_bits_raw_file_that_differs_exits_2_and_writes_nothing(tmp_path, monkeypatch, capsys):
    world = World()
    opener = world.install(monkeypatch)
    opener.answers[bm.raw_url(bm.TOB_OWNER, bm.TOB_REPOSITORY, bm.TOB_COMMIT, "skills/beta/SKILL.md")] = b"changed"
    world.write_frozen(tmp_path / "run")
    out = tmp_path / "manifest.json"
    assert bm.main(["--run-dir", str(tmp_path / "run"), "--out", str(out), "--cache", str(tmp_path / "cache"),
                    "--date", "2026-11-24"], environ={}, opener=opener) == 2
    assert not out.exists() and "Trail of Bits skill beta" in capsys.readouterr().err


def test_a_package_hash_in_two_sets_or_a_repeated_root_list_stops_the_build(tmp_path, monkeypatch):
    world = World()
    world.archives["msb-src005"] = [("artifacts/amos/SKILL.md", skill("wild"))]  # the tuning item now equals a held-out one
    opener = world.install(monkeypatch)
    world.write_frozen(tmp_path / "run")
    samples_path = tmp_path / "run" / "measure-manifest-v1.json"
    samples = json.loads(samples_path.read_text(encoding="utf-8"))
    samples["samples"][1]["package_sha256"] = package_hash({"SKILL.md": skill("wild")})
    samples_path.write_text(json.dumps(samples), encoding="utf-8")
    with pytest.raises(bm.BuildError, match="two sets"):
        bm.build(tmp_path / "run", cache=rb.Cache(tmp_path / "cache"), opener=opener, token=None, date="2026-11-24",
                 say=lambda _line: None)


def test_main_writes_the_manifest_with_lf_line_endings_and_prints_counts_only(tmp_path, monkeypatch, capsys):
    world = World()
    opener = world.install(monkeypatch)
    world.write_frozen(tmp_path / "run")
    out = tmp_path / "manifest.json"
    assert bm.main(["--run-dir", str(tmp_path / "run"), "--out", str(out), "--cache", str(tmp_path / "cache"),
                    "--date", "2026-11-24"], environ={}, opener=opener) == 0
    data = out.read_bytes()
    assert b"\r\n" not in data and data.endswith(b"\n")
    assert rb.load_manifest(out).sha256 == rb.manifest_sha256(json.loads(data))
    printed = capsys.readouterr().out
    assert MARKER not in printed and "msb-test / skillharm: 2 written, 0 excluded" in printed
