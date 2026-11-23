"""Builds `benchmarks/manifest.json` from the frozen measurement manifests and the sources (Rule benchmark, 10.2). Development
only: the orchestrator runs it once; `make check` and CI never do.

    uv run --locked python benchmarks/build_manifest.py --run-dir DIR --out benchmarks/manifest.json [--cache DIR] [--date D]

`--run-dir` holds the four frozen manifests (`manifest-v1.json`, `measure-manifest-v1.json`, `manifest-msb-test-v1.json`,
`measure-manifest-msb-test-v1.json`); the builder reads those four files there and nothing else. For each frozen item it
rebuilds the skill roots from the sources as the set was built when it was frozen, checks each root's engine package hash
against the frozen measurement manifest, and writes the files of each root with their hashes and where to fetch them. An item
that cannot be rebuilt exactly goes to `excluded` with its reason. The objects with a recorded hash (the six MaliciousSkillBench
archives, `package_manifest.csv`, `primary.parquet`) go through `rule_benchmark.fetch_object` and its cache; the repository
archives of the harmless skills and of the Trail of Bits skills and the GitHub API answers have no recorded hash and are read
into memory only, never cached. It prints counts, ids and reasons only, never a sample's text. `GH_TOKEN`, when set, goes to
api.github.com, codeload.github.com and raw.githubusercontent.com only."""
from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import urllib.parse
import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import NamedTuple

import rule_benchmark as rb

MSB_COMMIT = "893afd609be22a2dfac5a2b94bbebb4eeb99515e"
MSB_PACKAGES = f"https://raw.githubusercontent.com/protectskills/MaliciousSkillBench/{MSB_COMMIT}/packages/"
HF_REVISION = "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
TOB_OWNER, TOB_REPOSITORY = "trailofbits", "overtly-malicious-skills"
TOB_COMMIT = "4ffbf9461ef0505f9ce76a0d3694a18ec33ea531"
TOB_LICENCE = "none"
TOB_SKILLS = 4
GH_TOKEN_HOSTS = ("api.github.com", "codeload.github.com", "raw.githubusercontent.com")
MAX_ARCHIVE_BYTES = 40_000_000
MAX_EXCLUDED_SHARE = 0.05
JUNK = re.compile(r"(^|/)(\.DS_Store|__pycache__/.*|.*\.pyc|\.git/.*|node_modules/.*)$")
_TREE_URL = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/tree/([0-9a-f]{40})/(.*)")
MSB_LICENCE = "Apache-2.0 code, CC BY 4.0 metadata; artifacts keep their upstream terms"
FROZEN_FILES = ("manifest-v1.json", "measure-manifest-v1.json", "manifest-msb-test-v1.json", "measure-manifest-msb-test-v1.json")


class Pinned(NamedTuple):
    url: str
    sha256: str
    size: int
    kind: str
    title: str
    licence: str


SOURCES = {
    "msb-src002": Pinned(MSB_PACKAGES + "SRC002_packages.tar.gz",
                         "bf2532cb0e7fd3a76a2cf1bbb53cff1cd77fe67b3f152f802c084ef196860ed5", 1_637_031, "tar.gz",
                         "MaliciousSkillBench packages, MaliciousAgentSkillsBench (SRC002)", MSB_LICENCE),
    "msb-src004": Pinned(MSB_PACKAGES + "SRC004_packages.tar.gz",
                         "206ab5bde4177475ba1d9da3f711197c38e082329b77aee969f99ecbbc385701", 243_948, "tar.gz",
                         "MaliciousSkillBench packages, SkillLeakBench (SRC004)", MSB_LICENCE),
    "msb-src005": Pinned(MSB_PACKAGES + "SRC005_artifacts.tar.gz",
                         "2ad5fcdacd2f68d73727d4a93e346d081a5bb1ec13a801afbd4d35a2d6d8b473", 50_987, "tar.gz",
                         "MaliciousSkillBench artifacts, Agent Skill Malware (SRC005)", MSB_LICENCE),
    "msb-src009": Pinned(MSB_PACKAGES + "SRC009_packages.tar.gz",
                         "10bf2de3d35b50a3c8888356831d43b4963f61f726cab931aeab33ecd60c882f", 8_819_732, "tar.gz",
                         "MaliciousSkillBench packages, SkillHarm (SRC009)", MSB_LICENCE),
    "msb-src011": Pinned(MSB_PACKAGES + "SRC011_artifacts.tar.gz",
                         "db2da0e76041c73826e604453544bc0c3d3c7ce3c90c6db62e3dddcc23f9468a", 15_499, "tar.gz",
                         "MaliciousSkillBench artifacts, ATR Skill-Security Benchmark (SRC011)", MSB_LICENCE),
    "msb-src012": Pinned(MSB_PACKAGES + "SRC012_artifacts.tar.gz",
                         "b57c3663d9d943802bdb341659ba8e0cd0ffa4befcac407e268f4a8ad9a6398d", 11_832, "tar.gz",
                         "MaliciousSkillBench artifacts, SkillFortifyBench (SRC012)", MSB_LICENCE),
    "msb-primary": Pinned(f"https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench/resolve/{HF_REVISION}/primary.parquet",
                          "1d6382017f259bde0b699d402318f3c03f16b2e8ed2363a346b77a5465f06a06", 28_600_360, "parquet",
                          "MaliciousSkillBench primary table (skill texts)", "CC BY 4.0"),
}
PACKAGE_MANIFEST = Pinned(MSB_PACKAGES + "package_manifest.csv",
                          "0225ebe52782dae384ca6eb622566021c9c6b309867d65a8f1007d516242096a", 4_101_527, "csv",
                          "MaliciousSkillBench package manifest", "CC BY 4.0")
SOURCE_OF_MSB = {"SRC002": "msb-src002", "SRC004": "msb-src004", "SRC005": "msb-src005", "SRC009": "msb-src009",
                 "SRC011": "msb-src011", "SRC012": "msb-src012"}


def _stratum(label: str, title: str) -> dict:
    return {"label": label, "title": title}


SETS = {
    "held-out": {"title": "Held-out half of Spellwarden's labelled set", "role": "test", "strata": {
        "wild-liu": _stratum("malicious", "Public skills a study labelled malicious (Liu et al.)"),
        "wild-skillleak": _stratum("malicious", "Public skills that leak data (SkillLeakBench)"),
        "benign-wild": _stratum("benign", "Public skills listed as safe (Liu et al.)")}},
    "msb-test": {"title": "MaliciousSkillBench test split (source-disjoint)", "role": "test", "strata": {
        "skillharm": _stratum("malicious", "Constructed attacks (SkillHarm)"),
        "skillfortifybench-malicious": _stratum("malicious", "Constructed attacks (SkillFortifyBench)"),
        "atr-malicious": _stratum("malicious", "Curated attacks (ATR)"),
        "atr-benign": _stratum("benign", "Harmless skills (ATR)"),
        "skillfortifybench-benign": _stratum("benign", "Harmless skills (SkillFortifyBench)")}},
    "trailofbits": {"title": "Trail of Bits scanner-bypass skills", "role": "test", "report": rb.PER_ITEM, "strata": {
        "tob": _stratum("malicious", "Scanner-bypass skills (Trail of Bits)")}},
    "tuning": {"title": "Tuning half of Spellwarden's labelled set", "role": "tuning", "strata": {
        "wild-liu": _stratum("malicious", "Public skills a study labelled malicious (Liu et al.)"),
        "wild-skillleak": _stratum("malicious", "Public skills that leak data (SkillLeakBench)"),
        "wild-amos": _stratum("malicious", "A malware campaign (Agent Skill Malware)"),
        "benign-wild": _stratum("benign", "Public skills listed as safe (Liu et al.)")}},
}
MSB_TEST_STRATUM = {("SRC009", "malicious"): "skillharm", ("SRC012", "malicious"): "skillfortifybench-malicious",
                    ("SRC011", "malicious"): "atr-malicious", ("SRC011", "benign"): "atr-benign",
                    ("SRC012", "benign"): "skillfortifybench-benign"}
OWN_STRATA = {"wild-liu", "wild-skillleak", "wild-amos", "benign-wild"}
ATR_STRATA = {"curated-atr", "benign-atr-real", "benign-atr-hard"}  # left out of the held-out half (owner decision spec:Q1)


class BuildError(Exception):
    """The builder stops: nothing is written (exit 2)."""


REASON_MAX = 300


def short_reason(text: str) -> str:
    """An exclusion reason that fits the manifest's string limit (`rb.MAX_STRING`) whatever path it names (review r0:F4)."""
    return text if len(text) <= REASON_MAX else text[:REASON_MAX - 3] + "..."


class Excluded(Exception):
    """The item cannot be rebuilt exactly; it goes to `excluded` with this reason."""


class File(NamedTuple):
    path: str
    data: bytes
    origin: dict


# --- the rebuild rules of 10.2.1 ---------------------------------------------------------------------------------------------

def is_junk(path: str) -> bool:
    return bool(JUNK.search(path))


def clean(files: dict[str, bytes]) -> dict[str, bytes]:
    """`clean`: drop a file whose path the junk pattern matches and a file over 2,000,000 bytes. Nothing else."""
    return {path: data for path, data in files.items() if not is_junk(path) and len(data) <= rb.MAX_FILE_BYTES}


def export_safe(path: str) -> bool:
    """The export's name rule: no leading `/`, no empty, `.` or `..` part, at most 400 bytes in UTF-8, no NUL, no backslash."""
    return rb.valid_path(path)


def _dirname(path: str) -> str:
    return path.rpartition("/")[0]


def _basename(path: str) -> str:
    return path.rpartition("/")[2]


def skill_roots(names: list[str]) -> list[dict[str, str]]:
    """`skill_roots` for MaliciousSkillBench packages, over the cleaned paths in archive order: one `{key: path}` per skill
    root, where `key` is the path in the root and `path` the package path it comes from."""
    directories = {_dirname(path) for path in names if _basename(path) == "SKILL.md"}
    if not directories:
        markdown = [path for path in names if path.lower().endswith(".md")]
        if len(names) == 1 and markdown:
            return [{"SKILL.md": markdown[0]}]
        directories = {_dirname(path) for path in names if _basename(path).lower() == "skill.md"}
        if not directories:
            return []
    roots = []
    for directory in sorted(directories, key=len):
        prefix = f"{directory}/" if directory else ""
        nested = [f"{other}/" for other in directories if other != directory and other.startswith(prefix)]
        root: dict[str, str] = {}
        for path in names:
            if not path.startswith(prefix) or any(path.startswith(inner) for inner in nested):
                continue
            relative = path[len(prefix):]
            root["SKILL.md" if relative.lower() == "skill.md" else relative] = path
        if "SKILL.md" in root:
            roots.append(root)
    return roots


def package_members(members: list[tuple[str, bytes]], base: str) -> dict[str, tuple[str, bytes]]:
    """The regular files of one package in an archive, in archive order: a member named `base` (keyed by its base name) or
    under `base/` (keyed relative to it), never an absolute name or one with a `..` part. Value: (member name, bytes)."""
    files: dict[str, tuple[str, bytes]] = {}
    for name, data in members:
        if name.startswith("/") or ".." in name.split("/"):
            continue
        if name == base:
            files[_basename(base)] = (name, data)
        elif name.startswith(base + "/"):
            files[name[len(base) + 1:]] = (name, data)
    return files


def msb_roots(members: list[tuple[str, bytes]], base: str, source_id: str) -> list[list[File]]:
    """The skill roots of one MaliciousSkillBench package, after `clean`, `skill_roots` and the export's name rule."""
    found = package_members(members, base)
    kept = clean({key: data for key, (_name, data) in found.items()})
    names = [key for key in found if key in kept]
    roots = []
    for root in skill_roots(names):
        files = [File(key, kept[path], {"source": source_id, "member": found[path][0]})
                 for key, path in root.items() if export_safe(key)]
        roots.append(files)
    return roots


def match_frozen(roots: list[list[File]], frozen: list[str]) -> list[list[File]]:
    """The rebuilt roots in the frozen order, matched by engine hash: both must be the same hashes, each once."""
    by_hash: dict[str, list[File]] = {}
    for files in roots:
        value = rb.sample_hash({entry.path: entry.data for entry in files})
        if value in by_hash:
            raise Excluded("two rebuilt roots have the same package hash")
        by_hash[value] = files
    if sorted(by_hash) != sorted(frozen) or len(set(frozen)) != len(frozen):
        raise Excluded(f"rebuilt {len(roots)} roots whose package hashes are not the frozen ones")
    return [by_hash[value] for value in frozen]


# --- reading archives ----------------------------------------------------------------------------------------------------------

def tar_members(data: bytes) -> list[tuple[str, bytes]]:
    """The regular files of a tar.gz object, in archive order, read in memory."""
    found = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for info in archive:
            if info.isreg():
                handle = archive.extractfile(info)
                found.append((info.name, handle.read() if handle is not None else b""))
    return found


def zip_files(data: bytes) -> tuple[str, list[tuple[str, int, zipfile.ZipInfo]], zipfile.ZipFile]:
    """The top folder of a codeload archive and its regular files (no directories, no links) as (name, size, info)."""
    archive = zipfile.ZipFile(io.BytesIO(data))
    infos = [info for info in archive.infolist()
             if not info.is_dir() and (info.external_attr >> 16) & 0o170000 != 0o120000]
    tops = {info.filename.split("/", 1)[0] for info in archive.infolist()}
    if len(tops) != 1:
        raise Excluded("the repository archive does not have one top folder")
    return tops.pop(), [(info.filename, info.file_size, info) for info in infos], archive


def raw_url(owner: str, repository: str, commit: str, path: str) -> str:
    quoted = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
    return f"https://raw.githubusercontent.com/{owner}/{repository}/{commit}/{quoted}"


# --- the builder -------------------------------------------------------------------------------------------------------------

class Context(NamedTuple):
    cache: rb.Cache
    opener: rb.Opener
    token: str | None
    say: Callable[[str], None]


def _pinned(context: Context, pinned: Pinned) -> bytes:
    return rb.fetch_object(pinned.url, pinned.sha256, pinned.size, context.cache, opener=context.opener)


def _unpinned(context: Context, url: str, limit: int) -> bytes:
    data = rb.download(url, limit, opener=context.opener, token=context.token, token_hosts=GH_TOKEN_HOSTS)
    if len(data) > limit:
        raise Excluded(f"an object of this source is larger than {limit} bytes")
    return data


def _check_raw(context: Context, files: list[File]) -> None:
    for entry in files:
        try:
            data = _unpinned(context, entry.origin["url"], len(entry.data))
        except rb.FetchFailed as exc:
            # The status, not the message: the message holds the whole URL, and a reason must stay short (review r0:F4).
            raise Excluded(f"the raw file {entry.path} could not be fetched (HTTP {exc.status or 'error'})") from None
        if data != entry.data:
            raise Excluded(f"the raw file {entry.path} differs from the archive's")


def licence_of(context: Context, owner: str, repository: str) -> str:
    """The SPDX id GitHub reports for the repository, `NOASSERTION`, or `none` when it reports no licence (HTTP 404)."""
    url = f"https://api.github.com/repos/{owner}/{repository}/license"
    try:
        answer = json.loads(_unpinned(context, url, 1_000_000))
    except rb.FetchFailed as exc:
        if exc.status == 404:
            return "none"
        raise BuildError(f"the GitHub API did not answer for {owner}/{repository} ({exc}); set GH_TOKEN and run again") from None
    except ValueError:
        raise BuildError(f"the GitHub API answer for {owner}/{repository} is not JSON") from None
    spdx = (answer.get("license") or {}).get("spdx_id") if isinstance(answer, dict) else None
    return spdx if isinstance(spdx, str) and spdx else "NOASSERTION"


def harmless_root(context: Context, source_path: str, frozen: str) -> tuple[list[File], str]:
    """One harmless public skill: the files under its directory at the pinned commit, as collected, checked against the frozen
    hash and against raw.githubusercontent.com. Returns the files and the repository's licence."""
    match = _TREE_URL.fullmatch(source_path)
    if match is None:
        raise Excluded("the source path is not a GitHub tree URL at a 40-hex commit")
    owner, repository, commit, directory = match.groups()
    directory = directory.strip("/")
    try:
        data = _unpinned(context, f"https://codeload.github.com/{owner}/{repository}/zip/{commit}", MAX_ARCHIVE_BYTES)
    except rb.FetchFailed as exc:
        raise Excluded(f"the repository archive could not be fetched (HTTP {exc.status or 'error'})") from None
    try:
        top, infos, archive = zip_files(data)
    except zipfile.BadZipFile:
        raise Excluded("the repository archive is not a zip file") from None
    chosen = f"{top}/{directory}" if directory else top
    base = chosen + "/"
    skill_dirs = {_dirname(name) for name, _size, _info in infos if _basename(name) == "SKILL.md"}
    nested = [f"{other}/" for other in skill_dirs if other != chosen and other.startswith(base)]
    members: list[tuple[str, int, zipfile.ZipInfo]] = []
    for name, size, info in infos:
        if not name.startswith(base) or any(name.startswith(inner) for inner in nested):
            continue
        relative = name[len(base):]
        # What the collection left out (an unsafe name, a file over 2,000,000 bytes, the `clean` names) is left out before the
        # bound below, so the bound is the manifest's own (10.1.1): no skill is excluded for files that are not part of it.
        if relative.startswith("/") or ".." in relative.split("/") or size > rb.MAX_FILE_BYTES or is_junk(relative):
            continue
        members.append((relative, size, info))
    if len(members) > rb.MAX_FILES or sum(size for _relative, size, _info in members) > rb.MAX_ROOT_BYTES:
        raise Excluded("the skill holds more than 300 files or 5,000,000 bytes")
    files = clean({relative: archive.read(info) for relative, _size, info in members})
    if "SKILL.md" not in files:
        raise Excluded("the skill directory holds no SKILL.md")
    kept = [File(path, content, {"url": raw_url(owner, repository, commit, f"{directory}/{path}" if directory else path)})
            for path, content in sorted(files.items()) if export_safe(path)]
    match_frozen([kept], [frozen])
    _check_raw(context, kept)
    return kept, licence_of(context, owner, repository)


def tob_items(context: Context) -> list[tuple[str, list[File]]]:
    """The Trail of Bits skills: each `skills/<name>/` directory of the pinned archive is one item of one root holding every
    regular file under it as published (no `clean`, no `skill_roots`; the export's name rule only)."""
    url = f"https://codeload.github.com/{TOB_OWNER}/{TOB_REPOSITORY}/zip/{TOB_COMMIT}"
    try:
        data = _unpinned(context, url, MAX_ARCHIVE_BYTES)
        top, infos, archive = zip_files(data)
    except (rb.FetchFailed, Excluded, zipfile.BadZipFile) as exc:
        raise BuildError(f"the Trail of Bits archive cannot be read: {exc}") from None
    prefix = f"{top}/skills/"
    by_skill: dict[str, list[File]] = {}
    for name, _size, info in infos:
        if not name.startswith(prefix) or "/" not in name[len(prefix):]:
            continue
        skill, relative = name[len(prefix):].split("/", 1)
        if export_safe(relative):
            url = raw_url(TOB_OWNER, TOB_REPOSITORY, TOB_COMMIT, f"skills/{skill}/{relative}")
            by_skill.setdefault(skill, []).append(File(relative, archive.read(info), {"url": url}))
    items = []
    for skill, files in sorted(by_skill.items()):
        try:
            _check_raw(context, files)
        except Excluded as exc:
            raise BuildError(f"Trail of Bits skill {skill}: {exc}") from None
        items.append((f"m-tob-{skill}", sorted(files, key=lambda entry: entry.path)))
    return items


def _record(item_id: str, set_id: str, stratum: str, ref: str, roots: list[tuple[str, list[File]]],
            licence: str | None = None) -> dict:
    record: dict = {"id": item_id, "set": set_id, "stratum": stratum, "ref": ref,
                    "roots": [{"package_sha256": value,
                               "files": [{"path": entry.path, "sha256": hashlib.sha256(entry.data).hexdigest(),
                                          "bytes": len(entry.data), "from": entry.origin}
                                         for entry in sorted(files, key=lambda entry: entry.path)]}
                              for value, files in roots]}
    if licence is not None:
        record["licence"] = licence
    return record


def frozen_hashes(samples: list[dict]) -> dict[str, list[str]]:
    """Item id to its frozen engine hashes in frozen order: `<id>` for one root, `<id>.r1`, `<id>.r2`, ... for several."""
    single = {sample["id"]: [sample["package_sha256"]] for sample in samples if "unit" not in sample}
    several: dict[str, list[tuple[int, str]]] = {}
    for sample in samples:
        if "unit" in sample:
            number = int(sample["id"].rsplit(".r", 1)[1])
            several.setdefault(sample["unit"], []).append((number, sample["package_sha256"]))
    return {**single, **{unit: [value for _number, value in sorted(pairs)] for unit, pairs in several.items()}}


def _read_frozen(run_dir: Path) -> dict[str, dict]:
    found = {}
    for name in FROZEN_FILES:
        try:
            found[name] = json.loads((run_dir / name).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise BuildError(f"{name} cannot be read in --run-dir: {type(exc).__name__}") from None
    return found


def build(run_dir: Path, *, cache: rb.Cache, opener: rb.Opener, token: str | None, date: str,
          say: Callable[[str], None] = print) -> dict:
    """The manifest document, checked by `rule_benchmark.check_manifest`; raises `BuildError` when the builder must stop."""
    context = Context(cache, opener, token, say)
    frozen = _read_frozen(run_dir)
    own_hashes = frozen_hashes(frozen["measure-manifest-v1.json"]["samples"])
    test_hashes = frozen_hashes(frozen["measure-manifest-msb-test-v1.json"]["samples"])
    try:
        package_rows = list(csv.DictReader(io.StringIO(_pinned(context, PACKAGE_MANIFEST).decode("utf-8"))))
        members = {source_id: tar_members(_pinned(context, SOURCES[source_id]))
                   for source_id in SOURCE_OF_MSB.values()}
        primary = _pinned(context, SOURCES["msb-primary"])
    except rb.FetchFailed as exc:
        raise BuildError(str(exc)) from None
    packages = {row["benchmark_id"]: row for row in package_rows}
    import pyarrow.parquet as parquet

    table = parquet.read_table(io.BytesIO(primary), columns=["benchmark_id", "skill_text", "text_available"])
    rows: dict[str, list[tuple[object, object]]] = {}
    for key, text, available in zip(table.column("benchmark_id").to_pylist(), table.column("skill_text").to_pylist(),
                                    table.column("text_available").to_pylist(), strict=True):
        rows.setdefault(str(key), []).append((text, available))

    planned: list[tuple[str, str, str, Callable[[], dict]]] = []

    def msb_package(entry: dict, set_id: str, stratum: str, hashes: list[str]) -> dict:
        package = packages.get(entry["source_ref"])
        if package is None or package["source_id"] != entry["source"]:
            raise Excluded("the package manifest has no such package for this source")
        source_id = SOURCE_OF_MSB[entry["source"]]
        roots = match_frozen(msb_roots(members[source_id], package["package_relative_path"], source_id), hashes)
        return _record(entry["id"], set_id, stratum, entry["source_ref"], list(zip(hashes, roots, strict=True)))

    def msb_text(entry: dict, set_id: str, stratum: str, hashes: list[str]) -> dict:
        found = rows.get(entry["source_ref"], [])
        if len(found) != 1 or found[0][1] is not True or not isinstance(found[0][0], str):
            raise Excluded("the primary table does not hold the row once with its text")
        files = [File("SKILL.md", found[0][0].encode("utf-8"), {"source": "msb-primary", "row": entry["source_ref"]})]
        match_frozen([files], hashes)
        return _record(entry["id"], set_id, stratum, entry["source_ref"], [(hashes[0], files)])

    for entry in frozen["manifest-msb-test-v1.json"]["entries"]:
        stratum = MSB_TEST_STRATUM[(entry["source"], entry["label"])]
        build_one = msb_package if entry["content"] == "package" else msb_text
        planned.append((entry["id"], "msb-test", stratum,
                        lambda entry=entry, stratum=stratum, build_one=build_one: build_one(
                            entry, "msb-test", stratum, test_hashes.get(entry["id"], []))))
    for entry in frozen["manifest-v1.json"]["entries"]:
        if entry["stratum"] in ATR_STRATA:
            continue
        if entry["stratum"] not in OWN_STRATA:
            raise BuildError(f"item {entry['id']}: the frozen stratum {entry['stratum']} is not one the spec names")
        set_id = entry["half"]
        hashes = own_hashes.get(entry["id"], [])
        if entry["stratum"] == "benign-wild":
            def harmless(entry=entry, set_id=set_id, hashes=hashes) -> dict:
                if len(hashes) != 1:
                    raise Excluded("the frozen measurement manifest has no single hash for this skill")
                files, licence = harmless_root(context, entry["source_path"], hashes[0])
                return _record(entry["id"], set_id, "benign-wild", entry["source_ref"], [(hashes[0], files)], licence)
            planned.append((entry["id"], set_id, "benign-wild", harmless))
        else:
            planned.append((entry["id"], set_id, entry["stratum"],
                            lambda entry=entry, set_id=set_id, hashes=hashes: msb_package(entry, set_id, entry["stratum"],
                                                                                         hashes)))

    sources = {source_id: {"url": pinned.url, "sha256": pinned.sha256, "bytes": pinned.size, "kind": pinned.kind,
                           "title": pinned.title, "licence": pinned.licence} for source_id, pinned in SOURCES.items()}
    checked_sources = {source_id: dict(value) for source_id, value in sources.items()}
    items: list[dict] = []
    excluded: list[dict] = []
    for item_id, set_id, stratum, make in planned:
        try:
            record = make()
            rb.check_item(record, checked_sources, SETS)
        except Excluded as exc:
            excluded.append({"id": item_id, "set": set_id, "stratum": stratum, "reason": short_reason(str(exc)), "date": date})
            say(f"excluded {item_id} ({set_id}, {stratum}): {exc}")
            continue
        except rb.ManifestError as exc:
            excluded.append({"id": item_id, "set": set_id, "stratum": stratum,
                             "reason": f"the record breaks a manifest rule: {exc}", "date": date})
            say(f"excluded {item_id} ({set_id}, {stratum}): the record breaks a manifest rule")
            continue
        items.append(record)
    for item_id, files in tob_items(context):
        value = rb.sample_hash({entry.path: entry.data for entry in files})
        record = _record(item_id, "trailofbits", "tob", f"{TOB_OWNER}/{TOB_REPOSITORY}:skills/{item_id[len('m-tob-'):]}",
                         [(value, files)], TOB_LICENCE)
        try:
            rb.check_item(record, checked_sources, SETS)
        except rb.ManifestError as exc:
            raise BuildError(f"Trail of Bits item {item_id} breaks a manifest rule: {exc}") from None
        items.append(record)

    totals: dict[tuple[str, str], list[int]] = {}
    for record in items:
        totals.setdefault((record["set"], record["stratum"]), [0, 0])[0] += 1
    for record in excluded:
        totals.setdefault((record["set"], record["stratum"]), [0, 0])[1] += 1
    for (set_id, stratum), (written, left_out) in sorted(totals.items()):
        say(f"{set_id} / {stratum}: {written} written, {left_out} excluded")
        if left_out > MAX_EXCLUDED_SHARE * (written + left_out):
            raise BuildError(f"{set_id} / {stratum}: {left_out} of {written + left_out} items excluded, more than 5%; the owner "
                             "decides")
    if totals.get(("trailofbits", "tob"), [0, 0])[0] != TOB_SKILLS:
        raise BuildError(f"the Trail of Bits set must hold its {TOB_SKILLS} skills")
    used = {entry["from"]["source"] for record in items for root in record["roots"] for entry in root["files"]
            if "source" in entry["from"]}
    document = {"manifest": 1, "name": "spellwarden-rule-benchmark", "built": date,
                "sources": {source_id: value for source_id, value in sorted(sources.items()) if source_id in used},
                "sets": {set_id: SETS[set_id] for set_id in sorted(SETS)},
                "items": sorted(items, key=lambda record: record["id"]),
                "excluded": sorted(excluded, key=lambda record: (record["set"], record["stratum"], record["id"]))}
    try:
        rb.check_manifest(document)
    except rb.ManifestError as exc:
        raise BuildError(f"the manifest breaks a rule of 10.1.1: {exc}") from None
    return document


def manifest_text(document: dict) -> str:
    """The manifest as committed: UTF-8 JSON, `indent=1`, sorted keys, LF line endings."""
    return json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None, environ: Mapping[str, str] | None = None,
         opener: rb.Opener = rb.urllib_opener) -> int:
    environ = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(prog="build_manifest.py", description="Build benchmarks/manifest.json once.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=None)
    parser.add_argument("--date", default=datetime.date.today().isoformat())
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
            raise BuildError("--date must be YYYY-MM-DD")
        cache = rb.Cache(rb.cache_directory(args.cache, environ, windows=os.name == "nt"))
        document = build(args.run_dir, cache=cache, opener=opener, token=environ.get("GH_TOKEN") or None, date=args.date)
    except (BuildError, rb.BenchmarkError) as exc:
        print(f"build_manifest: {exc}", file=sys.stderr)
        return 2
    args.out.write_bytes(manifest_text(document).encode("utf-8"))
    print(f"wrote {args.out}: {len(document['items'])} items, {len(document['excluded'])} excluded, "
          f"sha256 {rb.manifest_sha256(document)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
