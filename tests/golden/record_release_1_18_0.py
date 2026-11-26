"""Records the reports the released 1.18.0 writes for every fixture root, in the seven formats it has, so 1.19.0 can be held to
them byte for byte: a scan without `--staged` writes what 1.18.0 wrote, apart from the scanner's own version string. Run it from
the repository root of a clone that holds the tag v1.18.0 (`git fetch --tags` if it does not):

    uv run --locked python tests/golden/record_release_1_18_0.py

It takes `src/` of the tag with `git archive` (the source the PyPI release was built from) and, for each root of
`record_1_17_0.scan_roots()`, copies the fixture into a fresh git repository and runs that source in a subprocess, once, in the
seven formats. It writes tests/golden/1.18.0/outputs.json: per root the exit code and the SHA-256 of each report, the CycloneDX
document without its `serialNumber` (`fixture_reports.as_version`). tests/test_golden_1_18_0.py compares the tree's reports with
these digests."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GOLDEN = HERE / "1.18.0"
RELEASE_TAG = "v1.18.0"
RECORDED_VERSION = "1.18.0"
# Fixture roots added after 1.18.0: not in the record. 1.20.0 adds `fixtures/selection` (Engine 1.20.0: scan selection, D33).
# 1.25.0 adds the fixtures of SW-CFG-015.
ADDED_AFTER_1_18_0: tuple[str, ...] = ("fixtures/selection", "fixtures/repos/follow-links/repo", "fixtures/config/SW-CFG-015/positive",
                                       "fixtures/config/SW-CFG-015/negative")


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


previous = _module("record_1_17_0", HERE / "record_1_17_0.py")
reports = previous.reports
scan_roots = previous.scan_roots
digest = previous.digest


def _released_env(source: Path) -> dict[str, str]:
    return {**reports.clean_environment(), "PYTHONPATH": str(source)}


def render_released(source: Path, repo: Path, out: Path) -> tuple[int, dict[str, bytes]]:
    """`spellwarden scan` of `repo` by the released source, in a subprocess, in the seven formats: the exit code and the bytes."""
    out.mkdir(parents=True, exist_ok=True)
    argv = reports.scan_argv(repo, out, reports.ALL_FORMATS)
    done = subprocess.run([sys.executable, "-m", "spellwarden_cli", *argv], capture_output=True, check=False,
                          env=_released_env(source), cwd=out)
    return done.returncode, {fmt: (out / name).read_bytes() for fmt, name in reports.ALL_FORMATS}


def record(ref: str = RELEASE_TAG) -> None:
    roots: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = previous.extract_release(ref, base / "release")
        version = previous.released_version(source)
        if version != RECORDED_VERSION:
            raise SystemExit(f"{ref} holds scanner {version}, not {RECORDED_VERSION}")
        for index, root in enumerate(scan_roots()):
            if root in ADDED_AFTER_1_18_0:
                continue
            work = base / str(index)
            code, outputs = render_released(source, reports.build_repo(root, work / "repo"), work / "out")
            roots[root] = {"exit_code": code, "outputs": {
                fmt: digest(reports.as_version(fmt, data, RECORDED_VERSION, RECORDED_VERSION)) for fmt, data in outputs.items()}}
    GOLDEN.mkdir(exist_ok=True)
    document = {"as_of": reports.AS_OF, "release_tag": ref, "scanner_version": RECORDED_VERSION, "roots": roots}
    (GOLDEN / "outputs.json").write_bytes((json.dumps(document, indent=1, sort_keys=True) + "\n").encode("utf-8"))


if __name__ == "__main__":
    record()
