"""Records what the released 1.20.0 writes, so 1.21.0 can be held to it (P6-15 fix guidance spec 6.12 E-7, 6.14). Run it from the
repository root of a clone that holds the tag v1.20.0 (`git fetch --tags` if it does not):

    uv run --locked python tests/golden/record_release_1_20_0.py

It takes `src/` of the tag with `git archive` (the source the PyPI release was built from) and, for each root of
`record_1_17_0.scan_roots()` (this release's fixture trees), copies the fixture into a fresh git repository and runs that source in
a subprocess, once, in the seven formats. It writes tests/golden/1.20.0/outputs.json: per root the exit code and the SHA-256 of
each report (`fixture_reports.as_version`, which leaves out a CycloneDX document's `serialNumber`). tests/test_golden_1_20_0.py
compares this tree's reports with these digests once `golden_fix.before_fix_guidance` has taken out what 1.21.0 adds."""
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GOLDEN = HERE / "1.20.0"
RELEASE_TAG = "v1.20.0"
RECORDED_VERSION = "1.20.0"
# Fixture roots added after 1.20.0: not in the record. None so far: fixtures/fix-guidance (1.21.0) is not a root of
# `record_1_17_0.ROOT_GLOBS`, so these digests cover the same roots as the tree's.
ADDED_AFTER_1_20_0: tuple[str, ...] = ()


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


previous = _module("record_1_17_0", HERE / "record_1_17_0.py")
release_1_18_0 = _module("record_release_1_18_0", HERE / "record_release_1_18_0.py")
reports = previous.reports
scan_roots = previous.scan_roots
digest = previous.digest


def record(ref: str = RELEASE_TAG) -> None:
    roots: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = previous.extract_release(ref, base / "release")
        version = previous.released_version(source)
        if version != RECORDED_VERSION:
            raise SystemExit(f"{ref} holds scanner {version}, not {RECORDED_VERSION}")
        for index, root in enumerate(scan_roots()):
            if root in ADDED_AFTER_1_20_0:
                continue
            work = base / str(index)
            code, outputs = release_1_18_0.render_released(source, reports.build_repo(root, work / "repo"), work / "out")
            roots[root] = {"exit_code": code, "outputs": {
                fmt: digest(reports.as_version(fmt, data, RECORDED_VERSION, RECORDED_VERSION)) for fmt, data in outputs.items()}}
    GOLDEN.mkdir(exist_ok=True)
    document = {"as_of": reports.AS_OF, "release_tag": ref, "scanner_version": RECORDED_VERSION, "roots": roots}
    (GOLDEN / "outputs.json").write_bytes((json.dumps(document, indent=1, sort_keys=True) + "\n").encode("utf-8"))


if __name__ == "__main__":
    record()
