"""Records the reports the released 1.17.0 writes for every fixture root, so 1.18.0 can be held to them byte for byte: without a
preset, or with `balanced`, a scan of 1.18.0 writes what 1.17.0 wrote, apart from the scanner's own version string. Run it from
the repository root of a clone that holds the tag v1.17.0 (`git fetch --tags` if it does not):

    uv run --locked python tests/golden/record_1_17_0.py

It takes `src/` of the tag with `git archive` (the source the PyPI release was built from), and for each root of `scan_roots()`
copies the fixture into a fresh git repository and runs that source in a subprocess, once, in the six formats 1.17.0 has. It
writes tests/golden/1.17.0/outputs.json: per root the exit code and the SHA-256 of each report, the CycloneDX document without
its `serialNumber` (`fixture_reports.as_version`). tests/test_golden_1_17_0.py compares 1.18.0's reports with these digests;
tests/cli/test_no_preset_unchanged.py imports `scan_roots`."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

GOLDEN = Path(__file__).resolve().parent / "1.17.0"
RELEASE_TAG = "v1.17.0"
RECORDED_VERSION = "1.17.0"
# Every directory the tests treat as a repository: the rule fixtures, the end-to-end repositories, the fixture homes and the A2A
# cards read as repositories, the fixtures 1.18.0 adds, and the golden repositories. A pattern that matches nothing adds nothing.
ROOT_GLOBS = ("fixtures/skills/*/positive", "fixtures/skills/*/negative", "fixtures/config/*/positive",
              "fixtures/config/*/negative", "fixtures/config/plugins-settings", "fixtures/orgrules/skills/*",
              "fixtures/repos/*/repo", "fixtures/html-escape", "fixtures/presets", "tests/fixtures/a2a",
              "tests/fixtures/homes/*", "tests/golden/1.0.0/repo", "tests/golden/1.13.0/repo")
ADDED_AFTER_1_17_0 = ("fixtures/html-escape", "fixtures/presets")  # fixtures 1.18.0 adds: not in the record


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reports = _module("fixture_reports", Path(__file__).resolve().parent / "fixture_reports.py")


def scan_roots() -> list[str]:
    """The fixture roots, repository-relative POSIX paths, sorted."""
    return sorted({path.relative_to(reports.ROOT).as_posix() for pattern in ROOT_GLOBS for path in reports.ROOT.glob(pattern)
                   if path.is_dir()})


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_release(ref: str, dest: Path) -> Path:
    """`src/` of `ref`, taken from this clone with `git archive`, under `dest`; returns `dest/src`."""
    done = subprocess.run(["git", "-C", str(reports.ROOT), "archive", "--format=tar", ref, "src"], capture_output=True,
                          check=False, env=reports.clean_environment())
    if done.returncode != 0:
        raise SystemExit(f"cannot read {ref} from this clone ({done.stderr.decode(errors='replace').strip()}); "
                         "fetch the tags first: git fetch --tags")
    with tarfile.open(fileobj=io.BytesIO(done.stdout)) as archive:
        archive.extractall(dest, filter="data")
    return dest / "src"


def _released_env(source: Path) -> dict[str, str]:
    return {**reports.clean_environment(), "PYTHONPATH": str(source)}


def released_version(source: Path) -> str:
    done = subprocess.run([sys.executable, "-c", "import spellwarden_scan; print(spellwarden_scan.__version__)"],
                          capture_output=True, text=True, check=True, env=_released_env(source), cwd=source)
    return done.stdout.strip()


def render_released(source: Path, repo: Path, out: Path) -> tuple[int, dict[str, bytes]]:
    """`spellwarden scan` of `repo` by the released source, in a subprocess, in the six formats: the exit code and the bytes."""
    out.mkdir(parents=True, exist_ok=True)
    argv = reports.scan_argv(repo, out, reports.SIX_FORMATS)
    done = subprocess.run([sys.executable, "-m", "spellwarden_cli", *argv], capture_output=True, check=False,
                          env=_released_env(source), cwd=out)
    return done.returncode, {fmt: (out / name).read_bytes() for fmt, name in reports.SIX_FORMATS}


def record(ref: str = RELEASE_TAG) -> None:
    roots: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        source = extract_release(ref, base / "release")
        version = released_version(source)
        if version != RECORDED_VERSION:
            raise SystemExit(f"{ref} holds scanner {version}, not {RECORDED_VERSION}")
        for index, root in enumerate(scan_roots()):
            if root in ADDED_AFTER_1_17_0:
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
