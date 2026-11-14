"""Records the CycloneDX documents of 1.14.0 (phase 3 batch 2a spec 11.5, T-8): the repository scan of tests/golden/1.13.0/repo.
Run it from the repository root after a change to the mapping, and review the diff:

    uv run --locked python tests/golden/record_1_14_0.py

tests/cli/test_cyclonedx_output.py imports `repository_document` from here."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

GOLDEN = Path(__file__).resolve().parent / "1.14.0"
ROOT = GOLDEN.parents[2]
AS_OF = "2026-11-14"


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def repository_document(base: Path) -> str:
    """The `--format cyclonedx` document of a committed copy of the 1.13.0 golden repository, at `base/repo`."""
    from spellwarden_cli.main import main

    record = _module("record_1_13_0", ROOT / "tests" / "golden" / "record_1_13_0.py")
    out = base / "repo.cdx.json"
    main(["scan", str(record.build_repo(base / "repo")), "--as-of", AS_OF, "--no-telemetry", "--quiet", "--format", "cyclonedx",
          "--output", str(out)])
    return out.read_bytes().decode("utf-8")


def record() -> None:
    GOLDEN.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        (GOLDEN / "repo.cdx.json").write_bytes(repository_document(Path(tmp) / "repository").encode("utf-8"))
    print(f"recorded the repository's CycloneDX document under {GOLDEN.relative_to(ROOT)}")


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "src"))
    record()
