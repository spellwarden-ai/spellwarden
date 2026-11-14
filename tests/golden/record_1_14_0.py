"""Records the CycloneDX documents of 1.14.0 (phase 3 batch 2a spec 11.5, T-8): the repository scan of tests/golden/1.13.0/repo
and the `--user` scan of each fixture home (and an `--inventory` of the Linux one). Run it from the repository root after a
change to the mapping, and review the diff:

    uv run --locked python tests/golden/record_1_14_0.py

tests/cli/test_cyclonedx_output.py imports `repository_document` and `home_document` from here."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
from datetime import date
from pathlib import Path

GOLDEN = Path(__file__).resolve().parent / "1.14.0"
ROOT = GOLDEN.parents[2]
AS_OF = "2026-11-14"
HOME_DOCUMENTS = (("linux", False), ("macos", False), ("windows", False), ("linux", True))
PLATFORMS = {"linux": "linux", "macos": "darwin", "windows": "win32"}


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


def home_document(base: Path, system: str, inventory: bool) -> str:
    """The CycloneDX document of a `--user` scan of the system's fixture home, read as on that system."""
    from spellwarden_cli.output import cyclonedx
    from spellwarden_cli.settings import Settings
    from spellwarden_cli import userscan

    homes = _module("homes", ROOT / "tests" / "cli" / "homes.py")
    home = homes.make_home(base, system)
    report, _ = userscan.scan(str(home), PLATFORMS[system], {}, settings=Settings(telemetry=False),
                              as_of=date.fromisoformat(AS_OF), inventory=inventory)
    return cyclonedx.render(report)


def home_name(system: str, inventory: bool) -> str:
    return f"home-{system}{'-inventory' if inventory else ''}.cdx.json"


def record() -> None:
    GOLDEN.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        (GOLDEN / "repo.cdx.json").write_bytes(repository_document(Path(tmp) / "repository").encode("utf-8"))
        for system, inventory in HOME_DOCUMENTS:
            base = Path(tmp) / home_name(system, inventory)
            base.mkdir()
            (GOLDEN / home_name(system, inventory)).write_bytes(home_document(base, system, inventory).encode("utf-8"))
    print(f"recorded {1 + len(HOME_DOCUMENTS)} CycloneDX documents under {GOLDEN.relative_to(ROOT)}")


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "src"))
    record()
