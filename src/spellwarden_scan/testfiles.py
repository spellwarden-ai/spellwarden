"""Which files are tests or fixtures (scan feedback fixes spec 4): a rule on the path alone, relative to the scan root, and
conservative (when in doubt a file is not classified, so its finding stays where it is most visible).

Presentation only in 1.27.0: no rule, severity, status or exit code reads `in_tests_or_fixtures`; SW-CFG-013 shares
`TEST_DIRECTORIES` through `under_test_directory`. The function's name does not start with "test", so pytest never collects it
from a test module that imports it, and the module's name matches neither `test_*.py` nor `*_test.py`."""
from __future__ import annotations

from fnmatch import fnmatchcase

# Directory segments, compared after str.lower(): pytest, unittest, Maven, Gradle (`src/test/`), Cargo, PHPUnit and Node test
# folders, SwiftPM's `Tests/`, Jest's `__tests__`, pytest, Rails and Jest fixture folders, and the Go command's `testdata`.
TEST_DIRECTORIES = frozenset({"test", "tests", "__tests__", "fixtures", "__fixtures__", "testdata", "test-data"})

_SCRIPT_KINDS = ("js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts")

# File names, matched case-sensitively as the test runners match them: pytest's `python_files` and its `conftest.py`, the Go
# command, Jest's `testMatch` and Vitest's `include`, RSpec's pattern.
TEST_FILE_PATTERNS: tuple[str, ...] = (
    "test_*.py", "*_test.py", "conftest.py", "*_test.go",
    *(f"*.test.{kind}" for kind in _SCRIPT_KINDS), *(f"*.spec.{kind}" for kind in _SCRIPT_KINDS),
    "*_spec.rb",
)


def under_test_directory(path: str) -> bool:
    """Whether a directory segment of `path` (every segment but the last), after `str.lower()`, is one of `TEST_DIRECTORIES`.
    Backslashes count as separators."""
    return any(part.lower() in TEST_DIRECTORIES for part in path.replace("\\", "/").split("/")[:-1])


def in_tests_or_fixtures(path: str, root: str = "") -> bool:
    """Whether `path` is a test or fixture file: a directory segment of its part under the scan root `root` is a test or fixture
    directory, or its file name matches one of `TEST_FILE_PATTERNS`. The root itself is never the reason; a path that is not under
    the root is judged as given. The prefix comparison is exact (archive and git paths are case-sensitive)."""
    relative = path.replace("\\", "/")
    prefix = root.replace("\\", "/").strip("/")
    if prefix and relative.startswith(prefix + "/"):
        relative = relative[len(prefix) + 1:]
    name = relative.rsplit("/", 1)[-1]
    return under_test_directory(relative) or any(fnmatchcase(name, pattern) for pattern in TEST_FILE_PATTERNS)
