"""Scan feedback fixes spec 4 (claims A1, A2, A3): the test-and-fixture path classifier. A rule on the path alone, relative to the
scan root, conservative; presentation only in 1.27.0. SW-CFG-013 shares its directory list."""
from __future__ import annotations

import pytest

import spellwarden_scan
from spellwarden_scan import in_tests_or_fixtures
from spellwarden_scan.rules import growth_cfg_013
from spellwarden_scan.testfiles import TEST_DIRECTORIES, TEST_FILE_PATTERNS, under_test_directory

INSIDE = [
    ("tests/a.py", ""), ("test/a.sh", ""), ("Tests/FooTests.swift", ""), ("src/test/java/FooTest.java", ""),
    ("pkg/__tests__/a.js", ""), ("a/fixtures/b.json", ""), ("__fixtures__/x", ""), ("testdata/in.txt", ""), ("test-data/x", ""),
    ("test_setup.py", ""), ("pkg/setup_test.py", ""), ("conftest.py", ""), ("cmd/x_test.go", ""), ("app.test.ts", ""),
    ("app.spec.tsx", ""), ("lib/x.test.mjs", ""), ("spec/models/user_spec.rb", ""), ("a\\tests\\b.py", ""),
    ("skills/a/tests/x.py", "skills/a"),
]
OUTSIDE = [
    ("docs/specs/x.md", ""), ("spec/spec_helper.rb", ""), ("api/spec/openapi.yaml", ""), (".github/workflows/test.yml", ""),
    ("tests", ""), ("test.py", ""), ("tests.py", ""), ("pkg/contest.py", ""), ("Test_setup.py", ""), ("APP.TEST.TS", ""),
    ("e2e/login.ts", ""), ("__mocks__/fs.js", ""), ("examples/x.sh", ""), ("benchmarks/x.py", ""), ("src/a.py", ""),
    ("tests/fixtures/s/SKILL.md", "tests/fixtures/s"), ("README.md", ""),
    ("/repo/tests/fixtures/s/SKILL.md", "/repo/tests/fixtures/s"), ("./tests/fixtures/s/SKILL.md", "tests/fixtures/s"),
    ("tests\\fixtures\\s\\SKILL.md", "./tests/fixtures/s/"),
]


@pytest.mark.parametrize(("path", "root"), INSIDE)
def test_a1_a_test_or_fixture_file_is_classified(path, root):
    assert in_tests_or_fixtures(path, root) is True


@pytest.mark.parametrize(("path", "root"), OUTSIDE)
def test_a1_any_other_file_is_not(path, root):
    assert in_tests_or_fixtures(path, root) is False


def test_a1_the_root_is_compared_without_its_slashes_and_a_path_outside_it_is_judged_as_given():
    assert in_tests_or_fixtures("skills/a/tests/x.py", "/skills/a/") is True
    assert in_tests_or_fixtures("tests/x.py", "skills/a") is True
    assert in_tests_or_fixtures("skills/a/x.py", "skills/a") is False
    assert in_tests_or_fixtures("Skills/A/x.py", "skills/a") is False       # an exact prefix only: no case folding of the root


def test_a2_the_definition_is_the_spec_s_and_the_name_is_exported_without_a_test_prefix():
    assert TEST_DIRECTORIES == frozenset({"test", "tests", "__tests__", "fixtures", "__fixtures__", "testdata", "test-data"})
    kinds = ("js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts")
    assert set(TEST_FILE_PATTERNS) == ({"test_*.py", "*_test.py", "conftest.py", "*_test.go", "*_spec.rb"}
                                       | {f"*.{runner}.{kind}" for runner in ("test", "spec") for kind in kinds})
    assert len(TEST_FILE_PATTERNS) == len(set(TEST_FILE_PATTERNS)) == 21
    assert "in_tests_or_fixtures" in spellwarden_scan.__all__ and not "in_tests_or_fixtures".startswith("test")


def test_a3_sw_cfg_013_reads_the_shared_directory_list_and_holds_none_of_its_own():
    assert not hasattr(growth_cfg_013, "_TEST_DIRS") and not hasattr(growth_cfg_013, "_under_tests")
    assert growth_cfg_013.under_test_directory is under_test_directory
    assert under_test_directory("Test\\.mcp.json") and under_test_directory("pkg/testdata/.vscode/mcp.json")
    assert not under_test_directory("tests") and not under_test_directory("contest-app/.mcp.json")
