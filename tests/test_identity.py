"""Spec 5.1 and claims E1, E3: the identities the registry gate compares, defined once in the engine. The vector files
under `tests/vectors/` are shared with the hosted side (`code/backend`), which tests its own implementations against
the same rows."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from spellwarden_scan.agentconfig import plugin_source
from spellwarden_scan.archive import unpack_zip
from spellwarden_scan.canonical import canonical_sha256
from spellwarden_scan.identity import (
    SKIP_DIRS,
    canonical_repo_url,
    fold_skill_name,
    is_loaded_variant,
    is_skill_file,
    is_skill_name_variant,
    marketplace_identity,
    nested_skill_roots,
    normalise_url,
    package_files,
    package_sha256,
    plugin_identity,
    request_link_url,
    server_identity,
)

VECTORS = Path(__file__).resolve().parent / "vectors"


def github_src(repo: str, **more):
    return plugin_source({"source": "github", "repo": repo, **more}, marketplace_root="")


def url_src(url: str, **more):
    return plugin_source({"source": "url", "url": url, **more}, marketplace_root="")


def local_src(path: str):
    return plugin_source(path, marketplace_root="")


def other_src():
    return plugin_source({"source": "npm", "package": "x"}, marketplace_root="")


def test_package_files_drops_nested_roots_git_spellwarden_ds_store_and_macosx():
    files = {"s/SKILL.md": b"a", "s/.git/x": b"", "s/.spellwarden/lock.json": b"", "s/.DS_Store": b"", "s/__MACOSX/._SKILL.md": b"",
             "s/inner/SKILL.md": b"n", "s/inner/t.py": b"", "s/lib/a.py": b"b"}
    got = package_files(files, "s", ["s/inner"])
    assert got.files == {"SKILL.md": b"a", "lib/a.py": b"b"} and got.unhashable == ()


def test_a_ds_store_in_a_subdirectory_is_dropped_too():
    got = package_files({"s/SKILL.md": b"a", "s/lib/.DS_Store": b"x", "s/lib/a.py": b"b"}, "s", [])
    assert got.files == {"SKILL.md": b"a", "lib/a.py": b"b"}


def test_files_outside_the_root_are_not_part_of_the_package():
    got = package_files({"s/SKILL.md": b"a", "t/SKILL.md": b"b", "sx/SKILL.md": b"c"}, "s", [])
    assert got.files == {"SKILL.md": b"a"}


def test_a_case_variant_is_renamed_to_skill_md():
    assert package_files({"s/skill.md": b"a"}, "s", []).files == {"SKILL.md": b"a"}


def test_a_case_variant_beside_a_real_skill_md_keeps_its_name():
    files = {"s/SKILL.md": b"a", "s/skill.md": b"b"}
    assert package_files(files, "s", []).files == {"SKILL.md": b"a", "skill.md": b"b"}


def test_a_skip_dir_under_the_root_makes_the_package_unhashable():
    got = package_files({"s/SKILL.md": b"a", "s/node_modules/x/index.js": b"", "s/lib/.venv/y": b""}, "s", [])
    assert got.unhashable == ("s/lib/.venv", "s/node_modules")
    assert got.files == {"SKILL.md": b"a"}


def test_every_skip_dir_is_listed_once_and_the_skip_dirs_are_the_four():
    assert SKIP_DIRS == ("node_modules", ".venv", "venv", "__pycache__")
    files = {"SKILL.md": b"a", "venv/a": b"", "venv/b": b"", "x/__pycache__/c.pyc": b""}
    assert package_files(files, "", []).unhashable == ("venv", "x/__pycache__")


def test_a_skip_dir_inside_a_nested_skill_is_not_this_packages_business():
    files = {"s/SKILL.md": b"a", "s/inner/SKILL.md": b"b", "s/inner/node_modules/x": b""}
    assert package_files(files, "s", ["s/inner"]).unhashable == ()


def test_root_empty_equals_sha256():
    files = {"SKILL.md": b"a", "x.py": b"b"}
    assert package_sha256(package_files(files, "", []).files) == canonical_sha256(files)


def _tree() -> dict[str, bytes]:
    return {
        "skills/top/SKILL.md": b"top", "skills/top/lib/a.py": b"a",
        "skills/top/inner/SKILL.md": b"inner", "skills/top/inner/b.py": b"b",
        "skills/cv/skill.md": b"cv", "skills/cv/data.txt": b"d",
    }


def _zip(path: Path, tree: dict[str, bytes], top: str) -> bytes:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in tree.items():
            archive.writestr(f"{top}/{name}", content)
        archive.writestr(f"{top}/skills/top/.DS_Store", b"finder")
        archive.writestr(f"__MACOSX/{top}/skills/top/._SKILL.md", b"fork")
    return path.read_bytes()


def _package_hash(files: dict[str, bytes], root: str) -> str:
    return package_sha256(package_files(files, root, nested_skill_roots(files, root)).files)


def test_forge_archive_and_checkout_hash_alike(tmp_path):
    tree = _tree()
    unpacked = unpack_zip(_zip(tmp_path / "repo.zip", tree, "repo-0123abc"))
    expected = {
        "skills/top": canonical_sha256({"SKILL.md": b"top", "lib/a.py": b"a"}),
        "skills/top/inner": canonical_sha256({"SKILL.md": b"inner", "b.py": b"b"}),
        "skills/cv": canonical_sha256({"SKILL.md": b"cv", "data.txt": b"d"}),
    }
    for root, digest in expected.items():
        assert _package_hash(tree, root) == digest, root
        assert _package_hash(unpacked, root) == digest, root


def test_crlf_checkout_is_a_different_package():
    lf = {"SKILL.md": b"line\n"}
    crlf = {"SKILL.md": b"line\r\n"}
    assert package_sha256(package_files(lf, "", []).files) != package_sha256(package_files(crlf, "", []).files)


def test_server_identity_vectors():
    assert server_identity("https://A.example.com:443/mcp/?b=2&a=1#f") == server_identity("https://a.example.com/mcp/?a=1&b=2")
    assert server_identity("https://x.example.com/?tenant=a") != server_identity("https://x.example.com/?tenant=b")
    assert server_identity("https://u:p@x.example.com/") == server_identity("https://x.example.com/")
    assert server_identity("https://${HOST}/mcp") is None


def test_server_identity_is_the_sha256_of_the_normalised_url_with_a_sorted_query():
    import hashlib

    assert server_identity("https://x.example.com/mcp?b=2&a=1") == hashlib.sha256(b"https://x.example.com/mcp?a=1&b=2").hexdigest()
    assert server_identity("https://x.example.com/mcp") == hashlib.sha256(b"https://x.example.com/mcp").hexdigest()


def test_the_query_is_sorted_by_name_then_value_after_one_percent_decoding():
    same = [("https://x.example.com/?a=2&a=1&b=%7e", "https://x.example.com/?b=~&a=1&a=2"),
            ("https://x.example.com/?q=%41", "https://x.example.com/?q=A"),
            ("https://x.example.com/?q=a%2fb", "https://x.example.com/?q=a/b")]
    for left, right in same:
        assert server_identity(left) == server_identity(right), left
    # decoded once only: an encoded percent sign stays a percent sign
    assert server_identity("https://x.example.com/?q=a%252Fb") != server_identity("https://x.example.com/?q=a%2Fb")
    assert server_identity("https://x.example.com/?a=1&a=2") != server_identity("https://x.example.com/?a=1")


def test_request_link_url_drops_userinfo_query_and_fragment():
    assert request_link_url("https://u:p@x.example.com:8443/mcp?x=1#f") == "https://x.example.com:8443/mcp"


def test_request_link_url_keeps_the_path_and_drops_a_default_port_only_when_it_is_default():
    assert request_link_url("HTTPS://X.example.com/a/b/?q=1") == "https://x.example.com/a/b"
    assert request_link_url("https://x.example.com:443/mcp") == "https://x.example.com/mcp"


def test_normalise_url_shares_vectors_with_the_hosted_side():
    cases = json.loads((VECTORS / "normalise_url.json").read_text())
    assert len(cases) >= 20 and any(case["output"] is None for case in cases)
    for case in cases:
        assert normalise_url(case["input"]) == case["output"], case


def test_normalise_url_refuses_what_the_splitter_refuses():
    assert normalise_url("https://x.example.com:99999/") is None and server_identity("https://x.example.com:99999/") is None
    assert normalise_url("https://x.exam\tple.com/") is None
    assert normalise_url("https://x.example.com/a\x00b") is None
    assert normalise_url("not a url") is None and normalise_url("") is None
    assert normalise_url("/relative/path") is None and normalise_url("x.example.com/mcp") is None
    assert normalise_url("https:///mcp") is None and normalise_url("https://x.example.com:65536/") is None


def test_canonical_repo_url_is_one_for_the_github_and_url_forms():
    assert (canonical_repo_url(github_src("Acme/Tools")) == canonical_repo_url(url_src("https://GitHub.com/acme/tools.git"))
            == canonical_repo_url(url_src("https://github.com/acme/tools/")) == "https://github.com/acme/tools")
    assert canonical_repo_url(local_src("./plugins/x")) is None and canonical_repo_url(other_src()) is None   # P36


def test_canonical_repo_url_of_an_error_or_an_unparsable_url_is_none():
    assert canonical_repo_url(github_src("not a repo")) is None
    assert canonical_repo_url(url_src("http://github.com/acme/tools")) is None
    assert canonical_repo_url(local_src("../escape")) is None


def test_nested_skill_roots_applies_the_command_rule_and_fold_skill_name():
    paths = ["s/SKILL.md", "s/inner/SKILL.md", "s/deep/x/skill.md", "s/skills/y/skill.md", "t/SKILL.md"]
    assert nested_skill_roots(paths, "s") == ("s/inner", "s/skills/y")   # P52: s/deep/x is not a skill
    assert fold_skill_name("Skill.MD") == "skill.md" and nested_skill_roots(["SKILL.md", "a/SKILL.md"], "") == ("a",)


def test_the_skill_file_rule_moved_into_the_engine():
    assert is_skill_file("a/SKILL.md") and is_skill_file("SKILL.md")
    assert is_skill_file("x/skills/y/Skill.md") and not is_skill_file("x/y/Skill.md")
    assert is_loaded_variant("Skills/y/skill.md") and not is_loaded_variant("a/SKILL.md")
    assert is_skill_name_variant("a/skill.md") and not is_skill_name_variant("a/SKILL.md")
    assert fold_skill_name("é") == fold_skill_name("é")


def test_a_case_variant_outside_skills_dir_stays_inside_the_package_hash():
    files = {"s/SKILL.md": b"a", "s/deep/x/skill.md": b"p", "s/deep/x/payload.js": b"q"}
    assert package_files(files, "s", nested_skill_roots(files, "s")).files == {
        "SKILL.md": b"a", "deep/x/skill.md": b"p", "deep/x/payload.js": b"q"}


def test_canonical_repo_url_lower_cases_the_path_on_github_com():
    assert canonical_repo_url(url_src("https://github.com/Acme/Tools")) == "https://github.com/acme/tools"
    assert canonical_repo_url(url_src("https://git.example.com/Acme/Tools")) == "https://git.example.com/Acme/Tools"


def test_plugin_identity_needs_a_full_commit():
    assert plugin_identity(github_src("acme/tools", sha="a" * 40)) == "git:https://github.com/acme/tools@" + "a" * 40
    assert plugin_identity(github_src("acme/tools", ref="b" * 40)) == "git:https://github.com/acme/tools@" + "b" * 40
    assert plugin_identity(github_src("acme/tools", ref="main")) is None and plugin_identity(github_src("acme/tools", ref="v1.2")) is None


def test_plugin_identity_lower_cases_the_commit_and_refuses_unpinned_local_and_other_sources():
    assert plugin_identity(github_src("acme/tools", sha="A" * 40)) == "git:https://github.com/acme/tools@" + "a" * 40
    assert plugin_identity(github_src("acme/tools", sha="a" * 40, ref="b" * 40)) is None   # no pin: they differ
    assert plugin_identity(github_src("acme/tools", sha="abc123")) is None
    assert plugin_identity(local_src("./p")) is None and plugin_identity(other_src()) is None
    assert plugin_identity(url_src("https://git.example.com/a/b.git", sha="c" * 40)) == "git:https://git.example.com/a/b@" + "c" * 40


def test_marketplace_identity_is_the_plugin_identity():
    source = github_src("Acme/Market", sha="d" * 40)
    assert marketplace_identity(source) == plugin_identity(source) == "git:https://github.com/acme/market@" + "d" * 40
    assert marketplace_identity(github_src("acme/market")) is None
