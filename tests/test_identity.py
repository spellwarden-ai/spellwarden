"""Spec 5.1 and claims E1, E3: the identities the registry gate compares, defined once in the engine. The vector files
under `tests/vectors/` are shared with the hosted side (`code/backend`), which tests its own implementations against
the same rows."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from spellwarden_scan.agentconfig import plugin_source
from spellwarden_scan.archive import unpack_zip
from spellwarden_scan.canonical import canonical_sha256
from spellwarden_scan.identity import (
    LAUNCH_OVERRIDE_ENV,
    LAUNCHER_FAMILY,
    QUIET_FLAGS,
    SKIP_DIRS,
    CommandIdentity,
    ParsedCommandIdentity,
    canonical_repo_url,
    command_identity,
    fold_skill_name,
    format_command_identity,
    is_launch_override_env,
    is_loaded_variant,
    is_skill_file,
    is_skill_name_variant,
    marketplace_identity,
    nested_skill_roots,
    normalise_url,
    package_files,
    package_sha256,
    parse_command_identity,
    plugin_identity,
    request_link_url,
    resolver_files,
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
    """Every row is `{input, output}`; `output` null is a URL the engine refuses. The hosted `normalise_url` (urlsplit)
    does not refuse: on those rows `hosted` records its answer, the string it returns or "error" where it raises, so
    the backend's parity test (plan Task 13) can hold both sides to the file (review finding r0:F8)."""
    cases = json.loads((VECTORS / "normalise_url.json").read_text())
    assert len(cases) >= 20 and any(case["output"] is None for case in cases)
    for case in cases:
        assert normalise_url(case["input"]) == case["output"], case
        assert set(case) <= {"input", "output", "hosted"} and ("hosted" in case) == (case["output"] is None), case
        if "hosted" in case:
            assert case["hosted"] == "error" or isinstance(case["hosted"], str), case


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


# --- Task 2: command identities (spec 5.1 "Pinned commands") --------------------------------------------------------

def _command_rows() -> list[dict]:
    return json.loads((VECTORS / "command_identity.json").read_text())


def test_command_identity_table():
    rows = _command_rows()
    assert len(rows) >= 40
    for row in rows:
        got = command_identity(row["command"], row["args"], row.get("env", {}))
        assert (got.identity, got.reason) == (row.get("identity"), row.get("reason")), row


def test_the_table_covers_every_reason_and_every_launcher():
    rows = _command_rows()
    assert {row["reason"] for row in rows if "reason" in row} == {"unpinned", "unknown_launcher", "unresolved", "launch_override"}
    identities = [row["identity"] for row in rows if "identity" in row]
    for launcher in LAUNCHER_FAMILY:
        assert any(identity.startswith(f"cmd:{launcher} ") for identity in identities), launcher


def test_no_identity_in_the_table_holds_a_userinfo_query_or_env_value():
    for row in _command_rows():
        identity = row.get("identity")
        if identity is None:
            continue
        for source in (part for part in identity.split(" ") if part.startswith("src=")):
            assert "@" not in source and "?" not in source and "#" not in source, identity
        assert "KEY=v" not in identity and "s3cret" not in identity and "u:p" not in identity and "?x=1" not in identity, identity


def test_an_argument_value_changes_the_identity_and_never_appears_in_it():
    image = "i@sha256:" + "c" * 64
    one = command_identity("docker", ["run", "-e", "TOKEN=aaa", image], {}).identity
    two = command_identity("docker", ["run", "-e", "TOKEN=bbb", image], {}).identity
    assert one != two and "aaa" not in one and "TOKEN" not in one and one.startswith("cmd:docker run " + image + " args=")


def test_the_env_value_never_changes_the_identity():
    base = command_identity("npx", ["pkg@1.0.0"], {}).identity
    assert command_identity("npx", ["pkg@1.0.0"], {"API_KEY": "one"}).identity == base
    assert command_identity("npx", ["pkg@1.0.0"], {"API_KEY": "two"}).identity == base


def test_a_source_changes_the_identity():
    plain = command_identity("npx", ["pkg@1.0.0"], {}).identity
    sourced = command_identity("npx", ["--registry", "https://r.example.com/", "pkg@1.0.0"], {}).identity
    moved = command_identity("npx", ["--registry", "https://s.example.com/", "pkg@1.0.0"], {}).identity
    assert len({plain, sourced, moved}) == 3


def test_a_comma_in_a_source_path_is_unresolved_so_the_encoding_stays_unambiguous():
    assert command_identity("npx", ["--registry", "https://r.example.com/a,b", "pkg@1.0.0"], {}) == CommandIdentity(None, "unresolved")


def test_command_identity_results_are_data():
    got = command_identity("npx", ["pkg@1.0.0"], {})
    assert got == CommandIdentity("cmd:npx pkg@1.0.0", None)
    with pytest.raises(AttributeError):
        got.identity = "x"  # type: ignore[misc]


def test_round_trip():
    identities = [row["identity"] for row in _command_rows() if "identity" in row]
    assert len(identities) >= 40
    for identity in identities:
        assert format_command_identity(parse_command_identity(identity)) == identity, identity


def test_parse_reads_the_four_parts():
    digest = "d" * 32
    parsed = parse_command_identity(f"cmd:pnpm dlx a@1.0.0 b@2.0.0 src=https://r.example.com/x,https://s.example.com args={digest}")
    assert parsed == ParsedCommandIdentity("pnpm dlx", ("a@1.0.0", "b@2.0.0"), ("https://r.example.com/x", "https://s.example.com"), digest)
    plain = parse_command_identity("cmd:uvx tool==1.0")
    assert plain == ParsedCommandIdentity("uvx", ("tool==1.0",), (), None)


@pytest.mark.parametrize("bad", [
    "cmd:npx", "cmd:npx pkg", "cmd:npx pkg@1.0.0 src=", "cmd:npx pkg@1.0.0 args=zz", "cmd:yarn x@1.0.0", "npx pkg@1.0.0",
    "cmd:npx  pkg@1.0.0", "cmd:npx pkg@1.0.0 ", "", "cmd:", "cmd:npx b@1.0.0 a@1.0.0", "cmd:npx a@1.0.0 a@1.0.0",
    "cmd:npx pkg@1.0.0 args=" + "A" * 32, "cmd:npx pkg@1.0.0 args=" + "a" * 31, "cmd:npx pkg@1.0.0 args=" + "a" * 33,
    "cmd:npx pkg@1.0.0 args=" + "a" * 32 + " src=https://r.example.com/", "cmd:npx pkg@1.0.0 src=https://u:p@r.example.com/",
    "cmd:npx pkg@1.0.0 src=https://r.example.com/?x=1", "cmd:npx pkg@1.0.0 src=https://r.example.com/,", "cmd:npx pkg@1.0.0 src=./local",
    "cmd:npx pkg@1.0.0 extra", "cmd:npx pkg@latest", "cmd:docker run img:1.2", "cmd:docker run img@sha256:" + "a" * 63,
    "cmd:uvx tool>=1.0", "cmd:pnpm pkg@1.0.0", "cmd:npx pkg@1.0.0 src=a src=b", "cmd:NPX pkg@1.0.0",
])
def test_parse_refuses_hand_edited_strings(bad):
    with pytest.raises(ValueError):
        parse_command_identity(bad)


def test_parse_errors_name_the_part():
    with pytest.raises(ValueError, match=r"^args: "):
        parse_command_identity("cmd:npx pkg@1.0.0 args=zz")
    with pytest.raises(ValueError, match=r"^launcher: "):
        parse_command_identity("cmd:yarn x@1.0.0")
    with pytest.raises(ValueError, match=r"^artefacts: "):
        parse_command_identity("cmd:npx pkg")
    with pytest.raises(ValueError, match=r"^src: "):
        parse_command_identity("cmd:npx pkg@1.0.0 src=")


def test_format_orders_the_parts():
    parsed = ParsedCommandIdentity("docker run", ("i@sha256:" + "a" * 64,), ("https://r.example.com/",), "0" * 32)
    assert format_command_identity(parsed) == "cmd:docker run i@sha256:" + "a" * 64 + " src=https://r.example.com/ args=" + "0" * 32


def test_resolver_files_finds_registry_and_index_lines():
    files = {".npmrc": b"registry=https://r.example.com/\n", "pyproject.toml": b"[tool.uv]\nindex-url = 'https://i.example.com/simple'\n",
             "bunfig.toml": b"[install]\nregistry = 'x'\n", "README.md": b"registry"}
    assert resolver_files(files, files.__getitem__) == {"npm": (".npmrc", "bunfig.toml"), "python": ("pyproject.toml",)}
    assert resolver_files({".npmrc": b"save-exact=true\n"}, {".npmrc": b"save-exact=true\n"}.__getitem__) == {}


@pytest.mark.parametrize("name, content, family", [
    (".npmrc", b"; a comment\n@acme:registry=https://r.example.com/\n", "npm"),
    (".npmrc", b"  registry = https://r.example.com/\n", "npm"),
    (".yarnrc.yml", b"npmRegistryServer: 'https://r.example.com'\n", "npm"),
    (".yarnrc.yml", b"npmScopes:\n  acme:\n    npmRegistryServer: x\n", "npm"),
    ("bunfig.toml", b"[install.scopes]\n'@acme' = 'https://r.example.com/'\n", "npm"),
    ("uv.toml", b"index-url = 'https://i.example.com/simple'\n", "python"),
    ("uv.toml", b"[[index]]\nurl = 'https://i.example.com/simple'\n", "python"),
    ("uv.toml", b"find-links = ['https://f.example.com']\n", "python"),
    ("pip.conf", b"[global]\nextra-index-url = https://i.example.com/simple\n", "python"),
    ("pyproject.toml", b"[[tool.uv.index]]\nurl = 'https://i.example.com/simple'\n", "python"),
    ("pyproject.toml", b"[project]\nname = 'x'\n[tool.uv]\ndefault-index = 'https://i.example.com/simple'\n", "python"),
    ("sub/dir/.npmrc", b"registry=https://r.example.com/\n", "npm"),
])
def test_resolver_files_recognises_each_form(name, content, family):
    assert resolver_files({name: content}, {name: content}.__getitem__) == {family: (name,)}


@pytest.mark.parametrize("name, content", [
    (".npmrc", b"//r.example.com/:_authToken=${TOKEN}\nsave-exact=true\n"),
    (".npmrc", b"# registry=https://r.example.com/\n"),
    (".yarnrc.yml", b"nodeLinker: node-modules\n"),
    ("bunfig.toml", b"[test]\nregistry = 'x'\n"),
    ("pyproject.toml", b"[project]\nname = 'x'\nindex = 'not uv'\n[tool.ruff]\nindex-url = 'x'\n"),
    ("pyproject.toml", b"[tool.uv]\nmanaged = true\n"),
    ("pip.conf", b"[global]\ntimeout = 5\n"),
    ("registry.txt", b"registry=https://r.example.com/\n"),
])
def test_resolver_files_ignores_what_redirects_nothing(name, content):
    assert resolver_files({name: content}, {name: content}.__getitem__) == {}


def test_resolver_files_reads_only_candidates_and_caps_the_read():
    reads = []
    contents = {".npmrc": b"registry=x\n", "a.txt": b"registry=x\n", "big/.npmrc": b"#" * (64 * 1024 + 1)}

    def read(name):
        reads.append(name)
        return contents[name]

    got = resolver_files(["a.txt", ".npmrc", "big/.npmrc"], read)
    assert "a.txt" not in reads
    assert got == {"npm": (".npmrc", "big/.npmrc")}   # the file over the cap is counted without being searched


def test_resolver_files_with_an_unreadable_file_fails_closed():
    def read(_name):
        raise OSError("gone")

    assert resolver_files([".npmrc"], read) == {"npm": (".npmrc",)}


def test_uvx_short_options_mean_their_long_forms():
    """uv's `-w`, `-i`, `-f`, `-b` and `-C` are `--with`, `--index-url`, `--find-links`, `--build-constraints` and
    `--config-setting`: `uvx -w safe==1.0.0 evil` is an unpinned launch of `evil`, never an identity naming `safe`."""
    assert command_identity("uvx", ["-w", "safe==1.0.0", "evil"], {}) == CommandIdentity(None, "unpinned")
    for short, long in (("-w", "--with"), ("-i", "--index-url"), ("-f", "--find-links"), ("-b", "--build-constraints"),
                        ("-C", "--config-setting")):
        value = "https://i.example.com/simple" if short in ("-i", "-f") else "x==1.0" if short == "-w" else "c.txt"
        got, want = (command_identity("uvx", [option, value, "pkg==1.0"], {}) for option in (short, long))
        assert got.identity is not None and got.identity.startswith("cmd:uvx pkg==1.0"), (short, got)
        if short in ("-w", "-i", "-f"):  # artefacts and sources are canonical; a value option stays in the args hash as written
            assert got == want, (short, got, want)


@pytest.mark.parametrize("name, content, family", [
    (".npmrc", b'"registry"=https://r.example.com/\n', "npm"),
    (".npmrc", b"'@acme:registry' = https://r.example.com/\n", "npm"),
    (".yarnrc.yml", b'"npmRegistryServer": "https://r.example.com"\n', "npm"),
    ("bunfig.toml", b'install.registry = "https://r.example.com/"\n', "npm"),
    ("bunfig.toml", b'install = { registry = "https://r.example.com/" }\n', "npm"),
    ("bunfig.toml", b'[install]\n"registry" = "https://r.example.com/"\n', "npm"),
    ("bunfig.toml", b'[install.registry]\nurl = "https://r.example.com/"\n', "npm"),
    ("uv.toml", b'[pip]\n"index-url" = "https://i.example.com/simple"\n', "python"),
    ("pyproject.toml", b'[tool]\nuv.index-url = "https://i.example.com/simple"\n', "python"),
    ("pyproject.toml", b'[tool.uv]\n"index-url" = "https://i.example.com/simple"\n', "python"),
    ("pyproject.toml", b'tool.uv = { index-url = "https://i.example.com/simple" }\n', "python"),
    ("pyproject.toml", b'[tool.uv.pip]\nextra-index-url = "https://i.example.com/simple"\n', "python"),
])
def test_resolver_files_match_the_key_as_the_tool_reads_it(name, content, family):
    """Quoted, dotted and inline-table spellings of the same key redirect resolution just the same (security review S5)."""
    assert resolver_files({name: content}, {name: content}.__getitem__) == {family: (name,)}


@pytest.mark.parametrize("name, content", [
    ("bunfig.toml", b'test = { registry = "x" }\n'),
    ("pyproject.toml", b'[tool]\nruff.index-url = "x"\n'),
    ("pyproject.toml", b'[tool.uv]\nindex-strategy = "first-index"\n'),
    ("pyproject.toml", b'tool.poetry = { index-url = "x" }\n'),
])
def test_resolver_files_still_ignore_other_tables_in_every_spelling(name, content):
    assert resolver_files({name: content}, {name: content}.__getitem__) == {}


def test_attached_short_option_values_are_the_option_and_its_value():
    """`-wevil pkg==1.0` installs `evil` as `-w evil` does: an attached value is split off, never left as an argument."""
    assert command_identity("uvx", ["-wevil", "pkg==1.0"], {}) == CommandIdentity(None, "unpinned")
    assert command_identity("uvx", ["-w=x==1.0", "pkg==1.0"], {}) == command_identity("uvx", ["--with", "x==1.0", "pkg==1.0"], {})
    attached = command_identity("uvx", ["-ihttps://i.example.com/simple", "pkg==1.0"], {})
    assert attached == command_identity("uvx", ["--index-url", "https://i.example.com/simple", "pkg==1.0"], {})
    assert command_identity("npx", ["-ppkg@1.0.0", "cmd"], {}) == command_identity("npx", ["-p", "pkg@1.0.0", "cmd"], {})
    # a cluster: booleans first, then the value option takes the rest of the token, or the next token
    assert command_identity("uvx", ["-qwevil", "pkg==1.0"], {}) == CommandIdentity(None, "unpinned")
    assert command_identity("uvx", ["-qw", "x==1.0", "pkg==1.0"], {}) == command_identity("uvx", ["--with", "x==1.0", "pkg==1.0"], {})
    assert command_identity("uvx", ["-yqi", "https://i.example.com/simple", "pkg==1.0"], {}) == attached
    # a letter the table does not know before the value option: the token stays an argument and consumes nothing
    unknown = command_identity("uvx", ["-Xw", "a==1.0", "b==2.0"], {})
    assert unknown.identity is not None and unknown.identity.startswith("cmd:uvx a==1.0 args=")
    prefixed = command_identity("npx", ["-C", "dir", "pkg@1.0.0"], {}).identity  # npm's `-C dir`: `dir` is a value, not the package
    assert prefixed is not None and prefixed.startswith("cmd:npx pkg@1.0.0 args=")
    image = "ghcr.io/acme/server@sha256:" + "a" * 64
    clustered = command_identity("docker", ["run", "-itp80:80", image], {}).identity  # `-i -t -p 80:80`: the image stays the image
    assert clustered is not None and clustered.startswith(f"cmd:docker run {image}")
    assert command_identity("docker", ["run", "-it", image], {}) == command_identity("docker", ["run", "-i", "-t", image], {})


@pytest.mark.parametrize("name, content, family", [
    ("pyproject.toml", b'[tool.uv]\nnote = """\n[tool.other]\n"""\nindex-url = "https://i.example.com/simple"\n', "python"),
    ("pyproject.toml", b"[tool.uv]\nnote = " + b"'" * 3 + b"\n" + b"'" * 3 + b"\n\"index-url\" = 'https://i.example.com/simple'\n", "python"),
    ("pyproject.toml", b'tool = { uv = { index-url = "https://i.example.com/simple" } }\n', "python"),
    ("pyproject.toml", b'tool = { poetry = { name = "x" }, uv = { pip = { index-url = "https://i.example.com/simple" } } }\n', "python"),
    ("bunfig.toml", b'install = { cache = { dir = "x" }, registry = "https://r.example.com/" }\n', "npm"),
    ("bunfig.toml", b'install = { x = "a\\"", registry = "https://r.example.com/" }\n', "npm"),
    ("bunfig.toml", b"install = { x = 'a\\', registry = 'https://r.example.com/' }\n", "npm"),
])
def test_resolver_files_see_through_multi_line_strings_and_nested_inline_tables(name, content, family):
    assert resolver_files({name: content}, {name: content}.__getitem__) == {family: (name,)}


@pytest.mark.parametrize("name, content", [
    ("pyproject.toml", b'[tool.uv]\nnote = """\nindex-url = "https://i.example.com/simple"\n"""\n'),
    ("pyproject.toml", b'tool = { other = { uv = { index-url = "x" } } }\n'),
    ("bunfig.toml", b'install = { scopes = "{ registry = 1 }" }\n'),
])
def test_resolver_files_do_not_read_keys_out_of_strings_or_other_tables(name, content):
    assert resolver_files({name: content}, {name: content}.__getitem__) == {}


def test_launch_override_env_prefixes():
    assert is_launch_override_env("npm_config_registry") and is_launch_override_env("NPM_CONFIG_X") and not is_launch_override_env("PATH")
    assert is_launch_override_env("NODE_OPTIONS") and not is_launch_override_env("NODE_ENV") and not is_launch_override_env("npm_token")
    assert "DYLD_INSERT_LIBRARIES" in LAUNCH_OVERRIDE_ENV and "npm_config_registry" not in LAUNCH_OVERRIDE_ENV


def test_the_registry_constants():
    assert LAUNCHER_FAMILY == {"npx": "npm", "bunx": "npm", "pnpm dlx": "npm", "uvx": "python", "pipx run": "python", "docker run": "docker"}
    assert set(QUIET_FLAGS) == set(LAUNCHER_FAMILY)
    assert QUIET_FLAGS["npx"] >= {"-y", "--yes", "-q", "--quiet", "--silent"}
    assert QUIET_FLAGS["docker run"] >= {"--rm", "-i", "--interactive", "-t", "--tty", "--init", "--name"}
    assert len(LAUNCH_OVERRIDE_ENV) == 22   # npm_config_* and NPM_CONFIG_* are matched by prefix
