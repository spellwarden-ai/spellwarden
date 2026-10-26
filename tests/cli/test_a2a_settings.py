"""O4 spec 6.2 and claims S5, S10 (settings part): the `a2a` mapping of `.spellwarden/config.yml`, its limits, the key file
read through the same reader as the setting that names it, and which keys are the base revision's on a pull or merge request."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import write_tree

from spellwarden_cli import paths
from spellwarden_cli.settings import A2A_KEYS_MAX, Flags, SettingsError, load_settings

JWKS = json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": "AAAA"}]}).encode()


def load(tmp_path: Path, config_text: str | None = None, files: dict | None = None, **kwargs):
    tree = dict(files or {})
    if config_text is not None:
        tree[".spellwarden/config.yml"] = config_text
    write_tree(tmp_path, tree)
    return load_settings(str(tmp_path), config=kwargs.pop("config", None), flags=Flags(), env={}, **kwargs)


def reader_of(files: dict[str, bytes]):
    """A base revision reader: the bytes of `files`, `FileNotFoundError` for any other path."""
    def read(relative: str, max_bytes: int) -> bytes:
        if relative not in files:
            raise FileNotFoundError(relative)
        if len(files[relative]) > max_bytes:
            raise paths.TooLarge(relative)
        return files[relative]

    return read


FULL = """version: 1
a2a:
  cards:
    - deploy/agent/card.json
  keys: .well-known/jwks.json
  agents:
    - https://agent.example.com/
    - https://example.com/agents/billing/card.json
    - http://10.0.0.5:8080/
"""


def test_the_a2a_mapping_is_read_and_the_key_file_with_it(tmp_path):
    settings = load(tmp_path, FULL, {".well-known/jwks.json": JWKS})
    assert settings.a2a.cards == ("deploy/agent/card.json",) and settings.a2a.keys == ".well-known/jwks.json"
    assert settings.a2a.agents == ("https://agent.example.com/", "https://example.com/agents/billing/card.json", "http://10.0.0.5:8080/")
    assert settings.a2a.keys_bytes == JWKS


def test_no_a2a_mapping_is_the_empty_default_and_a_missing_key_file_is_none(tmp_path):
    settings = load(tmp_path, "version: 1\n")
    assert (settings.a2a.cards, settings.a2a.keys, settings.a2a.agents, settings.a2a.keys_bytes) == ((), None, (), None)
    absent = load(tmp_path / "other", "version: 1\na2a:\n  keys: keys/missing.json\n")
    assert absent.a2a.keys == "keys/missing.json" and absent.a2a.keys_bytes is None  # `a2a_keys_missing` is the scan's notice


@pytest.mark.parametrize(("mapping", "fragment"), [
    ("a2a: yes", "`a2a` must be a mapping"),
    ("a2a:\n  card: [x]", "unknown key 'card'"),
    ("a2a:\n  cards: x", "`a2a.cards` must be a list of non-empty strings"),
    ("a2a:\n  cards: ['']", "`a2a.cards` must be a list of non-empty strings"),
    ("a2a:\n  cards:\n" + "".join(f"    - c{n}.json\n" for n in range(51)), "lists 51 entries; at most 50"),
    ("a2a:\n  cards: ['../x.json']", "is not a path inside the scan root"),
    ("a2a:\n  cards: ['/etc/x.json']", "is not a path inside the scan root"),
    ("a2a:\n  keys: ['a']", "`a2a.keys` must be one relative path"),
    ("a2a:\n  keys: ../jwks.json", "`a2a.keys`: '../jwks.json' is not a path inside the scan root"),
    ("a2a:\n  agents:\n" + "".join(f"    - https://a{n}.example.com/\n" for n in range(21)), "lists 21 entries; at most 20"),
    ("a2a:\n  agents: ['ftp://a.example.com/']", "is not an absolute http or https URL"),
    ("a2a:\n  agents: ['agent.example.com']", "is not an absolute http or https URL"),
    ("a2a:\n  agents: ['https://u:p@a.example.com/']", "holds userinfo"),
    ("a2a:\n  agents: ['https://tok@a.example.com/']", "holds userinfo"),
    ("a2a:\n  agents: ['https://a.example.com/#x']", "holds a fragment"),
    ("a2a:\n  agents: ['https://a.example.com/${HOST}/']", "holds a ${...} reference"),
    ("a2a:\n  agents: ['https://a.example.com/" + "p" * 1000 + "']", "is longer than 1000 characters"),
    ("a2a:\n  agents: ['https://a.example.com:99999/']", "is not an absolute http or https URL"),
])
def test_an_invalid_a2a_mapping_is_a_settings_error_naming_the_rule(tmp_path, mapping, fragment):
    with pytest.raises(SettingsError) as caught:
        load(tmp_path, f"version: 1\n{mapping}\n")
    assert fragment in str(caught.value) and str(caught.value).startswith(".spellwarden/config.yml: ")


def test_an_agent_url_of_exactly_1000_characters_is_accepted_and_http_is_accepted_and_never_fetched_by_the_settings(tmp_path):
    url = "https://a.example.com/" + "p" * (1000 - len("https://a.example.com/"))
    assert len(url) == 1000
    settings = load(tmp_path, f"version: 1\na2a:\n  agents: ['{url}', 'http://localhost:9000/']\n")
    assert settings.a2a.agents == (url, "http://localhost:9000/")


def test_a_key_file_over_64_kib_or_a_link_is_settings_invalid_naming_the_setting(tmp_path):
    with pytest.raises(SettingsError, match=r"a2a\.keys: k\.json is over 65536 bytes"):
        load(tmp_path, "version: 1\na2a:\n  keys: k.json\n", {"k.json": b"x" * (A2A_KEYS_MAX + 1)})
    root = tmp_path / "linked"
    write_tree(root, {"real.json": JWKS, ".spellwarden/config.yml": "version: 1\na2a:\n  keys: link.json\n"})
    (root / "link.json").symlink_to(root / "real.json")
    with pytest.raises(SettingsError, match=r"a2a\.keys: link\.json cannot be read"):
        load_settings(str(root), config=None, flags=Flags(), env={})


def test_the_key_file_is_read_through_the_same_reader_as_the_settings_file(tmp_path):
    """On a pull or merge request the settings file comes from the base revision, and so does the key file: a key file the
    working tree holds and the base lacks is not read (S5)."""
    files = {".spellwarden/config.yml": FULL.encode()}
    write_tree(tmp_path, {".well-known/jwks.json": b'{"keys": []}'})
    settings = load_settings(str(tmp_path), config=None, flags=Flags(), env={}, read=reader_of(files))
    assert settings.a2a.keys == ".well-known/jwks.json" and settings.a2a.keys_bytes is None
    files[".well-known/jwks.json"] = JWKS
    assert load_settings(str(tmp_path), config=None, flags=Flags(), env={}, read=reader_of(files)).a2a.keys_bytes == JWKS


BASE = {".spellwarden/config.yml": b"version: 1\na2a:\n  keys: base-keys.json\n  agents: ['https://base.example.com/']\n  cards: ['base-card.json']\n",
        "base-keys.json": JWKS}
HEAD_CONFIG = ("version: 1\na2a:\n  keys: head-keys.json\n  agents: ['https://head.example.com/']\n  cards: ['head-card.json']\n"
               "include: ['src/**']\n")


def test_s5_under_config_on_a_request_agents_and_keys_are_the_base_revisions_and_cards_the_config_files(tmp_path):
    write_tree(tmp_path, {"head.yml": HEAD_CONFIG, "head-keys.json": b'{"keys": []}'})
    settings = load_settings(str(tmp_path), config=str(tmp_path / "head.yml"), flags=Flags(), env={}, connected_read=reader_of(BASE))
    assert settings.a2a.agents == ("https://base.example.com/",)
    assert (settings.a2a.keys, settings.a2a.keys_bytes) == ("base-keys.json", JWKS)
    assert settings.a2a.cards == ("head-card.json",) and settings.include == ("src/**",)


def test_s5_the_base_revision_decides_even_when_it_has_no_a2a_mapping(tmp_path):
    write_tree(tmp_path, {"head.yml": HEAD_CONFIG})
    for base in ({".spellwarden/config.yml": b"version: 1\n"}, {}):
        settings = load_settings(str(tmp_path), config=str(tmp_path / "head.yml"), flags=Flags(), env={}, connected_read=reader_of(base))
        assert (settings.a2a.agents, settings.a2a.keys, settings.a2a.keys_bytes) == ((), None, None)
        assert settings.a2a.cards == ("head-card.json",)


def test_the_base_files_other_defects_do_not_matter_under_config_but_a_defect_in_its_a2a_mapping_is_refused(tmp_path):
    write_tree(tmp_path, {"head.yml": "version: 1\n"})
    other = {".spellwarden/config.yml": b"version: 1\nfail-on: sometimes\na2a:\n  agents: ['https://base.example.com/']\n"}
    settings = load_settings(str(tmp_path), config=str(tmp_path / "head.yml"), flags=Flags(), env={}, connected_read=reader_of(other))
    assert settings.a2a.agents == ("https://base.example.com/",)
    broken = {".spellwarden/config.yml": b"version: 1\na2a:\n  agents: ['ftp://x/']\n"}
    with pytest.raises(SettingsError, match="is not an absolute http or https URL"):
        load_settings(str(tmp_path), config=str(tmp_path / "head.yml"), flags=Flags(), env={}, connected_read=reader_of(broken))
    unreadable = {".spellwarden/config.yml": b"\xff\xfe"}
    assert load_settings(str(tmp_path), config=str(tmp_path / "head.yml"), flags=Flags(), env={},
                         connected_read=reader_of(unreadable)).a2a.agents == ()
    with pytest.raises(SettingsError):
        load_settings(str(tmp_path), config=str(tmp_path / "head.yml"), flags=Flags(), env={}, connected_read=reader_of(unreadable),
                      connected_credential=True)


def test_outside_a_request_config_decides_everything_and_the_key_file_is_the_working_trees(tmp_path):
    write_tree(tmp_path, {"head.yml": HEAD_CONFIG, "head-keys.json": JWKS})
    settings = load_settings(str(tmp_path), config=str(tmp_path / "head.yml"), flags=Flags(), env={})
    assert settings.a2a.agents == ("https://head.example.com/",) and settings.a2a.keys_bytes == JWKS


def test_the_settings_schema_describes_the_a2a_mapping():
    import jsonschema

    schema = json.loads((Path(__file__).resolve().parents[2] / "schemas" / "settings.schema.json").read_text(encoding="utf-8"))
    props = schema["properties"]["a2a"]["properties"]
    assert sorted(props) == ["agents", "cards", "keys"]
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate({"version": 1, "a2a": {"cards": ["a.json"], "keys": "k.json", "agents": ["https://a.example.com/", "http://a/"]}})
    for bad in ({"card": []}, {"cards": "x"}, {"keys": 1}, {"agents": ["ftp://a/"]}, {"agents": ["https://u@a/"]},
                {"agents": ["https://a/" + "p" * 1000]}, {"cards": ["c"] * 51}, {"agents": ["https://a/"] * 21}):
        assert list(validator.iter_errors({"version": 1, "a2a": bad})), bad
    assert list(validator.iter_errors({"version": 1, "a2a": "on"}))


# --- r0:F5: listed paths are stored normalised ------------------------------------------------------------------------------

def test_r0_f5_listed_cards_and_the_key_file_are_stored_as_the_normalised_path(tmp_path):
    """(r0:F5) `./deploy/card.json` names `deploy/card.json` and a trailing `/` is dropped: the setting keeps what `contain` returns, so
    the file set (which holds normalised paths) finds the file."""
    config = "version: 1\na2a:\n  cards: ['./deploy/card.json', 'deploy/agents/', './x/y.json/']\n  keys: ./keys/jwks.json\n"
    settings = load(tmp_path, config, {"keys/jwks.json": JWKS})
    assert settings.a2a.cards == ("deploy/card.json", "deploy/agents", "x/y.json")
    assert (settings.a2a.keys, settings.a2a.keys_bytes) == ("keys/jwks.json", JWKS)


def test_r0_f5_the_base_revision_key_file_named_with_a_dot_slash_is_still_the_base_revisions(tmp_path):
    base = {".spellwarden/config.yml": b"version: 1\na2a:\n  keys: ./base-keys.json\n", "base-keys.json": JWKS}
    write_tree(tmp_path, {"head.yml": "version: 1\na2a:\n  keys: head-keys.json\n  cards: ['./head-card.json']\n",
                          "head-keys.json": b'{"keys": []}'})
    settings = load_settings(str(tmp_path), config=str(tmp_path / "head.yml"), flags=Flags(), env={}, connected_read=reader_of(base))
    assert (settings.a2a.keys, settings.a2a.keys_bytes) == ("base-keys.json", JWKS)
    assert settings.a2a.cards == ("head-card.json",)


def test_r0_f5_a_card_listed_with_a_dot_slash_is_found_and_checked_not_file_missing(run_cli, make_repo, tmp_path):
    from jsonschema import validate

    schema = json.loads((Path(__file__).resolve().parents[2] / "schemas" / "report.schema.json").read_text(encoding="utf-8"))
    repo = make_repo(tmp_path / "repo", {"deploy/card.json": b'{"name": 1}',
                                         ".spellwarden/config.yml": "version: 1\na2a:\n  cards: ['./deploy/card.json']\n"})
    _, out, _ = run_cli(["scan", str(repo), "--format", "json", "--no-telemetry"], env={})
    report = json.loads(out)
    validate(report, schema)
    assert [(f["rule_id"], f["location"]["path"]) for f in report["findings"]] == [("SW-A2A-001", "deploy/card.json")]
    assert [n for n in report["notices"] if n["code"] == "file_missing"] == []
    assert [(a["path_form"], a["item"]) for a in report["agents"]] == [("listed", "a2a-card:deploy/card.json")]
