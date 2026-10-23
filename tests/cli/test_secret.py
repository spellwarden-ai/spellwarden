"""O3 spec 6.1, invariant 2, plan decision P16: `Secret` never prints, `take_secret` removes the variable, and
`read_credentials` reads the four credential variables once (`SPELLWARDEN_ORG` is read, not popped)."""
from __future__ import annotations

import copy
import dataclasses

from conftest import credential

from spellwarden_cli.secret import Credentials, Secret, read_credentials, take_secret


def test_secret_never_prints():
    s = Secret(credential("swk"))
    assert repr(s) == str(s) == "***" and f"{s}" == "***" and f"{s!r}" == "***"
    assert s.value.startswith("swk_") and bool(s)
    assert s == Secret(credential("swk")) and s != Secret("other") and s != credential("swk")
    assert hash(s) == hash(Secret(credential("swk")))


def test_secret_survives_copies_and_containers_without_printing():
    s = Secret(credential("swk"))
    assert copy.deepcopy(s).value == s.value
    assert credential("swk") not in repr([s]) + repr({"k": s}) + repr((s,))


def test_take_secret_pops_the_variable_and_ignores_empty():
    env = {"A": "x", "B": ""}
    assert take_secret(env, "A").value == "x"
    assert take_secret(env, "B") is None
    assert "A" not in env and "B" not in env
    assert take_secret(env, "C") is None


def test_read_credentials_pops_the_four_secrets_and_reads_the_org():
    env = {"SPELLWARDEN_API_KEY": credential("swk"), "SPELLWARDEN_ID_TOKEN": "id", "ACTIONS_ID_TOKEN_REQUEST_URL": "http://x/",
           "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "r3qt0k", "SPELLWARDEN_ORG": "acme", "PATH": "/bin"}
    found = read_credentials(env)
    assert env == {"SPELLWARDEN_ORG": "acme", "PATH": "/bin"}
    assert found.org == "acme"
    assert (found.key.value, found.id_token.value, found.request_url.value, found.request_token.value) == (
        credential("swk"), "id", "http://x/", "r3qt0k")
    assert credential("swk") not in repr(found) and "r3qt0k" not in repr(found)
    assert dataclasses.is_dataclass(found) and Credentials(None, None, None, None, None).key is None


def test_read_credentials_of_an_empty_environment_is_all_none():
    assert read_credentials({}) == Credentials(None, None, None, None, None)
    assert read_credentials({"SPELLWARDEN_ORG": ""}).org is None
