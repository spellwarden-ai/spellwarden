"""Credentials as objects that cannot be printed (O3 spec 6.1, invariant 2, plan decision P16). The one owner of
credential types: `main.py`, `run.py`, `api.py` and `connected.py` import them from here, so no module has a credential
as a plain `str` it could log. Pure: no network, no file."""
from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass

CREDENTIAL_VARIABLES = ("SPELLWARDEN_API_KEY", "SPELLWARDEN_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
                        "ACTIONS_ID_TOKEN_REQUEST_TOKEN")


class Secret:
    """A credential value. `repr`, `str` and every format give `"***"`; the value is `.value`, read only where the
    credential is sent (an `Authorization` header, the body of the exchange, the token endpoint's own request)."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    @property
    def value(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "***"

    def __str__(self) -> str:
        return "***"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(("Secret", self._value))

    def __bool__(self) -> bool:
        return bool(self._value)

    def __copy__(self) -> Secret:
        return self

    def __deepcopy__(self, _memo: dict) -> Secret:
        return self

    def __reduce__(self):
        raise TypeError("a Secret is not serialised")


def take_secret(environ: MutableMapping[str, str], name: str) -> Secret | None:
    """The variable `name` as a `Secret`, removed from `environ`; None when it is absent or empty (it is removed
    either way)."""
    value = environ.pop(name, None)
    return Secret(value) if value else None


@dataclass(frozen=True)
class Credentials:
    org: str | None
    key: Secret | None
    id_token: Secret | None
    request_url: Secret | None
    request_token: Secret | None


def read_credentials(environ: MutableMapping[str, str]) -> Credentials:
    """Reads the four credential variables once and removes them from `environ`; `SPELLWARDEN_ORG` is a slug, not a
    secret: it is read and stays."""
    org = environ.get("SPELLWARDEN_ORG") or None
    return Credentials(org=org, key=take_secret(environ, "SPELLWARDEN_API_KEY"),
                       id_token=take_secret(environ, "SPELLWARDEN_ID_TOKEN"),
                       request_url=take_secret(environ, "ACTIONS_ID_TOKEN_REQUEST_URL"),
                       request_token=take_secret(environ, "ACTIONS_ID_TOKEN_REQUEST_TOKEN"))


__all__ = ["CREDENTIAL_VARIABLES", "Credentials", "Secret", "read_credentials", "take_secret"]
