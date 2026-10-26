"""`.spellwarden/config.yml` and the flag, environment, file, default
precedence (spec 6.3). Unknown keys are errors; `probe-private` is never a
settings key, so the scanned revision cannot grant itself private probing. The `connected` mapping (O3 spec 6.2) holds
the repository's statement about connected mode: `pack` and `required` have no flag and no environment variable. The `a2a`
mapping (O4 spec 6.2) names the agent cards to check (`cards`), the key file that is the only trust root for their signatures
(`keys`) and the remote agents to fetch under `--probe` (`agents`); on a pull or merge request `keys` and `agents` are read
from the base revision, even under `--config`."""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from spellwarden_cli import paths, safe_yaml
from spellwarden_scan.glob import glob_match
from spellwarden_scan.relpath import UnsafePath, contain

CONFIG_PATH = ".spellwarden/config.yml"
FAIL_ON = ("critical", "high", "medium", "low", "never")
_KEYS = ("version", "include", "exclude", "fail-on", "probe", "telemetry", "connected", "a2a")
_A2A_KEYS = ("cards", "keys", "agents")
A2A_MAX_CARDS = 50
A2A_MAX_AGENTS = 20
A2A_AGENT_URL_MAX = 1000  # so that `a2a-agent:<url>` stays within the backend's 1024-character `item` field
A2A_KEYS_MAX = 64 * 1024
_CONNECTED_KEYS = ("pack", "upload", "required")
# A pack id (`baseline` or 32 hex), optionally `@N.N` (O3 spec 6.2).
CONNECTED_PACK_RE = re.compile(r"^(baseline|[0-9a-f]{32})(@[0-9]+\.[0-9]+)?$")
_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")


class SettingsError(ValueError):
    """Exit 2 with the error code `settings_invalid`; the message names the file (or variable) and the rule."""


@dataclass(frozen=True)
class Flags:
    fail_on: str | None = None
    probe: bool | None = None
    probe_private: bool | None = None
    telemetry: bool | None = None
    upload: bool | None = None  # --upload / --no-upload


@dataclass(frozen=True)
class Connected:
    pack: str | None = None
    upload: bool = True
    required: bool = False


@dataclass(frozen=True)
class A2a:
    """The `a2a` mapping (O4 spec 6.2). `keys_bytes` is the key file as the reader that read `keys` holds it (the base
    revision on a pull or merge request, else the working tree), None when `keys` is set and the file is absent."""
    cards: tuple[str, ...] = ()
    keys: str | None = None
    agents: tuple[str, ...] = ()
    keys_bytes: bytes | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class Settings:
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    fail_on: str = "high"
    probe: bool = False
    probe_private: bool = False
    telemetry: bool = True
    connected: Connected = Connected()
    a2a: A2a = A2a()


def env_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    folded = value.strip().lower()
    if folded in _TRUE:
        return True
    if folded in _FALSE:
        return False
    return None


def load_settings(root: str, *, config: str | None, flags: Flags, env: Mapping[str, str],
                  read: Callable[[str, int], bytes] | None = None,
                  connected_read: Callable[[str, int], bytes] | None = None,
                  connected_credential: bool = False) -> Settings:
    """`config` is the `--config` file (a path chosen by whoever runs the scanner); without it `.spellwarden/config.yml`
    is read, when it exists: through `read(relative, max_bytes)` when given (on a pull or merge request, the base
    revision's file, `ci.revision_source`; spec 6.3, D35), else from the working tree, contained. With `config` and
    `connected_read` (a request: the base revision's reader), `connected.pack` and `connected.required` come from the
    base revision's `.spellwarden/config.yml` and the rest of the settings from `config` (O3 spec 6.2, P47).
    `connected_credential` says a credential (`SPELLWARDEN_ORG` or a key) is present: the base mapping is then
    refused when invalid instead of defaulting (invariant 5)."""
    document, name = _read(root, config, read)
    values = _validate(document, name) if document is not None else {}
    mapping = values.get("connected", {})
    a2a_mapping = values.get("a2a", {})
    keys_read = read
    if config is not None and connected_read is not None:
        base_mapping = _base_connected(root, connected_read, strict=connected_credential)
        # O4 spec 6.2: on a request the base revision decides the agents and the keys, `--config` the cards
        base_a2a = _base_a2a(root, connected_read, strict=connected_credential)
        a2a_mapping = {"cards": a2a_mapping.get("cards", []), "keys": base_a2a.get("keys"), "agents": base_a2a.get("agents", [])}
        keys_read = connected_read
    else:
        base_mapping = mapping
    fail_on = flags.fail_on or _env_choice(env, "SPELLWARDEN_FAIL_ON") or values.get("fail-on") or "high"
    probe = _first(flags.probe, _env_flag(env, "SPELLWARDEN_PROBE"), values.get("probe"), False)
    probe_private = _first(flags.probe_private, _env_flag(env, "SPELLWARDEN_PROBE_PRIVATE"), False)
    # Telemetry is off when any source says so (spec 6.10: "off with any of").
    telemetry_off = (flags.telemetry is False or _env_flag(env, "SPELLWARDEN_TELEMETRY") is False
                     or env_bool(env.get("DO_NOT_TRACK")) is True or values.get("telemetry") is False)
    upload = _first(flags.upload, _env_flag(env, "SPELLWARDEN_UPLOAD"), mapping.get("upload"), True)
    connected = Connected(pack=base_mapping.get("pack"), upload=upload, required=base_mapping.get("required", False))
    keys = a2a_mapping.get("keys")
    a2a = A2a(cards=tuple(a2a_mapping.get("cards", ())), keys=keys, agents=tuple(a2a_mapping.get("agents", ())),
              keys_bytes=_read_keys(root, keys, keys_read) if keys else None)
    return Settings(include=tuple(values.get("include", ())), exclude=tuple(values.get("exclude", ())),
                    fail_on=fail_on, probe=probe, probe_private=probe_private, telemetry=not telemetry_off,
                    connected=connected, a2a=a2a)


def _base_connected(root: str, read: Callable[[str, int], bytes], *, strict: bool) -> dict:
    """The `connected` mapping alone of the base revision's file, validated on its own. The rest of that file is not
    the operator's choice under `--config` (1.1.1 never read it), so in free mode a base file that cannot be read or
    parsed, or whose other keys are invalid, gives the defaults rather than refusing a scan (invariant 1). The
    defaults must not weaken connected mode (invariant 5): with a credential present (`strict`), or when the base
    mapping says `required` with a defect elsewhere in it, the defect is `settings_invalid` as without `--config`."""
    try:
        document, name = _read(root, None, read)
    except SettingsError:
        if strict:
            raise
        return {}
    if document is None:
        return {}
    if not isinstance(document, dict):
        if strict:
            raise SettingsError(f"{name}: the file must be a mapping with `version: 1`")
        return {}
    mapping = document.get("connected")
    if mapping is None:
        return {}
    try:
        _validate_connected(mapping, name)
    except SettingsError:
        if strict or (isinstance(mapping, dict) and bool(mapping.get("required"))):
            raise
        return {}
    return mapping


def _base_a2a(root: str, read: Callable[[str, int], bytes], *, strict: bool) -> dict:
    """The `a2a` mapping alone of the base revision's file, validated on its own (O4 spec 6.2): the rest of that file is not the
    operator's choice under `--config`. A base file that cannot be read or parsed, or that has no `a2a` mapping, gives no
    agents and no keys (with a credential present, `strict`, an unreadable file is refused instead); an invalid `a2a`
    mapping is always `settings_invalid`: it is the base revision's own statement and the trust root of the signatures."""
    try:
        document, name = _read(root, None, read)
    except SettingsError:
        if strict:
            raise
        return {}
    if not isinstance(document, dict) or document.get("a2a") is None:
        return {}
    return _validate_a2a(document["a2a"], name)


def _read_keys(root: str, relative: str, reader: Callable[[str, int], bytes] | None) -> bytes | None:
    """The key file `relative` through the reader that read the setting that names it; None when it is absent. A file that
    cannot be read is `settings_invalid`: a trusted key file that cannot be read must not silently become "no keys"."""
    try:
        if reader is not None:
            return reader(relative, A2A_KEYS_MAX)
        return paths.read_contained(root, relative, max_bytes=A2A_KEYS_MAX)[0]
    except FileNotFoundError:
        return None
    except paths.TooLarge as exc:
        raise SettingsError(f"a2a.keys: {relative} is over {A2A_KEYS_MAX} bytes") from exc
    except (paths.UnsafePath, OSError) as exc:
        raise SettingsError(f"a2a.keys: {relative} cannot be read ({exc})") from exc


def _first(*values):
    return next(value for value in values if value is not None)


def _env_flag(env: Mapping[str, str], name: str) -> bool | None:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return None
    value = env_bool(raw)
    if value is None:
        raise SettingsError(f"{name}: {raw!r} is not one of true, false, 1, 0, yes, no, on, off")
    return value


def _env_choice(env: Mapping[str, str], name: str) -> str | None:
    raw = (env.get(name) or "").strip()
    if not raw:
        return None
    if raw not in FAIL_ON:
        raise SettingsError(f"{name}: {raw!r} is not one of {', '.join(FAIL_ON)}")
    return raw


def _read(root: str, config: str | None, read: Callable[[str, int], bytes] | None) -> tuple[object | None, str]:
    if config is not None:
        name = config
        try:
            with open(config, "rb") as handle:
                data = handle.read(safe_yaml.CONFIG_MAX + 1)
        except OSError as exc:
            raise SettingsError(f"{name}: cannot be read ({exc.strerror})") from exc
    else:
        name = CONFIG_PATH
        try:
            if read is not None:
                data = read(CONFIG_PATH, safe_yaml.CONFIG_MAX)
            else:
                data, _ = paths.read_contained(root, CONFIG_PATH, max_bytes=safe_yaml.CONFIG_MAX)
        except FileNotFoundError:
            return None, name
        except paths.TooLarge as exc:
            raise SettingsError(f"{name}: refused (too_large): more than {safe_yaml.CONFIG_MAX} bytes") from exc
        except (paths.UnsafePath, OSError) as exc:
            raise SettingsError(f"{name}: cannot be read ({exc})") from exc
    try:
        return safe_yaml.loads(data, max_bytes=safe_yaml.CONFIG_MAX, name=name), name
    except safe_yaml.YamlRefused as exc:
        raise SettingsError(str(exc)) from exc


def _validate(document: object, name: str) -> dict:
    """Hand-written check of `schemas/settings.schema.json` (no run-time JSON Schema dependency)."""
    if not isinstance(document, dict):
        raise SettingsError(f"{name}: the file must be a mapping with `version: 1`")
    for key in document:
        if key == "probe-private":
            raise SettingsError(f"{name}: unknown key 'probe-private' (private probing is set by --probe-private, "
                                "never by the scanned revision)")
        if key not in _KEYS:
            raise SettingsError(f"{name}: unknown key {str(key)!r}")
    if document.get("version") != 1 or isinstance(document.get("version"), bool):
        raise SettingsError(f"{name}: `version` must be 1")
    for key in ("include", "exclude"):
        value = document.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise SettingsError(f"{name}: `{key}` must be a list of non-empty strings")
    if "fail-on" in document and document["fail-on"] not in FAIL_ON:
        raise SettingsError(f"{name}: `fail-on` must be one of {', '.join(FAIL_ON)}")
    for key in ("probe", "telemetry"):
        if key in document and not isinstance(document[key], bool):
            raise SettingsError(f"{name}: `{key}` must be true or false")
    if "connected" in document:
        _validate_connected(document["connected"], name)
    values = dict(document)
    if "a2a" in document:
        values["a2a"] = _validate_a2a(document["a2a"], name)
    return values


def _validate_a2a(mapping: object, name: str) -> dict:
    """The `a2a` mapping of `schemas/settings.schema.json`: `cards` (at most 50 relative paths inside the scan root), `keys`
    (one such path) and `agents` (at most 20 absolute http or https URLs of at most 1000 characters, without userinfo, a
    fragment or `${`). An `http://` agent is accepted here and never fetched (O4 spec 6.2)."""
    if not isinstance(mapping, dict):
        raise SettingsError(f"{name}: `a2a` must be a mapping with the keys {', '.join(_A2A_KEYS)}")
    for key in mapping:
        if key not in _A2A_KEYS:
            raise SettingsError(f"{name}: a2a: unknown key {str(key)!r}")
    for key, limit in (("cards", A2A_MAX_CARDS), ("agents", A2A_MAX_AGENTS)):
        value = mapping.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise SettingsError(f"{name}: `a2a.{key}` must be a list of non-empty strings")
        if len(value) > limit:
            raise SettingsError(f"{name}: `a2a.{key}` lists {len(value)} entries; at most {limit}")
    if "keys" in mapping and (not isinstance(mapping["keys"], str) or not mapping["keys"]):
        raise SettingsError(f"{name}: `a2a.keys` must be one relative path")
    paths_named = [("cards", relative) for relative in mapping.get("cards", [])]
    paths_named += [("keys", mapping["keys"])] if "keys" in mapping else []
    for key, relative in paths_named:
        try:
            contain("", relative)
        except UnsafePath as exc:
            raise SettingsError(f"{name}: `a2a.{key}`: {relative!r} is not a path inside the scan root ({exc})") from exc
    for url in mapping.get("agents", []):
        _check_agent_url(url, name)
    return dict(mapping)


def _check_agent_url(url: str, name: str) -> None:
    problem = None
    if len(url) > A2A_AGENT_URL_MAX:
        problem = f"is longer than {A2A_AGENT_URL_MAX} characters"
    elif "${" in url:
        problem = "holds a ${...} reference"
    else:
        try:
            parts = urlsplit(url)
            host = parts.hostname
            port = parts.port
        except ValueError:
            parts, host, port = None, None, None
        if parts is None or parts.scheme not in ("http", "https") or not host:
            problem = "is not an absolute http or https URL"
        elif parts.username is not None or parts.password is not None or "@" in parts.netloc:
            problem = "holds userinfo"
        elif "#" in url:
            problem = "holds a fragment"
        elif port == 0:
            problem = "has port 0"
    if problem is not None:
        raise SettingsError(f"{name}: `a2a.agents`: {url[:80]!r} {problem}")


def _validate_connected(mapping: object, name: str) -> None:
    if not isinstance(mapping, dict):
        raise SettingsError(f"{name}: `connected` must be a mapping with the keys {', '.join(_CONNECTED_KEYS)}")
    for key in mapping:
        if key not in _CONNECTED_KEYS:
            raise SettingsError(f"{name}: connected: unknown key {str(key)!r}")
    pack = mapping.get("pack")
    if "pack" in mapping and (not isinstance(pack, str) or CONNECTED_PACK_RE.fullmatch(pack) is None):
        raise SettingsError(f"{name}: `connected.pack` must be baseline or a 32 character pack id, optionally followed "
                            "by @ and a version such as 1.4")
    for key in ("upload", "required"):
        if key in mapping and not isinstance(mapping[key], bool):
            raise SettingsError(f"{name}: `connected.{key}` must be true or false")


__all__ = ["A2A_KEYS_MAX", "A2A_MAX_AGENTS", "A2A_MAX_CARDS", "A2a", "CONFIG_PATH", "CONNECTED_PACK_RE", "FAIL_ON", "Connected",
           "Flags", "Settings", "SettingsError", "env_bool", "glob_match", "load_settings"]
