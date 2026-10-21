"""`.spellwarden/config.yml` and the flag, environment, file, default
precedence (spec 6.3). Unknown keys are errors; `probe-private` is never a
settings key, so the scanned revision cannot grant itself private probing."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from spellwarden_cli import paths, safe_yaml
from spellwarden_scan.glob import glob_match

CONFIG_PATH = ".spellwarden/config.yml"
FAIL_ON = ("critical", "high", "medium", "low", "never")
_KEYS = ("version", "include", "exclude", "fail-on", "probe", "telemetry")
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


@dataclass(frozen=True)
class Settings:
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    fail_on: str = "high"
    probe: bool = False
    probe_private: bool = False
    telemetry: bool = True


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
                  read: Callable[[str, int], bytes] | None = None) -> Settings:
    """`config` is the `--config` file (a path chosen by whoever runs the scanner); without it `.spellwarden/config.yml`
    is read, when it exists: through `read(relative, max_bytes)` when given (on a pull or merge request, the base
    revision's file, `ci.revision_source`; spec 6.3, D35), else from the working tree, contained."""
    document, name = _read(root, config, read)
    values = _validate(document, name) if document is not None else {}
    fail_on = flags.fail_on or _env_choice(env, "SPELLWARDEN_FAIL_ON") or values.get("fail-on") or "high"
    probe = _first(flags.probe, _env_flag(env, "SPELLWARDEN_PROBE"), values.get("probe"), False)
    probe_private = _first(flags.probe_private, _env_flag(env, "SPELLWARDEN_PROBE_PRIVATE"), False)
    # Telemetry is off when any source says so (spec 6.10: "off with any of").
    telemetry_off = (flags.telemetry is False or _env_flag(env, "SPELLWARDEN_TELEMETRY") is False
                     or env_bool(env.get("DO_NOT_TRACK")) is True or values.get("telemetry") is False)
    return Settings(include=tuple(values.get("include", ())), exclude=tuple(values.get("exclude", ())),
                    fail_on=fail_on, probe=probe, probe_private=probe_private, telemetry=not telemetry_off)


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
    return dict(document)


__all__ = ["CONFIG_PATH", "FAIL_ON", "Flags", "Settings", "SettingsError", "env_bool", "glob_match", "load_settings"]
