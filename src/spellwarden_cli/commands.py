"""Shared steps of the commands other than `scan` (spec 6.2, 6.6, 6.7): the scan root, the settings, a report
without probes, and atomic writes of `.spellwarden/` files that refuse symbolic links."""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from datetime import UTC, date, datetime

from spellwarden_cli import escape, run
from spellwarden_cli.report import Report
from spellwarden_cli.settings import Flags, Settings, SettingsError, load_settings

_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class CommandError(Exception):
    """A refusal that ends a command with exit 2; `fail` prints the message escaped."""


def scan_root(path: str) -> str:
    root = os.path.realpath(path)
    if not os.path.isdir(root):
        raise CommandError(f"{path} is not a directory")
    return root


def today() -> date:
    return datetime.now(UTC).date()


def iso_date(text: str) -> date:
    """The argparse type of `--as-of` and `--expires`: exactly `YYYY-MM-DD` (3.11's `fromisoformat` accepts more)."""
    if not _DATE.fullmatch(text):
        raise argparse.ArgumentTypeError(f"{text!r} is not a YYYY-MM-DD date")
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a valid date") from None


def settings_for(root: str, env: Mapping[str, str]) -> Settings:
    try:
        return load_settings(root, config=None, flags=Flags(), env=env)
    except SettingsError as exc:
        raise CommandError(str(exc)) from exc


def current_report(root: str, *, as_of: date, env: Mapping[str, str]) -> Report:
    """A scan of `root` as the baseline commands need it: the settings file's include and exclude apply, the
    probe never runs (these commands make no network call), the baseline in place is applied."""
    settings = dataclasses.replace(settings_for(root, env), probe=False)
    return run.scan(run.ScanOptions(root=root, settings=settings, as_of=as_of, env=dict(env)))


def write_in_root(root: str, relative: str, data: bytes) -> None:
    """Writes `root/relative` atomically (a temporary file in the same directory, then a rename). A symbolic link
    at any directory or at the target is refused, so a checked-out link cannot send the write outside the root."""
    parts = relative.split("/")
    current = root
    for part in parts[:-1]:
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise CommandError(f"{relative}: {part} is a symbolic link")
        os.makedirs(current, exist_ok=True)
    target = os.path.join(current, parts[-1])
    if os.path.islink(target):
        raise CommandError(f"{relative} is a symbolic link")
    handle, temporary = tempfile.mkstemp(dir=current, prefix=".spellwarden-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
        os.chmod(temporary, 0o644)
        os.replace(temporary, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def fail(message: str) -> int:
    print(f"spellwarden: error: {escape.terminal(message)}", file=sys.stderr)
    return 2
