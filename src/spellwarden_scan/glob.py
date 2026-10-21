"""The bounded path glob (phase O spec 6.3, Phase C spec 5.1): `fnmatch` per path segment, `**` for any number of
segments. One implementation for the CLI's `include` and `exclude` settings and the `files` of an org pattern
rule; moved here from `spellwarden_cli/settings.py` unchanged, because the engine may not import the CLI."""
from __future__ import annotations

import fnmatch


def glob_match(path: str, pattern: str) -> bool:
    """`fnmatch` per path segment (`*` never crosses `/`); a `**` segment matches zero or more segments.
    Patterns come from the scanned revision, so matching is bounded (spec 6.3): no recursion, and at most one
    segment comparison per (path segment, pattern segment) pair."""
    return _match(path.split("/"), pattern.strip("/").split("/"))


def _match(parts: list[str], pattern: list[str]) -> bool:
    # `reached` holds every count of path segments that the pattern segments read so far can consume.
    # A run of `**` collapses for free: `**` maps the set to everything from its smallest member up.
    reached = {0}
    for segment in pattern:
        if segment == "**":
            reached = set(range(min(reached), len(parts) + 1))
        else:
            reached = {index + 1 for index in reached
                       if index < len(parts) and fnmatch.fnmatchcase(parts[index], segment)}
        if not reached:
            return False
    return len(parts) in reached


__all__ = ["glob_match"]
