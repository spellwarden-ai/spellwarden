"""The containment rule of spec 6.13 as a pure string function (plan decision P2): a path read from the scanned
revision (a marketplace's local plugin source, a plugin manifest's reference, a listed file) is joined to a base
directory only when it cannot leave it. `spellwarden_cli.paths` re-exports `contain` and `UnsafePath`."""
from __future__ import annotations

import re

_DRIVE = re.compile(r"^[A-Za-z]:")


class UnsafePath(ValueError):
    """A relative path that is empty, absolute, drive- or UNC-qualified, or that could leave its base."""

    code = "unsafe_path"


def contain(base: str, relative: str) -> str:
    """`relative` joined to `base`, both POSIX paths relative to the scan root (`""` is the root). Refused: an empty
    path, a leading `/`, a drive (`C:`) or UNC (`\\\\`) prefix, any backslash, a NUL, a `..` segment, and a `.` or
    empty segment once one leading `./` and one trailing `/` are removed."""
    if not isinstance(relative, str) or relative == "":
        raise UnsafePath("empty path")
    if "\x00" in relative:
        raise UnsafePath("NUL in path")
    if "\\" in relative:
        raise UnsafePath("backslash in path")
    if relative.startswith("/"):
        raise UnsafePath("absolute path")
    if _DRIVE.match(relative):
        raise UnsafePath("drive-qualified path")
    rest = relative[2:] if relative.startswith("./") else relative
    if rest.endswith("/"):
        rest = rest[:-1]
    segments = rest.split("/")
    for segment in segments:
        if segment == "..":
            raise UnsafePath("parent segment")
        if segment in ("", "."):
            raise UnsafePath("empty or dot segment")
    base = base.strip("/")
    joined = f"{base}/{rest}" if base else rest
    if base and not joined.startswith(base + "/"):
        raise UnsafePath("outside its base")
    return joined
