"""The canonical package hash (spec 5.5): SHA-256 over `path NUL content NUL`
for every path in byte-wise sorted order. A path is encoded with `text.utf8` (1.18.0), so a caller's path that holds a lone
surrogate hashes as its U+FFFD form instead of raising; any other path gives the bytes it always gave."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping

from spellwarden_scan.text import utf8


def canonical_sha256(files: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for path in sorted(files, key=utf8):
        digest.update(utf8(path))
        digest.update(b"\x00")
        digest.update(files[path])
        digest.update(b"\x00")
    return digest.hexdigest()
