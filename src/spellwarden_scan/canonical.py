"""The canonical package hash (spec 5.5): SHA-256 over `path NUL content NUL`
for every path in byte-wise sorted order."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping


def canonical_sha256(files: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda p: p.encode("utf-8")):
        digest.update(path.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(files[path])
        digest.update(b"\x00")
    return digest.hexdigest()
