"""Spec 6.13 (plan decision P2): `contain` joins only paths that stay under their base."""
from __future__ import annotations

import pytest

from spellwarden_scan.relpath import UnsafePath, contain


@pytest.mark.parametrize("base, relative, joined", [
    ("", "./plugins/infra", "plugins/infra"),
    ("", "plugins/infra/", "plugins/infra"),
    ("tools", "./plugins/infra", "tools/plugins/infra"),
    ("tools/", "hooks/hooks.json", "tools/hooks/hooks.json"),
    ("", "a.b/c..d", "a.b/c..d"),
])
def test_contained_paths_are_joined(base, relative, joined):
    assert contain(base, relative) == joined


@pytest.mark.parametrize("relative", ["", "/x", "./../x", "../x", "a/../../x", "C:\\x", "C:x", "\\\\server\\share",
                                      "..\\x", "a\\b", "a//b", "./", ".", "a/./b", "a\x00b"])
def test_unsafe_paths_are_refused(relative):
    with pytest.raises(UnsafePath) as caught:
        contain("plugins", relative)
    assert caught.value.code == "unsafe_path"


def test_a_non_string_is_refused():
    with pytest.raises(UnsafePath):
        contain("", None)  # type: ignore[arg-type]
