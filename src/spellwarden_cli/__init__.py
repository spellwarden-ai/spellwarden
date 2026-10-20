"""spellwarden_cli: the `spellwarden` command (spec 6). The engine
(`spellwarden_scan`) is pure; this package does the I/O around it: files,
git, settings, outputs and, only where spec 6.8 to 6.11 allow, the network."""
from __future__ import annotations

from spellwarden_scan.version import RULES_VERSION, __version__

__all__ = ["RULES_VERSION", "__version__"]
