"""The JSON report (spec 6.9). `ensure_ascii` writes every non-ASCII character as `\\uXXXX`, so a bidirectional
or invisible character from the scanned revision is inert wherever the file is shown (spec 6.13)."""
from __future__ import annotations

import json

from spellwarden_cli.report import Report, to_json_dict


def render(report: Report) -> str:
    return json.dumps(to_json_dict(report), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
