"""P6-15 spec 6.12 E-9: before a release is published, every baseline rule's page answers. For each rule of
`RuleSet.baseline()`, a GET of its page (`Rule.page`, the address without campaign tags) must answer 200 itself, with no redirect,
and its body must hold the rule id. The release workflow's job `rule-pages` runs it before the jobs that publish; `make check`
never does, because every test runs offline (tests/test_check_rule_pages.py checks the logic with a stand-in for the network).

    uv run --locked python scripts/check-rule-pages.py
"""
from __future__ import annotations

import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable

from spellwarden_scan import RuleSet

TIMEOUT = 20
USER_AGENT = "spellwarden-release-check"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer of its own here: the page's address must be the page."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002 -- the handler's signature
        return None


def fetch(url: str) -> tuple[int, str]:
    """The status and the body of a GET of `url`, without following a redirect."""
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, ""


def problems(pages: Iterable[tuple[str, str]], get: Callable[[str], tuple[int, str]] = fetch) -> list[str]:
    """One line per rule whose page does not answer 200 with the rule id in its body; `pages` holds `(rule id, page)` pairs."""
    found = []
    for rule_id, page in pages:
        try:
            status, body = get(page)
        except OSError as error:
            found.append(f"{rule_id}: {page} could not be read ({type(error).__name__})")
            continue
        if status != 200:
            found.append(f"{rule_id}: {page} answered {status}, not 200")
        elif rule_id not in body:
            found.append(f"{rule_id}: {page} answered 200 without the rule id in its body")
    return found


def pages() -> list[tuple[str, str]]:
    return [(rule.id, rule.page) for rule in RuleSet.baseline() if rule.page is not None]


def main() -> int:
    listed = pages()
    found = problems(listed)
    for line in found:
        print(line, file=sys.stderr)
    print(f"{len(listed) - len(found)} of {len(listed)} rule pages answer")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
