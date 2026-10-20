"""`.spellwarden/baseline.yml` (spec 6.7): accepted findings, each with a reason, an addition date and an expiry
date. An entry suppresses its fingerprint while `added <= as_of <= expires`; an invalid entry suppresses nothing
and makes the scan exit 2. The commands `baseline add`, `prune` and `list` live here."""
from __future__ import annotations

import argparse
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta

from spellwarden_scan.model import Finding

from spellwarden_cli import commands, escape, paths, safe_yaml
from spellwarden_cli.report import Notice, ReportFinding

BASELINE_PATH = ".spellwarden/baseline.yml"
MALICIOUS_RULES = frozenset({"SW-SKL-004", "SW-SKL-008", "SW-CFG-006", "SW-CFG-007"})
MAX_SPAN_DAYS = 365
MALICIOUS_SPAN_DAYS = 30
DEFAULT_DAYS = 90
PRUNE_GRACE_DAYS = 30
REASON_MAX = 1000
_FINGERPRINT = re.compile(r"[0-9a-fA-F]{64}")
# The shape of a rule id, as `schemas/baseline.schema.json` states it (always used with `fullmatch`; ASCII digits only).
RULE_ID = re.compile(r"SW-(SKL|MCP|CFG)-[0-9]{3}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_TOP_KEYS = frozenset({"version", "accepted"})
_ENTRY_KEYS = frozenset({"fingerprint", "rule", "path", "reason", "added", "expires"})
_TEXT_KEYS = ("fingerprint", "rule", "path", "reason")
# Characters YAML may not hold raw, or reads as a line break inside a double-quoted scalar: escaped as \u or \U.
_YAML_UNSAFE = re.compile("[^\t\n\r\x20-\x7e\xa0-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]|[\x85\u2028\u2029\ufeff]")


class BaselineError(ValueError):
    """The file cannot be used at all (refused YAML, wrong shape, unknown key): exit 2, nothing suppressed."""


@dataclass(frozen=True)
class Entry:
    fingerprint: str
    rule: str
    path: str
    reason: str
    added: date
    expires: date


@dataclass(frozen=True)
class Baseline:
    entries: tuple[Entry, ...] = ()
    invalid: tuple[Notice, ...] = ()


def _date_of(value: object) -> date | None:
    """A YAML date (`2026-12-01` loads as `datetime.date`) or a `YYYY-MM-DD` string; a timestamp is not a date."""
    if isinstance(value, datetime):
        return None
    if isinstance(value, date):
        return value
    if isinstance(value, str) and _DATE.fullmatch(value):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _entry_of(raw: Mapping) -> tuple[Entry | None, str | None]:
    """The entry, or the reason it is invalid, for the checks that do not depend on the evaluation date."""
    fingerprint = raw.get("fingerprint") or ""
    if not _FINGERPRINT.fullmatch(fingerprint):
        return None, "fingerprint must be 64 hexadecimal characters"
    reason = raw.get("reason") or ""
    if not reason.strip():
        return None, "reason is missing"
    added, expires = _date_of(raw.get("added")), _date_of(raw.get("expires"))
    if added is None:
        return None, "added must be a YYYY-MM-DD date"
    if expires is None:
        return None, "expires must be a YYYY-MM-DD date"
    if added > expires:
        return None, f"added {added.isoformat()} is after expires {expires.isoformat()}"
    span = (expires - added).days
    if span > MAX_SPAN_DAYS:
        return None, f"expires is {span} days after added; the limit is {MAX_SPAN_DAYS} days"
    rule = raw.get("rule") or ""
    if rule in MALICIOUS_RULES and span > MALICIOUS_SPAN_DAYS:
        return None, f"{rule} is a malicious-indicator rule: at most {MALICIOUS_SPAN_DAYS} days between added and expires"
    return Entry(fingerprint.lower(), rule, raw.get("path") or "", reason, added, expires), None


def parse_baseline(document: object, *, name: str = BASELINE_PATH) -> Baseline:
    if not isinstance(document, dict):
        raise BaselineError(f"{name} must be a mapping with `version: 1`")
    unknown = sorted(str(key) for key in document if key not in _TOP_KEYS)
    if unknown:
        raise BaselineError(f"{name}: unknown key {unknown[0]!r}")
    version = document.get("version")
    if type(version) is not int or version != 1:
        raise BaselineError(f"{name}: version must be 1")
    accepted = document.get("accepted")
    if accepted is None:
        accepted = []
    if not isinstance(accepted, list):
        raise BaselineError(f"{name}: accepted must be a list")
    entries: list[Entry] = []
    invalid: list[Notice] = []
    for number, raw in enumerate(accepted, start=1):
        if not isinstance(raw, dict):
            raise BaselineError(f"{name}: entry {number} is not a mapping")
        unknown = sorted(str(key) for key in raw if key not in _ENTRY_KEYS)
        if unknown:
            raise BaselineError(f"{name}: entry {number} has the unknown key {unknown[0]!r}")
        for key in _TEXT_KEYS:
            if raw.get(key) is not None and not isinstance(raw[key], str):
                raise BaselineError(f"{name}: entry {number}: {key} must be text")
        if raw.get("rule") and not RULE_ID.fullmatch(raw["rule"]):
            raise BaselineError(f"{name}: entry {number}: rule must be a rule id such as SW-SKL-007")
        entry, problem = _entry_of(raw)
        if entry is None:
            invalid.append(Notice("baseline_invalid", name, f"entry {number}: {problem}"))
        else:
            entries.append(entry)
    return Baseline(tuple(entries), tuple(invalid))


def load_baseline(root: str, relative: str = BASELINE_PATH, *, required: bool = False) -> Baseline:
    try:
        relative = paths.contain("", relative)
    except paths.UnsafePath as exc:
        raise BaselineError(f"{relative}: the baseline must be a path inside the scan root") from exc
    try:
        data, _mode = paths.read_contained(root, relative, max_bytes=safe_yaml.BASELINE_MAX)
    except FileNotFoundError:
        if required:
            raise BaselineError(f"{relative} does not exist") from None
        return Baseline()
    except paths.TooLarge as exc:
        raise BaselineError(f"{relative} is larger than {safe_yaml.BASELINE_MAX} bytes") from exc
    except (OSError, paths.UnsafePath) as exc:
        raise BaselineError(f"{relative} cannot be read: {exc}") from exc
    try:
        document = safe_yaml.loads(data, max_bytes=safe_yaml.BASELINE_MAX, name=relative)
    except safe_yaml.YamlRefused as exc:
        raise BaselineError(str(exc)) from exc
    return parse_baseline(document, name=relative)


def _span(entry: Entry) -> int:
    return (entry.expires - entry.added).days


def _problem_at(entry: Entry, finding: Finding, as_of: date) -> str | None:
    """The checks that need the evaluation date or the matched finding."""
    if entry.added > as_of:
        return f"added {entry.added.isoformat()} is after the evaluation date {as_of.isoformat()}"
    if finding.malicious_indicator and _span(entry) > MALICIOUS_SPAN_DAYS:
        return (f"{finding.rule_id} is a malicious indicator: at most {MALICIOUS_SPAN_DAYS} days between added and "
                f"expires, this entry has {_span(entry)}")
    return None


def apply(baseline: Baseline, findings: Sequence[ReportFinding], *, as_of: date, name: str = BASELINE_PATH
          ) -> tuple[list[ReportFinding], list[Notice], list[Notice]]:
    """`(findings with their suppression, notices, errors)`. Idempotent: applying twice gives the same findings."""
    notices: list[Notice] = []
    errors: list[Notice] = list(baseline.invalid)
    reported: set[Entry] = set()
    by_fingerprint: dict[str, list[Entry]] = {}
    for entry in baseline.entries:
        by_fingerprint.setdefault(entry.fingerprint, []).append(entry)
    kept: list[ReportFinding] = []
    for item in findings:
        finding = item.finding
        chosen: Entry | None = None
        for entry in by_fingerprint.get(finding.fingerprint, ()):
            problem = _problem_at(entry, finding, as_of)
            if problem is not None:
                if entry not in reported:
                    reported.add(entry)
                    errors.append(Notice("baseline_invalid", name, f"{entry.fingerprint[:12]}: {problem}"))
                continue
            if as_of > entry.expires:
                notices.append(Notice("baseline_expired", finding.location.path,
                                      f"The acceptance of {finding.rule_id} ({entry.fingerprint[:12]}) expired on "
                                      f"{entry.expires.isoformat()}; the finding counts again."))
                continue
            chosen = entry
            break
        if chosen is None:
            kept.append(replace(item, suppressed=False, baseline=None))
            continue
        if (chosen.rule and chosen.rule != finding.rule_id) or (chosen.path and chosen.path != finding.location.path):
            notices.append(Notice("baseline_mismatch", finding.location.path,
                                  f"The entry {chosen.fingerprint[:12]} names {chosen.rule or '-'} {chosen.path or '-'}; "
                                  f"the finding is {finding.rule_id} {finding.location.path}. It still applies."))
        kept.append(replace(item, suppressed=True, baseline={"reason": chosen.reason, "added": chosen.added.isoformat(),
                                                              "expires": chosen.expires.isoformat()}))
    for entry in baseline.entries:
        if entry not in reported and entry.added > as_of:
            errors.append(Notice("baseline_invalid", name, f"{entry.fingerprint[:12]}: added {entry.added.isoformat()} "
                                                           f"is after the evaluation date {as_of.isoformat()}"))
    return kept, notices, errors


def entry_state(entry: Entry, *, as_of: date, current: Mapping[str, Finding]) -> str:
    finding = current.get(entry.fingerprint)
    if entry.added > as_of or (finding is not None and _problem_at(entry, finding, as_of) is not None):
        return "invalid"
    if as_of > entry.expires:
        return "expired"
    if finding is None:
        return "unmatched"
    return "active"


def _scalar(text: str) -> str:
    """A YAML double-quoted scalar: JSON's escaping (valid YAML) plus \\u escapes for what YAML reads otherwise."""
    quoted = json.dumps(text, ensure_ascii=False)
    return _YAML_UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}" if ord(m.group()) <= 0xFFFF else f"\\U{ord(m.group()):08x}",
                            quoted)


def render_baseline(entries: Sequence[Entry]) -> bytes:
    ordered = sorted(entries, key=lambda e: (e.path, e.rule, e.fingerprint))
    if not ordered:
        return b"version: 1\naccepted: []\n"
    lines = ["version: 1", "accepted:"]
    for entry in ordered:
        lines += [f"  - fingerprint: {_scalar(entry.fingerprint)}", f"    rule: {_scalar(entry.rule)}",
                  f"    path: {_scalar(entry.path)}", f"    reason: {_scalar(entry.reason)}",
                  f"    added: {entry.added.isoformat()}", f"    expires: {entry.expires.isoformat()}"]
    return ("\n".join(lines) + "\n").encode("utf-8")


# --- commands --------------------------------------------------------------------------------------------------------

def _days(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of days") from None
    if value < 1:
        raise argparse.ArgumentTypeError("--days must be at least 1")
    return value


def add_parser(commands_: argparse._SubParsersAction) -> None:
    parser = commands_.add_parser("baseline", help="Accept findings with a reason and an expiry date.")
    actions = parser.add_subparsers(dest="baseline_command", required=True, parser_class=type(parser))
    add = actions.add_parser("add", help="Accept findings in .spellwarden/baseline.yml.")
    add.add_argument("path", nargs="?", default=".")
    which = add.add_mutually_exclusive_group(required=True)
    which.add_argument("--fingerprint", nargs="+", metavar="FP", help="The fingerprints of the findings to accept.")
    which.add_argument("--all", action="store_true", help="Accept every current finding not yet accepted.")
    add.add_argument("--reason", required=True, help="Why the finding is acceptable; kept in the file.")
    until = add.add_mutually_exclusive_group()
    until.add_argument("--expires", type=commands.iso_date, metavar="YYYY-MM-DD")
    until.add_argument("--days", type=_days, metavar="N", help="Expiry after N days (default 90; 30 for a malicious indicator).")
    add.set_defaults(handler=cmd_add)
    prune = actions.add_parser("prune", help="Remove entries that match nothing or expired more than 30 days ago.")
    prune.add_argument("path", nargs="?", default=".")
    prune.set_defaults(handler=cmd_prune)
    listing = actions.add_parser("list", help="Print every entry with its state.")
    listing.add_argument("path", nargs="?", default=".")
    listing.set_defaults(handler=cmd_list)
    for sub in (add, prune, listing):
        sub.add_argument("--as-of", type=commands.iso_date, dest="as_of", metavar="YYYY-MM-DD",
                         help="The evaluation date (default: today in UTC).")


def _prepare(args: argparse.Namespace, *, rewrite: bool) -> tuple[str, date, Baseline]:
    root = commands.scan_root(args.path)
    try:
        existing = load_baseline(root)
    except BaselineError as exc:
        raise commands.CommandError(str(exc)) from exc
    if rewrite and existing.invalid:
        raise commands.CommandError(f"{BASELINE_PATH} has invalid entries; fix them first ({existing.invalid[0].message})")
    return root, args.as_of or commands.today(), existing


def _expiry(args: argparse.Namespace, finding: Finding, as_of: date) -> date:
    malicious = finding.malicious_indicator or finding.rule_id in MALICIOUS_RULES
    limit = MALICIOUS_SPAN_DAYS if malicious else MAX_SPAN_DAYS
    if args.expires is not None:
        expires = args.expires
    elif args.days is not None:
        expires = as_of + timedelta(days=args.days)
    else:
        expires = as_of + timedelta(days=min(DEFAULT_DAYS, limit))
    span = (expires - as_of).days
    if span < 0:
        raise commands.CommandError(f"the expiry {expires.isoformat()} is before the addition date {as_of.isoformat()}")
    if span > limit:
        kind = "a malicious indicator" if malicious else "a finding"
        raise commands.CommandError(f"{finding.rule_id} {finding.fingerprint[:12]}: {kind} can be accepted for at most "
                                    f"{limit} days; {expires.isoformat()} is {span} days after {as_of.isoformat()}")
    return expires


def cmd_add(args: argparse.Namespace) -> int:
    reason = args.reason
    if not reason.strip() or len(reason) > REASON_MAX:
        return commands.fail(f"--reason must hold between 1 and {REASON_MAX} characters")
    try:
        root, as_of, existing = _prepare(args, rewrite=True)
        report = commands.current_report(root, as_of=as_of, env=os.environ)
        if any(error.code == "baseline_invalid" for error in report.errors):
            raise commands.CommandError(f"{BASELINE_PATH} has invalid entries; fix them first")
        if args.all:
            chosen = [item.finding for item in report.findings if not item.suppressed]
        else:
            current = {item.finding.fingerprint: item.finding for item in report.findings}
            missing = [fp for fp in args.fingerprint if fp.lower() not in current]
            if missing:
                raise commands.CommandError(f"no current finding has the fingerprint {missing[0][:12]}")
            chosen = [current[fp.lower()] for fp in dict.fromkeys(args.fingerprint)]
        entries = {entry.fingerprint: entry for entry in existing.entries}
        for finding in chosen:
            entries[finding.fingerprint] = Entry(finding.fingerprint, finding.rule_id, finding.location.path, reason, as_of,
                                                 _expiry(args, finding, as_of))
        if not chosen:
            print("Nothing to accept: every current finding is already accepted or there are none.")
            return 0
        commands.write_in_root(root, BASELINE_PATH, render_baseline(list(entries.values())))
    except (commands.CommandError, OSError) as exc:
        return commands.fail(str(exc))
    print(f"Accepted {len(chosen)} finding{'s' if len(chosen) != 1 else ''} in {BASELINE_PATH}.")
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    try:
        root, as_of, existing = _prepare(args, rewrite=True)
        if not existing.entries:
            print("Nothing to prune.")
            return 0
        report = commands.current_report(root, as_of=as_of, env=os.environ)
        current = {item.finding.fingerprint for item in report.findings}
        cutoff = as_of - timedelta(days=PRUNE_GRACE_DAYS)
        kept = [entry for entry in existing.entries if entry.fingerprint in current and entry.expires >= cutoff]
        removed = len(existing.entries) - len(kept)
        if removed:
            commands.write_in_root(root, BASELINE_PATH, render_baseline(kept))
    except (commands.CommandError, OSError) as exc:
        return commands.fail(str(exc))
    print(f"Removed {removed} entr{'ies' if removed != 1 else 'y'} from {BASELINE_PATH}.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    try:
        root, as_of, existing = _prepare(args, rewrite=False)
        report = commands.current_report(root, as_of=as_of, env=os.environ)
    except commands.CommandError as exc:
        return commands.fail(str(exc))
    current = {item.finding.fingerprint: item.finding for item in report.findings}
    for entry in sorted(existing.entries, key=lambda e: (e.expires, e.fingerprint)):
        state = entry_state(entry, as_of=as_of, current=current)
        print(f"{state:<9} {entry.expires.isoformat()}  {entry.fingerprint[:12]}  {escape.terminal(entry.rule or '-')}  "
              f"{escape.terminal(entry.path or '-')}  {escape.terminal(entry.reason)}")
    for notice in existing.invalid:
        print(f"{'invalid':<9} {escape.terminal(notice.message)}")
    return 0
