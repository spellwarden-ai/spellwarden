"""`spellwarden scan --analyze` (Phase 4 batch B spec 11.3): after the rules, each skill's SKILL.md and scripts go to the
model endpoint the user names (`model_client.py`), and the report gains one `analysis` entry per skill (the fields of spec
6.4) and the notice `model_assisted`. Imported only under `--analyze`, so a scan without it builds no request and imports no
module of the model client.

Advisory everywhere (owner decision idea:Q4): an analysis is never a finding, and its verdicts never change the exit code,
a rule count or a `--fail-on` outcome. A skill the analyzer could not read (past `--analyze-max-bytes`, or a file that is
not text) is `incomplete` with its limit and the notice `analysis_incomplete`; whether that also makes the scan incomplete
is decided by `incomplete_analysis_is_scan_error` alone (spec:Q4, D23).

The cache (`--analyze-cache DIR`) holds analysed results only, one JSON file per package hash, analyzer version and model;
it never holds the key, a request or an answer's text. A cache file that cannot be read is analysed again, and a directory
that cannot be written is said in the notice `model_assisted`: neither ends the scan."""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from spellwarden_scan import analyzer
from spellwarden_scan.evidence import mask_credentials
from spellwarden_scan.identity import package_files, package_sha256

from spellwarden_cli.discover import Discovery, SkillPackage
from spellwarden_cli.files import FILE_MAX
from spellwarden_cli.report import Notice, ReportFinding
from spellwarden_cli.secret import Secret

ANALYZER_GUIDE_URL = ("https://spellwarden.ai/docs/model-assisted-analyzer?utm_source=scanner&utm_medium=cli"
                      "&utm_campaign=analyzer")
WAY = "endpoint"  # spec 6.4 `way`: the user's own endpoint (the hosted product's ways are `credits` and `gateway`)
CACHE_VERSION = 1


def incomplete_analysis_is_scan_error(limit_code: str) -> bool:
    """spec:Q4 and D23: when a skill is past the analyzer's bound (`too_large`) or holds a file that is not text (`not_text`),
    only the analysis is incomplete; the scan's errors, and so its exit code, are unchanged. The other answer (exit 2) is
    `return True` here, with its test (tests/cli/test_analyze_command.py) and the README's "Limits"."""
    if limit_code not in analyzer.LIMIT_CODES:
        raise ValueError(f"not a limit of the analyzer: {limit_code!r}")
    return False


@dataclass(frozen=True)
class AnalyzeOptions:
    """The flags of `--analyze` (spec 11.3); `key` is SPELLWARDEN_MODEL_KEY, None when unset."""
    endpoint: str
    model: str
    key: Secret | None = field(default=None, repr=False)
    max_bytes: int = analyzer.ANALYZER_MAX_BYTES
    cache_dir: str | None = None


def _root(skill: SkillPackage) -> str:
    return "" if skill.path == "." else skill.path


def _package_hash(skill: SkillPackage) -> str | None:
    identified = package_files(skill.engine_files(), _root(skill), skill.nested)
    return None if identified.unhashable else package_sha256(identified.files)


def cache_path(cache_dir: str, package_hash: str, model: str) -> str:
    """Spec 11.3: the cache file of one package hash, analyzer version and model."""
    digest = hashlib.sha256(f"{package_hash}\n{analyzer.ANALYZER_VERSION}\n{model}".encode()).hexdigest()
    return os.path.join(cache_dir, f"{digest}.json")


def _read_cache(path: str, package_hash: str, model: str) -> list[dict] | None:
    """The cached categories, or None when there is no usable entry (absent, unreadable, or not this key's)."""
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError, RecursionError):  # RecursionError: a file nested deeper than the JSON reader's stack
        return None
    if not isinstance(document, dict) or (document.get("cache"), document.get("package_sha256"), document.get(
            "analyzer_version"), document.get("model")) != (CACHE_VERSION, package_hash, analyzer.ANALYZER_VERSION, model):
        return None
    categories = document.get("categories")
    if (not isinstance(categories, list) or not all(_cached_category(entry) for entry in categories)
            or [entry["id"] for entry in categories] != list(analyzer.CATEGORIES)):
        return None
    return categories


_CACHED_KEYS = frozenset({"id", "verdict", "confidence", "summary", "spans", "spans_left_out"})
_SPAN_KEYS = frozenset({"path", "line", "text"})


def _cached_category(entry: object) -> bool:
    """A category as `CategoryVerdict.to_dict()` wrote it; anything else makes the cache file unusable (it is re-analysed).
    A cache file is trusted no more than an answer (r0:F4): the summary, the spans and their count must be within the caps
    `parse_reply` applies, and masking the summary or a span with `mask_credentials` must change nothing."""
    return (isinstance(entry, dict) and set(entry) == _CACHED_KEYS and entry["verdict"] in analyzer.VERDICTS
            and entry["confidence"] in analyzer.CONFIDENCE and _kept_text(entry["summary"], analyzer.SUMMARY_MAX)
            and type(entry["spans_left_out"]) is int and entry["spans_left_out"] >= 0 and isinstance(entry["spans"], list)
            and len(entry["spans"]) <= analyzer.MAX_SPANS
            and all(isinstance(span, dict) and set(span) == _SPAN_KEYS and isinstance(span["path"], str)
                    and type(span["line"]) is int and span["line"] >= 1 and _kept_text(span["text"], analyzer.SPAN_MAX)
                    for span in entry["spans"]))


def _kept_text(text: object, limit: int) -> bool:
    return isinstance(text, str) and len(text) <= limit and mask_credentials(text) == text


def _write_cache(path: str, package_hash: str, model: str, categories: list[dict]) -> bool:
    """Writes the cache file through a temporary file in its directory; False when the directory or the file cannot be
    written. A cache that cannot be kept never ends the scan (advisory, spec 11.3): the notice `model_assisted` says so."""
    document = {"cache": CACHE_VERSION, "package_sha256": package_hash, "analyzer_version": analyzer.ANALYZER_VERSION,
                "model": model, "categories": categories}
    name = None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handle = tempfile.NamedTemporaryFile(dir=os.path.dirname(path), prefix=".spellwarden-", delete=False)
        name = handle.name
        with handle:
            handle.write(json.dumps(document, sort_keys=True, ensure_ascii=True).encode("utf-8"))
        os.replace(name, path)
        return True
    except OSError:
        return False
    finally:
        if name is not None and os.path.exists(name):  # the temporary file of a write that did not finish
            try:
                os.unlink(name)
            except OSError:
                pass


def _entry(skill: SkillPackage, package_hash: str | None, options: AnalyzeOptions, status: str, **extra) -> dict:
    measured = analyzer.is_measured(options.model)
    entry = {"skill": skill.path, "skill_file": skill.as_written(skill.engine_key()), "status": status,
             "package_sha256": package_hash,
             "analyzer_version": analyzer.ANALYZER_VERSION, "model": options.model, "measured": measured is not None,
             "measured_on": measured_name(measured), "way": WAY, "run_id": None, "finished_at": None, "cached": False,
             "categories": []}
    entry.update(extra)
    return entry


def measured_name(key: str | None) -> str | None:
    """The model the rates were measured on, as spec 6.4's `measured_on` names it (the entry's display name)."""
    if key is None:
        return None
    return analyzer.MEASURED_MODELS[key].get("name", key)


def _with_rules(categories: list[dict], found: dict[str, bool], skill: SkillPackage) -> list[dict]:
    """The categories as the report shows them: `rules_found` added, and a span of the request's SKILL.md named as the
    repository writes the skill file (a case variant such as `skill.md`, r0:F2). The cache keeps the request's names."""
    written = posixpath.basename(skill.variant) if skill.variant is not None else analyzer.SKILL_FILE

    def span(one: dict) -> dict:
        return {**one, "path": written} if one["path"] == analyzer.SKILL_FILE else one

    return [{**category, "spans": [span(one) for one in category["spans"]], "rules_found": found[category["id"]]}
            for category in categories]


def limit_message(limit: analyzer.NotAnalyzed) -> str:
    """The notice `analysis_incomplete` (spec 4.8): the limit and the way out."""
    if limit.code == "too_large":
        return (f"Not analysed: SKILL.md and scripts are {limit.bytes:,} bytes, more than the {limit.max:,} the analyzer reads. "
                "Split the skill, or raise the bound with --analyze-max-bytes.")
    return f"Not analysed: {limit.path} is not UTF-8 text, and the analyzer reads text files only."


def _unread(found: Discovery, skill: SkillPackage, errors: Sequence[Notice] = (),
            refused: Mapping[str, str] | None = None) -> tuple[str, str] | None:
    """The file that makes the skill one the scan did not read whole (spec 4.8): `(path relative to the skill, why)`, else
    None. First a file of any kind whose front matter the engine refused (`front_matter`: `refused`, from `run.engine_findings`,
    maps the skill to it): then no rule judged the package, so nothing of it may be shown as analysed. Else the first file
    `analyzer.build_request` would send but the scan did not read: why is `link` (a member link that was not followed), `size`
    (a script over `FILE_MAX`, the scan's error `unreadable`, also listed in the file set's `too_large`) or `front_matter` (the
    error `unreadable` of the run's `errors`, which discovery never held). `skill.engine_files()` leaves such a file out, so
    sending the rest would show content the user controls as analysed."""
    prefix = "" if skill.path == "." else f"{skill.path}/"
    if refused is not None and skill.path in refused:
        return refused[skill.path][len(prefix):], "front_matter"
    links = set(skill.links)
    sized = {notice.path for notice in found.errors if notice.code == "unreadable"}
    if found.fileset is not None:
        sized.update(found.fileset.too_large)
    refused = {notice.path for notice in errors if notice.code == "unreadable"} - sized - links
    for path in sorted(sized | links | refused):
        if not path.startswith(prefix) or any(path.startswith(f"{nested}/") for nested in skill.nested):
            continue
        relative = path[len(prefix):]
        if analyzer.selects(relative, path, skill.executable):
            return relative, "link" if path in links else "front_matter" if path in refused else "size"
    return None


def _unread_message(relative: str, why: str) -> str:
    """The notice `analysis_incomplete` of a file the scan did not read: what it is and the way out."""
    if why == "front_matter":
        return (f"Not analysed: the front matter of {relative} is past a limit of the scanner, so the rules did not judge the "
                "skill and the analyzer cannot read it whole. Make the front matter smaller, or leave the skill out.")
    if why == "link":
        return (f"Not analysed: {relative} is a symbolic link the scan did not follow, so the analyzer cannot read the skill "
                "whole. Replace the link with the file it leads to.")
    return (f"Not analysed: {relative} is larger than {FILE_MAX // 2**20} MiB and was not read, so the analyzer cannot read "
            "the skill whole. Make the file smaller, or leave it out of the skill.")


def analyse(found: Discovery, findings: Sequence[ReportFinding], options: AnalyzeOptions, notices: list[Notice],
            errors: list[Notice], *, client_factory: Callable[[AnalyzeOptions], object] | None = None,
            refused: Mapping[str, str] | None = None) -> tuple[dict, ...]:
    """One `analysis` entry per skill, in path order; appends `analysis_incomplete` notices (or errors, by
    `incomplete_analysis_is_scan_error`) and the one `model_assisted` notice. `findings` are the scan's, after the baseline:
    a category whose rules have an open finding in the skill carries `rules_found: true`. `refused` is `run.engine_findings`'s
    map of the packages whose front matter it refused: such a skill is `incomplete` and nothing is sent for it."""
    if client_factory is None:
        from spellwarden_cli import model_client  # here: only a scan with --analyze imports the network module

        def client_factory(opts: AnalyzeOptions):
            return model_client.ModelClient(opts.endpoint, opts.model, opts.key)

    client = client_factory(options)
    open_ids: dict[str, set[str]] = {}
    for item in findings:
        if not item.suppressed:
            open_ids.setdefault(item.item, set()).add(item.finding.rule_id)
    entries: list[dict] = []
    unwritten: list[str] = []  # the skills whose result the cache directory could not keep
    for skill in sorted(found.skills, key=lambda one: one.path):
        package_hash = _package_hash(skill)
        rules = analyzer.rules_found(open_ids.get(skill.path, ()))
        unread = _unread(found, skill, errors, refused)
        if unread is not None:  # before the cache and the request: nothing is sent or kept for a skill not read whole
            prefix = "" if skill.path == "." else f"{skill.path}/"
            # a file whose front matter was refused was read, so its size is known; the others were not read (10 MiB or more)
            size = len(skill.files.get(prefix + unread[0], b"")) if unread[1] == "front_matter" else FILE_MAX
            limit = analyzer.NotAnalyzed("too_large", bytes=size, max=options.max_bytes, path=unread[0])
            notice = Notice("analysis_incomplete", skill.path, _unread_message(*unread))
            (errors if incomplete_analysis_is_scan_error(limit.code) else notices).append(notice)
            entries.append(_entry(skill, package_hash, options, "incomplete", limit=limit.to_dict()))
            continue
        cached_path = cache_path(options.cache_dir, package_hash, options.model) if options.cache_dir and package_hash else None
        cached = _read_cache(cached_path, package_hash, options.model) if cached_path else None
        if cached is not None:
            entries.append(_entry(skill, package_hash, options, "analyzed", cached=True,
                                  categories=_with_rules(cached, rules, skill)))
            continue
        request = analyzer.build_request(skill.engine_files(), root=_root(skill), max_bytes=options.max_bytes,
                                         executable_paths=skill.engine_executable())
        if isinstance(request, analyzer.NotAnalyzed):
            notice = Notice("analysis_incomplete", skill.path, limit_message(request))
            (errors if incomplete_analysis_is_scan_error(request.code) else notices).append(notice)
            entries.append(_entry(skill, package_hash, options, "incomplete", limit=request.to_dict()))
            continue
        entries.append(_call(skill, package_hash, options, client, request, rules, cached_path, unwritten))
    notices.append(summary_notice(entries, options, cache_unwritable=bool(unwritten)))
    return tuple(entries)


def _call(skill: SkillPackage, package_hash: str | None, options: AnalyzeOptions, client, request: analyzer.AnalyzerRequest,
          rules: dict[str, bool], cached_path: str | None, unwritten: list[str]) -> dict:
    from spellwarden_cli.model_client import ModelError

    try:
        reply = client.complete(request.system, request.user, max_tokens=analyzer.ANALYZER_MAX_TOKENS)
    except ModelError as error:
        endpoint = {"code": error.code, "status": error.status, "message": error.message}
        return _entry(skill, package_hash, options, "not_analyzed", reason="endpoint_error", endpoint=endpoint)
    if options.key is not None and options.key.value:  # a model that repeats the key: it never reaches a report or the cache
        reply = reply.replace(options.key.value, "***")
    result = analyzer.parse_reply(reply, request)
    if result.status != "analyzed":
        return _entry(skill, package_hash, options, "no_verdict", reason=result.reason)
    categories = [category.to_dict() for category in result.categories]
    if cached_path is not None and package_hash is not None:
        if not _write_cache(cached_path, package_hash, options.model, categories):
            unwritten.append(skill.path)
    return _entry(skill, package_hash, options, "analyzed", categories=_with_rules(categories, rules, skill))


def summary_notice(entries: Sequence[dict], options: AnalyzeOptions, *, cache_unwritable: bool = False) -> Notice:
    """The notice `model_assisted` (spec 11.3, 4.10): what was analysed by which model, that it is advisory, the measured
    label and the guide; with `cache_unwritable`, that the directory of `--analyze-cache` could not be written."""
    counts = {status: sum(1 for entry in entries if entry["status"] == status) for status in analyzer.STATUSES}
    issues = sum(1 for entry in entries for category in entry["categories"] if category["verdict"] == "issue")
    label = analyzer.measured_label(options.model)
    parts = [f"Model-assisted analyzer ({options.model}): {counts['analyzed']} of {len(entries)} skills analysed, "
             f"{issues} {'category' if issues == 1 else 'categories'} with an issue"]
    for status, words in (("no_verdict", "without a verdict"), ("incomplete", "not read whole"),
                          ("not_analyzed", "not analysed")):
        if counts[status]:
            parts.append(f"{counts[status]} {words}")
    message = ", ".join(parts) + ". Advisory: its verdicts never change the exit code."
    if cache_unwritable:
        message += " The directory of --analyze-cache could not be written, so results were not kept there."
    if label is not None:
        message += f" {label}"
    return Notice("model_assisted", "", f"{message} Guide: {ANALYZER_GUIDE_URL}")


__all__ = ["ANALYZER_GUIDE_URL", "AnalyzeOptions", "analyse", "cache_path", "incomplete_analysis_is_scan_error",
           "limit_message", "summary_notice"]
