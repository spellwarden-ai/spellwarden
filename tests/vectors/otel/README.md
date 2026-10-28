# OTLP normaliser vectors (runtime traces spec 4.9, claim E4)

Shared with the hosted side, as `normalise_url.json` and `command_identity.json` are. Each file is a JSON array of
vectors; `tests/otel/test_dialects.py` (`dialects.json`, `fields.json`, `identifiers.json`, `content.json`) and
`tests/otel/test_claude_code.py` (`claude_code.json`) run every vector in OTLP/JSON and in protobuf.

A vector:

- `name`: unique across the files;
- `signal`: `traces` or `logs`; `content`: the `normalise(..., content=)` flag (default false);
- `resource`: the resource attributes, `scope`: the scope name (default `test`);
- `items`: spans (`name`, `kind`, `trace_id`, `span_id`, `parent_span_id`, `start`, `end`, `status`, `attributes`,
  `events` of `name`, `time`, `attributes`) or log records (`event_name`, `body`, `time`, `observed`, `trace_id`,
  `span_id`, `severity`, `attributes`); attribute values are plain JSON: a string, a boolean, an integer, a float, a list
  (an array value), an object (a kvlist), or `{"$bytes": "<base64>"}`;
- `expect`: one object per kept record, in order: a subset of `Record.to_dict(content=True)`, with `$absent` listing
  fields that must be absent;
- `stats` (optional): a subset of `Stats.to_dict()`; `resources` (optional): the exact `ResourceInfo.to_dict()` list.

Defaults: trace id `5b8efff798038103d269b633813fc60c`, span id the item's position plus one as 16 hex digits, start
`1761600000000000000` plus one second per item, end start plus 250 ms. `tests/otel/otel_support.py` (`build_request`)
is the reference builder.
