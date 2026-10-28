# Recorded telemetry (runtime traces spec 7.1)

The release gate of 1.7.0 records each producer's OTLP/HTTP requests with a capture receiver on localhost, scrubs them
(host names, user and organisation ids, emails, paths under a home directory and session ids replaced by fixed values,
inside JSON-string attributes too) and commits them here, one directory per producer:

- `<producer>/<n>.traces.pb` and `<n>.logs.pb`: protobuf bodies, re-serialised by the reference package;
- `<producer>/<n>.traces.json` and `<n>.logs.json`: OTLP/JSON bodies, written with the ids as hex;
- `<body>.expected.json`: what `normalise(..., content=True)` gives for the body (claim E10), written by
  `uv run --locked python tests/otel/write_expected.py` and read in review.

Each producer's directory holds a `PRODUCER.md` naming its version and settings. The gate record (spec section 16 in
the hosted repository) states what the recordings showed.
