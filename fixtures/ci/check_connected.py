"""Asserts one connected e2e run (O3 plan P23): python fixtures/ci/check_connected.py <recording.json> <report.json>
--credential oidc|key.

<recording.json> is what `fake_api.py --record` wrote, <report.json> the scan's JSON report. Checked: the requests are
exactly the sequence of the credential (`oidc`: the token endpoint with the audience, the exchange, the policy, the
registry check, the upload; `key`: the organisation listing first, no token call, then the same three), none was
unscripted, no credential of the run is in a request body or header where it does not belong (the code host's token only in
the exchange body, the token request's own token only in the token request, a CI token or key only as `Authorization`),
no credential is in the report, and the report's `connected` block holds the credential kind, the policy source, at least
one item not admitted and an uploaded result. Exits 1 listing every failed assertion. Standard library only."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

POLICY = "/api/v1/orgs/acme/ci/policy"
CHECK = "/api/v1/orgs/acme/ci/registry-check"
SCANS = "/api/v1/orgs/acme/ci/scans"
SEQUENCES = {
    "oidc": [("GET", "/idtoken"), ("POST", "/api/public/ci/token"), ("GET", POLICY), ("POST", CHECK), ("POST", SCANS)],
    "key": [("GET", "/api/v1/orgs"), ("GET", POLICY), ("POST", CHECK), ("POST", SCANS)],
}
AUDIENCE = "https://dash.spellwarden.ai/ci/acme"


def _json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _bearer(request: dict) -> str | None:
    for name, value in request["headers"].items():
        if name.lower() == "authorization":
            return value.split(" ", 1)[1] if " " in value else value
    return None


def check(recording: list[dict], report: dict, credential: str) -> list[str]:
    problems: list[str] = []
    sequence = [(request["method"], urlsplit(request["path"]).path) for request in recording]
    if sequence != SEQUENCES[credential]:
        problems.append(f"the requests were {sequence}, expected {SEQUENCES[credential]}")
    for request in recording:
        if request.get("unscripted"):
            problems.append(f"{request['method']} {request['path']} was not scripted")
    secrets: dict[str, str] = {}
    if credential == "oidc" and recording:
        token_request = recording[0]
        query = parse_qs(urlsplit(token_request["path"]).query)
        if query.get("audience") != [AUDIENCE]:
            problems.append(f"the token request asked for the audience {query.get('audience')}, expected {AUDIENCE}")
        provider = (token_request["response"]["body"] or {}).get("value")
        request_token = _bearer(token_request)
        if provider:
            secrets["provider token"] = provider
        if request_token:
            secrets["token request token"] = request_token
        exchange = next((r for r in recording if urlsplit(r["path"]).path == "/api/public/ci/token"), None)
        if exchange is not None:
            if (exchange["body"] or {}).get("token") != provider:
                problems.append("the exchange body does not carry the code host's token")
            if _bearer(exchange) is not None:
                problems.append("the exchange carried an Authorization header")
            session = (exchange["response"]["body"] or {}).get("token")
            if session:
                secrets["CI token"] = session
    elif credential == "key" and recording:
        key = _bearer(recording[0])
        if key:
            secrets["CI key"] = key
    for name, value in secrets.items():
        for request in recording:
            path = urlsplit(request["path"]).path
            body = json.dumps(request["body"])
            headers = {key.lower(): header for key, header in request["headers"].items()}
            if name == "provider token" and path != "/api/public/ci/token" and (value in body or value in json.dumps(headers)):
                problems.append(f"the {name} is in {request['method']} {path}")
            if name == "provider token" and path == "/api/public/ci/token" and value in json.dumps(headers):
                problems.append(f"the {name} is in a header of the exchange")
            if name == "token request token" and path != "/idtoken" and (value in body or value in json.dumps(headers)):
                problems.append(f"the {name} is in {request['method']} {path}")
            if name in ("CI token", "CI key") and value in body:
                problems.append(f"the {name} is in the body of {request['method']} {path}")
            if name in ("CI token", "CI key") and any(value in header for key, header in headers.items() if key != "authorization"):
                problems.append(f"the {name} is in a header other than Authorization on {path}")
        if value in json.dumps(report):
            problems.append(f"the {name} is in the report")
    scans = [request for request in recording if urlsplit(request["path"]).path == SCANS]
    if scans:
        uploaded = (scans[0]["body"] or {}).get("report", {})
        if "upload" in (uploaded.get("connected") or {}):
            problems.append("the uploaded report carries connected.upload")
    block = report.get("connected")
    if not isinstance(block, dict):
        return [*problems, "the report has no connected block"]
    if block.get("credential") != credential:
        problems.append(f"connected.credential is {block.get('credential')!r}, expected {credential!r}")
    if (block.get("policy") or {}).get("source") not in ("org_rules", "pack"):
        problems.append(f"connected.policy.source is {(block.get('policy') or {}).get('source')!r}")
    registry = block.get("registry") or {}
    if not registry.get("not_admitted", 0) >= 1:
        problems.append(f"connected.registry.not_admitted is {registry.get('not_admitted')!r}, expected at least 1")
    status = (block.get("upload") or {}).get("status")
    if status != "uploaded":
        problems.append(f"connected.upload.status is {status!r}, expected 'uploaded'")
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("recording")
    parser.add_argument("report")
    parser.add_argument("--credential", choices=sorted(SEQUENCES), required=True)
    args = parser.parse_args(argv)
    problems = check(_json(args.recording), _json(args.report), args.credential)
    for problem in problems:
        print(f"FAIL connected {args.credential}: {problem}")
    if not problems:
        print(f"ok connected {args.credential}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
