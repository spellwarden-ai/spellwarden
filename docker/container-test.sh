#!/usr/bin/env bash
# Spec 7.2: a git workspace whose files and .git belong to root, scanned by the image's own uid 10001, is listed
# through git (the scanner sets safe.directory for that one work tree) and its skill is found.
set -euo pipefail
image="$1"
ws="$(mktemp -d)"

# root <command> <path>...: sudo where it needs no password (CI runners), else the image's own root user on a bind
# mount of the workspace's parent directory (a developer machine without passwordless sudo).
root() {
  if sudo -n true 2>/dev/null; then sudo "$@"; return; fi
  local parent
  parent="$(dirname "$ws")"
  docker run --rm --user 0 --entrypoint "$1" -v "$parent:$parent" "$image" "${@:2}"
}
trap 'root rm -rf "$ws"' EXIT
mkdir -p "$ws/.claude/skills/deploy"
printf -- '---\nname: deploy\ndescription: Deploys the service.\nversion: 1.0.0\nlicense: Apache-2.0\n---\n\n# deploy\n\nRun the deploy script.\n' \
  > "$ws/.claude/skills/deploy/SKILL.md"
git -C "$ws" init -q
git -C "$ws" add -A
git -C "$ws" -c user.name=t -c user.email=t@example.invalid commit -q -m fixture
chmod -R a+rX "$ws"
root chown -R 0:0 "$ws"

uid="$(docker run --rm --entrypoint id "$image" -u)"
test "$uid" = 10001 || { echo "the image runs as uid $uid, expected 10001" >&2; exit 1; }

set +e
docker run --rm -v "$ws:/src" "$image" scan /src --format json --no-telemetry > "$ws.json"
code=$?
set -e
test "$code" = 0 || { echo "scan exited $code" >&2; cat "$ws.json" >&2; exit 1; }
python3 - "$ws.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
codes = [n["code"] for n in report["notices"]]
assert "git_unavailable" not in codes, f"git was not used: {codes}"
kinds = {(i["kind"], i["path"]) for i in report["items"]}
assert ("skill", ".claude/skills/deploy") in kinds, kinds
print("container test passed: listed through git as uid 10001, skill found")
PY
rm -f "$ws.json"
