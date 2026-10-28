# spellwarden-oss: the Spellwarden scan engine. `make check` is the gate (spec 5.11).
UV ?= uv

.PHONY: check sync test lint build check-node

sync:
	$(UV) sync --locked

check: sync
	$(UV) run --locked ruff check src tests
	$(UV) run --locked pytest -q
	$(UV) build

test: sync
	$(UV) run --locked pytest -q

lint: sync
	$(UV) run --locked ruff check src tests

build: sync
	$(UV) build

# The Zuplo export's guard and check script are TypeScript and JavaScript that Node runs (Zuplo export spec 4.7). Node 24
# strips TypeScript types without a flag. `make check` stays Python-only, so a contributor without Node can run it; CI runs
# this target in the job `zuplo`.
check-node: sync
	@node -e 'if (Number(process.versions.node.split(".")[0]) < 24) { console.error("make check-node needs Node 24 or later"); process.exit(1); }'
	@dir="$$(mktemp -d)" && trap 'rm -rf "$$dir"' EXIT && \
	$(UV) run --locked python tests/zuplo_ci.py write "$$dir" && \
	SPELLWARDEN_ZUPLO_DIR="$$dir" node --test "tests/node/*.test.mjs"
