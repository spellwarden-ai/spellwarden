# spellwarden-oss: the Spellwarden scan engine. `make check` is the gate (spec 5.11).
UV ?= uv

.PHONY: check sync test lint build

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
