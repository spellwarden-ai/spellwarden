"""Shared builders of the agent card tests: a clean 1.0 card and its serialisation. Imported by name (`from a2a_cards import
...`); the test directories hold no `__init__.py`, so `tests/` is on the import path."""
from __future__ import annotations

import copy
import json
from pathlib import Path

SPEC_CARDS = Path(__file__).resolve().parent / "fixtures" / "a2a" / "spec"
CLEAN = {
    "name": "Invoice Helper",
    "description": "Summarises supplier invoices for the accounts team.",
    "version": "1.2.0",
    "supportedInterfaces": [{"url": "https://agent.example.com/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
    "provider": {"organization": "Example Inc.", "url": "https://example.com"},
    "capabilities": {"streaming": True},
    "securitySchemes": {"oauth": {"oauth2SecurityScheme": {"flows": {"authorizationCode": {
        "authorizationUrl": "https://auth.example.com/authorize", "tokenUrl": "https://auth.example.com/token",
        "pkceRequired": True, "scopes": {"invoices.read": "Read invoices"}}}}}},
    "securityRequirements": [{"schemes": {"oauth": {"list": ["invoices.read"]}}}],
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "summarise", "name": "Summarise invoice", "description": "Summarises one invoice.",
                "tags": ["invoices"], "examples": ["Summarise invoice 42"]}],
}


def clean_card() -> dict:
    """A fresh copy of the clean 1.0 card: valid, over HTTPS, OAuth with PKCE, no signature."""
    return copy.deepcopy(CLEAN)


def card_bytes(card: dict) -> bytes:
    """The card as served: two-space indented JSON, so every member sits on its own line."""
    return (json.dumps(card, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def spec_card(name: str) -> bytes:
    return (SPEC_CARDS / f"{name}-sample-card.json").read_bytes()
