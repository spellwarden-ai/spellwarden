"""The agent card migration checklist (O4 spec 5.8): thirteen items in a fixed order, each present when its condition holds,
the last always. A `ready` card's checklist is the single `rescan` item. Pure: it reads the parsed card and the findings
`evaluate_agent_card` produced for it."""
from __future__ import annotations

import re
from collections.abc import Sequence

from spellwarden_scan._json import Obj
from spellwarden_scan.a2a import AgentCardDocument, capped
from spellwarden_scan.model import ChecklistItem, Finding

ITEMS: tuple[tuple[str, str], ...] = (
    ("well_known_path", "Serve the card at /.well-known/agent-card.json"),
    ("supported_interfaces", "Move url, preferredTransport and additionalInterfaces into supportedInterfaces, each with url, "
                             "protocolBinding and protocolVersion"),
    ("interface_version", 'Declare protocolVersion "1.0" on each interface, without a patch number'),
    ("extended_card", "Replace supportsAuthenticatedExtendedCard with capabilities.extendedAgentCard"),
    ("state_history", "Remove capabilities.stateTransitionHistory"),
    ("security_requirements", 'Rename security to securityRequirements, in the form {"schemes": {"name": {"list": [scopes]}}}, '
                              "on the card and on each skill"),
    ("scheme_wrappers", "Write each security scheme under its type key (apiKeySecurityScheme, httpAuthSecurityScheme, "
                        "oauth2SecurityScheme, openIdConnectSecurityScheme, mtlsSecurityScheme) and rename in to location"),
    ("oauth_flows", "Replace the implicit and password flows with the authorization code flow with PKCE, or the device code "
                    "flow"),
    ("one_flow", "Split OAuth schemes that list more than one flow into one scheme per flow"),
    ("pkce", "Set pkceRequired to true on authorization code flows"),
    ("wire_changes", "Update the agent and its clients for the 1.0 protocol: PascalCase method names, SCREAMING_SNAKE_CASE enum "
                     "values, the A2A-Version header, REST paths without /v1"),
    ("resign", "Sign the card again after these changes, over its RFC 8785 canonical form, with an asymmetric algorithm"),
    ("rescan", "Re-run the Spellwarden scan"),
)
_WRAPPERS = ("apiKeySecurityScheme", "httpAuthSecurityScheme", "oauth2SecurityScheme", "openIdConnectSecurityScheme",
             "mtlsSecurityScheme")


_MAJOR_MINOR = re.compile(r"[0-9]+\.[0-9]+")


def _interface_version_item(root: Obj) -> bool:
    if "protocolVersion" in root:
        return True
    for interface in capped(root.get("supportedInterfaces"), "interfaces"):
        if isinstance(interface, Obj):
            version = interface.get("protocolVersion")  # missing, with a patch number, or not a version at all
            if not isinstance(version, str) or _MAJOR_MINOR.fullmatch(version) is None:
                return True
    return False


def _scheme_bodies(root: Obj):
    schemes = root.get("securitySchemes")
    for scheme in (list(schemes.values())[:50] if isinstance(schemes, Obj) else ()):
        if isinstance(scheme, Obj):
            yield scheme


def _security_member(root: Obj) -> bool:
    if "security" in root:
        return True
    return any(isinstance(skill, Obj) and "security" in skill for skill in capped(root.get("skills"), "skills"))


def _legacy_scheme(root: Obj) -> bool:
    for scheme in _scheme_bodies(root):
        if "type" in scheme or "in" in scheme:
            return True
        body = scheme.get("apiKeySecurityScheme")
        if isinstance(body, Obj) and "in" in body:
            return True
    return False


def _several_flows(root: Obj) -> bool:
    for scheme in _scheme_bodies(root):
        bodies = [scheme] + [scheme[key] for key in _WRAPPERS if isinstance(scheme.get(key), Obj)]
        for body in bodies:
            flows = body.get("flows")
            if isinstance(flows, Obj) and len(flows) > 1:
                return True
    return False


def a2a_checklist(document: AgentCardDocument, findings: Sequence[Finding]) -> tuple[ChecklistItem, ...]:
    """The checklist of one card (5.8), in the order of `ITEMS`. A card that could not be read has only `rescan`."""
    fired = {finding.rule_id for finding in findings}
    root = document.root
    older = document.card_format in ("0.3", "0.2")
    conditions = dict.fromkeys((key for key, _ in ITEMS), False)
    if root is not None:
        capabilities = root.get("capabilities")
        conditions.update(
            well_known_path="SW-A2A-003" in fired or document.card_format == "0.2",
            supported_interfaces=any(key in root for key in ("url", "preferredTransport", "additionalInterfaces")),
            interface_version=_interface_version_item(root),
            extended_card="supportsAuthenticatedExtendedCard" in root or "supportsExtendedAgentCard" in root,
            state_history=isinstance(capabilities, Obj) and "stateTransitionHistory" in capabilities,
            security_requirements=_security_member(root),
            scheme_wrappers=_legacy_scheme(root),
            oauth_flows="SW-A2A-005" in fired,
            one_flow=_several_flows(root),
            pkce="SW-A2A-006" in fired,
            wire_changes=older,
        )
        signed = isinstance(root.get("signatures"), list) and bool(root["signatures"])
        migrating = any(conditions[key] for key, _ in ITEMS[1:10])
        conditions["resign"] = (signed and migrating) or bool(fired & {"SW-A2A-010", "SW-A2A-017"})
    conditions["rescan"] = True
    return tuple(ChecklistItem(order, key, text) for order, (key, text) in enumerate(ITEMS, start=1) if conditions[key])
