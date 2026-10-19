"""Regular expressions and word lists shared by rules (spec 5.3, 5.4). Each
constant names the rules that use it. All patterns are case-insensitive
unless the rule says otherwise."""
from __future__ import annotations

import re

_I = re.IGNORECASE

# SW-SKL-001, SW-MCP-011
INJECTION: tuple[re.Pattern, ...] = tuple(re.compile(p, _I) for p in (
    r"ignore (all |any |the |your )?(previous|prior|above|earlier) (instructions|prompts|rules)",
    r"disregard (the |your )?(system|previous|prior)",
    r"you are now (a|an|the)\b",
    r"(do not|don't|never) (tell|inform|mention|reveal) (this |it )?(to )?the user",
    r"without (telling|informing|asking) the user",
    r"pretend (you|to be|that)\b",
    r"override (the |your |any )?(instructions|rules|guidelines|safety)",
    r"new (system )?instructions:",
    r"from now on,? you",
))

# SW-SKL-013
SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy", "tiny.cc",
    "shorturl.at", "rebrand.ly", "t.ly", "v.gd", "s.id",
})

# SW-SKL-011 and evidence.mask_credentials (case-sensitive: the shapes are exact)
CREDENTIAL_PATTERNS: tuple[re.Pattern, ...] = tuple(re.compile(p) for p in (
    r"AKIA[0-9A-Z]{16}",
    r"ASIA[0-9A-Z]{16}",
    r"gh[pousr]_[A-Za-z0-9]{36,}",
    r"github_pat_[A-Za-z0-9_]{22,}",
    r"glpat-[A-Za-z0-9_-]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"sk-ant-[A-Za-z0-9_-]{20,}",
    r"sk-[A-Za-z0-9]{32,}",
    r"AIza[0-9A-Za-z_-]{35}",
    r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}",
))
# SW-SKL-011: an assignment of a secret-like name to a quoted value that is not a placeholder
ASSIGNED_SECRET = re.compile(r"""(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*["']([^"'\s]{8,})["']""", _I)
PLACEHOLDER = re.compile(r"(xxx|\.\.\.|<|your[_-]|example|changeme|\$\{|\$[A-Z_]+)", _I)

# SW-SKL-008, SW-SKL-012
SECRET_PATHS = re.compile(
    r"(~?/?\.ssh/|id_(rsa|ed25519|ecdsa)|~?/?\.aws/|\.env\b|~?/?\.netrc|~?/?\.npmrc|~?/?\.pypirc|~?/?\.git-credentials|"
    r"~?/?\.docker/config\.json|~?/?\.kube/config|/etc/(passwd|shadow)|~?/?\.config/gh/hosts\.yml|~?/?\.claude\.json|"
    r"credentials(\.json)?\b)", _I)
# SW-SKL-012 only
MORE_SECRET_PATHS = re.compile(r"(~?/?\.gnupg/|~?/?\.password-store|\.pem\b|\.p12\b|keychain)", _I)

# SW-SKL-005
AGENT_CONFIG_PATHS = re.compile(
    r"(\.claude/settings(\.local)?\.json|~?/?\.claude\.json|\.claude/hooks|\.mcp\.json|\.cursor/mcp\.json|\.vscode/mcp\.json|"
    r"\.codex/config\.toml|\.gemini/settings\.json|claude_desktop_config\.json)", _I)
