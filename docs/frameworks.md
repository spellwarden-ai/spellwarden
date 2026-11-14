# Framework tags

Every rule carries MITRE ATLAS technique ids and OWASP Agentic Skills Top 10 ids next to its OWASP Agentic Top 10, OWASP MCP
Top 10 and NIST SP 800-53 tags. This file records what each rule is tagged with and where the lists come from. The data is in
`src/spellwarden_scan/frameworks/`; this file is written from it by `scripts/frameworks/build_atlas_scope.py docs`.

## Versions

| Tag | Framework | Version | Source |
|---|---|---|---|
| atlas | MITRE ATLAS | content release 2026.10, data format 6.1.0, modified 2026-10-28 | github.com/mitre-atlas/atlas-data, file dist/v6/ATLAS-2026.10.yaml |
| owasp_ast | OWASP Agentic Skills Top 10 | 1.0 (2026 edition), incubator project under public review | https://owasp.org/www-project-agentic-skills-top-10/ |

An empty ATLAS column means no technique fits the rule; the reason is in the table below and in `NO_ATLAS`. The ATLAS
file has no deprecation marker, so "not deprecated" means "present in release 2026.10".

## Mapping

| Rule | MITRE ATLAS | OWASP AST |
|---|---|---|
| SW-A2A-001 | no technique (card format, transport, authorization-flow and parser hygiene) | none |
| SW-A2A-002 | no technique (card format, transport, authorization-flow and parser hygiene) | none |
| SW-A2A-003 | no technique (card format, transport, authorization-flow and parser hygiene) | none |
| SW-A2A-004 | no technique (card format, transport, authorization-flow and parser hygiene) | none |
| SW-A2A-005 | no technique (card format, transport, authorization-flow and parser hygiene) | none |
| SW-A2A-006 | no technique (card format, transport, authorization-flow and parser hygiene) | none |
| SW-A2A-007 | AML.T0132 Misconfigured or Publicly Exposed AI Services | none |
| SW-A2A-008 | AML.T0055 Unsecured Credentials | none |
| SW-A2A-009 | no technique (card format, transport, authorization-flow and parser hygiene) | none |
| SW-A2A-010 | AML.T0074 Masquerading | none |
| SW-A2A-011 | AML.T0074 Masquerading | none |
| SW-A2A-012 | AML.T0074 Masquerading | none |
| SW-A2A-013 | AML.T0074 Masquerading | none |
| SW-A2A-014 | AML.T0051.001 LLM Prompt Injection: Indirect; AML.T0110.000 AI Agent Tool Poisoning: Definition and Instructions | none |
| SW-A2A-015 | AML.T0055 Unsecured Credentials | none |
| SW-A2A-016 | AML.T0074 Masquerading | none |
| SW-A2A-017 | AML.T0074 Masquerading | none |
| SW-A2A-018 | no technique (card format, transport, authorization-flow and parser hygiene) | none |
| SW-A2A-019 | no technique (card format, transport, authorization-flow and parser hygiene) | none |
| SW-CFG-001 | no technique (plain HTTP transport) | none |
| SW-CFG-002 | AML.T0055 Unsecured Credentials; AML.T0083 Credentials from AI Agent Configuration | none |
| SW-CFG-003 | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | AST02, AST07 |
| SW-CFG-004 | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | none |
| SW-CFG-005 | AML.T0142 Event Triggered Execution | none |
| SW-CFG-006 | AML.T0142 Event Triggered Execution; AML.T0086 Exfiltration via AI Agent Tool Invocation | none |
| SW-CFG-007 | AML.T0142 Event Triggered Execution; AML.T0011.001 User Execution: Malicious Package | none |
| SW-CFG-008 | AML.T0081 Modify AI Agent Configuration | none |
| SW-CFG-009 | AML.T0010.005 Supply Chain Compromise: AI Agent Tool; AML.T0109 AI Supply Chain Rug Pull | AST02, AST07 |
| SW-CFG-010 | AML.T0083 Credentials from AI Agent Configuration | none |
| SW-CFG-012 | AML.T0053 AI Agent Tool Invocation | none |
| SW-CFG-013 | AML.T0053 AI Agent Tool Invocation | none |
| SW-MCP-001 | AML.T0084.001 Discover AI Agent Configuration: Tool Definitions; AML.T0132 Misconfigured or Publicly Exposed AI Services | none |
| SW-MCP-002 | no technique (authentication method, transport and protocol-version hygiene) | none |
| SW-MCP-003 | no technique (authentication method, transport and protocol-version hygiene) | none |
| SW-MCP-004 | no technique (authentication method, transport and protocol-version hygiene) | none |
| SW-MCP-005 | no technique (authentication method, transport and protocol-version hygiene) | none |
| SW-MCP-006 | no technique (authentication method, transport and protocol-version hygiene) | none |
| SW-MCP-007 | no technique (authentication method, transport and protocol-version hygiene) | none |
| SW-MCP-008 | no technique (authentication method, transport and protocol-version hygiene) | none |
| SW-MCP-009 | no technique (authentication method, transport and protocol-version hygiene) | none |
| SW-MCP-010 | no technique (authentication method, transport and protocol-version hygiene) | none |
| SW-MCP-011 | AML.T0110.000 AI Agent Tool Poisoning: Definition and Instructions; AML.T0051.001 LLM Prompt Injection: Indirect | none |
| SW-REG-001 | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | AST09 |
| SW-REG-002 | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | AST09 |
| SW-REG-003 | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | AST09 |
| SW-SKL-001 | AML.T0051.001 LLM Prompt Injection: Indirect; AML.T0110.000 AI Agent Tool Poisoning: Definition and Instructions | AST05 |
| SW-SKL-002 | AML.T0068 LLM Prompt Obfuscation; AML.T0110.000 AI Agent Tool Poisoning: Definition and Instructions | AST05 |
| SW-SKL-003 | AML.T0081 Modify AI Agent Configuration | AST03 |
| SW-SKL-004 | AML.T0011.002 User Execution: Poisoned AI Agent Tool | AST01 |
| SW-SKL-005 | AML.T0081 Modify AI Agent Configuration | AST03 |
| SW-SKL-006 | AML.T0101 Data Destruction via AI Agent Tool Invocation | none |
| SW-SKL-007 | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | AST02 |
| SW-SKL-008 | AML.T0086 Exfiltration via AI Agent Tool Invocation; AML.T0037 Data from Local System | AST01 |
| SW-SKL-009 | AML.T0010.005 Supply Chain Compromise: AI Agent Tool | AST02, AST07 |
| SW-SKL-010 | AML.T0011.001 User Execution: Malicious Package | AST02 |
| SW-SKL-011 | AML.T0055 Unsecured Credentials | none |
| SW-SKL-012 | AML.T0098 AI Agent Tool Credential Harvesting | none |
| SW-SKL-013 | AML.T0025 Exfiltration via Cyber Means | none |
| SW-SKL-014 | AML.T0011.001 User Execution: Malicious Package | none |
| SW-SKL-015 | no technique (metadata hygiene) | AST04 |
| SW-SKL-019 | AML.T0051.001 LLM Prompt Injection: Indirect | AST05 |
| SW-SKL-031 | no technique (metadata hygiene) | AST04 |
| SW-SKL-032 | AML.T0011 User Execution | AST01 |
| SW-SKL-036 | AML.T0053 AI Agent Tool Invocation | AST03 |
| SW-SKL-037 | AML.T0010.005 Supply Chain Compromise: AI Agent Tool; AML.T0109 AI Supply Chain Rug Pull | AST02, AST07 |

## Review record

The mapping was drafted from the rule titles. Each row was read against the rule's title and the description of each
technique in ATLAS 2026.10 (the descriptions printed from the release file). Corrections made after that reading:
none. The OWASP AST column is the mapping spellwarden.ai already published, carried over row for row.
A correction to a row is made in `tests/frameworks_expected.py`, in the rule's `make_rule` call and here, with the reason.
