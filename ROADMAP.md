# Roadmap

What is being built, what comes next, what is being considered and what is not planned, for the open-source scanner in this repository and for the hosted product at spellwarden.ai that runs the same engine.

This page carries no dates. An item moves up when it is built, and [CHANGELOG.md](CHANGELOG.md) records each release. To ask for something or to argue against something here, open an issue: [CONTRIBUTING.md](CONTRIBUTING.md) says how.

## Shipped

The scanner checks agent skills, MCP client configurations, Claude Code settings and hooks, plugin marketplaces, instruction files and A2A agent cards, and probes remote MCP servers against the 2026-07-28 specification when asked. The README's first section, [What it checks and what it does not](README.md#what-it-checks-and-what-it-does-not), is the short version; the guides at [spellwarden.ai/docs](https://spellwarden.ai/docs?utm_source=github&utm_medium=readme&utm_campaign=roadmap) cover each feature, and [CHANGELOG.md](CHANGELOG.md) lists every release.

## Being built now

- **Reading more of what agents load.** The repository scan and the workstation scan read more of the files that Codex, Gemini CLI, Cursor, Windsurf and Copilot load, wherever the vendor's documentation names the file and an existing rule can judge it.
- **Fix guidance in every finding.** Each rule gets one sentence that says how to fix what it found and a link to its page, shown in every report, in code scanning alerts, in the pull request comment and in the hosted dashboard.
- **A compatibility pledge.** Rule ids are never reused or renamed, the report formats change only as [Schemas and compatibility](README.md#schemas-and-compatibility) says, and a deprecation is announced at least one minor version before it takes effect. A test in the release workflow holds the scanner to it.

## Next

In no fixed order.

- **A public benchmark of the rules.** One command that runs the released scanner over fixed, public sets of malicious and harmless content and prints the detection and false-positive rates for each rule, published with every release, with the samples the rules missed.
- **Disguised content.** A measurement of how many detections survive when the same content is written another way (look-alike letters, hidden characters, encoding layers), then a normalisation step before the rules match, where the measurement shows a gain.
- **Published rates for the model-assisted analyzer.** `--analyze` says "Unmeasured model" today. Its detection and false-positive rates are to be measured on held-out skills and published.
- **The analyzer beyond skills.** Today it reads a skill's `SKILL.md` and scripts. Next it reads instruction files, plugin commands and agents, hooks and the descriptions a probed MCP server sends, and a documented recipe covers one open model on a local server.
- **Rules for the OWASP entries that have none.** Where a check before install can honestly detect part of an entry, a measured rule; where it cannot, a plain statement of what answers it.
- **Repositories the scan cannot read whole.** Fewer scans that end incomplete on large repositories: the skill's own directory instead of the whole archive, and symbolic links that stay inside the scanned tree. The rule does not change: content left unread never looks like a pass.
- **More export targets for policy packs.** AWS AgentCore Policy and Cloudflare's sandbox egress proxy are named in the code as planned targets.
- **Signed attestations** for skills and servers that were scanned and admitted.
- **A way to report misses and false alarms** with issue forms, and a public corpus of the accepted samples, each one a test.

## Being considered

Not decided. Each of these changes what the scanner sends or where it runs, so it is weighed before it is promised.

- A check of the dependencies a skill or a server brings against a database of known vulnerabilities. It would be off by default, because it sends package names and versions to a third party.
- A public advisory feed of skills and MCP servers confirmed to be malicious, in a format existing tools read.
- Reading MCP servers that are declared in the code of an agent framework, not only in configuration files.
- A guard that compares a server's tools with the pinned ones at the moment the server starts.
- An editor extension that shows findings when agent content is saved, and a GitHub App that checks pull requests without a workflow file.
- A2A beyond agent cards: rules for which agent may call which, and A2A agents in the private registry of the hosted product.
- A self-hosted option for the hosted product.

## Not planned

Each of these is a product of its own, and each would pull the scanner away from checking what agents load before they load it.

- An inline gateway or firewall that inspects the traffic between an agent and its tools. Policy packs export to the tools that do this.
- Hosting MCP servers, or brokering their OAuth credentials.
- Red teaming of a customer's agents.
- A device-management agent.
- A store that sells third-party skills or servers.
