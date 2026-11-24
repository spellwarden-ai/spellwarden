# Roadmap

What is being built, what comes next, what is being considered and what is not planned, for the open-source scanner in this repository and for the hosted product at spellwarden.ai that runs the same engine.

This page carries no dates. An item moves up when it is built, and [CHANGELOG.md](CHANGELOG.md) records each release. To ask for something or to argue against something here, open an issue: [CONTRIBUTING.md](CONTRIBUTING.md) says how.

## Shipped

The scanner checks agent skills, MCP client configurations, Claude Code settings and hooks, plugin marketplaces, instruction files and A2A agent cards, and probes remote MCP servers against the 2026-07-28 specification when asked. The README's first section, [What it checks and what it does not](README.md#what-it-checks-and-what-it-does-not), is the short version; the guides at [spellwarden.ai/docs](https://spellwarden.ai/docs?utm_source=github&utm_medium=readme&utm_campaign=roadmap) cover each feature, and [CHANGELOG.md](CHANGELOG.md) lists every release.

Since 1.20.0 the repository scan and the workstation scan read the files that Codex, Gemini CLI, Cursor, Windsurf (Devin Desktop) and Copilot load, wherever the vendor's documentation names the file and an existing rule can judge it: their configuration, hooks, commands, subagents and rule files, and the plugins installed in the home. The README's [What a scan reads](README.md#what-a-scan-reads) lists every path.

Since 1.21.0 every finding carries its rule's fix sentence and a link to the rule's page, in every report, in code scanning alerts and in the pull request comment ([How to fix](README.md#how-to-fix)).

Since 1.21.0 a rule id is never reused or renamed and a deprecation is announced at least one minor version ahead, held by a test that every build runs ([Schemas and compatibility](README.md#schemas-and-compatibility)).

Since 1.21.0 every release measures the skill rules on fixed public sets of malicious and harmless skills, rules only and with no model, and publishes each rule's detection and false-positive rates with the samples the rules missed ([Measured rates](README.md#measured-rates), [benchmarks/RESULTS.md](benchmarks/RESULTS.md)).

Since 1.23.0 a skill read from a large repository's archive is read whole: the scanner reads a symbolic link to a file inside the scanned tree at its target, measures the path bound on the path in the repository and bounds an archive's entries, and a link that leaves the tree is still left unread, with an incomplete scan that says so ([What a scan reads](README.md#what-a-scan-reads)). The hosted scan's part (a repository's archive up to 50 MiB zipped and a re-measurement of the first catalog round) is still to come.

Since 1.22.0 the skill rules also read a normalised copy of the text, so that content written another way (look-alike letters, hidden characters, base64) is still found, and every release measures how many detections survive disguised versions of the malicious skills ([Disguised content](README.md#disguised-content)). Since 1.22.0 the rules also read text files up to 10 MiB, so a file padded past 1 MiB no longer hides its content.

## Being built now

Nothing at the moment: the next item comes from the list below.

## Next

In no fixed order.

- **Published rates for the model-assisted analyzer.** `--analyze` says "Unmeasured model" today. Its detection and false-positive rates are to be measured on held-out skills and published.
- **The analyzer beyond skills.** Today it reads a skill's `SKILL.md` and scripts. Next it reads instruction files, plugin commands and agents, hooks and the descriptions a probed MCP server sends, and a documented recipe covers one open model on a local server.
- **Rules for the OWASP entries that have none.** Where a check before install can honestly detect part of an entry, a measured rule; where it cannot, a plain statement of what answers it.
- **Repositories the scan cannot read whole, in the hosted product.** The scanner's part shipped in 1.23.0. Next the hosted scan reads a repository's archive up to 50 MiB zipped and lists a marketplace without unpacking it, and the first catalog round is measured again. The rule does not change: content left unread never looks like a pass.
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

## Not planned

Each of these is a product of its own, and each would pull the scanner away from checking what agents load before they load it.

- An inline gateway or firewall that inspects the traffic between an agent and its tools. Policy packs export to the tools that do this.
- Hosting MCP servers, or brokering their OAuth credentials.
- Red teaming of a customer's agents.
- A device-management agent.
- A store that sells third-party skills or servers.
