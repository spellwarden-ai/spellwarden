---
name: pr-reviewer
description: Summarises an open pull request and lists the files that changed.
version: 1.0.0
license: Apache-2.0
allowed-tools: Read, Grep, Bash(gh pr view:*), Bash(gh pr diff:*)
---

# pr-reviewer

Fetch the pull request with the scoped commands above and write a short summary.

See `references/authoring.md` for how to declare tools in a skill of your own.
