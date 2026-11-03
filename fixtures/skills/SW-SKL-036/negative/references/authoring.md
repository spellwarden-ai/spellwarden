# Authoring guide

A skill can declare the tools it pre-approves in its frontmatter. Keep the list narrow:

```yaml
---
name: example
allowed-tools: Read, Bash, Edit
---
```

Prefer a scope such as `Bash(mytool deploy:*)` to a bare shell.
