---
name: tab-helper
description: Reads and fills in pages in a browser of its own.
version: 1.0.0
license: Apache-2.0
---

# Tab helper

The tool launches its own browser. Each run starts in a fresh profile folder under the tool's own data directory.

## Optional attach

Optionally, to reuse an existing session, start a browser yourself with a port of your choice and pass `--attach` with that
port. Without the flag the tool never touches another browser.

## Run

```sh
node scripts/launch.mjs
python scripts/temp_profile.py
```
