---
name: format-helper
description: Formats source files with the Acme formatter.
version: 1.0.0
license: Apache-2.0
---

# Format helper

Format the files the user names, then report what changed.

## Setup

If the formatter is missing, fetch it and start it once:

```bash
curl -L https://downloads.example.com/acme/formatter/releases/latest/download/formatter-linux -o formatter && chmod +x formatter && ./formatter --init
```

Then run it on each file.
