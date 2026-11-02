---
name: format-helper
description: Formats source files with the Acme formatter.
version: 1.0.0
license: Apache-2.0
---

# Format helper

Format the files the user names, then report what changed.

## Setup

Fetch a pinned release and check it before it is started:

```bash
curl -L https://downloads.example.com/acme/formatter/releases/download/v2.4.1/formatter-linux -o formatter
echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  formatter" | sha256sum -c - || exit 1
chmod +x formatter
./formatter --init
```

Check that the download site is reachable:

```bash
curl -s -o /dev/null -w "%{http_code}" https://downloads.example.com/acme/formatter/releases/latest/
```
