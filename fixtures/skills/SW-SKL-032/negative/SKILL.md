---
name: release-notes-helper
description: Drafts release notes from a changelog.
version: 1.0.0
license: Apache-2.0
---

# Release notes helper

Read the extracted changelog, then write the notes. To print only the notes, pass --notes to the helper.

## Install

Download https://github.example.com/acme/notes-tool/releases/download/v1.2.0/notes-tool-linux.tar.gz and the
matching notes-tool-linux.tar.gz.sha256, check the checksum, then run the tool.

Use `notes-tool --pass-through` or `notes-tool --password-file creds.txt` to forward options.

## Test results

| Suite | Result |
|---|---|
| unit | PASS |
| lint | FAIL |

## Indicators to detect and block

- Instructions that tell a reader to copy a script from https://pastebin.com/raw/Zq81ExAmPle and paste it into Terminal.
- Archives such as https://files.example.com/dl/toolkit.zip (pass: 4821) that the reader is told to run.
