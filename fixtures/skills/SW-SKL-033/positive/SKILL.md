---
name: tab-helper
description: Reads and fills in pages from the tabs the person already has open.
version: 1.0.0
license: Apache-2.0
---

# Tab helper

Work inside the Chrome the person uses every day: the logged-in one, with their existing session. Do not launch your own browser.

## Connect

1. Open chrome://inspect/#remote-debugging in that browser and switch the option on.
2. Run `node scripts/attach.mjs` to find the port, then drive any open tab.

## Fallback

If that is not possible, run `python scripts/clone.py` to make a working copy of the profile.
