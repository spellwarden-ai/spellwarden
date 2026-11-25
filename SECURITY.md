# Security policy

## Reporting a security problem

Report it through GitHub's private vulnerability reporting for this repository (the button "Report a vulnerability" under the Security tab), or by email. Both reach the maintainers, and both get a first answer within five working days.

Send an email to `security@spellwarden.ai`. Do not open a public issue for a security problem.

This covers the scanner and the engine in this repository, the GitHub Action (`spellwarden-ai/scan` on GitHub), the GitLab CI component (`spellwarden-ai/scan` on GitLab), the Infra Pack and the hosted product at spellwarden.ai.

Say what you found and where: the command, the file or the API route, what you saw, the steps that show it, the scanner version and the rules version (`spellwarden version` prints both), and how to reach you. Leave out real credentials, customer secrets and other people's personal data.

If you need to run tests against the hosted product to confirm a problem, ask first: its terms ask users not to attack, overload or test the security of the service without written permission. The scanner runs on your own machine, so you can test it there as you like.

You get a first answer within five working days. The address is for security reports only, and mail to it is screened for spam before anyone reads it.

## A way past a rule

A rule that misses something is usually not a security problem, and a public issue with a harmless sample is the right place for it: see [CONTRIBUTING.md](CONTRIBUTING.md).

Use private reporting or send it to `security@spellwarden.ai` instead when the sample is a working attack, or when publishing the method would help someone hide malicious content from the scanner before a fix is released. After the fix is released, a bypass can join the public corpus of accepted samples in `fixtures/community/`, and only with your agreement in writing.

## Which versions get fixes

Fixes are made on the latest release. Upgrade to it first: `pip install --upgrade spellwarden`, and move the pin of the Action or the component to the same version.

## Checking what you run

Every part of a release is signed: the PyPI files, the container image, the tags of the Action and the component, and a release manifest that ties them together. The README shows the command that verifies each, under [Verifying what you run](README.md#verifying-what-you-run).

More on reporting: [spellwarden.ai/docs/security-and-data](https://spellwarden.ai/docs/security-and-data?utm_source=github&utm_medium=readme&utm_campaign=security-policy#reporting-a-security-problem). The same contact is in [security.txt](https://spellwarden.ai/.well-known/security.txt).
