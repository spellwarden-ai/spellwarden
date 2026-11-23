# Governance

How decisions are made in this project today, and what you can rely on if that changes.

## Who decides

The scanner is built and maintained by NETBEARS TEAM SRL, the company that operates Spellwarden. Its maintainers decide what is merged, which rules ship, when a release is made and what the [roadmap](ROADMAP.md) holds. Today that is one maintainer.

Decisions are made in the open where they can be: a change arrives as a pull request, a rule is proposed in an issue first, and every release is described in [CHANGELOG.md](CHANGELOG.md). Anyone can disagree in an issue, and a maintainer answers with the reason.

## How a rule changes

A rule is added, changed or retired only in a release, and the release notes say what a user will see change. A change to what a rule detects raises the rules version, which every report carries. Rule ids are never reused. [CONTRIBUTING.md](CONTRIBUTING.md) says what a new rule needs.

## Becoming a maintainer

A maintainer is someone who has contributed over time: rules, fixes, reviews of other people's pull requests, answers in issues. The existing maintainers invite a contributor whose work they have come to rely on, and the invitation and its acceptance are recorded in this file. There is no fixed number of contributions and no vote.

## Who pays for the work

Spellwarden sells a hosted product that runs this same engine: scans kept over time, policy, evals and a private registry, sold by subscription. That income pays for the work on the scanner. The scanner, its rules, the GitHub Action and the GitLab component stay free under Apache-2.0, and the hosted product pins a released version of this package, so there is one engine and no private copy of it.

## If the company stops

- The licence is Apache-2.0 and cannot be taken back for a version that was released. Anyone may keep using, changing and publishing the code.
- The scanner runs on your machine or runner and needs no Spellwarden service. In free mode the only call to Spellwarden is the usage ping in CI. A ping that fails never changes a report or an exit code, and it can be switched off.
- Released packages are on PyPI and released images in the container registry. Each is signed, and the README shows how to verify one, so a copy you keep can be checked later.
- The rules, their fixtures and their tests are all in this repository. Nothing a scan needs is held elsewhere.

## Changing this file

A change to this file is made by pull request, like any other.
