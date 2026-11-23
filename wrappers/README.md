# Wrappers

The GitHub Action (`spellwarden-ai/scan`) and the GitLab CI/CD component (`gitlab.com/spellwarden-ai/scan`) run this scanner and live in their own repositories. This directory holds what this repository keeps about them: `scan-action.ref`, the Action commit the release workflow tests against this repository's wheel (`scripts/release-wrappers.py` writes it), and this note.

## The `preset` input (1.18.0)

Both wrappers take an input `preset` from their 1.18.0 release:

| Wrapper | Input | Values | How the scanner receives it |
|---|---|---|---|
| GitHub Action | `preset`, `description: "strict, balanced or low-noise; empty uses the scanner's settings"` | empty (the default), `strict`, `balanced`, `low-noise` | `--preset VALUE` when not empty |
| GitLab component | `spec:inputs: preset: {default: "", options: ["", "strict", "balanced", "low-noise"]}` | the same | the variable `SW_PRESET`, which `spellwarden ci-run gitlab` turns into `--preset VALUE` when not empty |

Empty passes no flag: the scanner's own settings decide (`SPELLWARDEN_PRESET`, else the `preset` of `.spellwarden/config.yml`, which on a pull or merge request is read from the base revision). A value outside the list fails the wrapper's input check before the scan, as every other input does. Each wrapper's README has the input's row; their CI runs on Linux and Windows runners. What a preset does: the README's "Presets".

## The `follow-links` input (1.20.0)

Both wrappers take an input `follow-links` from their 1.20.0 release:

| Wrapper | Input | Values | How the scanner receives it |
|---|---|---|---|
| GitHub Action | `follow-links`, `description: "true to follow a linked directory in an instruction folder; false by default"` | `false` (the default), `true` | `--follow-links` when `true` |
| GitLab component | `spec:inputs: follow-links: {default: false, type: boolean}`, as its other true or false inputs | the same | the variable `SW_FOLLOW_LINKS`, which `spellwarden ci-run gitlab` turns into `--follow-links` when it is `true` |

`false` passes no flag, and so does an empty or unset `SW_FOLLOW_LINKS`: a linked directory in an instruction folder is then the notice `symlink_skipped` and the files reached only through it are not judged. Any other value fails the wrapper's input check before the scan (the Action's own check; GitLab refuses a value that is not a boolean when it creates the pipeline), and `spellwarden ci-run gitlab` refuses another `SW_FOLLOW_LINKS` as a usage problem, as every other input. The lock does not record the argument, so a job that runs `scan --locked` with the input on needs a lock written with `spellwarden lock --follow-links`. What the argument follows and what it never follows: the README's "Instruction files".
