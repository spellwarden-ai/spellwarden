# Wrappers

The GitHub Action (`spellwarden-ai/scan`) and the GitLab CI/CD component (`gitlab.com/spellwarden-ai/scan`) run this scanner and live in their own repositories. This directory holds what this repository keeps about them: `scan-action.ref`, the Action commit the release workflow tests against this repository's wheel (`scripts/release-wrappers.py` writes it), and this note.

## The `preset` input (1.18.0)

Both wrappers take an input `preset` from their 1.18.0 release:

| Wrapper | Input | Values | How the scanner receives it |
|---|---|---|---|
| GitHub Action | `preset`, `description: "strict, balanced or low-noise; empty uses the scanner's settings"` | empty (the default), `strict`, `balanced`, `low-noise` | `--preset VALUE` when not empty |
| GitLab component | `spec:inputs: preset: {default: "", options: ["", "strict", "balanced", "low-noise"]}` | the same | the variable `SW_PRESET`, which `spellwarden ci-run gitlab` turns into `--preset VALUE` when not empty |

Empty passes no flag: the scanner's own settings decide (`SPELLWARDEN_PRESET`, else the `preset` of `.spellwarden/config.yml`, which on a pull or merge request is read from the base revision). A value outside the list fails the wrapper's input check before the scan, as every other input does. Each wrapper's README has the input's row; their CI runs on Linux and Windows runners. What a preset does: the README's "Presets".
