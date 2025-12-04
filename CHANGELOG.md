# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [0.3.0] - 2025-12-03

### Added
- JSONL audit log and `seatbelt log`.
- `kubectl`, `terraform` and `gh` presets.
- `confirm` decision, with precedence between presets and user rules.
- `disable` for turning off a preset rule by id.

## [0.2.0] - 2025-10-20

### Added
- A real shell parser: quoting, `$(...)`, backticks, here-documents, subshells and
  control flow.
- Wrappers are looked through: `sudo`, `env`, `xargs`, `find -exec`, `bash -c` and more.

### Changed
- Commands that can't be parsed are denied.

## [0.1.0] - 2025-10-06

### Added
- `seatbelt check`, YAML rules, and `git` and `rm` presets.
- Claude Code PreToolUse hook.
