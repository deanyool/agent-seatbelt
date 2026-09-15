# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [1.4.0] - 2026-09-14

### Added
- The audit log masks common credential shapes before writing.
- `seatbelt hook claude-code --auto-approve`.
- `seatbelt log --since` and `--rule`.

### Changed
- Allowed commands from `seatbelt check` read "matched this rule" rather than repeating
  the id.
- Hook commands are quoted for the shell only when the path needs it.

## [1.3.0] - 2026-09-07

### Added
- zsh coverage: `$=x`, `$~x`, `${(e)x}`, `if x { y }`, the `-` precommand modifier, and
  `repeat`.
- More programs are refused as opaque: `parallel`, `at`, `script`, `tmux`, `strace` and
  similar, plus the `let` builtin.

### Fixed
- `[[ $x -eq 1 ]]` evaluates `$x` as an expression, which can run code, so comparing a
  variable with an arithmetic operator is now refused.
- `$[...]`, the old spelling of arithmetic expansion, is refused for the same reason.
- A `)` in a here-document inside `$(...)` ends the substitution in bash 3.2, and the rest
  of the body then runs as commands. Bodies with unbalanced parentheses there are refused.
- `$$(` is refused, because bash reads it one way when finding the end of a word and
  another when expanding it.

## [1.2.0] - 2026-08-30

### Added
- Protected paths: writes to seatbelt's own files, shell profiles, `~/.ssh`, Git hooks
  and `/etc` are denied, through redirects, common file tools and agent edit tools.
- The hook checks `Edit`, `MultiEdit`, `Write` and `NotebookEdit`.

### Changed
- Bump go.yaml.in/yaml/v3 to v3.0.5.

### Security
- A policy file in the working directory is no longer loaded. A cloned repository could
  use one to relax its own rules.

## [1.1.0] - 2026-07-17

### Added
- Differential testing against a real bash, in `go test` and `make soak`.

### Fixed
- Bash brace-expands `{a},b}`, which the parser read as literal text.
- Bash brace-expands inside `<(...)`, even across spaces. Braces there are now refused.
- `2>&-1` is two tokens: it closes stderr and passes `1` as an argument.
- Backticks drop backslash-newlines before parsing.
- Bash 3.2 strips backslash-newlines from `$(...)` before it looks for comments, so a
  comment ending in a backslash is now refused.

## [1.0.0] - 2026-04-18

### Added
- `seatbelt mcp-proxy`, a policy proxy for stdio MCP servers.
- `seatbelt hook install` and `seatbelt hook print`.
- `seatbelt init`, `seatbelt policy show` and `seatbelt policy validate`.
- Tool rules in policies, and the `mcp` preset.
- The hook checks `mcp__*` tools.
- `FuzzEvaluate`, `FuzzDisguises` and `FuzzGlobalFlags`.
- Full documentation in `docs/`.

### Changed
- First stable policy format. `version: 1` files will keep working.

## [0.5.0] - 2026-01-31

### Added
- Plan-then-commit: `confirm_mode: plan`, `seatbelt plan`, digest-bound approval.
- `aws` and `sf` presets.
- `colon_subcommands`, for tools like `sf data:query`.

## [0.4.0] - 2026-01-12

### Added
- Shell shim mode and `seatbelt run`.
- `psql` and `mysql` presets, and `flag_values` rules.
- Declared global flags. An allow rule now needs every flag ahead of the subcommand to
  be declared.
- Dangerous environment variables such as `LD_PRELOAD` and `GIT_SSH_COMMAND` are denied.

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
