# Policy reference

A policy is a YAML file. Unknown fields are errors, so a typo can't quietly turn a
rule into something that never matches. Check a file with
`seatbelt policy validate FILE`.

```yaml
version: 1
presets: [git, gh, rm, kubectl]
disable: [git/skip-hooks]

settings:
  default: deny
  unknown_commands: allow
  unknown_tools: allow
  unparsed: deny
  dynamic: deny
  confirm_mode: ask
  audit_log: ~/logs/seatbelt.jsonl
  dangerous_env: [MY_PLUGIN_PATH]

commands:
  deployctl:
    global_flags:
      value: [--cluster]
      bool: [--quiet]
    value_flags: [--env, --output]

rules:
  - id: deploy-staging
    command: deployctl
    subcommand: [push]
    flag_values:
      - flags: [--env]
        any: [staging]
    decision: allow

tools:
  - id: read-tickets
    tool: "mcp__tickets__get_*"
    decision: allow
```

## Where the policy comes from

In order: `--policy FILE`, `$SEATBELT_POLICY`, `./.seatbelt.yaml`,
`~/.config/seatbelt/policy.yaml`, then the built-in default, which loads every preset.

## Decisions

| Decision | Hook | Shim and `run` | MCP proxy |
| --- | --- | --- | --- |
| `allow` | stays silent, so Claude Code's own permission flow continues | runs | forwards |
| `confirm` | answers `ask` | prompts on the terminal, refuses without one | refuses with a tool error |
| `deny` | answers `deny` | refuses, exit 126 | refuses with a tool error |

With `confirm_mode: plan`, every confirm queues the command in the plan file
instead, and the caller is told it has not run.

## Precedence

Rules are checked as a set, so their order doesn't matter.

1. A `deny` from any rule wins. A user rule cannot allow what a preset denies. To
   lift a preset's deny, name the rule in `disable`.
2. Otherwise your own rules beat preset rules.
3. Within a layer, `confirm` beats `allow`.
4. With no match, a program with a preset or rule gets `settings.default`, and any
   other program gets `settings.unknown_commands`.

A chain of commands takes the strictest result of its parts.

## settings

| Key | Default | Meaning |
| --- | --- | --- |
| `default` | `deny` | A governed program with no matching rule. |
| `unknown_commands` | `allow` | A program no preset or rule mentions. |
| `unknown_tools` | `allow` | A tool name no tool rule matches. |
| `unparsed` | `deny` | Input that can't be read with confidence. `confirm` is accepted, `allow` is an error. |
| `dynamic` | `deny` | An `allow` that depends on an expansion, such as `git log $X`. |
| `confirm_mode` | `ask` | `ask` or `plan`. |
| `audit_log` | `~/.seatbelt/audit.jsonl` | Log location. `$SEATBELT_AUDIT_LOG` also sets it. |
| `dangerous_env` | see below | Extra variable names to refuse. |


## rules

| Key | Meaning |
| --- | --- |
| `id` | Required. Preset rules are named `preset/id`. |
| `command` | Required. A name or list of names, or `*` for any program. Matched against the lower-cased base name, so `/usr/bin/GIT` is `git`. |
| `subcommand` | One path or a list of alternatives. See below. |
| `flags` | A list means any of them. Or a map with `any`, `all` and `none`. |
| `args` | Patterns for positional arguments after the subcommand. A list means any, or use a map with `any`, `all` and `none`. |
| `flag_values` | A list of `{flags, any, none}` that test the values given to flags. |
| `decision` | Required. `allow`, `confirm` or `deny`. |
| `reason` | Shown to the agent and written to the log. |

Every condition present must hold.

### Subcommand paths

A path is space-separated patterns matched against positional arguments in order,
skipping flags: `pr merge` matches `gh pr merge 1` and `gh pr --repo o/r merge 1`.
The marker `$` means no more positional arguments, so `branch $` matches
`git branch -a` but not `git branch new`.

For an `allow` rule the path only counts if every flag ahead of it is declared in
`commands`. An undeclared flag might take a value, and then the words after it
aren't the subcommand.

### Flags

`-rf` matches rules for `-r`, `-f` and `-rf`. `--force=false` counts as `--force`.
Everything after `--` is positional. For strict rules (`confirm` and `deny`) an
abbreviation counts too, because git and getopt accept any unique prefix: `--forc`
matches `--force`.

### Patterns

Plain text is a glob where `*` and `?` also cross slashes, matched against the whole
string. Text starting with `re:` is a Go regular expression, unanchored, and those
run in linear time. A pattern matching an expansion is a guess, so it resolves
toward safety: strict rules assume it matches and allow rules assume it doesn't.

## commands

| Key | Meaning |
| --- | --- |
| `aliases` | Other program names that act the same, like `tofu` for `terraform`. |
| `global_flags.value` | Flags before the subcommand that take a value. |
| `global_flags.bool` | Flags before the subcommand that don't. |
| `value_flags` | Flags that take a value anywhere. |
| `single_dash` | `-name` is one flag, not a cluster, as with Terraform and `find`. |
| `colon_subcommands` | `data:query` means `data query`, as with oclif tools. |

Declaring a command makes it governed, so unmatched uses get `settings.default`.

## tools

Tool rules match named calls, from the hook or the MCP proxy.

| Key | Meaning |
| --- | --- |
| `id` | Required. |
| `tool` | Required. A pattern or list, tried against the full name and the part after the last `__`. |
| `input` | A map of argument name to patterns, using the same forms as `args`. Non-string values are matched as JSON. |
| `decision` | Required. |
| `reason` | Shown to the agent. |
