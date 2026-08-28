# agent-seatbelt

A policy layer between AI agents and dangerous CLIs.

Give a coding agent a shell and it will, sooner or later, run `git push --force`,
`kubectl delete` or `terraform destroy` with total confidence. Permission prompts help
until you've approved your fiftieth `npm test` and stop reading them.

Seatbelt reads every command before it runs, and answers **allow**, **confirm** or
**deny** from a YAML policy. It knows what `sudo env A=1 bash -c "r\m -rf build"` really
does, and when it can't work out what a command does, it says no.

![seatbelt checking commands in a terminal](docs/demo.gif)

- **Reads commands the way a shell does.** Quoting, chains, pipes, subshells,
  substitutions, here-documents, wrappers and nested shells.
- **Denies what it can't read.** `$(echo rm) -rf x` has no fixed program name, so it
  doesn't get the benefit of the doubt.
- **Ships with presets** for `git`, `gh`, `rm`, `kubectl`, `terraform`, `aws`, `psql`,
  `mysql` and the Salesforce `sf` CLI. Reading is allowed, writing confirms, and deleting
  is denied.
- **Plugs in three ways:** a Claude Code PreToolUse hook, shell shims on `PATH`, and an
  MCP proxy.
- **Plan-then-commit.** Queue writes in a file, have a person approve that exact list,
  then run it.
- **Keeps a JSONL audit log** of every decision, searchable with `seatbelt log`.
- **One static binary.** It never calls the network.

Seatbelt is a guardrail, not a sandbox. Read [what it doesn't protect
against](#limitations) before relying on it.

## Quick start

You need Go 1.24 or newer.

```sh
go install github.com/deanyool/agent-seatbelt/cmd/seatbelt@latest
```

It works with no configuration. The built-in policy loads every preset:

```text
$ seatbelt check 'git status && git push origin main'
ALLOW   git status
        git/read: matched this rule
CONFIRM git push origin main
        git/write: this changes the repository

$ seatbelt check 'kubectl --context prod delete ns payments'
DENY    kubectl --context prod delete ns payments
        kubectl/delete: deleting cluster resources is never allowed

$ seatbelt check 'sudo env FOO=1 bash -c "r\m -rf /tmp/build"'
DENY    FOO=1 r\m -rf /tmp/build
        rm/delete: deleting files is never allowed

$ seatbelt check '$(echo rm) -rf /tmp/build'
DENY    $(echo rm) -rf /tmp/build
        seatbelt/unparsed: cannot read this command with confidence: the program name $(echo rm) is only known at run time

$ seatbelt check 'psql -c "select 1; drop table users"'
DENY    psql -c "select 1; drop table users"
        psql/destructive: DROP, TRUNCATE and DELETE are never allowed
```

`seatbelt check` exits 0 for allow, 3 for confirm and 4 for deny, so scripts can use it
too.

### Protect Claude Code

```sh
seatbelt hook install
```

This adds a [PreToolUse hook](https://code.claude.com/docs/en/hooks) to
`~/.claude/settings.json` and leaves the rest of the file alone. From then on, every Bash
command, file edit and MCP call goes through seatbelt:

```text
$ echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
    | seatbelt hook claude-code
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"seatbelt: force pushes rewrite shared history (rule git/force-push)"}}
```

The model sees the reason and can change course. Allowed commands produce no output, so
Claude Code's own permissions keep working as before.

### Protect anything else

Shims work for any agent that uses `PATH`:

```sh
seatbelt shim install git kubectl terraform
export PATH="$HOME/.seatbelt/shims:$PATH"
```

Wrap a stdio MCP server to apply the same policy to its tools:

```json
{
  "mcpServers": {
    "tickets": {
      "command": "seatbelt",
      "args": ["mcp-proxy", "--server", "tickets", "--", "npx", "some-tickets-server"]
    }
  }
}
```

See [docs/integrations.md](docs/integrations.md) for the details of each.

## Configuration

`seatbelt init` writes a commented starter policy to `~/.config/seatbelt/policy.yaml`.
Here's a small one:

```yaml
version: 1
presets: [git, rm, kubectl]

settings:
  default: deny            # a preset's program, but no rule matched
  unknown_commands: allow  # a program no preset mentions, like npm
  unparsed: deny           # can't be read with confidence
  dynamic: deny            # an allow that depends on $VARIABLES
  confirm_mode: ask        # or "plan" to queue instead of asking

rules:
  - id: commit-freely
    command: git
    subcommand: [add, commit]
    decision: allow

  - id: no-prod
    command: kubectl
    flag_values:
      - flags: [--context]
        any: ["prod-*"]
    decision: deny
    reason: production goes through CI
```

The rules that decide the outcome, in order:

1. A `deny` from anywhere wins. To lift a preset's deny, name it in `disable`.
2. Your rules beat preset rules.
3. Within a layer, `confirm` beats `allow`.
4. A chain of commands takes the strictest result of its parts.

A rule can match on `command`, `subcommand`, `flags`, `args` and `flag_values`, with globs
or `re:` regular expressions. Abbreviated flags, clustered flags (`-rf`), `--flag=value`
and flags ahead of the subcommand are all handled, so `git -C /tmp push --forc` is still a
force push.

The policy is loaded from `--policy`, `$SEATBELT_POLICY`,
`~/.config/seatbelt/policy.yaml`, or else the built-in default. A file in the current
directory is never loaded, so a repository can't relax the rules applied to it.

The full reference is in [docs/policy.md](docs/policy.md), and the presets are described in
[docs/presets.md](docs/presets.md).

## Plan-then-commit

Set `confirm_mode: plan` and anything that would ask a person is queued instead. The agent
is told it hasn't run. Later, you review the list and approve it on your terminal:

```sh
seatbelt plan show
seatbelt plan approve   # asks you to type a code from the plan's digest
seatbelt plan apply     # re-checks each command, then runs them in order
```

An approval covers one exact list. Adding a command voids it, and so does editing the
file. There's no flag to skip the prompt, because anything a flag can do, an agent with a
shell can do too.

## Audit log


```text
$ seatbelt log --decision deny --since 24h
2026-03-02 22:36:49  DENY    hook  git push --force origin main  [git/force-push]
```

## How it works

```text
"sudo env A=1 sh -c 'git status && rm x'"
    parse    words, operators, nesting, here-documents, substitutions
    flatten  look through sudo, env, sh -c, eval, xargs, find -exec
    match    every command against the policy
    decide   the strictest result wins

sudo (wrapper)   env (wrapper)   sh (wrapper)   git status: ALLOW   rm x: DENY   ==> DENY
```

The parser in `internal/shell` is built around one rule: when it isn't sure what the shell
will do, it returns an error, and an error is a denial. Forms it doesn't model, such as
`case`, function definitions and `${!x}`, are refused rather than guessed at.

The property that matters is that every command the shell really runs is in the list the
parser returned, and that is tested directly. A differential test generates scripts, runs
them under a real bash with stub commands that record every call, and fails if bash ran
anything the parser didn't list. Fuzz targets then hide destructive commands behind random
quoting, wrappers and control flow, and require a denial every time.

Evaluating a command takes about 10 microseconds. One hook call, including process start
and loading the policy, takes about 17 ms. Those are measured on an Apple M5, and
[docs/how-it-works.md](docs/how-it-works.md) has the details.

## Limitations

Seatbelt decides from the text of a command, and it runs as you. It stops confident
mistakes. It does not stop a determined adversary.

- **Code in another language isn't read.** `python3 -c`, `node -e` and `perl -e` can do
  anything, and with `unknown_commands: allow` they run.
- **Scripts and builds are single commands.** `./deploy.sh` and `make clean` look like one
  allowed program, and seatbelt can't see inside them.
- **Remote commands aren't seen.** `ssh host '...'`, `docker run` and `curl -X DELETE`
  reach things seatbelt knows nothing about.
- **The agent runs as your user.** Protected paths block the obvious routes to seatbelt's
  own files, but this isn't a security boundary.
- **zsh support is best effort.** The parser targets POSIX sh and bash, plus the zsh forms
  that turn up in practice. fish isn't modeled.
- **`cd` isn't followed**, and symlinks aren't resolved, when checking protected paths.
- **SQL is matched by pattern, not parsed.** Use a read-only role for anything important.

If you need a real boundary, use one: a container, a read-only database role, a narrowly
scoped token, a protected branch. [docs/threat-model.md](docs/threat-model.md) goes through
all of this, including exactly what fails open.

## Contributing

Reports of commands that slip through are especially welcome.
[CONTRIBUTING.md](CONTRIBUTING.md) explains how to report one and how to test changes to
the parser.

## License

MIT. See [LICENSE](LICENSE).
