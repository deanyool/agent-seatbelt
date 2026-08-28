# Integrations

All three integrations use the same policy and the same audit log.

## Claude Code hook

`seatbelt hook claude-code` implements the
[PreToolUse hook](https://code.claude.com/docs/en/hooks). Install it with:

```sh
seatbelt hook install             # your user settings
seatbelt hook install --project   # .claude/settings.json in this directory
seatbelt hook print               # print the JSON and do nothing
```

Which adds this to `settings.json`, keeping everything else in the file:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|MultiEdit|Write|NotebookEdit|mcp__.*",
        "hooks": [
          { "type": "command", "command": "/path/to/seatbelt hook claude-code" }
        ]
      }
    ]
  }
}
```

What the hook does with each tool:

| Tool | Check |
| --- | --- |
| `Bash` | Parses `tool_input.command` and evaluates it. |
| `Edit`, `MultiEdit`, `Write`, `NotebookEdit` | Checks the file path against the protected paths. |
| `mcp__*` | Evaluates the tool rules. |
| anything else | No opinion. |

| Decision | Output |
| --- | --- |
| allow | Nothing, exit 0. Claude Code's normal permission flow carries on. |
| confirm | `permissionDecision: "ask"`, exit 0. |
| deny | `permissionDecision: "deny"` with the reason, exit 0. The model sees the reason. |
| any failure | Message on stderr, exit 2. |

Staying silent on allow matters: an `allow` answer skips Claude Code's own prompts,
which would give the agent more than it had before. Pass `--auto-approve` if that's
what you want.

Every failure exits 2 because Claude Code treats any other nonzero exit as a broken
hook and runs the tool anyway. A broken policy file therefore blocks every checked
tool until it's fixed.

A hook that hits its timeout does not block the call. Seatbelt answers in tens of
milliseconds, so this needs something like a hung disk, but it is worth knowing.

## Shell shims

Shims catch commands from anything that uses `PATH`, not only from one agent.

```sh
seatbelt shim install git kubectl terraform
export PATH="$HOME/.seatbelt/shims:$PATH"   # in the agent's environment
```

Each shim is a symlink to seatbelt. When it runs, seatbelt evaluates the arguments,
then finds the real program further along `PATH` and replaces itself with it, so
exit codes, streams and signals behave normally. A refused command exits 126.

A shim sees arguments after the shell has expanded them, so there's nothing to parse
and no expansion to worry about. In exchange it sees only the program it shadows:
`/usr/bin/git` called by full path goes straight past it. Use the hook as well if you
can.

## MCP proxy

Wrap a stdio MCP server in your client's config:

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

The proxy reads every message from the client. `tools/call` is checked against the
tool rules using the name `mcp__tickets__<tool>`. A refused call never reaches the
server, and the client receives a tool result with `isError: true` and the reason,
which the model can read and react to.

Denied tools are removed from `tools/list` too, so the model doesn't plan around
them. Pass `--show-denied` to keep them listed.

Client messages are decoded and re-encoded before they're forwarded, so the server
gets exactly what was checked. Two parsers can disagree about JSON with a duplicated
`name` key, but only one reading ever reaches the server. Keys that differ only in
case from `method`, `params`, `name` or `arguments` are refused, because Go servers
match struct fields without regard to case.

The proxy has no person to ask, so `confirm` is a refusal unless `confirm_mode` is
`plan`.

## Plan-then-commit

Set `confirm_mode: plan` and anything that would ask a person goes to a plan file
instead, and the agent is told it hasn't run.

```text
$ seatbelt plan show
2 pending, not approved, digest 3f2a9c81d0b7
a41c9e02  git push origin main
          in /home/me/app
          this changes the repository
7bd03f11  kubectl apply -f deploy.yaml
          in /home/me/app
          this changes the cluster

$ seatbelt plan approve
  a41c9e02  git push origin main
            in /home/me/app
  7bd03f11  kubectl apply -f deploy.yaml
            in /home/me/app
Type 3f2a9c to approve these 2 command(s): 3f2a9c
approved. Run `seatbelt plan apply` to execute it.

$ seatbelt plan apply
+ git push origin main
+ kubectl apply -f deploy.yaml
applied 2 command(s)
```

Approval reads from the terminal, not from stdin, and there is no flag to skip it,
because anything a flag can do, an agent with a shell can do too. An approval covers
one exact list: adding a command voids it, and so does editing the file. `apply`
re-checks each command against the current policy right before running it, stops at
the first failure, and uses up the approval either way. The `seatbelt` preset denies
`plan approve` and `plan apply` when they arrive through a checked channel.

## Audit log

Every decision made by the hook, shims, proxy and `run` is appended to

```sh
seatbelt log --decision deny --since 24h
seatbelt log --grep prod --source hook --limit 20
seatbelt log --json | jq .command
```
