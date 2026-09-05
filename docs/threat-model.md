# Threat model

Seatbelt is a guardrail, not a sandbox. Knowing the difference is the point of this
page.

## What it's for

An AI agent with a shell is mostly helpful and occasionally catastrophic. The failure
is usually a confident mistake: it deletes the wrong directory, force pushes over a
colleague's work, or runs a migration against production. Seatbelt stops those before
they run, says why, and leaves a record.

It assumes an agent that is **capable and careless**, and it holds up well against one
that is trying to work around a denial, because the usual workarounds (quoting tricks,
wrappers, `bash -c`, `$(...)`) are exactly what it reads through.

## What it does not protect against

**A determined adversary.** Seatbelt runs as you, and it decides based on the text of a
command. Nothing stops an agent, or a prompt injection steering one, from:

- **Running code in a language.** `python3 -c`, `node -e`, `perl -e`, `ruby -e` and
  `awk` can do anything, and seatbelt doesn't read inside them. With
  `unknown_commands: allow` these run. Set it to `confirm` or `deny` for a stricter
  posture, at the cost of more interruptions.
- **Running a script or a build.** `./deploy.sh`, `make clean`, `npm run wipe` and
  anything else that executes a file is a single allowed command as far as seatbelt can
  tell. A script the agent wrote one step earlier counts too.
- **Reaching the network or another machine.** `ssh host 'rm -rf /'`, `docker run` and
  `kubectl exec` run commands that seatbelt doesn't see. `curl -X DELETE` against an API
  is just `curl`.
- **Deleting by other means.** `mv x /dev/null`, `> file`, `tar --remove-files`,
  `git stash` followed by a clean and `cp /dev/null file` all destroy data without
  `rm`. The presets catch common forms, not all forms.
- **Tampering with seatbelt.** The agent runs as your user, so it can edit the same
  files you can. Protected paths block the obvious routes, including through edit
  tools, but a Python one-liner isn't checked. The plan digest catches accidents, not
  an adversary, because the plan file has no secret behind it.

If you need a boundary, use a real one: a container or VM, a read-only database role,
an IAM policy, an API token with narrow scopes, a protected branch. Those are enforced
by something the agent can't talk its way past. Seatbelt is the layer that makes
day-to-day mistakes rarer and easier to see.

## Limits of the parser

- **It targets POSIX sh and bash.** zsh is a much larger language. The zsh forms that
  turn up in practice are handled (`=cmd`, `$=x`, `${(e)x}`, `if x { y }`, the
  `noglob`, `nocorrect` and `-` modifiers, `repeat`), but coverage is best effort, and
  fish isn't modeled at all.
- **Aliases and functions already in the shell are invisible.** If the shell that runs
  the command has `alias ls='something else'` from a profile, seatbelt checks `ls`.
- **Globs are treated as text in arguments.** `git add *` is checked as written, so a
  file named `--force` in the directory could become a flag. Globs in the program
  position are refused.
- **`cd` isn't followed.** `cd .git/hooks && echo x > pre-commit` isn't recognized as a
  write to a protected path, because the path is relative to a directory that changed.
  Symlinks aren't resolved either.
- **Variables set by other means aren't tracked.** Dangerous environment variables are
  caught in `NAME=value`, `export` and `declare`, but not through `read` or `printf -v`.
- **Wrappers are a list.** A program that runs other programs and isn't in the list or
  the refused list looks like an ordinary program. `npx`, `uv run` and `bundle exec` are
  in that position.
- **SQL is matched by pattern, not parsed.** `SELECT dangerous_function()` passes if the
  function's name isn't listed. Use a read-only database role for anything that matters.

## Failure behavior

| Situation | Result |
| --- | --- |
| Command can't be parsed | Denied |
| Hook payload is malformed or missing fields | Blocked, exit 2 |
| Policy file is broken | Hook blocks everything it checks, shims refuse to run |
| Policy file is missing | Falls back to the built-in default, all presets |
| Audit log can't be written | Warning on stderr, the decision still stands |
| No terminal for a confirm prompt | Refused |
| Hook times out in Claude Code | **The call proceeds.** This is Claude Code's behavior for a timed-out hook |

The audit log fails open on purpose: a full disk shouldn't turn a read-only command into
an outage. Everything else fails closed.
