# How it works

Seatbelt is a static checker. It reads a command as text, works out every program the
shell would start, and matches each one against a policy. It never runs anything to
find out.

```text
"sudo env A=1 sh -c 'git status && rm x'"
        |
        |  shell.Parse: words, operators, nesting
        v
sudo env A=1 sh -c '...'
        |
        |  shell.Flatten: look through wrappers and nested shells
        v
sudo (wrapper)   env (wrapper)   sh (wrapper)   git status   rm x
        |
        |  policy.Evaluate: each command, then the strictest result
        v
ALLOW git status   DENY rm x   ==>  DENY
```

## The parser

`internal/shell` is a hand-written recursive descent parser for the parts of POSIX sh
and bash that decide what runs. It tracks single and double quotes, backslashes, line
continuations, comments, redirections, here-documents, `$(...)`, backticks, process
substitution, subshells, brace groups, `if`, `while`, `until`, `for` and `[[ ]]`.

It flattens control flow on purpose. A command in a branch that would never run still
appears in the list, so the list is a superset of what happens.

**It refuses what it doesn't model.** `case`, function definitions, C-style `for`,
arrays, arithmetic on variables, `${!x}`, `${x@P}` and similar all return an error,
and the policy turns an error into a denial. Refusing is cheap: agents rarely need
those forms, and when they do, the denial explains itself and the agent rewrites the
command.

Each word carries what's known about it:

| Word | Value | Flags |
| --- | --- | --- |
| `r"m"` | `rm` | quoted |
| `$X` | unknown | dynamic, may split |
| `"$X"` | unknown | dynamic |
| `a-$X` | `a-` + unknown | dynamic, may split |
| `*.go` | `*.go` | glob |
| `{a,b}` | unknown | dynamic, may split |

## Programs computed at run time

If the program name isn't fixed text, there's nothing to check, so it's refused.
That covers `$X`, `$(echo rm)`, `r${x}m`, `{rm,-rf,x}`, `/bin/r?`, `$'\x72\x6d'` and
zsh's `=rm`.

The name itself is reduced to a lower-cased base name, so `/usr/bin/git`, `./git`,
`GIT` and `g"i"t` are all `git`. Case folding matters because macOS volumes are usually
case-insensitive, and there `RM` really does run `rm`.

## Wrappers

`shell.Flatten` knows the flags of programs that exist to run another program: `sudo`,
`doas`, `env`, `command`, `builtin`, `exec`, `nohup`, `setsid`, `nice`, `ionice`, `time`,
`timeout`, `stdbuf`, `unbuffer`, `caffeinate`, `chroot`, `noglob`, `busybox`, `toybox`,
`watch` and `xargs`. An unknown flag is an error, because it might take a value, and
then the next word isn't the command.

Shells, `eval`, `watch` and `env -S` take code as text, and that text is parsed in
turn. `find -exec` is taken apart the same way. A shell with no `-c` and no file reads
stdin, which can't be inspected, so `curl ... | sh` is refused.

Programs that run a command line in a form seatbelt doesn't unpack, like `parallel`,
`at`, `tmux`, `script` and `strace`, are refused outright, along with builtins that
change what later commands mean, like `alias`, `trap` and `source`.

## Matching

`policy` splits each command's arguments using its `CommandSpec`: which flags are
global, which take values, whether `-abc` is a cluster or one long flag. Then every
rule for that program is tried, and precedence picks the winner (see
[policy.md](policy.md)).

Expansions meet the matcher in three places, and all resolve toward safety:

- A pattern can't be tested against an unknown value, so a strict rule assumes it
  matches and an allow rule assumes it doesn't.
- An unknown subcommand gets the `dynamic` decision.
- An allow is a claim about the whole command line, so if an expansion could add a flag
  or an argument, the allow is replaced by the `dynamic` decision. `"$X"` after `-m` or
  after `--` is safe, since it can't become a flag.
