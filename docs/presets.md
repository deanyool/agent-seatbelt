# Presets

Presets are ordinary policy files embedded in the binary. Read one with
`seatbelt preset show NAME`. They all follow the same shape: reading is allowed, writing
confirms, deleting is denied, and anything in the program's territory that no rule
mentions gets `settings.default`, which is deny.

| Preset | Programs | Allowed | Confirm | Denied |
| --- | --- | --- | --- | --- |
| `git` | `git` | status, log, diff, show, blame, fetch, listings | add, commit, push, pull, merge, rebase, checkout | force push, `reset --hard`, `clean`, branch and tag deletes, `rm`, `filter-branch`, `--no-verify`, `-c` overrides |
| `gh` | `gh` | list, view, diff, checks, search, GET `api` | create, edit, comment, merge, `api` writes | any delete, `auth token`, `pr merge --admin` |
| `rm` | `rm`, `rmdir`, `unlink`, `shred`, `find`, `dd`, `rsync`, `mkfs` | `find` without `-delete` | `rsync` | every delete, `find -delete`, `dd of=`, `rsync --delete`, `truncate` |
| `kubectl` | `kubectl`, `oc`, `kubecolor` | get, describe, logs, top, `config view` | apply, patch, scale, exec, reading secrets | delete, drain, replace, `apply --prune` |
| `terraform` | `terraform`, `tofu` | plan, show, validate, output, `state list` | apply, init, import, `state mv` | destroy, `apply -destroy`, `-auto-approve`, `state rm`, `force-unlock` |
| `aws` | `aws` | `describe-*`, `list-*`, `get-*`, `s3 ls` | `create-*`, `put-*`, `run-*`, `s3 cp`, reading secrets | `delete-*`, `terminate-*`, `s3 rm`, `s3 rb`, `s3 sync --delete` |
| `psql` | `psql` | `-c` with SELECT, SHOW, EXPLAIN or `\d` | INSERT, UPDATE, ALTER, `-f` | DROP, TRUNCATE, DELETE, `\!`, `COPY ... PROGRAM`, no `-c` at all |
| `mysql` | `mysql`, `mariadb`, `mysqladmin` | `-e` with SELECT, SHOW, DESCRIBE | INSERT, UPDATE, ALTER | DROP, TRUNCATE, DELETE, `INTO OUTFILE`, `system`, no `-e` at all |
| `sf` | `sf`, `sfdx` | org list, `data query`, `sobject describe`, previews | data create and update, deploy, retrieve | `data delete`, `org delete`, `project delete`, `apex run` |
| `mcp` | tool calls | | | tools named like delete, drop, destroy, truncate, purge, wipe, remove, erase |
| `seatbelt` | `seatbelt` | check, log, `plan add`, `plan show` | | `plan approve`, `plan apply`, `init`, `shim`, `hook` |

The `seatbelt` preset is always loaded.

## Changing what a preset does

Add a rule of your own to loosen a `confirm`:

```yaml
rules:
  - id: commit-freely
    command: git
    subcommand: [add, commit]
    decision: allow
```

Your rules beat preset rules, but a deny always wins. To lift a deny, disable it by
name, and then decide what should happen instead:

```yaml
disable: [rm/delete]
rules:
  - id: relative-paths-only
    command: rm
    args:
      none: ["/*", "~*", "*..*"]
    decision: allow
```

`seatbelt preset show git` shows the rule ids. In the example, `rm -rf build` is allowed.
`rm /etc/hosts`, `rm ../x` and `rm "$X"` don't match the rule, because an expansion is
assumed to be what an allow rule forbids, so they fall through to `settings.default`,
which is deny.
