# Security

## What counts as a vulnerability

Seatbelt's job is to refuse commands that its policy denies. The most useful
reports are bypasses: a command that the shell would run, but that `seatbelt check`
allows, or reports as something it isn't. For example, a destructive `rm` hidden
behind quoting, a wrapper or control flow that the parser lists wrongly.

Also in scope:

- The hook, a shim or the MCP proxy allowing something the policy denies.
- A way for a checked command to change seatbelt's own policy, audit log or plan
  without being refused.
- Plan approval being skipped or reused for a different list.
- Credentials written to the audit log unmasked when they match a shape the
  README says is masked.

Out of scope are the gaps listed under Limitations in the README, such as code run
through `python3 -c`, scripts, or commands on another machine. Seatbelt is a
guardrail, not a sandbox.

## How to report

Please use GitHub's private vulnerability reporting on this repository (Security
tab, "Report a vulnerability") rather than a public issue. Include the exact
command, the policy if it isn't the default, `seatbelt --version`, and your OS and
shell.

You should hear back within a week. Fixes for bypasses go into a patch release, and
the command that slipped through becomes a regression test.

## Supported versions

Only the latest release gets fixes.
