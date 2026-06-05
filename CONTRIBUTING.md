# Contributing

Thanks for looking. Bug reports about a command that slips past a policy are the
most valuable thing you can send.

## Reporting a bypass

Include the exact command string, the shell it runs under, and the output of
`seatbelt check --json '...'`. If you have found a way to make a real destructive
command read as safe, open a private security advisory on the repository instead
of a public issue.

## Setup

You need Go 1.24 or newer, and bash for the parser comparison tests.

```sh
make build     # builds ./seatbelt
make test      # everything, including the end-to-end tests
make short     # skips the tests that spawn bash
make lint      # golangci-lint v2
make fuzz      # runs each fuzz target for 60s, or set FUZZTIME
make soak      # compares the parser with your bash on 200k scripts, or set SOAK
```

## Changing the parser

The parser has one rule: when it isn't sure what the shell will do, it returns an
error. So adding support for new syntax is a security change, and it needs:

- a row in the table tests in `internal/shell`
- a script in `knownScripts` in `internal/shell/differential_test.go`, if bash can
  run it
- a soak run with `make soak` on your machine

If you find a mismatch with bash, the fix is usually to refuse the input rather
than to model it.

## Adding or changing a preset

Presets live in `internal/presets/*.yaml`. Each one has a table in
`internal/policy/presets_test.go` with commands that must allow, confirm and deny.
Every new rule needs rows in that table, including the spellings you expect people
to use: abbreviated flags, flags before the subcommand, path-qualified binaries.

Rules for presets:

- reading is allowed, writing confirms, deleting is denied
- an allow rule must not match something that writes, so prefer `branch $` to
  `branch` and add a separate rule for the write
- no vendor, company or environment names

## Style

Run `gofmt`. Keep dependencies to what's in `go.mod` today unless there's a strong
reason. Table-driven tests are the default here. Commit messages are short and
lowercase.

## Releases

Bump `internal/version/version.go`, move the changelog entries under a new version
heading, and tag `vX.Y.Z`. The `.goreleaser.yaml` config builds the archives;
`make release-check` validates it.
