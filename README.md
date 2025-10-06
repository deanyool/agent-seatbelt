# agent-seatbelt

Stops AI coding agents from running dangerous commands.

## Install

    go install github.com/deanyool/agent-seatbelt/cmd/seatbelt@latest

## Use

    seatbelt check 'git push --force'

Claude Code hook, in settings.json:

    {"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"seatbelt hook"}]}]}}

Rules live in internal/presets for now.
