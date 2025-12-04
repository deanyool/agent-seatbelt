# agent-seatbelt

Stops AI coding agents from running dangerous commands. Every command goes through a
policy first, and gets allow, confirm or deny.

## Install

    go install github.com/deanyool/agent-seatbelt/cmd/seatbelt@latest

## Use

    seatbelt check 'git push --force'
    seatbelt log --decision deny

Claude Code hook, in settings.json:

    {"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"seatbelt hook claude-code"}]}]}}

## Policy

Without a config it loads every preset (git, gh, rm, kubectl, terraform). To write your
own, put a file at ~/.config/seatbelt/policy.yaml or ./.seatbelt.yaml:

    version: 1
    presets: [git, rm]
    rules:
      - id: no-sudo
        command: sudo
        decision: deny

Deny always wins. Your rules beat presets. Commands the parser can't read are denied.
