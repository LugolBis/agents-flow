---
name: safe-inspection
description: "Inspect an environment via a strict allowlist of read-only commands (pwd, ls, find, cat, head, tail, file, stat, git status/log/diff/ls-files)."
metadata:
  agents: "shell_inspector"
  tools: "shell_inspect"
---

# safe-inspection

> A CrewAI Skill is a set of **instructions** loaded into the agent's prompt. It grants **no permissions**:
> permissions originate from `config/permissions.jsonc` and are enforced by the tool code.

## Objective
Assess environment state without ability to introduce modifications.

## Preconditions
- Single simple command per invocation.

## Parameters / Tools
Tools: shell_inspect.
shell_inspect(command, cwd).

## Results
Capped command output with secrets automatically redacted.

## Possible Errors
`shell_metacharacters`, `forbidden_command`, `command_not_allowlisted`, `flag_not_allowed`, `outside_allowed_roots`, `not_regular_file`.

## Permissions
`shell.inspect` capability — independent of developer capability.

## Security Boundaries
- No shell execution: argv executed directly, trusted absolute binary paths, empty env, bounded execution time/CPU/RAM/output.
- `find -exec/-delete`, `tail -f`, `git -c`, `--output` forbidden.
- Command rejection is an enforced rule, not an obstacle to bypass.

## Tests
tests/security/test_commands.py

## Guidelines
To search: `find . -name '*.py' -maxdepth 3` ; to read: `head -n 50 <file>`.