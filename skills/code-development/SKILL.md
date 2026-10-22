---
name: code-development
description: "Design, fix, refactor, and test code adhering to project conventions, with writes subject to Git guardrails."
metadata:
  agents: "developer"
  tools: "read_file, list_dir, search_in_files, create_file, modify_file, check_file_modifiable (run_tests if enabled)"
---

# code-development

> A CrewAI Skill is a set of **instructions** loaded into the agent's prompt. It grants **no permissions**:
> permissions originate from `config/permissions.jsonc` and are enforced by the tool code.

## Objective
Deliver minimal, readable, and tested code changes.

## Preconditions
- Read affected files and existing tests first.

## Parameters / Tools
Tools: read_file, list_dir, search_in_files, create_file, modify_file, check_file_modifiable (run_tests if enabled).
See safe-file-editing. `run_tests(path)` only if administrator enabled it inside a sandbox.

## Results
Created/modified files, added tests, justification, and explicit statement of what was NOT executed.

## Possible Errors
See safe-file-editing; `tests_disabled` if test execution is turned off.

## Permissions
`fs.read`, `fs.write`, `exec.tests` (tool disabled by default). No shell, no internet access, no secrets.

## Security Boundaries
- Bash is out of scope: do not write shell scripts to bypass the inspector.
- Never claim a test passed without having executed it.
- No dependencies added without absolute necessity.

## Tests
tests/tools/test_file_tools.py

## Guidelines
Write unit tests alongside code changes. If tests cannot be run, provide the exact command to run manually and state it clearly.