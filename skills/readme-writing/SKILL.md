---
name: readme-writing
description: "Draft or improve a project README and technical documentation based on actual code analysis, without inventing anything."
metadata:
  agents: "doc_writer"
  tools: "read_file, list_dir, search_in_files, scan_project, create_file, modify_file, check_file_modifiable"
---

# readme-writing

> A CrewAI Skill is a set of **instructions** loaded into the agent's prompt. It grants **no permissions**:
> permissions originate from `config/permissions.jsonc` and are enforced by the tool code.

## Objective
Exact, verifiable documentation free of secrets.

## Preconditions
- Ran `scan_project` and inspected files cited in the README.

## Parameters / Tools
Tools: read_file, list_dir, search_in_files, scan_project, create_file, modify_file, check_file_modifiable.
See safe-file-editing.

## Results
Created README (or `README.proposed.md` if existing README cannot be overwritten directly) + list of unverified items.

## Possible Errors
See safe-file-editing.

## Permissions
`fs.read`, `fs.write`.

## Security Boundaries
- Never invent features, commands, dependencies, or test outputs: mark as "unverified".
- Environment variables: names and description only, never concrete secret values.

## Tests
tests/tools/test_file_tools.py

## Guidelines
Suggested sections based on project: overview, features, architecture, prerequisites, installation, configuration, environment variables, usage, testing, structure, troubleshooting, limitations, license/contributing (if known).