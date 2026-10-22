---
name: safe-file-editing
description: "Create and modify files adhering to the Git rule: an existing file is modifiable only if tracked, committed, and clean."
metadata:
  agents: "file_editor, developer, doc_writer"
  tools: "read_file, list_dir, search_in_files, create_file, modify_file, check_file_modifiable"
---

# safe-file-editing

> A CrewAI Skill is a set of **instructions** loaded into the agent's prompt. It grants **no permissions**:
> permissions originate from `config/permissions.jsonc` and are enforced by the tool code.

## Objective
Write without overwriting uncommitted or unsaved work.

## Preconditions
- Read the file before modifying it.
- `check_file_modifiable` can be invoked before `modify_file` to determine status.

## Parameters / Tools
Tools: read_file, list_dir, search_in_files, create_file, modify_file, check_file_modifiable.
create_file(path, content) ; modify_file(path, edits[{old,new}] | content) ; edits = all-or-nothing, each `old` must be unique.

## Results
Written path + verification (hash, diff --stat). If direct modification is blocked: original file stays INTACT and a proposed file `<name>.proposed<ext>` is written with an explanation.

## Possible Errors
`already_exists`, `edit_not_unique`, `outside_allowed_roots`, `path_traversal`, `symlink_in_path`, `denied_by_pattern`, `write_denied_by_pattern`, `secret_in_content`, `content_too_large`, `binary_file`.

## Permissions
`fs.read` (+ `fs.write` to create/modify).

## Security Boundaries
- Never attempt an alternate path, symlink, or alternate tool following a refusal.
- `.env` files, keys, `.git/`, `.github/workflows/**`, and `.gitattributes` are strictly write-protected.
- A newly created file not yet committed cannot be modified directly: succeed in one write or request a commit.

## Tests
tests/tools/test_file_tools.py ; tests/security/test_git_guard.py

## Guidelines
Prefer `edits` (minimal precise changes) over overwriting full `content`. After modification, report actual verified diff rather than assumed content.