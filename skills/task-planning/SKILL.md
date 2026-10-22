---
name: task-planning
description: "Deconstruct a request into a JSON plan of verifiable steps assigned to specialized agents, with explicit dependencies and limits."
metadata:
  agents: "orchestrator"
  tools: "(none)"
---

# task-planning

> A CrewAI Skill is a set of **instructions** loaded into the agent's prompt. It grants **no permissions**:
> permissions originate from `config/permissions.jsonc` and are enforced by the tool code.

## Objective
Produce a plan that code can validate deterministically (existing agents, acyclic graph, bounded step count) prior to execution.

## Preconditions
- User request is unambiguous; if unclear, produce a single-step plan asking for clarification.
- Only agents listed in planning context are available.

## Parameters / Tools
Tools: (none).
Plan = {goal, steps:[{id, agent, instruction, expected_output, depends_on[]}]}. Short `id` (s1, s2…). `agent` ∈ provided list. `depends_on` references only PRIOR steps.

## Results
JSON object matching `Plan` schema (validated by `agents_flow.crew.plan.validate_plan`).

## Possible Errors
Unknown agent, cycle detected, dependency on non-existent step, too many steps, instruction too long: plan rejected; single re-planning allowed.

## Permissions
None: orchestrator holds no tools and no capabilities.

## Security Boundaries
- Include in `instruction` only information necessary for the step (need-to-know principle).
- Never include secrets, raw web content, or full file contents in an instruction.
- A write step must always follow a read/analysis step; a commit step is separate from a write step.
- No step can be assigned to the orchestrator itself.

## Tests
tests/integration/test_orchestrator.py (plan validation)

## Guidelines
Rules: prefer concise plans; parallelization is optional; every step must have a verifiable `expected_output` (e.g. "list of cited URLs", "created file path").