//! Plan produced by the orchestrator, VALIDATED by code before any execution: the LLM proposes, the code disposes — existing agents,
//! acyclic graph, bounded number of steps and instruction size. An invalid plan is never executed.
use crate::config::models::agents::OrchestrationCfg;
use crate::engine::protocol::extract_json;
use crate::util::clip;

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::LazyLock;

static ID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]{0,15}$").unwrap());

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PlanStep {
    pub id: String,
    pub agent: String,
    pub instruction: String,
    pub expected_output: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub goal: String,
    pub steps: Vec<PlanStep>,
}

impl Plan {
    /// Parses model output (JSON possibly wrapped in fences/prose) and checks the field constraints.
    pub fn from_text(raw: &str) -> Result<Plan, String> {
        let plan: Plan = serde_json::from_str(&extract_json(raw))
            .map_err(|err| format!("invalid JSON plan : {err}"))?;

        plan.check_fields()?;
        Ok(plan)
    }

    pub fn check_fields(&self) -> Result<(), String> {
        if self.goal.chars().count() < 3 {
            return Err("goal too short".into());
        }

        if self.steps.is_empty() {
            return Err("at least one step is required".into());
        }

        for step in &self.steps {
            if !ID_RE.is_match(&step.id) {
                return Err(format!(
                    "invalid step identifier : '{}'",
                    clip(&step.id, 20)
                ));
            }

            if step.instruction.chars().count() < 5 || step.expected_output.chars().count() < 3 {
                return Err(format!(
                    "{}: instruction or result expected is too short",
                    step.id
                ));
            }
        }
        Ok(())
    }
}

/// JSON Schema of `Plan`, specialised for this run: `agent` is an ENUM of the real worker ids (constrained decoding cannot invent an agent),
/// the number of steps and the instruction length follow the orchestration limits. `validate_plan` still re-checks everything in code.
pub fn plan_schema(workers: &[String], cfg: &OrchestrationCfg) -> serde_json::Value {
    serde_json::json!({
    "type": "object", "additionalProperties": false, "required": ["goal", "steps"],
    "properties": {
        "goal": {"type": "string", "minLength": 3},
        "steps": {"type": "array", "minItems": 1, "maxItems": cfg.max_steps, "items": {
            "type": "object", "additionalProperties": false, "required": ["id", "agent", "instruction", "expected_output"],
            "properties": {
                "id": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,15}$"},
                "agent": {"enum": workers},
                "instruction": {"type": "string", "minLength": 5, "maxLength": cfg.max_instruction_chars},
                "expected_output": {"type": "string", "minLength": 3},
                "depends_on": {"type": "array", "items": {"type": "string"}}
            }}}
    }})
}

/// Returns the list of errors (empty = valid plan).
pub fn validate_plan(plan: &Plan, workers: &[String], cfg: &OrchestrationCfg) -> Vec<String> {
    let mut errors = Vec::new();
    if plan.steps.len() > cfg.max_steps {
        errors.push(format!(
            "too many steps ({} > {})",
            plan.steps.len(),
            cfg.max_steps
        ));
    }

    let ids: Vec<&str> = plan.steps.iter().map(|step| step.id.as_str()).collect();
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        errors.push("duplicated step identifiers".into());
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for step in &plan.steps {
        if !workers.contains(&step.agent) {
            errors.push(format!(
                "{}: unknown agent '{}' or forbidden (allowed : {})",
                step.id,
                step.agent,
                workers.join(", ")
            ));
        }

        if step.instruction.chars().count() > cfg.max_instruction_chars {
            errors.push(format!(
                "{}: too long instruction (> {})",
                step.id, cfg.max_instruction_chars
            ));
        }

        for dependency in &step.depends_on {
            if *dependency == step.id {
                errors.push(format!("{}: depends from itself", step.id));
            } else if !ids.contains(&dependency.as_str()) {
                errors.push(format!("{}: unknown dependency '{dependency}'", step.id));
            } else if !seen.contains(dependency.as_str()) {
                errors.push(format!(
                    "{}: depends on '{dependency}' who's not an ancestor (order or cycle)",
                    step.id
                ));
            }
        }
        seen.insert(&step.id);
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    fn step(id: &str, agent: &str, deps: &[&str]) -> PlanStep {
        PlanStep {
            id: id.into(),
            agent: agent.into(),
            instruction: "do the thing".into(),
            expected_output: "result".into(),
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
        }
    }
    #[test]
    fn plan_validation() {
        let cfg = OrchestrationCfg::default();
        let w = vec!["a".to_string(), "b".to_string()];
        let ok = Plan {
            goal: "goal".into(),
            steps: vec![step("s1", "a", &[]), step("s2", "b", &["s1"])],
        };
        assert!(validate_plan(&ok, &w, &cfg).is_empty());
        let bad = Plan {
            goal: "goal".into(),
            steps: vec![
                step("s1", "zzz", &["s2"]),
                step("s2", "a", &["s2", "nope"]),
                step("s2", "a", &[]),
            ],
        };
        let e = validate_plan(&bad, &w, &cfg).join("|");
        for needle in [
            "unknown",
            "forbidden",
            "duplicated",
            "depends from itself",
            "unknown dependency",
            "not an ancestor",
        ] {
            assert!(e.contains(needle), "{needle} in {e}");
        }
        let many = Plan {
            goal: "goal".into(),
            steps: (0..9).map(|i| step(&format!("s{i}"), "a", &[])).collect(),
        };
        assert!(validate_plan(&many, &w, &cfg)[0].contains("too many steps"));
    }
    #[test]
    fn parsing_from_wrapped_json() {
        let raw = "Voici le plan:\n```json\n{\"goal\":\"Résumer\",\"steps\":[{\"id\":\"s1\",\"agent\":\"a\",\"instruction\":\"lis le fichier\",\"expected_output\":\"résumé\"}]}\n```";
        assert_eq!(Plan::from_text(raw).unwrap().steps[0].depends_on.len(), 0);
        assert!(Plan::from_text("{\"goal\":\"x\",\"steps\":[]}").is_err());
        assert!(Plan::from_text("{\"goal\":\"abc\",\"steps\":[{\"id\":\"S 1\",\"agent\":\"a\",\"instruction\":\"lis le fichier\",\"expected_output\":\"abc\"}]}").is_err());
        assert!(
            Plan::from_text("{\"goal\":\"abc\",\"extra\":1,\"steps\":[]}").is_err(),
            "unknown keys refused"
        );
    }

    #[test]
    fn plan_schema_matches_plan_struct() {
        let w = vec!["a".to_string(), "b".to_string()];
        let sc = crate::schema::OutputSchema::compile(
            "plan",
            plan_schema(&w, &OrchestrationCfg::default()),
        )
        .unwrap();

        let good = serde_json::to_value(Plan {
            goal: "goal".into(),
            steps: vec![step("s1", "a", &[]), step("s2", "b", &["s1"])],
        })
        .unwrap();

        assert!(sc.check(&good).is_ok());

        let bad = serde_json::to_value(Plan {
            goal: "goal".into(),
            steps: vec![step("s1", "root", &[])],
        })
        .unwrap();

        assert!(
            sc.check(&bad)
                .unwrap_err()
                .join(" ")
                .contains("/steps/0/agent"),
            "unknown agent rejected by the schema itself"
        );
    }
}
