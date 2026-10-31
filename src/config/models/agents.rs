use crate::config::models::core::OMap;
use crate::config::models::helpers::{
    bad, between, deserialize_from_string_or_number, ge, lit, one,
};
use crate::error::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentLimits {
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_iter: u32,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_execution_time: u64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_retry_limit: u32,
    pub max_rpm: Option<u32>,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            max_iter: 10,
            max_execution_time: 300,
            max_retry_limit: 1,
            max_rpm: None,
        }
    }
}

impl AgentLimits {
    fn validate(&self, id: &str) -> Result<()> {
        between(
            &format!("agents.{id}.limits.max_iter"),
            self.max_iter as i64,
            1,
            50,
        )?;
        between(
            &format!("agents.{id}.limits.max_execution_time"),
            self.max_execution_time as i64,
            10,
            3600,
        )?;
        between(
            &format!("agents.{id}.limits.max_retry_limit"),
            self.max_retry_limit as i64,
            0,
            5,
        )?;
        if self.max_rpm == Some(0) {
            return Err(bad(&format!("agents.{id}.limits.max_rpm"), "should be ≥ 1"));
        }
        Ok(())
    }
}

/// `output_schema` of an agent: a path (relative to the config directory, e.g. "schemas/report.schema.json") or an inline JSON Schema.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum SchemaSource {
    File(String),
    Inline(serde_json::Value),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub role: String,
    pub goal: String,
    pub backstory: String,
    #[serde(default)]
    pub responsibilities: Vec<String>,
    #[serde(default)]
    pub inputs: String,
    #[serde(default)]
    pub outputs: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default)]
    pub guardrails: Vec<String>,
    #[serde(default)]
    pub llm: Option<String>,
    /// Structured output: the agent's FINAL answer must be a JSON document valid against this schema (omitted = free text, as before).
    #[serde(default)]
    pub output_schema: Option<SchemaSource>,
    #[serde(default)]
    pub limits: AgentLimits,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OrchestrationCfg {
    pub default_mode: String,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_steps: usize,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_replans: u32,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_retries_per_step: u32,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_instruction_chars: usize,
}

impl Default for OrchestrationCfg {
    fn default() -> Self {
        Self {
            default_mode: "plan".into(),
            max_steps: 8,
            max_replans: 1,
            max_retries_per_step: 2,
            max_instruction_chars: 2000,
        }
    }
}

impl OrchestrationCfg {
    fn validate(&self) -> Result<()> {
        lit(
            "orchestration.default_mode",
            &self.default_mode,
            &["plan", "hierarchical", "sequential"],
        )?;
        between("orchestration.max_steps", self.max_steps as i64, 1, 20)?;
        between("orchestration.max_replans", self.max_replans as i64, 0, 3)?;
        between(
            "orchestration.max_retries_per_step",
            self.max_retries_per_step as i64,
            0,
            5,
        )?;
        ge(
            "orchestration.max_instruction_chars",
            self.max_instruction_chars as i64,
            100,
        )
    }
}

fn default_llm() -> String {
    "${AGENTS_FLOW_MODEL:-anthropic/claude-sonnet-5-5}".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentsConfig {
    #[serde(
        default = "one",
        deserialize_with = "deserialize_from_string_or_number"
    )]
    pub version: u32,
    #[serde(default = "default_llm")]
    pub default_llm: String,
    #[serde(default)]
    pub orchestration: OrchestrationCfg,
    pub agents: OMap<AgentSpec>,
}

impl AgentsConfig {
    pub fn validate(&self) -> Result<()> {
        self.orchestration.validate()?;
        for (id, agent_spec) in self.agents.iter() {
            agent_spec.limits.validate(id)?;
        }
        Ok(())
    }
}
