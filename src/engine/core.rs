//! Agent engine (inspired by CrewAI's agent loop). One agent = role/goal/backstory + skills + the tools it was GRANTED + an LLM.
//! Native tool calling (OpenAI/Anthropic) or the ReAct text protocol; iteration, wall-clock, retry and rate limits from `agents.jsonc`;
//! context-window management; deterministic guardrails with bounded retries. Second barrier: any tool call outside the agent's granted
//! list is blocked HERE (independently of the tool layer's own `authorize`).
use super::{
    errors::AgentError,
    helpers::{delegation_defs, Delegate},
    models::TaskInput,
    protocol::Guardrail,
    skill::{load_skills, Skill},
};

use crate::{
    config::{models::agents::AgentSpec, Settings},
    schema::OutputSchema,
};
use crate::{
    error::{Error, Result},
    util::progress,
};
use crate::{
    llm::core::{Llm, Message, ToolCall},
    util::random_agent_verb,
};
use crate::{
    security::runtime::{ToolDef, ToolHost},
    util::progress_done,
};

use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::{collections::VecDeque, result};

/// Which output schema governs a run: the agent's configured one, none, or an explicit one (e.g. the planner's built-in Plan schema).
#[derive(Clone)]
pub enum SchemaChoice {
    Configured,
    Disabled,
    Override(Arc<OutputSchema>),
}

pub struct Agent {
    pub id: String,
    pub spec: AgentSpec,
    pub tools: Vec<ToolDef>,
    pub manager: bool,
    pub(super) skills: Vec<Skill>,
    pub(super) schema: Option<Arc<OutputSchema>>,
    pub(super) llm: Arc<dyn Llm>,
    pub(super) rpm: Mutex<VecDeque<Instant>>,
}

impl Agent {
    pub fn new(
        host: &dyn ToolHost,
        settings: &Settings,
        id: &str,
        llm: Arc<dyn Llm>,
        manager: bool,
    ) -> Result<Agent> {
        let spec = settings
            .agents
            .agents
            .get(id)
            .cloned()
            .ok_or_else(|| Error::config(format!("agent inconnu : {id}")))?;

        if manager && id != crate::config::ORCHESTRATOR_ID {
            return Err(Error::config("only the orchestrator could ba manager"));
        }

        let skills = load_skills(
            &settings
                .config_dir
                .parent()
                .map(|p| p.join("skills"))
                .unwrap_or_default(),
            &spec.skills,
        )?;

        // an agent only receives granted and enabled tools; the manager only receives the delegation tools
        let tools = if manager {
            delegation_defs()
        } else {
            host.tool_defs(id)?
        };

        let schema = settings.output_schemas.get(id).cloned();

        Ok(Agent {
            id: id.to_string(),
            spec,
            tools,
            manager,
            skills,
            schema,
            llm,
            rpm: Mutex::new(VecDeque::new()),
        })
    }

    /// The agent's configured output schema, if any.
    pub fn output_schema(&self) -> Option<&Arc<OutputSchema>> {
        self.schema.as_ref()
    }

    /// Runs one task. The guardrail result (if any) is sent back to the agent for a correction, at most `retries` times; then the task fails.
    /// Same contract as before: for an agent WITHOUT `output_schema` nothing changes; with one, the returned text is the canonical JSON.
    pub fn run(
        &self,
        host: &dyn ToolHost,
        input: &TaskInput,
        guard: Option<&Guardrail>,
        retries: u32,
        delegate: Option<Delegate>,
    ) -> std::result::Result<String, AgentError> {
        self.run_with(
            host,
            input,
            guard,
            retries,
            delegate,
            SchemaChoice::Configured,
        )
    }

    /// Runs one task. The guardrail result (if any) is sent back to the agent for a correction, at most `retries` times; then the task fails.
    pub fn run_with(
        &self,
        host: &dyn ToolHost,
        input: &TaskInput,
        guard: Option<&Guardrail>,
        retries: u32,
        delegate: Option<Delegate>,
        choice: SchemaChoice,
    ) -> result::Result<String, AgentError> {
        let schema: Option<Arc<OutputSchema>> = match choice {
            SchemaChoice::Configured => self.schema.clone(),
            SchemaChoice::Disabled => None,
            SchemaChoice::Override(out_schema) => Some(out_schema),
        };

        let mut msgs = vec![
            Message::system(self.system_prompt(!self.llm.native_tools(), schema.as_deref())),
            Message::user(Self::user_prompt(input)),
        ];

        for attempt in 0..=retries {
            progress(
                format!(
                    "Attempt [{}/{}] : Agent {} is {}...",
                    attempt + 1,
                    retries,
                    self.id,
                    random_agent_verb()
                )
                .as_str(),
            );

            let mut out = self.run_loop(host, &mut msgs, delegate)?;
            if let Some(sc) = &schema {
                match self.enforce_schema(&msgs, &out, sc) {
                    Ok(canonical) => out = canonical,
                    Err(AgentError::Schema(fb)) if attempt >= retries => {
                        progress_done();
                        return Err(AgentError::Schema(fb));
                    }
                    Err(AgentError::Schema(fb)) => {
                        progress_done();
                        msgs.push(Message::assistant(out, vec![]));
                        msgs.push(Message::user(format!("Your answer was rejected by an automatic verification : {fb}\nCorrect it and generate the complete final answer.")));
                        continue;
                    }
                    Err(e) => {
                        progress_done();
                        return Err(e);
                    }
                }
            }

            let Some(guard_fn) = guard else {
                return Ok(out);
            };

            match guard_fn(&out) {
                Ok(()) => return Ok(out),
                Err(fb) if attempt >= retries => {
                    progress_done();
                    return Err(AgentError::Guardrail(fb));
                }
                Err(fb) => {
                    progress_done();
                    msgs.push(Message::assistant(out, vec![]));
                    msgs.push(Message::user(format!("Your answer was rejected by an automatic verification : {fb}\nCorrect it and generate the complete final answer.")));
                }
            }
        }

        progress_done();
        Err(AgentError::Guardrail("reached the retry limit".into()))
    }
}

#[allow(dead_code)]
fn _u(_: ToolCall) {}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::engine::helpers::{fit_context, parse_react, tokens_count};
    use crate::engine::models::Step;
    use crate::engine::protocol::extract_json;

    use super::*;
    #[test]
    fn react_parsing() {
        match parse_react(
            "Thought: x\nAction: read_file\nAction Input: {\"path\": \"a.txt\"}\nObservation: nope",
        ) {
            Step::Action { name, input } => {
                assert_eq!(name, "read_file");
                assert_eq!(input["path"], "a.txt");
            }
            _ => panic!(),
        }
        match parse_react("Thought: done\nFinal Answer: 42") {
            Step::Final(t) => assert_eq!(t, "42"),
            _ => panic!(),
        }
        match parse_react("just text") {
            Step::Final(t) => assert_eq!(t, "just text"),
            _ => panic!(),
        }
        assert_eq!(
            extract_json("```json\n{\"a\": {\"b\": \"}\"}}\n``` trailing"),
            "{\"a\": {\"b\": \"}\"}}"
        );
    }
    #[test]
    fn context_is_bounded_and_pairs_stay_together() {
        let mut m = vec![Message::system("s"), Message::user("u")];
        for i in 0..40 {
            m.push(Message::assistant(
                "",
                vec![ToolCall {
                    id: format!("{i}"),
                    name: "t".into(),
                    arguments: json!({}),
                }],
            ));
            m.push(Message::tool(&format!("{i}"), "x".repeat(4000)));
        }
        fit_context(&mut m, 3000);
        assert!(tokens_count(&m) <= 3500 && m[0].role == "system" && m[1].role == "user");
        for (i, x) in m.iter().enumerate() {
            if x.role == "tool" {
                assert!(
                    m[i - 1].role == "assistant" || m[i - 1].role == "tool",
                    "orphan tool message"
                );
            }
        }
    }
}
