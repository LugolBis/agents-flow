//! Orchestration. Three modes, from most controlled to most free:
//!  * `pipeline` (hand-written sequential plan): deterministic, auditable — README, translation, summary, research, inspection;
//!  * `plan` (default): the orchestrator — WITHOUT tools — proposes a JSON `Plan`; the code validates it (agents, order, bounds); each step
//!    runs with a context limited to its declared dependencies, guardrails and bounded retries;
//!  * `hierarchical`: the orchestrator delegates to workers through two delegation tools (routing decided by the LLM, no validated plan).
//! In every mode no worker can delegate and every agent can only use its own tools.
use serde_json::{json, Value};

use super::guardrails::{build_guardrail, compose, markdown_preserved, strip_ambiguities};
use super::plan::{validate_plan, Plan, PlanStep};
use crate::config::{models::agents::OrchestrationCfg, Settings, ORCHESTRATOR_ID};
use crate::engine::core::SchemaChoice;
use crate::engine::{
    core::Agent,
    models::TaskInput,
    protocol::{Guardrail, ASK_QUESTION},
};
use crate::error::{Error, Result};
use crate::llm::core::{build_llm, Llm};
use crate::schema::OutputSchema;
use crate::security::{audit::Event, runtime::ToolHost};
use crate::team::plan::plan_schema;
use crate::util::{clip, progress, progress_done};
use std::collections::{BTreeMap, HashMap};
use std::result;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct RunReport {
    pub mode: String,
    pub request: String,
    pub plan: Option<Plan>,
    pub step_results: Vec<(String, String)>,
    pub final_text: String,
    pub error: Option<String>,
    pub audit: BTreeMap<String, usize>,
    pub denials: Vec<Event>,
    pub warnings: Vec<String>,
    /// Parsed results of agents that define an `output_schema` (already validated): per step id, and the orchestrator's final answer.
    pub step_json: Vec<(String, Value)>,
    pub final_json: Option<Value>,
}

impl RunReport {
    pub fn ok(&self) -> bool {
        self.error.is_none()
    }

    /// Machine-readable report (`--json`): structured results appear as real JSON values, free-text ones as strings.
    pub fn to_json(&self) -> Value {
        let steps: serde_json::Map<String, Value> = self
            .step_results
            .iter()
            .map(|(id, text)| {
                (
                    id.clone(),
                    self.step_json
                        .iter()
                        .find(|(id_, _)| id_ == id)
                        .map(|(_, value)| value.clone())
                        .unwrap_or_else(|| json!(text)),
                )
            })
            .collect();

        json!({"ok": self.ok(), "mode": self.mode, "request": self.request, "plan": self.plan, "steps": steps,
               "final": self.final_json.clone().unwrap_or_else(|| json!(self.final_text)), "final_is_json": self.final_json.is_some(),
               "audit": self.audit, "denials": self.denials, "warnings": self.warnings, "error": self.error})
    }
}

pub struct Orchestrator {
    host: Arc<dyn ToolHost>,
    agents: HashMap<String, Agent>,
    cfg: OrchestrationCfg,
    llm_override: Option<Arc<dyn Llm>>,
    plan_schema: Arc<OutputSchema>,
}

const PLAN_EXAMPLE: &str = r#"{"goal": "…", "steps": [{"id": "s1", "agent": "<identifiant>", "instruction": "…", "expected_output": "…", "depends_on": []}]}"#;

impl Orchestrator {
    /// `llm_override`: use one LLM for every agent (tests); otherwise each agent gets its configured profile.
    pub fn new(
        host: Arc<dyn ToolHost>,
        llm_override: Option<Arc<dyn Llm>>,
    ) -> Result<Orchestrator> {
        host.verify_registry()?;
        let settings = host.settings();
        let mut agents = HashMap::new();

        for (id, spec) in settings.agents.agents.iter() {
            let llm = match &llm_override {
                Some(l) => l.clone(),
                None => build_llm(settings, spec.llm.as_deref())?,
            };

            agents.insert(
                id.clone(),
                Agent::new(host.as_ref(), settings, id, llm, false)?,
            );
        }

        let cfg = settings.agents.orchestration.clone();
        let plan_schema = Arc::new(OutputSchema::compile(
            "plan",
            plan_schema(&settings.worker_ids(), &cfg),
        )?);

        Ok(Orchestrator {
            cfg: settings.agents.orchestration.clone(),
            host,
            agents,
            llm_override,
            plan_schema,
        })
    }

    fn st(&self) -> &Settings {
        self.host.settings()
    }

    /// Parsed JSON of an agent's (canonical) answer, only for agents that define an `output_schema`.
    fn json_of(&self, agent: &str, text: &str) -> Option<Value> {
        self.st()
            .output_schemas
            .contains_key(agent)
            .then(|| serde_json::from_str(text).ok())
            .flatten()
    }

    pub fn workers(&self) -> Vec<String> {
        self.st().worker_ids()
    }

    pub fn catalogue(&self) -> String {
        self.workers()
            .iter()
            .map(|agent_id| {
                let spec = self.st().agents.agents.get(agent_id).unwrap();
                let tools = self
                    .host
                    .policy()
                    .tools_for(agent_id)
                    .unwrap_or_default()
                    .join(", ");

                format!(
                    "- {agent_id} : {}\n    inputs : {}\n    outputs : {}\n    tools : {}",
                    spec.goal,
                    spec.inputs,
                    spec.outputs,
                    if tools.is_empty() { "(aucun)" } else { &tools }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn guard(&self, agent: &str, extra: Option<&Guardrail>) -> Result<Option<Guardrail>> {
        let guardrail = build_guardrail(
            &self
                .st()
                .agents
                .agents
                .get(agent)
                .map(|spec| spec.guardrails.clone())
                .unwrap_or_default(),
            &self.host,
        )?;

        Ok(match (guardrail, extra) {
            (Some(guardrail_), Some(fn_)) => Some(compose(vec![guardrail_, fn_.clone()])),
            (Some(guardrail_), None) => Some(guardrail_),
            (None, Some(fn_)) => Some(fn_.clone()),
            (None, None) => None,
        })
    }

    pub fn propose_plan(
        &self,
        request: &str,
        feedback: Option<&str>,
    ) -> result::Result<Plan, String> {
        let orch = &self.agents[ORCHESTRATOR_ID];
        let mut desc = format!(
            "Break down the following request into a step-by-step plan. \
     Do NOT execute anything; you have no tools at your disposal.\n\n\
     REQUEST:\n{request}\n\n\
     AVAILABLE AGENTS (use these exact identifiers):\n{}\n\n\
     Constraints: at most {} steps; \
     `depends_on` may only reference preceding steps; \
     include only the information necessary for the specific step within each `instruction`; \
     a writing step must follow an analysis step; \
     a Git commit is a separate step assigned to `git_repo_manager`.\n\n\
     Respond ONLY with a JSON object in the following format: {PLAN_EXAMPLE}",
            self.catalogue(),
            self.cfg.max_steps,
        );

        if let Some(f) = feedback {
            desc.push_str(&format!(
                "\n\nYour previous plan was REJECTED for these reasons; correct them:\n{f}"
            ));
        }

        let input = TaskInput {
            description: desc,
            expected: "A JSON object compliant to the schema Plan.".into(),
            context: vec![],
        };

        // the planner ALWAYS answers under the built-in Plan schema (independent of any `output_schema` configured for the orchestrator's final report)
        let raw = orch
            .run_with(
                self.host.as_ref(),
                &input,
                None,
                0,
                None,
                SchemaChoice::Override(self.plan_schema.clone()),
            )
            .map_err(|err| {
                format!(
                    "scheduler failed ({}) : {}",
                    err.kind(),
                    clip(&err.to_string(), 600)
                )
            })?;

        Plan::from_text(&raw).map_err(|e| format!("unreadable scheduler output ({e})"))
    }

    pub fn plan_and_validate(&self, request: &str) -> result::Result<Plan, String> {
        let mut feedback: Option<String> = None;

        for index in 0..=self.cfg.max_replans {
            progress(
                format!(
                    "Orchestrator is planning... [{}/{}]",
                    index + 1,
                    self.cfg.max_replans
                )
                .as_str(),
            );

            match self.propose_plan(request, feedback.as_deref()) {
                Err(e) => feedback = Some(e),
                Ok(plan) => {
                    let errors = validate_plan(&plan, &self.workers(), &self.cfg);

                    if errors.is_empty() {
                        return Ok(plan);
                    }

                    feedback = Some(
                        errors
                            .iter()
                            .map(|err| format!("- {err}"))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                }
            }
        }

        Err(format!(
            "invalid plan after {} retry(s) :\n{}",
            self.cfg.max_replans + 1,
            feedback.unwrap_or_default()
        ))
    }

    pub fn execute_plan(
        &self,
        plan: &Plan,
        request: &str,
        mode: &str,
        extra: &HashMap<String, Guardrail>,
    ) -> RunReport {
        let mut report = RunReport {
            mode: mode.into(),
            request: request.into(),
            plan: Some(plan.clone()),
            ..Default::default()
        };

        let start = self.host.audit().len();
        let mut results: Vec<(String, String)> = Vec::new();

        for (index, step) in plan.steps.iter().enumerate() {
            progress(
                format!(
                    "Step [{}/{}] : Agent '{}' is processing...",
                    index + 1,
                    plan.steps.len(),
                    step.agent
                )
                .as_str(),
            );

            let guard = match self.guard(&step.agent, extra.get(&step.id)) {
                Ok(g) => g,
                Err(e) => {
                    progress_done();
                    report.error = Some(format!("ConfigError: {e}"));
                    break;
                }
            };

            let context: Vec<(String, String)> = step
                .depends_on
                .iter()
                .filter_map(|dependency| results.iter().find(|(id, _)| id == dependency).cloned())
                .collect();

            let input = TaskInput {
                description: step.instruction.clone(),
                expected: step.expected_output.clone(),
                context,
            };

            match self.agents[&step.agent].run(
                self.host.as_ref(),
                &input,
                guard.as_ref(),
                self.cfg.max_retries_per_step,
                None,
            ) {
                Ok(text) => results.push((step.id.clone(), text)),
                Err(err) => {
                    progress_done();
                    report.error = Some(format!("{}: {}", err.kind(), clip(&err.to_string(), 300)));
                    break;
                }
            }
        }

        if report.error.is_none() {
            let input = TaskInput {
                description: "Draft a final summary for the user based on the results from the preceding steps (using the provided context). Outline the actions taken, the outcomes, any security-related refusals or failures encountered, and the limitations. Do not include any claims that are not supported by the results from the steps.".into(),
                expected: "A clear, accurate, and verifiable summary.".into(), context: results.clone(),
            };

            match self.guard(ORCHESTRATOR_ID, None).map(|guard_| {
                self.agents[ORCHESTRATOR_ID].run(
                    self.host.as_ref(),
                    &input,
                    guard_.as_ref(),
                    self.cfg.max_retries_per_step,
                    None,
                )
            }) {
                Ok(Ok(text)) => {
                    report.final_json = self.json_of(ORCHESTRATOR_ID, &text);
                    report.final_text = text;
                }
                Ok(Err(err)) => {
                    progress_done();
                    report.error = Some(format!("{}: {}", err.kind(), clip(&err.to_string(), 300)))
                }
                Err(err) => {
                    progress_done();
                    report.error = Some(format!("ConfigError: {err}"))
                }
            }
        }

        progress_done();

        for step in &plan.steps {
            if !results.iter().any(|(id, _)| *id == step.id) {
                report
                    .warnings
                    .push(format!("step {} isn't finished", step.id));
            }
        }

        report.step_json = plan
            .steps
            .iter()
            .filter_map(|step_| {
                results
                    .iter()
                    .find(|(id, _)| *id == step_.id)
                    .and_then(|(_, text)| self.json_of(&step_.agent, text))
                    .map(|value| (step_.id.clone(), value))
            })
            .collect();

        report.step_results = results;
        self.finish(&mut report, start);
        report
    }

    fn finish(&self, report: &mut RunReport, start: usize) {
        let events = self.host.audit().events_since(start);
        for event in &events {
            *report
                .audit
                .entry(
                    event
                        .get("decision")
                        .and_then(|decision| decision.as_str())
                        .unwrap_or("?")
                        .to_string(),
                )
                .or_default() += 1;
        }

        report.denials = events
            .into_iter()
            .filter(|event| {
                event.get("decision").and_then(|decision| decision.as_str()) == Some("deny")
            })
            .collect();
    }

    pub fn run_plan(&self, request: &str) -> RunReport {
        match self.plan_and_validate(request) {
            Ok(plan) => self.execute_plan(&plan, request, "plan", &HashMap::new()),
            Err(err) => RunReport {
                mode: "plan".into(),
                request: request.into(),
                error: Some(err),
                ..Default::default()
            },
        }
    }

    pub fn run_hierarchical(&self, request: &str) -> RunReport {
        let mut report = RunReport {
            mode: "hierarchical".into(),
            request: request.into(),
            ..Default::default()
        };

        let start = self.host.audit().len();
        let settings = self.st();

        let llm = match &self.llm_override {
            Some(llm_override) => Ok(llm_override.clone()),
            None => build_llm(
                settings,
                settings
                    .agents
                    .agents
                    .get(ORCHESTRATOR_ID)
                    .and_then(|s| s.llm.as_deref()),
            ),
        };

        let manager = llm
            .and_then(|llm_| Agent::new(self.host.as_ref(), settings, ORCHESTRATOR_ID, llm_, true));

        match manager {
            Err(err) => report.error = Some(format!("ConfigError: {err}")),
            Ok(agent_m) => {
                let delegate = |tool: &str, who: &str, what: &str, ctx: &str| -> String {
                    let Some(agent) = self.agents.get(who) else {
                        return format!("REFUSED : unknown agent '{who}'.");
                    };

                    let expected = if tool == ASK_QUESTION {
                        "Concise and accurate response."
                    } else {
                        "Complete, accurate result, with limitations and refusals indicated."
                    };

                    let context = if ctx.trim().is_empty() {
                        vec![]
                    } else {
                        vec![(
                            "context provided by the manager".to_string(),
                            ctx.to_string(),
                        )]
                    };

                    let guard = self.guard(who, None).ok().flatten();
                    match agent.run(
                        self.host.as_ref(),
                        &TaskInput {
                            description: what.to_string(),
                            expected: expected.into(),
                            context,
                        },
                        guard.as_ref(),
                        self.cfg.max_retries_per_step,
                        None,
                    ) {
                        Ok(text) => text,
                        Err(err) => format!(
                            "FAILURE of agent {who} ({}): {}",
                            err.kind(),
                            clip(&err.to_string(), 300)
                        ),
                    }
                };

                let input = TaskInput {
                    description: format!("{request}\n\nAVAILABLE AGENTS (delegate using the provided tools, one agent at a time):\n{}", self.catalogue()),
                    expected: "Complete result, faithful to the agents' findings, with limitations and refusals noted.".into(), context: vec![],
                };

                match agent_m.run(self.host.as_ref(), &input, None, 0, Some(&delegate)) {
                    Ok(text) => {
                        report.final_json = self.json_of(ORCHESTRATOR_ID, &text);
                        report.final_text = text;
                    }
                    Err(err) => {
                        report.error =
                            Some(format!("{}: {}", err.kind(), clip(&err.to_string(), 300)))
                    }
                }
            }
        }

        self.finish(&mut report, start);
        report
    }

    pub fn run_pipeline(&self, name: &str, params: &HashMap<String, String>) -> Result<RunReport> {
        let (plan, extra, request) = pipeline_plan(self.host.as_ref(), name, params)?;
        let mut cfg = self.cfg.clone();
        cfg.max_instruction_chars = 10_000;

        let errors = validate_plan(&plan, &self.workers(), &cfg);

        if !errors.is_empty() {
            return Ok(RunReport {
                mode: format!("pipeline:{name}"),
                request,
                error: Some(errors.join("; ")),
                ..Default::default()
            });
        }

        let mut report = self.execute_plan(&plan, &request, &format!("pipeline:{name}"), &extra);

        if name == "translate" && report.ok() {
            self.verify_translation(&mut report, &params["dest"]);
        }
        Ok(report)
    }

    /// Deterministic check: the written file matches the translation produced.
    fn verify_translation(&self, report: &mut RunReport, dest: &str) {
        let written = match self.host.read_text(dest) {
            Ok(text) => text.trim().to_string(),
            Err(_) => {
                report.warnings.push(format!(
                    "the destination file '{dest}' cannot be found after execution"
                ));
                return;
            }
        };

        let produced = report
            .step_results
            .iter()
            .find(|(id, _)| id == "tr")
            .map(|(_, text)| text.trim().to_string())
            .unwrap_or_default();

        if !produced.is_empty() && written != produced && !written.contains(&produced) {
            report.warnings.push(
                "The written file differs from the translation produced in the 'tr' step: needs to be proofread."
                    .into(),
            );
        }
    }
}

/// Static plans validated by code (no LLM involved in planning).
pub fn pipeline_plan(
    host: &dyn ToolHost,
    name: &str,
    pipeline: &HashMap<String, String>,
) -> Result<(Plan, HashMap<String, Guardrail>, String)> {
    let fn_get = |key: &str| {
        pipeline
            .get(key)
            .cloned()
            .ok_or_else(|| Error::config(format!("missing parameter for pipeline '{name}': {key}")))
    };

    let fn_step =
        |id: &str, agent: &str, deps: &[&str], instruction: String, expected: &str| PlanStep {
            id: id.into(),
            agent: agent.into(),
            instruction,
            expected_output: expected.into(),
            depends_on: deps.iter().map(|text| text.to_string()).collect(),
        };

    let none = HashMap::new();
    match name {
        "readme" => {
            let path = fn_get("path")?;
            let plan = Plan { goal: format!("README of {path}"), steps: vec![
                fn_step("arch", "architecture_explorer", &[], format!("Statically analyzes the project '{path}' (scan_project, python_import_graph, reading of key files). Reports: stack, entry points, modules, dependencies, test commands ACTUALLY present, and configuration. Distinguishes between [observed: file] and [deduced]."), "Factual architecture report with file references."),
                fn_step("doc", "doc_writer", &["arch"], format!("Based on the architecture report, create or improve the README for '{path}' (README.md). Do not invent anything; mark any unverified information as 'unverified'. Use `modify_file` if README.md already exists (the tool will create README.proposed.md if direct modification is prohibited); otherwise, use `create_file`."), "Path to the written documentation file and list of unverified points."),
            ] };

            Ok((plan, none, format!("README of {path}")))
        }
        "translate" => {
            let (src, dest) = (fn_get("source")?, fn_get("dest")?);
            let source_text = host.read_text(&src).map_err(Error::from)?;

            let plan = Plan { goal: format!("Translate {src} to {dest}"), steps: vec![
                fn_step("tr", "translator_fr_en", &[], format!("Read the file '{src}' using read_file (ignoring line numbering) and translate it from French to English. Preserve titles, tables, lists, code blocks, `inline code`, and URLs exactly as they appear. Return ONLY the Markdown translation, followed by a line '---AMBIGUITIES---' and any potential ambiguities."), "Complete Markdown translation."),
                fn_step("save", "file_editor", &["tr"], format!("Write the translation (excluding the AMBIGUITIES section) to the file '{dest}' using `create_file`. Report the path written to, or indicate a refusal."), "Path of the created file."),
            ] };

            let mut extra = HashMap::new();
            extra.insert(
                "tr".to_string(),
                strip_ambiguities(markdown_preserved(&source_text)),
            );

            Ok((plan, extra, format!("Translation from {src} to {dest}")))
        }
        "summarize" => {
            let path = fn_get("path")?;
            let level = pipeline
                .get("level")
                .cloned()
                .unwrap_or_else(|| "detailed".into());

            let plan = Plan { goal: format!("Summarize {path}"), steps: vec![fn_step("sum", "document_analyst", &[], format!("Read '{path}' using read_document and produce a summary at the '{level}' level (short | detailed | executive), including page/section references and extraction limits."), "Summary with references.")] };

            Ok((plan, none, format!("Summary of {path}")))
        }
        "research" => {
            let q = fn_get("question")?;
            let plan = Plan { goal: clip(&q, 100), steps: vec![fn_step("web", "web_researcher", &[], format!("Search: {q}. Consult multiple sources and cite only the URLs obtained by your tools."), "Summary with a list of source URLs.")] };

            Ok((plan, none, q))
        }
        "inspect" => {
            let q = fn_get("question")?;
            let plan = Plan {
                goal: clip(&q, 100),
                steps: vec![fn_step(
                    "ins",
                    "shell_inspector",
                    &[],
                    format!("Inspect the environment to answer: {q}. A simple command per call."),
                    "Factual observation based on the releases.",
                )],
            };

            Ok((plan, none, q))
        }
        other => Err(Error::config(format!(
            "unknown pipeline: {other} (readme | translate | summarize | research | inspect)"
        ))),
    }
}
