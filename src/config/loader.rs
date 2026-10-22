//! Loading and cross-validation of the policy files. Fail closed (`Error::Config`) on any inconsistency:
//! same agents in agents/permissions; granted tools exist; never granted AND denied; agent holds ALL capabilities of a granted tool;
//! the orchestrator has no tool and no capability; delegations target existing agents.

use super::jsonc::{expand_str, load_jsonc, EnvMap};
use crate::config::agents::AgentsConfig;
use crate::config::deployment::DeploymentConfig;
use crate::config::permissions::PermissionsConfig;
use crate::config::tools::{ToolsConfig, CAPABILITIES};
use crate::error::{Error, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const ORCHESTRATOR_ID: &str = "orchestrator";

#[derive(Debug, Clone)]
/// Represent the settings of the harness.
pub struct Settings {
    pub config_dir: PathBuf,
    pub permissions: PermissionsConfig,
    pub agents: AgentsConfig,
    pub tools: ToolsConfig,
    pub deployment: DeploymentConfig,
}

fn parse<T: serde::de::DeserializeOwned>(val: serde_json::Value, file: &str) -> Result<T> {
    serde_json::from_value(val)
        .map_err(|err| Error::config(format!("invalid config ({file}) :\n{err}")))
}

impl Settings {
    /// Load the settings from the `config` directory and the environment variables.
    pub fn load(
        config_dir: Option<&Path>,
        env: Option<&EnvMap>,
        load_deployment: bool,
    ) -> Result<Settings> {
        let base = match config_dir {
            Some(d) => d.to_path_buf(),
            None => PathBuf::from(
                std::env::var("AGENTS_FLOW_CONFIG_DIR").unwrap_or_else(|_| "config".into()),
            ),
        };

        let base = crate::util::realpath(&base);

        let mut permissions: PermissionsConfig = parse(
            load_jsonc(&base.join("permissions.jsonc"), env)?,
            "permissions.jsonc",
        )?;

        let mut agents: AgentsConfig =
            parse(load_jsonc(&base.join("agents.jsonc"), env)?, "agents.jsonc")?;
        let tools: ToolsConfig = parse(load_jsonc(&base.join("tools.jsonc"), env)?, "tools.jsonc")?;

        let dep_file = base.join("deployment.jsonc");
        let mut deployment: DeploymentConfig = if load_deployment && dep_file.exists() {
            parse(load_jsonc(&dep_file, env)?, "deployment.jsonc")?
        } else {
            DeploymentConfig::default()
        };

        // Defaults carry `${VAR:-x}` templates: expand them too.
        permissions.audit.path = expand_str(&permissions.audit.path, env)?;
        agents.default_llm = expand_str(&agents.default_llm, env)?;
        deployment.client_audit_path = expand_str(&deployment.client_audit_path, env)?;
        permissions.validate()?;
        agents.validate()?;
        deployment.validate()?;

        let settings = Settings {
            config_dir: base,
            permissions,
            agents,
            tools,
            deployment,
        };
        settings.validate_cross_references()?;

        Ok(settings)
    }

    /// Validate the configurations.
    pub fn validate_cross_references(&self) -> Result<()> {
        let (perms, agents, tools) = (
            &self.permissions.agents,
            &self.agents.agents,
            &self.tools.tools,
        );

        let (pk, ak): (BTreeSet<&String>, BTreeSet<&String>) =
            (perms.keys().collect(), agents.keys().collect());

        if pk != ak {
            let diff: Vec<&&String> = pk.symmetric_difference(&ak).collect();
            return Err(Error::config(format!(
                "agents.jsonc et permissions.jsonc divergent : {diff:?}"
            )));
        }

        for (agent_id, perm) in perms.iter() {
            let both: BTreeSet<&String> = perm
                .tools
                .iter()
                .filter(|tool_name| perm.deny_tools.contains(tool_name))
                .collect();

            if !both.is_empty() {
                return Err(Error::config(format!(
                    "{agent_id} : the followings tools are both accepted and prohibited : {both:?}"
                )));
            }

            for tool_id in &perm.tools {
                let spec = tools.get(tool_id).ok_or_else(|| {
                    Error::config(format!(
                        "{agent_id} : unknown tool '{tool_id}' (it is absent from tools.jsonc)"
                    ))
                })?;

                let missing: BTreeSet<&String> = spec
                    .capabilities
                    .iter()
                    .filter(|capa| !perm.capabilities.contains(capa))
                    .collect();

                if !missing.is_empty() {
                    return Err(Error::config(format!("{agent_id} : the tool '{tool_id}' required {missing:?} who's not owned by the agent")));
                }
            }

            for target in &perm.can_delegate_to {
                if !perms.contains_key(target) || target == agent_id {
                    return Err(Error::config(format!(
                        "{agent_id} : invalid delgation to '{target}'"
                    )));
                }
            }
        }

        let llm = &self.deployment.llm;
        if !llm.profiles.is_empty() && !llm.profiles.contains_key(&llm.default) {
            return Err(Error::config(format!(
                "deployment.llm.default='{}' doesn't exist in llm.profiles",
                llm.default
            )));
        }

        for (agent_id, spec) in agents.iter() {
            if let Some(profile) = &spec.llm {
                if !llm.profiles.is_empty() && !llm.profiles.contains_key(profile) {
                    return Err(Error::config(format!(
                        "{agent_id} : unknown LLM profile '{profile}'"
                    )));
                }
            }
        }

        let orch = perms
            .get(ORCHESTRATOR_ID)
            .ok_or_else(|| Error::config("The 'orchestrator' agent is mandatory"))?;
        if !orch.tools.is_empty() || !orch.capabilities.is_empty() {
            return Err(Error::config("The orchestrator shouldn't have tool or capacity, his role should limit to orchestration."));
        }

        for (tool_id, spec) in tools.iter() {
            let unknown_capa: Vec<&String> = spec
                .capabilities
                .iter()
                .filter(|capa| !CAPABILITIES.contains(&capa.as_str()))
                .collect();

            if !unknown_capa.is_empty() {
                return Err(Error::config(format!(
                    "Tool {tool_id} : unknown capacities {unknown_capa:?}"
                )));
            }

            if !spec.class_path.starts_with("agents_flow.tools.") {
                return Err(Error::config(format!("Tool {tool_id} : the class should be under 'agents_flow.tools.' (restricted dynamic loading)")));
            }
        }
        Ok(())
    }

    /// Get the list of agents (excluding the orchestrators).
    pub fn worker_ids(&self) -> Vec<String> {
        self.agents
            .agents
            .keys()
            .filter(|ag| ag.as_str() != ORCHESTRATOR_ID)
            .cloned()
            .collect()
    }
}
