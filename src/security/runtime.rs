//! Single assembly of the guards + the centralised permission policy.
//! `PermissionPolicy` is the ONLY source of truth for «which agent may use which tool». It is consulted at two independent places:
//! (1) when an agent is built (it only receives granted tools); (2) on EVERY tool call (`authorize`): even if a tool were handed to the
//! wrong agent, the call would be refused.
use super::audit::AuditLogger;
use super::commands::CommandPolicy;
use super::git_guard::{
    executor::GitExec, local_writer::GitLocalWriter, reader::GitReader, state::GitFileState,
};
use super::network::{fetcher::SafeFetcher, transport::Transport};
use super::path_guard::guard::PathGuard;
use super::secrets::SecretRedactor;

use crate::{
    config::{
        models::{core::OMap, permissions::AgentPerm, tools::ToolSpec},
        Settings,
    },
    error::{Error, Result, SecResult, SecurityError},
    security::secrets,
    tools,
    util::{expanduser, is_under, realpath},
};

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct PermissionPolicy {
    agents: OMap<AgentPerm>,
    tools: OMap<ToolSpec>,
}

/// State shared during a run (sources seen, files created…), read by the guardrails.
#[derive(Default, Debug, Clone)]
pub struct SessionState {
    pub seen_urls: BTreeSet<String>,
    pub created_files: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub schema: Value,
}

#[derive(Debug, Clone)]
pub enum ToolOutcome {
    Ok(String),
    Failure { message: String, code: String },
}

pub struct SecurityRuntime {
    pub settings: Arc<Settings>,
    pub policy: PermissionPolicy,
    pub redactor: Arc<SecretRedactor>,
    pub audit: AuditLogger,
    pub paths: Arc<PathGuard>,
    pub git_exec: Arc<GitExec>,
    pub git_reader: Arc<GitReader>,
    pub git_state: GitFileState,
    pub git_writer: GitLocalWriter,
    pub commands: CommandPolicy,
    pub fetcher: SafeFetcher,
    pub session: Mutex<SessionState>,
    /// Injectable transports (tests); None = real network.
    pub github_transport: Option<Arc<dyn Transport>>,
    pub search_transport: Option<Arc<dyn Transport>>,
}

impl PermissionPolicy {
    pub fn new(settings: &Settings) -> Self {
        PermissionPolicy {
            agents: settings.permissions.agents.clone(),
            tools: settings.tools.tools.clone(),
        }
    }

    pub fn agent_ids(&self) -> Vec<String> {
        self.agents.keys().cloned().collect()
    }

    pub fn tools_for(&self, agent_id: &str) -> SecResult<Vec<String>> {
        let perm = self.agents.get(agent_id).ok_or(SecurityError::permission(
            "unknown_agent",
            format!("unknown agent : {agent_id}"),
        ))?;

        Ok(perm
            .tools
            .iter()
            .filter(|tool| {
                self.tools
                    .get(tool)
                    .map(|spec| spec.enabled)
                    .unwrap_or(false)
            })
            .cloned()
            .collect())
    }

    pub fn authorize(&self, agent_id: &str, tool_id: &str) -> SecResult<()> {
        let perm = self.agents.get(agent_id).ok_or(SecurityError::permission(
            "unknown_agent",
            format!("unknown agent : {agent_id}"),
        ))?;

        let spec = self.tools.get(tool_id).ok_or(SecurityError::permission(
            "unknown_tool",
            format!("unknown tool : {tool_id}"),
        ))?;

        if !spec.enabled {
            return Err(SecurityError::permission(
                "tool_disabled",
                format!("deactivated tool : {tool_id}"),
            ));
        }

        if perm.deny_tools.iter().any(|tool| tool == tool_id) {
            return Err(SecurityError::permission(
                "tool_denied",
                format!("tool explicitly forbidden for the agent {agent_id}"),
            ));
        }

        if !perm.tools.iter().any(|tool| tool == tool_id) {
            return Err(SecurityError::permission(
                "tool_not_granted",
                format!("tool not granted to {agent_id}"),
            ));
        }

        let missing: BTreeSet<&String> = spec
            .capabilities
            .iter()
            .filter(|capa| !perm.capabilities.contains(capa))
            .collect();

        if !missing.is_empty() {
            return Err(SecurityError::permission(
                "capability_missing",
                format!("missing capacities : {missing:?}"),
            ));
        }

        Ok(())
    }

    pub fn can_delegate(&self, from: &str, to: &str) -> bool {
        self.agents
            .get(from)
            .map(|perm| {
                perm.can_delegate_to
                    .iter()
                    .any(|other_agent| other_agent == to)
            })
            .unwrap_or(false)
    }

    pub fn matrix(&self) -> Vec<(String, Vec<String>, Vec<String>, Vec<String>)> {
        self.agents
            .iter()
            .map(|(agt, perm)| {
                let (mut caps, mut deny) = (perm.capabilities.clone(), perm.deny_tools.clone());
                caps.sort();
                deny.sort();
                (
                    agt.clone(),
                    caps,
                    self.tools_for(agt).unwrap_or_default(),
                    deny,
                )
            })
            .collect()
    }
}

impl ToolOutcome {
    pub fn text(&self) -> &str {
        match self {
            ToolOutcome::Ok(tool) => tool,
            ToolOutcome::Failure { message, .. } => message,
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, ToolOutcome::Ok(_))
    }
}

/// What the engine needs from a tool backend: implemented by `SecurityRuntime` (in-process) and by the WSL client.
pub trait ToolHost: Send + Sync {
    fn settings(&self) -> &Settings;
    fn policy(&self) -> &PermissionPolicy;
    fn audit(&self) -> &AuditLogger;
    fn tool_defs(&self, agent_id: &str) -> SecResult<Vec<ToolDef>>;
    fn call(&self, agent_id: &str, tool_id: &str, args: &Value) -> ToolOutcome;
    fn session(&self) -> SessionState;
    fn read_text(&self, path: &str) -> SecResult<String>;
    fn backend_name(&self) -> String {
        "local".into()
    }

    /// Secret detection used by the `no_secrets` guardrail.
    fn contains_secret(&self, text: &str) -> bool {
        !secrets::scan_for_secrets(text).is_empty()
    }

    /// Config <-> code consistency check (only meaningful where tools live).
    fn verify_registry(&self) -> Result<()> {
        Ok(())
    }
}

impl SecurityRuntime {
    pub fn new(settings: Arc<Settings>, fetcher: Option<SafeFetcher>) -> Result<SecurityRuntime> {
        let redactor = Arc::new(SecretRedactor::new(None));
        let audit_path = expanduser(&settings.permissions.audit.path);

        let audit = AuditLogger::new(
            Some(audit_path),
            redactor.clone(),
            settings.permissions.audit.max_field_chars,
        );

        let paths = Arc::new(PathGuard::new(&settings.permissions.fs)?);
        let gcfg = &settings.permissions.git;
        let mut dirs = settings.permissions.shell.trusted_dirs();

        if !cfg!(windows) {
            dirs.push(PathBuf::from("/usr/local/bin"));
        }

        let git_exec = Arc::new(GitExec::new(gcfg, paths.clone(), &dirs));
        let git_reader = Arc::new(GitReader::new(
            git_exec.clone(),
            paths.clone(),
            redactor.clone(),
        ));

        let git_state = GitFileState::new(git_exec.clone());
        let git_writer =
            GitLocalWriter::new(git_exec.clone(), paths.clone(), gcfg, redactor.clone());

        let commands = CommandPolicy::new(
            &settings.permissions.shell,
            paths.clone(),
            Some(git_reader.clone()),
            redactor.clone(),
        )?;

        let rt_red = redactor.clone();
        let filter = Box::new(move |url: &str| -> SecResult<()> {
            // classic exfiltration channel: a URL (path/query) carrying a recognisable secret
            if rt_red.contains_secret(url) {
                Err(SecurityError::network(
                    "secret_in_url",
                    "The URL contains what appears to be a secret: request denied (exfiltration)",
                ))
            } else {
                Ok(())
            }
        });

        let fetcher = fetcher
            .unwrap_or_else(|| SafeFetcher::new(&settings.permissions.network, None, None))
            .with_url_filter(filter);

        let rt = SecurityRuntime {
            settings: settings.clone(),
            policy: PermissionPolicy::new(&settings),
            redactor,
            audit,
            paths,
            git_exec,
            git_reader,
            git_state,
            git_writer,
            commands,
            fetcher,
            session: Mutex::new(SessionState::default()),
            github_transport: None,
            search_transport: None,
        };

        rt.assert_policy_outside_roots()?;
        Ok(rt)
    }

    /// Config, audit log and the program's own install directory must NOT be inside an agent-reachable perimeter:
    /// otherwise an agent could rewrite its own policy, the audit trail or the binary.
    fn assert_policy_outside_roots(&self) -> Result<()> {
        let mut protected: Vec<(&str, PathBuf)> = vec![
            ("configuration directory", self.settings.config_dir.clone()),
            (
                "audit journal",
                expanduser(&self.settings.permissions.audit.path),
            ),
        ];

        if let Ok(exe) = std::env::current_exe() {
            if let Some(d) = exe.parent() {
                protected.push(("program installation directory", d.to_path_buf()));
            }
        }

        for (label, p) in protected {
            let real = realpath(&p);

            for root in &self.paths.roots {
                if is_under(&real, &root.path) {
                    return Err(Error::config(format!(
                        "{label} ({}) is in the root '{}' ({}) : refused",
                        real.display(),
                        root.name,
                        root.path.display()
                    )));
                }
            }
        }

        Ok(())
    }

    /// System read (outside agent tools) for the orchestrator: same path guards.
    pub fn read_text_impl(&self, path: &str, max_bytes: Option<u64>) -> SecResult<String> {
        let rp = self.paths.resolve(path, "read", None)?;
        let limit = max_bytes.unwrap_or(self.settings.permissions.fs.max_read_bytes);
        let data = crate::util::read_up_to(&rp.real, limit + 1)
            .map_err(|_| SecurityError::path("not_found", "file not found"))?;

        if data.len() as u64 > limit {
            return Err(SecurityError::path("file_too_large", "file too large"));
        }

        if data[..data.len().min(8000)].contains(&0) {
            return Err(SecurityError::path("binary_file", "fichier binaire"));
        }

        Ok(String::from_utf8_lossy(&data).into_owned())
    }
}

impl ToolHost for SecurityRuntime {
    fn settings(&self) -> &Settings {
        &self.settings
    }

    fn policy(&self) -> &PermissionPolicy {
        &self.policy
    }

    fn audit(&self) -> &AuditLogger {
        &self.audit
    }

    fn tool_defs(&self, agent_id: &str) -> SecResult<Vec<ToolDef>> {
        let mut defs = Vec::new();

        for id in self.policy.tools_for(agent_id)? {
            self.policy.authorize(agent_id, &id)?; // explicit re-check

            if let Some(t) = tools::find(&id) {
                defs.push(ToolDef {
                    name: id,
                    description: t.tool.description().to_string(),
                    schema: t.schema.json_schema(),
                });
            }
        }
        Ok(defs)
    }

    fn call(&self, agent_id: &str, tool_id: &str, args: &Value) -> ToolOutcome {
        tools::call(self, agent_id, tool_id, args)
    }

    fn session(&self) -> SessionState {
        self.session.lock().unwrap().clone()
    }

    fn read_text(&self, path: &str) -> SecResult<String> {
        self.read_text_impl(path, None)
    }

    fn contains_secret(&self, text: &str) -> bool {
        self.redactor.contains_secret(text)
    }

    fn verify_registry(&self) -> Result<()> {
        tools::verify_registry(self)
    }
}
