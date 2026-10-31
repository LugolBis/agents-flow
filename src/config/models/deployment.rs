use crate::config::core::OMap;
use crate::config::models::helpers::*;
use crate::error::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WslCfg {
    pub exe: String,
    pub distro: String,
    pub user: Option<String>,
    pub launch: String,
    pub install_dir: String,
    pub env_file: String,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub startup_timeout_s: f64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub call_timeout_s: f64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_message_bytes: usize,
}

impl Default for WslCfg {
    fn default() -> Self {
        Self {
            exe: "wsl.exe".into(),
            distro: "Ubuntu".into(),
            user: None,
            launch: "auto".into(),
            install_dir: "~/agwo".into(),
            env_file: "~/.config/agwo/env".into(),
            startup_timeout_s: 90.0,
            call_timeout_s: 180.0,
            max_message_bytes: 8_000_000,
        }
    }
}

impl WslCfg {
    /// Every value ends up on a command line: restricted to safe characters (no space, quote or metacharacter).
    fn validate(&self) -> Result<()> {
        pat("wsl.exe", &self.exe, r"^[A-Za-z0-9_.:\\/ ()-]{1,200}$")?;
        pat("wsl.distro", &self.distro, r"^[A-Za-z0-9._-]{1,64}$")?;
        if let Some(u) = &self.user {
            pat("wsl.user", u, r"^[A-Za-z0-9._-]{1,64}$")?;
        }
        lit(
            "wsl.launch",
            &self.launch,
            &["auto", "shell-type-none", "exec"],
        )?;
        pat(
            "wsl.install_dir",
            &self.install_dir,
            r"^(~|/)[A-Za-z0-9_./~+-]{0,200}$",
        )?;
        pat(
            "wsl.env_file",
            &self.env_file,
            r"^(~|/)[A-Za-z0-9_./~+-]{0,200}$",
        )?;
        gt_le("wsl.startup_timeout_s", self.startup_timeout_s, 600.0)?;
        gt_le("wsl.call_timeout_s", self.call_timeout_s, 3600.0)?;
        between(
            "wsl.max_message_bytes",
            self.max_message_bytes as i64,
            100_000,
            64_000_000,
        )
    }
}

/// OpenAI-compatible server (LM Studio).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LLMProfile {
    pub model: String,
    #[serde(default = "lm_url")]
    pub base_url: String,
    #[serde(default = "lm_key")]
    pub api_key: String,
    #[serde(
        default = "temp",
        deserialize_with = "deserialize_from_string_or_number"
    )]
    pub temperature: f64,
    #[serde(
        default = "tmo",
        deserialize_with = "deserialize_from_string_or_number"
    )]
    pub timeout_s: f64,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    /// Context REALLY loaded in the server (cannot be guessed for a local model).
    #[serde(
        default = "ctx",
        deserialize_with = "deserialize_from_string_or_number"
    )]
    pub context_window: usize,
    /// true: native OpenAI tool calls; false: ReAct text format (slower, accepted by any model).
    #[serde(default, deserialize_with = "deserialize_string_or_bool")]
    pub function_calling: bool,
    /// Constrained decoding for agents that define `output_schema`: "auto" (send `response_format: json_schema`; if the server rejects it, remember
    /// and fall back to prompt + validation) | "json_schema" (always send it; a rejection is an error) | "off" (prompt + validation only).
    #[serde(default = "so_auto")]
    pub structured_output: String,
}

impl LLMProfile {
    fn validate(&self, name: &str) -> Result<()> {
        let f = format!("llm.profiles.{name}");

        if self.model.is_empty() || self.model.len() > 200 {
            return Err(bad(&format!("{f}.model"), "longueur 1..200"));
        }

        pat(&format!("{f}.base_url"), &self.base_url, r"^https?://\S+$")?;

        if !(0.0..=2.0).contains(&self.temperature) {
            return Err(bad(&format!("{f}.temperature"), "doit être entre 0 et 2"));
        }

        gt_le(&format!("{f}.timeout_s"), self.timeout_s, 3600.0)?;

        lit(
            &format!("{f}.structured_output"),
            &self.structured_output,
            &["auto", "json_schema", "off"],
        )?;

        ge(
            &format!("{f}.context_window"),
            self.context_window as i64,
            2048,
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LLMSection {
    pub default: String,
    pub profiles: OMap<LLMProfile>,
}

impl Default for LLMSection {
    fn default() -> Self {
        Self {
            default: "lmstudio".into(),
            profiles: OMap::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeploymentConfig {
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub version: u32,
    /// "local" : tools run in this process (Linux, Windows native, macOS); "wsl": agent loop here, ALL tools executed in WSL.
    pub backend: String,
    pub wsl: WslCfg,
    pub client_audit_path: String,
    pub llm: LLMSection,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            version: 1,
            backend: "local".into(),
            wsl: WslCfg::default(),
            client_audit_path: "${AGENTS_FLOW_CLIENT_AUDIT_LOG:-./audit/client-audit.jsonl}".into(),
            llm: LLMSection::default(),
        }
    }
}

impl DeploymentConfig {
    pub fn validate(&self) -> Result<()> {
        lit("deployment.backend", &self.backend, &["local", "wsl"])?;
        self.wsl.validate()?;

        for (n, p) in self.llm.profiles.iter() {
            p.validate(n)?;
        }

        Ok(())
    }
}
