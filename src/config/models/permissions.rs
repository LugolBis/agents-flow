use crate::config::core::OMap;
use crate::config::models::helpers::*;
use crate::error::Result;
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCfg {
    pub name: String,
    pub path: String,
    #[serde(default, deserialize_with = "deserialize_string_or_bool")]
    pub write: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FsCfg {
    pub roots: Vec<RootCfg>,
    /// No «/» : file name at any depth. With «/» : relative path (matches any suffix unless it starts with «/»).
    pub deny_globs: Vec<String>,
    pub deny_exceptions: Vec<String>,
    pub write_deny_globs: Vec<String>,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_read_bytes: u64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_write_bytes: u64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_list_entries: usize,
    /// WSL: /mnt/c... expose Windows drives (different link/permission semantics, escapes the sandbox): refused unless explicit.
    #[serde(deserialize_with = "deserialize_string_or_bool")]
    pub allow_windows_drives: bool,
}

impl Default for FsCfg {
    fn default() -> Self {
        Self {
            roots: vec![],
            deny_globs: vec![],
            deny_exceptions: vec![],
            write_deny_globs: vec![],
            max_read_bytes: 2_000_000,
            max_write_bytes: 1_000_000,
            max_list_entries: 500,
            allow_windows_drives: false,
        }
    }
}

impl FsCfg {
    fn validate(&self) -> Result<()> {
        if self.roots.is_empty() {
            return Err(bad("fs.roots", "doit contenir au moins une racine"));
        }
        ge("fs.max_read_bytes", self.max_read_bytes as i64, 1000)?;
        ge("fs.max_write_bytes", self.max_write_bytes as i64, 100)?;
        ge("fs.max_list_entries", self.max_list_entries as i64, 1)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GithubCfg {
    pub api_base: String,
    pub token_env: String,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub timeout_s: f64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_bytes: usize,
}

impl Default for GithubCfg {
    fn default() -> Self {
        Self {
            api_base: "https://api.github.com".into(),
            token_env: "GITHUB_READ_TOKEN".into(),
            timeout_s: 15.0,
            max_bytes: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GitCfg {
    pub author_name: String,
    pub author_email: String,
    pub protected_branches: Vec<String>,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_commit_files: usize,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub timeout_s: f64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_output_bytes: usize,
    pub github: GithubCfg,
}

impl Default for GitCfg {
    fn default() -> Self {
        Self {
            author_name: "agwo-agent".into(),
            author_email: "agent@agwo.invalid".into(),
            protected_branches: vec!["main".into(), "master".into()],
            max_commit_files: 50,
            timeout_s: 20.0,
            max_output_bytes: 200_000,
            github: GithubCfg::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ShellCfg {
    /// Can only REDUCE the command set : a name without a coded validator fails startup.
    pub enabled_commands: Vec<String>,
    pub trusted_path_dirs: Vec<String>,
    /// Windows hosts: extra trusted directories (env vars like %ProgramFiles% are expanded) searched for `git.exe`.
    pub trusted_path_dirs_windows: Vec<String>,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub timeout_s: f64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_output_bytes: usize,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub cpu_seconds: u64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub memory_mb: u64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub find_max_depth: usize,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_path_args: usize,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_line_count: usize,
}

impl Default for ShellCfg {
    fn default() -> Self {
        Self {
            enabled_commands: [
                "pwd", "ls", "find", "cat", "head", "tail", "file", "stat", "git",
            ]
            .map(String::from)
            .to_vec(),
            trusted_path_dirs: vec!["/usr/bin".into(), "/bin".into()],
            trusted_path_dirs_windows: vec![
                r"%ProgramFiles%\Git\cmd".into(),
                r"%ProgramFiles(x86)%\Git\cmd".into(),
                r"%LOCALAPPDATA%\Programs\Git\cmd".into(),
            ],
            timeout_s: 10.0,
            max_output_bytes: 100_000,
            cpu_seconds: 10,
            memory_mb: 2048,
            find_max_depth: 6,
            max_path_args: 10,
            max_line_count: 2000,
        }
    }
}

impl ShellCfg {
    fn validate(&self) -> Result<()> {
        gt_le("shell.timeout_s", self.timeout_s, 120.0)?;
        ge("shell.max_output_bytes", self.max_output_bytes as i64, 1000)?;
        between("shell.cpu_seconds", self.cpu_seconds as i64, 1, 300)?;
        ge("shell.memory_mb", self.memory_mb as i64, 64)?;
        between("shell.find_max_depth", self.find_max_depth as i64, 1, 20)?;
        between("shell.max_path_args", self.max_path_args as i64, 1, 50)?;
        ge("shell.max_line_count", self.max_line_count as i64, 1)
    }

    /// Directories searched for external executables (git): configured dirs for this OS family, existing only.
    pub fn trusted_dirs(&self) -> Vec<std::path::PathBuf> {
        let list: Vec<String> = if cfg!(windows) {
            self.trusted_path_dirs_windows
                .iter()
                .chain(self.trusted_path_dirs.iter())
                .map(|d| expand_percent(d))
                .collect()
        } else {
            self.trusted_path_dirs.clone()
        };

        list.into_iter()
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_dir())
            .collect()
    }
}

/// `%NAME%` expansion (Windows-style) for trusted directory lists.
pub fn expand_percent(s: &str) -> String {
    let rx = Regex::new(r"%([^%]+)%").unwrap();
    rx.replace_all(s, |c: &regex::Captures| {
        std::env::var(&c[1]).unwrap_or_else(|_| c[0].to_string())
    })
    .into_owned()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetCfg {
    pub allow_domains: Vec<String>,
    pub deny_domains: Vec<String>,
    pub allowed_ports: Vec<u16>,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_redirects: u32,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_bytes: usize,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub timeout_s: f64,
    #[serde(deserialize_with = "deserialize_string_or_bool")]
    pub respect_robots: bool,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub min_interval_s: f64,
    pub user_agent: String,
    pub allowed_content_types: Vec<String>,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_crawl_pages: usize,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_crawl_depth: usize,
    pub search_provider: String,
    pub search_base_url: Option<String>,
    pub search_api_key_env: String,
}

impl Default for NetCfg {
    fn default() -> Self {
        Self {
            allow_domains: vec![],
            deny_domains: vec![],
            allowed_ports: vec![80, 443],
            max_redirects: 3,
            max_bytes: 2_000_000,
            timeout_s: 15.0,
            respect_robots: true,
            min_interval_s: 1.0,
            user_agent: "agwo-research/0.1 (+respects robots.txt)".into(),
            allowed_content_types: [
                "text/html",
                "text/plain",
                "application/json",
                "application/xml",
                "text/xml",
                "application/xhtml+xml",
            ]
            .map(String::from)
            .to_vec(),
            max_crawl_pages: 10,
            max_crawl_depth: 2,
            search_provider: "none".into(),
            search_base_url: None,
            search_api_key_env: "BRAVE_API_KEY".into(),
        }
    }
}

impl NetCfg {
    fn validate(&self) -> Result<()> {
        between("network.max_redirects", self.max_redirects as i64, 0, 10)?;
        ge("network.max_bytes", self.max_bytes as i64, 10_000)?;
        gt_le("network.timeout_s", self.timeout_s, 60.0)?;
        if !(0.0..=30.0).contains(&self.min_interval_s) {
            return Err(bad("network.min_interval_s", "doit être entre 0 et 30"));
        }
        between(
            "network.max_crawl_pages",
            self.max_crawl_pages as i64,
            1,
            50,
        )?;
        between("network.max_crawl_depth", self.max_crawl_depth as i64, 0, 5)?;
        lit(
            "network.search_provider",
            &self.search_provider,
            &["none", "brave", "searxng"],
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DocsCfg {
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_file_mb: u64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_pages: usize,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_chars: usize,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_zip_uncompressed_mb: u64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_image_pixels: u64,
    #[serde(deserialize_with = "deserialize_string_or_bool")]
    pub ocr_enabled: bool,
}

impl Default for DocsCfg {
    fn default() -> Self {
        Self {
            max_file_mb: 25,
            max_pages: 200,
            max_chars: 200_000,
            max_zip_uncompressed_mb: 200,
            max_image_pixels: 50_000_000,
            ocr_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RunTestsCfg {
    #[serde(deserialize_with = "deserialize_string_or_bool")]
    pub enabled: bool,
    pub argv: Vec<String>,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub timeout_s: f64,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_output_bytes: usize,
}

impl Default for RunTestsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            argv: vec![],
            timeout_s: 300.0,
            max_output_bytes: 200_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditCfg {
    pub path: String,
    #[serde(deserialize_with = "deserialize_from_string_or_number")]
    pub max_field_chars: usize,
}

impl Default for AuditCfg {
    fn default() -> Self {
        Self {
            path: "${AGENTS_FLOW_AUDIT_LOG:-~/.local/state/agwo/audit.jsonl}".into(),
            max_field_chars: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentPerm {
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub deny_tools: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub can_delegate_to: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionsConfig {
    #[serde(
        default = "one",
        deserialize_with = "deserialize_from_string_or_number"
    )]
    pub version: u32,
    pub fs: FsCfg,
    #[serde(default)]
    pub git: GitCfg,
    #[serde(default)]
    pub shell: ShellCfg,
    #[serde(default)]
    pub network: NetCfg,
    #[serde(default)]
    pub documents: DocsCfg,
    #[serde(default)]
    pub test_runner: RunTestsCfg,
    #[serde(default)]
    pub audit: AuditCfg,
    pub agents: OMap<AgentPerm>,
}

impl PermissionsConfig {
    pub fn validate(&self) -> Result<()> {
        lit("version", &self.version.to_string(), &["1"])?;
        self.fs.validate()?;
        self.shell.validate()?;
        self.network.validate()?;
        lit(
            "git.github.api_base",
            &self.git.github.api_base,
            &["https://api.github.com"],
        )?;
        gt_le("git.timeout_s", self.git.timeout_s, 120.0)?;
        gt_le("git.github.timeout_s", self.git.github.timeout_s, 60.0)?;
        ge(
            "git.max_output_bytes",
            self.git.max_output_bytes as i64,
            1000,
        )?;
        ge("git.max_commit_files", self.git.max_commit_files as i64, 1)?;
        gt_le("test_runner.timeout_s", self.test_runner.timeout_s, 3600.0)?;
        ge(
            "audit.max_field_chars",
            self.audit.max_field_chars as i64,
            20,
        )?;
        for (id, p) in self.agents.iter() {
            unknown_caps(&format!("agents.{id}.capabilities"), &p.capabilities)?;
        }
        Ok(())
    }
}
