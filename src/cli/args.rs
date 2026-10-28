use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "agwo",
    version,
    about = "Secure multi-agent team (Rust): centralised permissions, tool-side guardrails, audit."
)]
pub struct Cli {
    /// Directory holding permissions/agents/tools[/deployment].jsonc (default: $AGENTS_FLOW_CONFIG_DIR or ./config)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Show the agent × capability × tool matrix.
    Permissions,
    /// Replay real attacks against the real tools in a disposable repository (no LLM, no network).
    Verify,
    /// Environment checks (platform, git, WSL, LLM server).
    Doctor,
    /// Run a request: the orchestrator plans, the code validates, agents execute.
    Run {
        request: String,
        #[arg(long, default_value = "plan", value_parser = ["plan", "hierarchical"])]
        mode: String,
    },
    /// Run a hand-written, validated pipeline.
    Pipeline {
        name: String,
        #[arg(short = 'p', long = "param", value_parser = parse_kv)]
        params: Vec<(String, String)>,
    },
    /// Show the audit trail.
    Audit {
        #[arg(long, default_value_t = 30)]
        tail: usize,
        #[arg(long)]
        denials: bool,
    },
    /// Ask the configured LLM for a one-word answer.
    LlmCheck {
        #[arg(long)]
        profile: Option<String>,
    },
    /// WSL backend helpers.
    #[command(subcommand)]
    Wsl(WslCmd),
    /// (internal) tool executor speaking JSON lines on stdin/stdout.
    #[command(hide = true)]
    Executor {
        #[arg(long)]
        serve: bool,
        #[arg(long)]
        env_file: Option<PathBuf>,
        #[arg(long, default_value_t = 8_000_000)]
        max_bytes: usize,
    },
}

#[derive(Subcommand)]
pub enum WslCmd {
    /// Copy config + skills + the LINUX build of this program into the WSL distribution.
    Sync {
        #[arg(long)]
        binary: PathBuf,
    },
}

fn parse_kv(text: &str) -> std::result::Result<(String, String), String> {
    text.split_once('=')
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .ok_or_else(|| "expected : key=value".to_string())
}
