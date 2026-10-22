use crate::config::core::OMap;
use crate::config::models::helpers::{deserialize_string_or_bool, one};
use serde::Deserialize;

/// Closed vocabulary of capabilities.
pub const CAPABILITIES: &[&str] = &[
    "fs.read",
    "fs.write",
    "git.read",
    "git.write_local",
    "github.read",
    "shell.inspect",
    "net.read",
    "exec.tests",
];

fn get_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpec {
    #[serde(rename = "class", alias = "class_path")]
    pub class_path: String,
    pub capabilities: Vec<String>,
    #[serde(default = "get_true", deserialize_with = "deserialize_string_or_bool")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolsConfig {
    #[serde(default = "one")]
    pub version: u32,
    pub tools: OMap<ToolSpec>,
}
