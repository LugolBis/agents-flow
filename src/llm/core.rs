//! LLM clients. Two wire formats, both over rustls (no OpenSSL): OpenAI-compatible chat completions (LM Studio, vLLM, llama.cpp,
//! OpenAI...) and the Anthropic Messages API. `function_calling=false` selects the ReAct text protocol (any model, slower).
//! Why not a generic provider string: local model ids often contain «/» (`qwen/qwen3-coder-30b`) and the real loaded context window and
//! tool-calling support cannot be guessed — both are driven by `deployment.jsonc`.
use crate::config::Settings;
use crate::error::{Error, Result};
use crate::llm::anthropic::Anthropic;
use crate::llm::openai::OpenAiCompat;
use crate::schema::OutputSchema;
use crate::security::runtime::ToolDef;
use serde_json::Value;
use std::fmt::{self, Display, Formatter};
use std::result;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub role: &'static str,
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub tool_call_id: Option<String>,
}

impl Message {
    pub fn system(text: impl Into<String>) -> Self {
        Self {
            role: "system",
            content: text.into(),
            tool_calls: vec![],
            tool_call_id: None,
        }
    }

    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: "user",
            content: text.into(),
            tool_calls: vec![],
            tool_call_id: None,
        }
    }

    pub fn assistant(text: impl Into<String>, calls: Vec<ToolCall>) -> Self {
        Self {
            role: "assistant",
            content: text.into(),
            tool_calls: calls,
            tool_call_id: None,
        }
    }

    pub fn tool(id: &str, text: impl Into<String>) -> Self {
        Self {
            role: "tool",
            content: text.into(),
            tool_calls: vec![],
            tool_call_id: Some(id.to_string()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Completion {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Debug)]
pub enum LlmError {
    /// network, 429, 5xx: worth retrying
    Transient(String),
    Fatal(String),
}

impl Display for LlmError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            LlmError::Transient(message) | LlmError::Fatal(message) => write!(f, "{message}"),
        }
    }
}

pub trait Llm: Send + Sync {
    fn complete(
        &self,
        msgs: &[Message],
        tools: &[ToolDef],
        stop: &[&str],
    ) -> result::Result<Completion, LlmError>;
    fn native_tools(&self) -> bool;
    /// Usable context in tokens.
    fn context_tokens(&self) -> usize;
    fn max_output_tokens(&self) -> usize {
        1024
    }
    fn describe(&self) -> String;

    // ONE JSON document conforming to `schema`, generated WITHOUT tools. Providers that can constrain decoding override this; the default is a
    /// plain completion (the prompt already carries the schema) — the caller always validates the result, so the default is safe.
    fn complete_structured(
        &self,
        msgs: &[Message],
        schema: &OutputSchema,
    ) -> result::Result<Completion, LlmError> {
        let _ = schema;
        self.complete(msgs, &[], &[])
    }
}

/// Named profile > default profile > `default_llm` string (`anthropic/<model>` or `openai/<model>`).
pub fn build_llm(settings: &Settings, profile: Option<&str>) -> Result<Arc<dyn Llm>> {
    let profiles = &settings.deployment.llm.profiles;

    if !profiles.is_empty() {
        let name = profile.unwrap_or(&settings.deployment.llm.default);
        let profile = profiles
            .get(name)
            .ok_or_else(|| Error::config(format!("unknown LLM profile : {name}")))?;

        return Ok(Arc::new(OpenAiCompat::from_profile(profile)));
    }

    let spec = settings.agents.default_llm.as_str();
    match spec.split_once('/') {
        Some(("anthropic", m)) => Ok(Arc::new(Anthropic { model: m.into(), key_env: "ANTHROPIC_API_KEY".into(), max_tokens: 4096, timeout_s: 300.0 })),
        Some(("openai", m)) => Ok(Arc::new(OpenAiCompat { model: m.into(), base_url: "https://api.openai.com/v1".into(), api_key: std::env::var("OPENAI_API_KEY").unwrap_or_default(), temperature: 0.2, max_tokens: None, timeout_s: 300.0, function_calling: true, context_window: 128_000, structured_output: "auto".into(), schema_unsupported: AtomicBool::new(false) })),
        _ => Err(Error::config(format!("unsupported LLM provider: '{spec}' (define deployment.llm.profiles for an OpenAI-compatible server, or default_llm = anthropic/<model> | openai/<model>)"))),
    }
}
