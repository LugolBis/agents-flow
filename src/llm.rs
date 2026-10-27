//! LLM clients. Two wire formats, both over rustls (no OpenSSL): OpenAI-compatible chat completions (LM Studio, vLLM, llama.cpp,
//! OpenAI...) and the Anthropic Messages API. `function_calling=false` selects the ReAct text protocol (any model, slower).
//! Why not a generic provider string: local model ids often contain «/» (`qwen/qwen3-coder-30b`) and the real loaded context window and
//! tool-calling support cannot be guessed — both are driven by `deployment.jsonc`.
use crate::config::{models::deployment::LLMProfile, Settings};
use crate::error::{Error, Result};
use crate::security::runtime::ToolDef;
use crate::util::clip;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fmt::{self, Display, Formatter};
use std::io::Read;
use std::result;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
}

fn loopback(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|url_| {
            url_.host_str().map(|host| {
                host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
            })
        })
        .unwrap_or(false)
}

fn post_json(
    url: &str,
    headers: &[(&str, String)],
    body: &Value,
    timeout_s: f64,
) -> std::result::Result<Value, LlmError> {
    let mut cfg = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs_f64(timeout_s)))
        .http_status_as_error(false);

    if loopback(url) {
        cfg = cfg.proxy(None);
    }

    let agent = ureq::Agent::new_with_config(cfg.build());
    let mut rb = agent.post(url).header("Content-Type", "application/json");

    for (k, v) in headers {
        rb = rb.header(*k, v.as_str());
    }

    let mut resp = rb
        .send(serde_json::to_string(body).unwrap_or_default())
        .map_err(|e| {
            LlmError::Transient(format!(
                "unable to connect to the LLM server ({})",
                format!("{e}").chars().take(120).collect::<String>()
            ))
        })?;

    let status = resp.status().as_u16();
    let mut text = String::new();

    resp.body_mut()
        .as_reader()
        .take(32 << 20)
        .read_to_string(&mut text)
        .map_err(|_| LlmError::Transient("illegible LLM response".into()))?;

    if status == 429 || status >= 500 {
        return Err(LlmError::Transient(format!("LLM server: HTTP {status}")));
    }

    if status >= 400 {
        return Err(LlmError::Fatal(format!(
            "LLM server: HTTP {status} {}",
            clip(&text, 300)
        )));
    }
    serde_json::from_str(&text).map_err(|_| LlmError::Fatal("non-JSON LLM response".into()))
}

fn parse_args(value: &Value) -> Value {
    match value {
        Value::String(text) => {
            serde_json::from_str(if text.trim().is_empty() { "{}" } else { text })
                .unwrap_or_else(|_| Value::String(text.clone()))
        }
        other => other.clone(),
    }
}

pub struct OpenAiCompat {
    pub model: String,
    pub base_url: String,
    pub api_key: String,
    pub temperature: f64,
    pub max_tokens: Option<u32>,
    pub timeout_s: f64,
    pub function_calling: bool,
    pub context_window: usize,
}

impl OpenAiCompat {
    pub fn from_profile(profile: &LLMProfile) -> Self {
        Self {
            model: profile.model.clone(),
            base_url: profile.base_url.clone(),
            api_key: profile.api_key.clone(),
            temperature: profile.temperature,
            max_tokens: profile.max_tokens,
            timeout_s: profile.timeout_s,
            function_calling: profile.function_calling,
            context_window: profile.context_window,
        }
    }
}

impl Llm for OpenAiCompat {
    fn complete(
        &self,
        msgs: &[Message],
        tools: &[ToolDef],
        stop: &[&str],
    ) -> result::Result<Completion, LlmError> {
        let messages: Vec<Value> = msgs.iter().map(
            |message| match message.role {
                "tool" => json!({"role": "tool", "tool_call_id": message.tool_call_id, "content": message.content}),
                "assistant" if !message.tool_calls.is_empty() => json!({"role": "assistant", "content": if message.content.is_empty() { Value::Null } else { json!(message.content) },
                "tool_calls": message.tool_calls.iter().map(|c| json!({"id": c.id, "type": "function", "function": {"name": c.name, "arguments": c.arguments.to_string()}})).collect::<Vec<_>>()}),
                other => json!({"role": other, "content": message.content}),
        }).collect();

        let mut body = json!({"model": self.model, "messages": messages, "temperature": self.temperature, "stream": false});

        if let Some(max_tokens) = self.max_tokens {
            body["max_tokens"] = json!(max_tokens);
        }

        if self.function_calling && !tools.is_empty() {
            body["tools"] = json!(tools.iter().map(|tool| json!({"type": "function", "function": {"name": tool.name, "description": tool.description, "parameters": tool.schema}})).collect::<Vec<_>>());
        }

        if !stop.is_empty() {
            body["stop"] = json!(stop);
        }

        let value = post_json(
            &format!("{}/chat/completions", self.base_url.trim_end_matches('/')),
            &[("Authorization", format!("Bearer {}", self.api_key))],
            &body,
            self.timeout_s,
        )?;

        let msg = value
            .pointer("/choices/0/message")
            .ok_or_else(|| LlmError::Fatal("LLM response without options".into()))?;

        let calls = msg
            .get("tool_calls")
            .and_then(Value::as_array)
            .map(|array| {
                array
                    .iter()
                    .enumerate()
                    .map(|(index, tool_call)| ToolCall {
                        id: tool_call
                            .get("id")
                            .and_then(Value::as_str)
                            .map(String::from)
                            .unwrap_or_else(|| format!("call_{index}")),
                        name: tool_call
                            .pointer("/function/name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        arguments: parse_args(
                            tool_call
                                .pointer("/function/arguments")
                                .unwrap_or(&Value::Null),
                        ),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Completion {
            content: msg
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            tool_calls: calls,
        })
    }

    fn native_tools(&self) -> bool {
        self.function_calling
    }

    fn context_tokens(&self) -> usize {
        (self.context_window as f64 * 0.85) as usize
    }

    fn max_output_tokens(&self) -> usize {
        self.max_tokens.unwrap_or(1024) as usize
    }

    fn describe(&self) -> String {
        format!(
            "{} @ {} (function_calling={}, ctx={})",
            self.model, self.base_url, self.function_calling, self.context_window
        )
    }
}

pub struct Anthropic {
    pub model: String,
    pub key_env: String,
    pub max_tokens: u32,
    pub timeout_s: f64,
}
impl Llm for Anthropic {
    fn complete(
        &self,
        msgs: &[Message],
        tools: &[ToolDef],
        _stop: &[&str],
    ) -> std::result::Result<Completion, LlmError> {
        let key = std::env::var(&self.key_env)
            .ok()
            .filter(|key| !key.is_empty())
            .ok_or_else(|| LlmError::Fatal(format!("variable {} missing", self.key_env)))?;

        let system: String = msgs
            .iter()
            .filter(|message| message.role == "system")
            .map(|message| message.content.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");

        let mut out: Vec<Value> = Vec::new();
        for message in msgs.iter().filter(|message| message.role != "system") {
            match message.role {
                "tool" => {
                    let block = json!({"type": "tool_result", "tool_use_id": message.tool_call_id, "content": message.content});

                    match out.last_mut() {
                        Some(last)
                            if last["role"] == "user"
                                && last["content"]
                                    .as_array()
                                    .map(|array| {
                                        array
                                            .first()
                                            .map(|first| first["type"] == "tool_result")
                                            .unwrap_or(false)
                                    })
                                    .unwrap_or(false) =>
                        {
                            last["content"].as_array_mut().unwrap().push(block)
                        }
                        _ => out.push(json!({"role": "user", "content": [block]})),
                    }
                }
                "assistant" => {
                    let mut blocks = Vec::new();

                    if !message.content.is_empty() {
                        blocks.push(json!({"type": "text", "text": message.content}));
                    }

                    for tool_call in &message.tool_calls {
                        blocks.push(json!({"type": "tool_use", "id": tool_call.id, "name": tool_call.name, "input": tool_call.arguments}));
                    }

                    if blocks.is_empty() {
                        blocks.push(json!({"type": "text", "text": "…"}));
                    }
                    out.push(json!({"role": "assistant", "content": blocks}));
                }
                _ => out.push(json!({"role": "user", "content": message.content})),
            }
        }

        let mut body = json!({"model": self.model, "max_tokens": self.max_tokens, "system": system, "messages": out});
        if !tools.is_empty() {
            body["tools"] = json!(tools.iter().map(|tool| json!({"name": tool.name, "description": tool.description, "input_schema": tool.schema})).collect::<Vec<_>>());
        }

        let post = post_json(
            "https://api.anthropic.com/v1/messages",
            &[
                ("x-api-key", key),
                ("anthropic-version", "2023-06-01".into()),
            ],
            &body,
            self.timeout_s,
        )?;

        let blocks = post
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| LlmError::Fatal("Anthropic response with no content".into()))?;

        let content = blocks
            .iter()
            .filter(|block| block["type"] == "text")
            .filter_map(|block| block["text"].as_str())
            .collect::<Vec<_>>()
            .join("");

        let calls = blocks
            .iter()
            .filter(|block| block["type"] == "tool_use")
            .map(|block| ToolCall {
                id: block["id"].as_str().unwrap_or("").into(),
                name: block["name"].as_str().unwrap_or("").into(),
                arguments: block["input"].clone(),
            })
            .collect();

        Ok(Completion {
            content,
            tool_calls: calls,
        })
    }

    fn native_tools(&self) -> bool {
        true
    }

    fn context_tokens(&self) -> usize {
        150_000
    }

    fn max_output_tokens(&self) -> usize {
        self.max_tokens as usize
    }

    fn describe(&self) -> String {
        format!("anthropic/{}", self.model)
    }
}

/// Deterministic LLM for tests: pops scripted completions.
pub struct ScriptedLlm {
    pub script: Mutex<VecDeque<Completion>>,
    pub native: bool,
    pub seen: Mutex<Vec<Vec<Message>>>,
}

impl ScriptedLlm {
    pub fn new(native: bool, script: Vec<Completion>) -> Self {
        Self {
            script: Mutex::new(script.into()),
            native,
            seen: Mutex::new(vec![]),
        }
    }
}

impl Llm for ScriptedLlm {
    fn complete(
        &self,
        msgs: &[Message],
        _t: &[ToolDef],
        _s: &[&str],
    ) -> std::result::Result<Completion, LlmError> {
        self.seen.lock().unwrap().push(msgs.to_vec());
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| LlmError::Fatal("script LLM épuisé".into()))
    }

    fn native_tools(&self) -> bool {
        self.native
    }

    fn context_tokens(&self) -> usize {
        100_000
    }

    fn describe(&self) -> String {
        "scripted".into()
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
        Some(("openai", m)) => Ok(Arc::new(OpenAiCompat { model: m.into(), base_url: "https://api.openai.com/v1".into(), api_key: std::env::var("OPENAI_API_KEY").unwrap_or_default(), temperature: 0.2, max_tokens: None, timeout_s: 300.0, function_calling: true, context_window: 128_000 })),
        _ => Err(Error::config(format!("unsupported LLM provider: '{spec}' (define deployment.llm.profiles for an OpenAI-compatible server, or default_llm = anthropic/<model> | openai/<model>)"))),
    }
}
