//! LLM clients. Two wire formats, both over rustls (no OpenSSL): OpenAI-compatible chat completions (LM Studio, vLLM, llama.cpp,
//! OpenAI...) and the Anthropic Messages API. `function_calling=false` selects the ReAct text protocol (any model, slower).
//! Why not a generic provider string: local model ids often contain «/» (`qwen/qwen3-coder-30b`) and the real loaded context window and
//! tool-calling support cannot be guessed — both are driven by `deployment.jsonc`.
use crate::config::{models::deployment::LLMProfile, Settings};
use crate::error::{Error, Result};
use crate::schema::OutputSchema;
use crate::security::runtime::ToolDef;
use crate::util::clip;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fmt::{self, Display, Formatter};
use std::io::Read;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// "auto" | "json_schema" | "off" (see `LLMProfile::structured_output`).
    pub structured_output: String,
    schema_unsupported: AtomicBool,
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
            structured_output: profile.structured_output.clone(),
            schema_unsupported: AtomicBool::new(false),
        }
    }

    /// Request body; `schema` adds `response_format` (OpenAI-style structured outputs, also accepted by LM Studio / vLLM / llama.cpp servers).
    pub fn build_body(
        &self,
        msgs: &[Message],
        tools: &[ToolDef],
        stop: &[&str],
        schema: Option<&OutputSchema>,
    ) -> Value {
        let messages_parsed: Vec<Value> = msgs.iter().map(|msg| match msg.role {
            "tool" => json!({"role": "tool", "tool_call_id": msg.tool_call_id, "content": msg.content}),
            "assistant" if !msg.tool_calls.is_empty() => json!({"role": "assistant", "content": if msg.content.is_empty() { Value::Null } else { json!(msg.content) },
                "tool_calls": msg.tool_calls.iter().map(|tool_call| json!({"id": tool_call.id, "type": "function", "function": {"name": tool_call.name, "arguments": tool_call.arguments.to_string()}})).collect::<Vec<_>>()}),
            other => json!({"role": other, "content": msg.content}),
        }).collect();

        let mut body = json!({"model": self.model, "messages": messages_parsed, "temperature": self.temperature, "stream": false});
        if let Some(t) = self.max_tokens {
            body["max_tokens"] = json!(t);
        }

        if self.function_calling && !tools.is_empty() {
            body["tools"] = json!(tools.iter().map(|tool| json!({"type": "function", "function": {"name": tool.name, "description": tool.description, "parameters": tool.schema}})).collect::<Vec<_>>());
        }

        if !stop.is_empty() {
            body["stop"] = json!(stop);
        }

        if let Some(sc) = schema {
            body["response_format"] = json!({"type": "json_schema", "json_schema": {"name": sc.api_name(), "schema": sc.schema, "strict": false}});
        }
        body
    }

    fn send(&self, body: &Value) -> result::Result<Completion, LlmError> {
        let value = post_json(
            &format!("{}/chat/completions", self.base_url.trim_end_matches('/')),
            &[("Authorization", format!("Bearer {}", self.api_key))],
            body,
            self.timeout_s,
        )?;

        let msg = value
            .pointer("/choices/0/message")
            .ok_or_else(|| LlmError::Fatal("LLM answer without choice".into()))?;

        let calls = msg
            .get("tool_calls")
            .and_then(Value::as_array)
            .map(|array| {
                array
                    .iter()
                    .enumerate()
                    .map(|(index, val_)| ToolCall {
                        id: val_
                            .get("id")
                            .and_then(Value::as_str)
                            .map(String::from)
                            .unwrap_or_else(|| format!("call_{index}")),
                        name: val_
                            .pointer("/function/name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        arguments: parse_args(
                            val_.pointer("/function/arguments").unwrap_or(&Value::Null),
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
}

impl Llm for OpenAiCompat {
    fn complete(
        &self,
        msgs: &[Message],
        tools: &[ToolDef],
        stop: &[&str],
    ) -> result::Result<Completion, LlmError> {
        self.send(&self.build_body(msgs, tools, stop, None))
    }

    fn complete_structured(
        &self,
        msgs: &[Message],
        schema: &OutputSchema,
    ) -> result::Result<Completion, LlmError> {
        let plain = || self.send(&self.build_body(msgs, &[], &[], None));

        if self.structured_output == "off"
            || (self.structured_output == "auto" && self.schema_unsupported.load(Ordering::Relaxed))
        {
            return plain();
        }

        match self.send(&self.build_body(msgs, &[], &[], Some(schema))) {
            // 400/422 = the server does not understand `response_format`: remember it (auto) and degrade to prompt + validation
            Err(LlmError::Fatal(m))
                if self.structured_output == "auto"
                    && (m.contains("HTTP 400") || m.contains("HTTP 422")) =>
            {
                self.schema_unsupported.store(true, Ordering::Relaxed);
                plain()
            }
            other => other,
        }
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

impl Anthropic {
    fn convert(msgs: &[Message]) -> (String, Vec<Value>) {
        let system: String = msgs
            .iter()
            .filter(|msg| msg.role == "system")
            .map(|msg| msg.content.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");

        let mut out: Vec<Value> = Vec::new();
        for message in msgs.iter().filter(|msg| msg.role != "system") {
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
        (system, out)
    }

    fn call(&self, body: &Value) -> result::Result<Value, LlmError> {
        let key = std::env::var(&self.key_env)
            .ok()
            .filter(|k| !k.is_empty())
            .ok_or_else(|| LlmError::Fatal(format!("variable {} missing", self.key_env)))?;

        post_json(
            "https://api.anthropic.com/v1/messages",
            &[
                ("x-api-key", key),
                ("anthropic-version", "2023-06-01".into()),
            ],
            body,
            self.timeout_s,
        )
    }
}

impl Llm for Anthropic {
    fn complete(
        &self,
        msgs: &[Message],
        tools: &[ToolDef],
        _stop: &[&str],
    ) -> result::Result<Completion, LlmError> {
        let (system, out) = Self::convert(msgs);
        let mut body = json!({"model": self.model, "max_tokens": self.max_tokens, "system": system, "messages": out});

        if !tools.is_empty() {
            body["tools"] = json!(tools.iter().map(|tool| json!({"name": tool.name, "description": tool.description, "input_schema": tool.schema})).collect::<Vec<_>>());
        }

        let value = self.call(&body)?;
        let blocks = value
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| LlmError::Fatal("Anthropic's answer without content".into()))?;

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

    /// Constrained generation through a FORCED tool call whose `input_schema` is the output schema (the model cannot answer in prose).
    fn complete_structured(
        &self,
        msgs: &[Message],
        schema: &OutputSchema,
    ) -> std::result::Result<Completion, LlmError> {
        let (system, out) = Self::convert(msgs);
        let body = json!({"model": self.model, "max_tokens": self.max_tokens, "system": system, "messages": out,
            "tools": [{"name": "submit_result", "description": "Submit the final structured response.", "input_schema": schema.wrapped_for_tool()}],
            "tool_choice": {"type": "tool", "name": "submit_result"}});

        let value = self.call(&body)?;
        let input = value
            .get("content")
            .and_then(Value::as_array)
            .and_then(|array| array.iter().find(|block| block["type"] == "tool_use"))
            .map(|block| block["input"].clone())
            .ok_or_else(|| {
                LlmError::Fatal("Anthropic's answer without call to structured tool".into())
            })?;

        let value = if schema.is_object_root() {
            input
        } else {
            input.get("result").cloned().unwrap_or(Value::Null)
        };

        Ok(Completion {
            content: value.to_string(),
            tool_calls: vec![],
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
    /// Answers for `complete_structured` (when empty, falls back to `script` like the trait default); `structured_seen` records schema names.
    pub structured: Mutex<VecDeque<Completion>>,
    pub structured_seen: Mutex<Vec<String>>,
}

impl ScriptedLlm {
    pub fn new(native: bool, script: Vec<Completion>) -> Self {
        Self {
            script: Mutex::new(script.into()),
            native,
            seen: Mutex::new(vec![]),
            structured: Mutex::new(VecDeque::new()),
            structured_seen: Mutex::new(vec![]),
        }
    }
    pub fn with_structured(self, answers: Vec<Completion>) -> Self {
        *self.structured.lock().unwrap() = answers.into();
        self
    }
}

impl Llm for ScriptedLlm {
    fn complete(
        &self,
        msgs: &[Message],
        _t: &[ToolDef],
        _s: &[&str],
    ) -> result::Result<Completion, LlmError> {
        self.seen.lock().unwrap().push(msgs.to_vec());
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| LlmError::Fatal("LLM script exhausted".into()))
    }

    fn complete_structured(
        &self,
        msgs: &[Message],
        schema: &OutputSchema,
    ) -> result::Result<Completion, LlmError> {
        self.structured_seen
            .lock()
            .unwrap()
            .push(schema.name.clone());
        self.seen.lock().unwrap().push(msgs.to_vec());

        match self.structured.lock().unwrap().pop_front() {
            Some(completion) => Ok(completion),
            None => self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| LlmError::Fatal("LLM script exhausted".into())),
        }
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
        Some(("openai", m)) => Ok(Arc::new(OpenAiCompat { model: m.into(), base_url: "https://api.openai.com/v1".into(), api_key: std::env::var("OPENAI_API_KEY").unwrap_or_default(), temperature: 0.2, max_tokens: None, timeout_s: 300.0, function_calling: true, context_window: 128_000, structured_output: "auto".into(), schema_unsupported: AtomicBool::new(false) })),
        _ => Err(Error::config(format!("unsupported LLM provider: '{spec}' (define deployment.llm.profiles for an OpenAI-compatible server, or default_llm = anthropic/<model> | openai/<model>)"))),
    }
}
