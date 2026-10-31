use crate::config::models::deployment::LLMProfile;
use crate::llm::core::{Completion, Llm, LlmError, Message, ToolCall};
use crate::llm::helpers::{parse_args, post_json};
use crate::schema::OutputSchema;
use crate::security::runtime::ToolDef;

use serde_json::{json, Value};

use std::result;
use std::sync::atomic::{AtomicBool, Ordering};

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
    pub(super) schema_unsupported: AtomicBool,
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
