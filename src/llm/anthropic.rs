use crate::llm::core::{Completion, Llm, LlmError, Message, ToolCall};
use crate::llm::helpers::post_json;
use crate::schema::OutputSchema;
use crate::security::runtime::ToolDef;
use serde_json::{json, Value};
use std::result;

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
