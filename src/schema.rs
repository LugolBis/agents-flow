//! Structured outputs: a compiled JSON Schema (`OutputSchema`) shared by the config loader, the LLM clients (constrained decoding),
//! the agent engine (final-answer enforcement) and the orchestrator (plan + report).
//! The same object does three jobs: it is SENT to the model when the provider can constrain decoding, it is PRINTED in the prompt for
//! providers/models that cannot, and it VALIDATES the answer in code — whatever the model did, nothing non-conforming leaves an agent.
//! `$ref` resolution over HTTP or from the file system is disabled (crate built without `resolve-http`/`resolve-file`): a schema must be
//! self-contained, otherwise loading it fails (fail closed).
use crate::{
    error::{Error, Result},
    util::clip,
};
use serde_json::{json, Value};
use std::{fmt, result, sync::Arc};

pub const MAX_SCHEMA_BYTES: usize = 256 * 1024;
const MAX_ERRORS: usize = 8;

#[derive(Clone)]
pub struct OutputSchema {
    pub name: String,
    pub schema: Value,
    validator: Arc<jsonschema::Validator>,
}

impl fmt::Debug for OutputSchema {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutputSchema")
            .field("name", &self.name)
            .finish()
    }
}

impl OutputSchema {
    /// Compiles and checks a schema (draft from `$schema`, else the latest). Any problem is a configuration error.
    pub fn compile(name: &str, schema: Value) -> Result<OutputSchema> {
        if !(schema.is_object() || schema.is_boolean()) {
            return Err(Error::config(format!(
                "output_schema '{name}' : a JSON Schema (object) is expected"
            )));
        }

        if schema.to_string().len() > MAX_SCHEMA_BYTES {
            return Err(Error::config(format!(
                "output_schema '{name}' : schema too large (> {MAX_SCHEMA_BYTES} octets)"
            )));
        }

        let validator = jsonschema::validator_for(&schema)
            .map_err(|err| Error::config(format!("invalid output_schema '{name}' : {err}")))?;

        Ok(OutputSchema {
            name: name.to_string(),
            schema,
            validator: Arc::new(validator),
        })
    }

    /// Up to 8 readable violations, each prefixed by the JSON pointer of the offending value.
    pub fn check(&self, value: &Value) -> result::Result<(), Vec<String>> {
        let errs: Vec<String> = self
            .validator
            .iter_errors(value)
            .take(MAX_ERRORS)
            .map(|err| {
                let path = err.instance_path.to_string();
                clip(
                    &format!("{}: {err}", if path.is_empty() { "(root)" } else { &path }),
                    240,
                )
            })
            .collect();

        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    /// Extracts a JSON value from model output (fences / prose tolerated) and validates it. `Err` = feedback for the model.
    pub fn parse(&self, text: &str) -> std::result::Result<Value, String> {
        let value = extract_json_value(text)
            .ok_or_else(|| "no valid JSON found in the answer".to_string())?;

        self.check(&value).map_err(|err| err.join(" ; "))?;
        Ok(value)
    }

    /// Compact canonical form handed to downstream agents, guardrails and the audit.
    pub fn canonical(value: &Value) -> String {
        serde_json::to_string(value).unwrap_or_default()
    }

    /// Provider-safe identifier (`[A-Za-z0-9_-]{1,64}`).
    pub fn api_name(&self) -> String {
        let name: String = self
            .name
            .chars()
            .map(|char_| {
                if char_.is_ascii_alphanumeric() || char_ == '_' || char_ == '-' {
                    char_
                } else {
                    '_'
                }
            })
            .take(64)
            .collect();

        if name.is_empty() {
            "result".into()
        } else {
            name
        }
    }

    /// Prompt block for the system message (used whether or not the provider also constrains decoding).
    pub fn prompt_block(&self, react: bool) -> String {
        format!("\n# Output format (MANDATORY)\nYour final answer should be a unique JSON document compliant with the JSON Schema given below : no text before or after, no Markdown block. Don't invert values ; don't add any property not authorized by the schema.{}\nJSON Schema « {} » :\n{}\n",
            if react { " With the protocol ReAct, write the `Final Answer:` followed by the JSON." } else { "" }, self.name, self.schema)
    }

    /// Anthropic tool inputs must be objects: non-object roots are wrapped as `{"result": <schema>}`.
    pub fn is_object_root(&self) -> bool {
        self.schema.get("type").and_then(Value::as_str) == Some("object")
    }

    pub fn wrapped_for_tool(&self) -> Value {
        if self.is_object_root() {
            self.schema.clone()
        } else {
            json!({"type": "object", "properties": {"result": self.schema}, "required": ["result"], "additionalProperties": false})
        }
    }
}

/// First JSON value in `text`: the whole text, a fenced block, or the first balanced `{…}` / `[…]` (string-aware).
pub fn extract_json_value(text: &str) -> Option<Value> {
    let text_trim = text.trim();
    if let Ok(v) = serde_json::from_str::<Value>(text_trim) {
        return Some(v);
    }

    let start = text_trim.find(['{', '['])?;
    let open = text_trim.as_bytes()[start];
    let close = if open == b'{' { b'}' } else { b']' };

    let (mut depth, mut in_str, mut esc) = (0i32, false, false);
    for (index, byte) in text_trim.bytes().enumerate().skip(start) {
        if in_str {
            if esc {
                esc = false
            } else if byte == b'\\' {
                esc = true
            } else if byte == b'"' {
                in_str = false
            }
            continue;
        }

        if byte == b'"' {
            in_str = true
        } else if byte == open {
            depth += 1
        } else if byte == close {
            depth -= 1;

            if depth == 0 {
                return serde_json::from_str(&text_trim[start..=index]).ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s() -> OutputSchema {
        OutputSchema::compile("report", json!({"type": "object", "properties": {"status": {"enum": ["ok", "ko"]}, "items": {"type": "array", "items": {"type": "string"}, "maxItems": 2}}, "required": ["status"], "additionalProperties": false})).unwrap()
    }
    #[test]
    fn extraction_variants() {
        assert_eq!(extract_json_value("{\"a\":1}").unwrap()["a"], 1);
        assert_eq!(
            extract_json_value("Voici :\n```json\n{\"a\": {\"b\": \"}\"}}\n```\nfin").unwrap()["a"]
                ["b"],
            "}"
        );
        assert_eq!(extract_json_value("liste: [1,2,3] ok").unwrap()[2], 3);
        assert!(
            extract_json_value("pas de json").is_none() && extract_json_value("{\"a\":").is_none()
        );
    }
    #[test]
    fn validation_reports_paths() {
        let sc = s();
        assert!(sc
            .parse("```json\n{\"status\":\"ok\",\"items\":[\"a\"]}\n```")
            .is_ok());
        let e = sc
            .parse("{\"status\":\"maybe\",\"items\":[\"a\",\"b\",\"c\"],\"extra\":1}")
            .unwrap_err();
        assert!(
            e.contains("/status") && e.contains("/items") && e.contains("extra"),
            "{e}"
        );
        assert!(sc.parse("{}").unwrap_err().contains("status"));
    }
    #[test]
    fn compile_is_fail_closed() {
        assert!(OutputSchema::compile("x", json!({"type": "nonsense"})).is_err());
        assert!(OutputSchema::compile("x", json!("string")).is_err());
        assert!(
            OutputSchema::compile("x", json!({"$ref": "http://example.invalid/schema.json"}))
                .is_err(),
            "remote $ref must never be resolved"
        );
        assert!(
            OutputSchema::compile("x", json!({"$ref": "file:///etc/passwd"})).is_err(),
            "file $ref must never be resolved"
        );
        assert!(
            OutputSchema::compile(
                "x",
                json!({"$defs": {"a": {"type": "string"}}, "$ref": "#/$defs/a"})
            )
            .is_ok(),
            "local $ref is fine"
        );
    }
    #[test]
    fn tool_wrapping_for_non_object_roots() {
        let arr = OutputSchema::compile(
            "list",
            json!({"type": "array", "items": {"type": "string"}}),
        )
        .unwrap();
        assert_eq!(arr.wrapped_for_tool()["required"], json!(["result"]));
        assert_eq!(s().wrapped_for_tool(), s().schema);
        assert_eq!(
            OutputSchema::compile("a b/c", json!({}))
                .unwrap()
                .api_name(),
            "a_b_c"
        );
    }
}
