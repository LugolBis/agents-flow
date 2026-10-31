use crate::llm::core::LlmError;
use crate::util::clip;
use serde_json::Value;
use std::io::Read;
use std::time::Duration;

pub(super) fn loopback(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|url_| {
            url_.host_str().map(|host| {
                host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
            })
        })
        .unwrap_or(false)
}

pub(super) fn post_json(
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

pub(super) fn parse_args(value: &Value) -> Value {
    match value {
        Value::String(text) => {
            serde_json::from_str(if text.trim().is_empty() { "{}" } else { text })
                .unwrap_or_else(|_| Value::String(text.clone()))
        }
        other => other.clone(),
    }
}
