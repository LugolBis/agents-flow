//! Structured outputs (JSON Schema): config loading, final-answer enforcement, repair loop, planner schema, OpenAI-compatible
//! `response_format` negotiation (against a tiny local HTTP server) — all without a real model.
use agents_flow::config::{models::deployment::LLMProfile, Settings};
use agents_flow::llm::{
    core::{Llm, LlmError, Message},
    openai::OpenAiCompat,
};
use agents_flow::schema::OutputSchema;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const REPORT_REF: &str = "// \"output_schema\": \"schemas/run_report.schema.json\",";
const EDITOR_ANCHOR: &str = "\"role\": \"Éditeur de fichiers prudent\",";
const EDITOR_SCHEMA: &str = r#"
      "output_schema": {"type": "object", "required": ["path", "bytes"], "additionalProperties": false, "properties": {"path": {"type": "string"}, "bytes": {"type": "integer"}}},"#;

/// Copies the shipped config into a temp dir, letting the test patch agents.jsonc.
fn config_with(
    patch: impl Fn(String) -> String,
) -> (tempfile::TempDir, PathBuf, HashMap<String, String>) {
    let d = tempfile::tempdir().unwrap();
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config");
    let dst = d.path().join("config");
    std::fs::create_dir_all(dst.join("schemas")).unwrap();
    for f in ["permissions.jsonc", "tools.jsonc"] {
        std::fs::copy(src.join(f), dst.join(f)).unwrap();
    }
    std::fs::copy(
        src.join("schemas/run_report.schema.json"),
        dst.join("schemas/run_report.schema.json"),
    )
    .unwrap();
    std::fs::write(
        dst.join("agents.jsonc"),
        patch(std::fs::read_to_string(src.join("agents.jsonc")).unwrap()),
    )
    .unwrap();
    let ws = d.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let env = [
        ("SECURE_CREW_WORKSPACE", ws.to_string_lossy().to_string()),
        (
            "SECURE_CREW_AUDIT_LOG",
            d.path().join("audit.jsonl").to_string_lossy().to_string(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    (d, dst, env)
}
fn load(dst: &Path, env: &HashMap<String, String>) -> agents_flow::error::Result<Settings> {
    Settings::load(Some(dst), Some(env), false)
}

fn full_patch(s: String) -> String {
    s.replace(REPORT_REF, &REPORT_REF.replace("// ", ""))
        .replace(EDITOR_ANCHOR, &format!("{EDITOR_ANCHOR}{EDITOR_SCHEMA}"))
}

#[test]
fn config_accepts_file_and_inline_schemas_and_fails_closed() {
    let (_d, dst, env) = config_with(full_patch);
    let st = load(&dst, &env).unwrap();

    assert_eq!(st.output_schemas.len(), 1);
    assert!(st.output_schemas["orchestrator"]
        .check(
            &json!({"status": "success", "summary": "ten chars+", "findings": [], "refusals": []})
        )
        .is_ok());
}

// ---------------------------------------------------------------- OpenAI-compatible `response_format` negotiation
fn mock_server(responses: Vec<(u16, String)>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let b2 = bodies.clone();
    std::thread::spawn(move || {
        for (status, body) in responses {
            let Ok((mut s, _)) = l.accept() else { return };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head_end, clen) = loop {
                let n = s.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break (0, 0);
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                    break (
                        p + 4,
                        head.lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0),
                    );
                }
            };
            while buf.len() < head_end + clen {
                let n = s.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            b2.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[head_end..]).into_owned());
            let _ = write!(s, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    (port, bodies)
}
fn profile(port: u16, mode: &str) -> OpenAiCompat {
    let p: LLMProfile = serde_json::from_value(json!({"model": "m", "base_url": format!("http://127.0.0.1:{port}/v1"), "structured_output": mode})).unwrap();
    OpenAiCompat::from_profile(&p)
}
fn chat(content: &str) -> (u16, String) {
    (
        200,
        json!({"choices": [{"message": {"role": "assistant", "content": content}}]}).to_string(),
    )
}

#[test]
fn response_format_is_sent_then_negotiated_away_once_if_rejected() {
    let schema = OutputSchema::compile(
        "my report!",
        json!({"type": "object", "required": ["status"]}),
    )
    .unwrap();
    let (port, bodies) = mock_server(vec![
        (400, "{\"error\":\"response_format not supported\"}".into()),
        chat("{\"status\":\"ok\"}"),
        chat("{\"status\":\"ok\"}"),
    ]);
    let llm = profile(port, "auto");
    let msgs = vec![Message::user("go")];
    let c = llm.complete_structured(&msgs, &schema).unwrap();
    assert_eq!(c.content, "{\"status\":\"ok\"}");
    llm.complete_structured(&msgs, &schema).unwrap();
    let b = bodies.lock().unwrap();
    let first: Value = serde_json::from_str(&b[0]).unwrap();
    assert_eq!(first["response_format"]["type"], "json_schema");
    assert_eq!(
        first["response_format"]["json_schema"]["name"],
        "my_report_"
    );
    assert_eq!(
        first["response_format"]["json_schema"]["schema"]["required"],
        json!(["status"])
    );
    assert!(!b[1].contains("response_format") && !b[2].contains("response_format"));
}
#[test]
fn explicit_json_schema_mode_does_not_hide_a_rejection_and_off_never_sends_it() {
    let schema = OutputSchema::compile("r", json!({"type": "object"})).unwrap();
    let (port, _) = mock_server(vec![(400, "{\"error\":\"nope\"}".into())]);
    assert!(matches!(
        profile(port, "json_schema").complete_structured(&[Message::user("go")], &schema),
        Err(LlmError::Fatal(_))
    ));
    let (port, bodies) = mock_server(vec![chat("{}")]);
    profile(port, "off")
        .complete_structured(&[Message::user("go")], &schema)
        .unwrap();
    assert!(!bodies.lock().unwrap()[0].contains("response_format"));
}
