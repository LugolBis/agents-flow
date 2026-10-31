//! Structured outputs (JSON Schema): config loading, final-answer enforcement, repair loop, planner schema, OpenAI-compatible
//! `response_format` negotiation (against a tiny local HTTP server) — all without a real model.
use agents_flow::config::{models::deployment::LLMProfile, Settings};
use agents_flow::engine::{core::Agent, models::TaskInput};
use agents_flow::llm::{
    core::{Completion, Llm, LlmError, Message, ToolCall},
    mock::ScriptedLlm,
    openai::OpenAiCompat,
};
use agents_flow::schema::OutputSchema;
use agents_flow::security::runtime::SecurityRuntime;
use agents_flow::team::orchestrator::Orchestrator;
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
fn text(s: &str) -> Completion {
    Completion {
        content: s.into(),
        tool_calls: vec![],
    }
}
fn task() -> TaskInput {
    TaskInput {
        description: "do it".into(),
        expected: "json".into(),
        context: vec![],
    }
}
fn full_patch(s: String) -> String {
    s.replace(REPORT_REF, &REPORT_REF.replace("// ", ""))
        .replace(EDITOR_ANCHOR, &format!("{EDITOR_ANCHOR}{EDITOR_SCHEMA}"))
}

#[test]
fn config_accepts_file_and_inline_schemas_and_fails_closed() {
    let (_d, dst, env) = config_with(full_patch);
    let st = load(&dst, &env).unwrap();
    assert_eq!(st.output_schemas.len(), 2);
    assert!(st.output_schemas["orchestrator"]
        .check(
            &json!({"status": "success", "summary": "ten chars+", "findings": [], "refusals": []})
        )
        .is_ok());
    // no schema configured anywhere = nothing changes (backward compatible)
    let (_d2, dst2, env2) = config_with(|s| s);
    assert!(load(&dst2, &env2).unwrap().output_schemas.is_empty());
    // fail closed: traversal, missing file, broken schema, remote $ref
    for (bad, why) in [
        ("\"output_schema\": \"../permissions.jsonc\",", "traversal"),
        ("\"output_schema\": \"schemas/nope.json\",", "missing"),
        ("\"output_schema\": {\"type\": \"nonsense\"},", "broken"),
        (
            "\"output_schema\": {\"$ref\": \"http://example.invalid/x.json\"},",
            "remote ref",
        ),
    ] {
        let (_d3, dst3, env3) = config_with(|s| s.replace(REPORT_REF, bad));
        assert!(
            load(&dst3, &env3).is_err(),
            "{why} must be refused at load time"
        );
    }
}

#[test]
fn orchestrator_and_worker_structured_outputs_end_to_end() {
    let (d, dst, env) = config_with(full_patch);
    let st = Arc::new(load(&dst, &env).unwrap());
    let rt = Arc::new(SecurityRuntime::new(st, None).unwrap());
    let plan = json!({"goal": "Créer un fichier", "steps": [{"id": "s1", "agent": "file_editor", "instruction": "Crée hello.txt contenant hi", "expected_output": "chemin et taille", "depends_on": []}]});
    let report_json = json!({"status": "success", "summary": "hello.txt a été créé (2 octets).", "findings": [{"fact": "fichier créé", "source": "s1", "confidence": "observed"}], "refusals": []});
    let llm = Arc::new(
        ScriptedLlm::new(
            true,
            vec![
                text(&plan.to_string()),
                Completion {
                    content: String::new(),
                    tool_calls: vec![ToolCall {
                        id: "c1".into(),
                        name: "create_file".into(),
                        arguments: json!({"path": "hello.txt", "content": "hi"}),
                    }],
                },
                text("```json\n{\"path\": \"hello.txt\", \"bytes\": 2}\n```"),
                text("Tout est terminé, voici un résumé en prose."),
            ],
        )
        .with_structured(vec![text(&report_json.to_string())]),
    );
    let report = Orchestrator::new(rt, Some(llm.clone() as Arc<dyn Llm>))
        .unwrap()
        .run_plan("Crée hello.txt");
    assert!(report.ok(), "{:?}", report.error);
    assert_eq!(
        std::fs::read_to_string(d.path().join("ws/hello.txt")).unwrap(),
        "hi"
    );
    assert_eq!(
        report.step_json,
        vec![("s1".to_string(), json!({"path": "hello.txt", "bytes": 2}))]
    );
    assert_eq!(
        report.step_results[0].1,
        r#"{"path":"hello.txt","bytes":2}"#
    );
    assert_eq!(report.final_json.as_ref().unwrap()["status"], "success");
    assert_eq!(
        llm.structured_seen.lock().unwrap().as_slice(),
        ["orchestrator"]
    );
    let j = report.to_json();
    assert_eq!(
        (
            j["final_is_json"].clone(),
            j["steps"]["s1"]["bytes"].clone()
        ),
        (json!(true), json!(2))
    );
}

#[test]
fn planner_cannot_use_an_unknown_agent_and_is_not_blocked_by_the_report_schema() {
    let (_d, dst, env) = config_with(full_patch);
    let rt = Arc::new(SecurityRuntime::new(Arc::new(load(&dst, &env).unwrap()), None).unwrap());
    let bad = json!({"goal": "x y z", "steps": [{"id": "s1", "agent": "root_shell", "instruction": "rm -rf everything", "expected_output": "nothing"}]});
    let llm = Arc::new(ScriptedLlm::new(
        true,
        vec![
            text(&bad.to_string()),
            text(&bad.to_string()),
            text(&bad.to_string()),
            text(&bad.to_string()),
        ],
    ));
    let r = Orchestrator::new(rt, Some(llm.clone() as Arc<dyn Llm>))
        .unwrap()
        .run_plan("do bad things");
    assert!(
        r.error.as_deref().unwrap_or("").contains("plan invalide") && r.step_results.is_empty()
    );
    assert!(llm
        .structured_seen
        .lock()
        .unwrap()
        .iter()
        .all(|n| n == "plan"));
    assert!(r.error.unwrap().contains("/steps/0/agent"));
}

#[test]
fn repair_loop_then_exhaustion() {
    let (_d, dst, env) = config_with(full_patch);
    let st = Arc::new(load(&dst, &env).unwrap());
    let rt = SecurityRuntime::new(st.clone(), None).unwrap();
    let llm = Arc::new(
        ScriptedLlm::new(
            true,
            vec![
                text("{\"path\": \"a\"}"),
                text("{\"path\": \"a\", \"bytes\": 1}"),
            ],
        )
        .with_structured(vec![text("{\"path\": \"a\", \"bytes\": \"many\"}")]),
    );
    let agent = Agent::new(&rt, &st, "file_editor", llm.clone() as Arc<dyn Llm>, false).unwrap();
    assert_eq!(
        agent.run(&rt, &task(), None, 1, None).unwrap(),
        r#"{"path":"a","bytes":1}"#
    );
    assert!(llm
        .seen
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .iter()
        .any(|m| m.content.contains("ne respecte pas le JSON Schema")));
    let llm2 = Arc::new(
        ScriptedLlm::new(true, vec![text("not json at all")])
            .with_structured(vec![text("{\"nope\": true}")]),
    );
    let a2 = Agent::new(&rt, &st, "file_editor", llm2 as Arc<dyn Llm>, false).unwrap();
    let e = a2.run(&rt, &task(), None, 0, None).unwrap_err();
    assert_eq!(e.kind(), "SchemaViolation");
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
