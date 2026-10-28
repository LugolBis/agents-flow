//! The Windows<->WSL bridge protocol, exercised over a REAL subprocess (the Linux/host build of this binary).
use agents_flow::remote::client::ExecutorClient;
use serde_json::json;
use std::time::Duration;

#[test]
fn executor_roundtrip() {
    let d = tempfile::tempdir().unwrap();
    let ws = d.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    std::env::set_var("AGENTS_FLOW_WORKSPACE", &ws);
    std::env::set_var("AGENTS_FLOW_AUDIT_LOG", d.path().join("a.jsonl"));
    let cfg = format!("{}/config", env!("CARGO_MANIFEST_DIR"));
    let argv = vec![
        env!("CARGO_BIN_EXE_agwo").to_string(),
        "executor".into(),
        "--serve".into(),
        "--config".into(),
        cfg,
    ];
    let (c, hello) = ExecutorClient::spawn(
        &argv,
        Duration::from_secs(60),
        Duration::from_secs(60),
        8_000_000,
    )
    .unwrap();
    assert_eq!(hello["protocol"], 1);
    assert_eq!(hello["arch"], std::env::consts::ARCH);
    let r = c.request(json!({"op": "tool", "agent": "file_editor", "tool": "create_file", "args": {"path": "é.txt", "content": "héllo 😀"}})).unwrap();
    assert_eq!(r["outcome"]["ok"], true, "{r}");
    assert_eq!(
        std::fs::read_to_string(ws.join("é.txt")).unwrap(),
        "héllo 😀"
    );
    assert_eq!(r["audit"][0]["decision"], "allow");
    let r = c.request(json!({"op": "tool", "agent": "translator_fr_en", "tool": "create_file", "args": {"path": "y.txt", "content": "y"}})).unwrap();
    assert_eq!(r["outcome"]["code"], "tool_denied");
    let r = c
        .request(json!({"op": "read_text", "path": "é.txt"}))
        .unwrap();
    assert_eq!(r["text"], "héllo 😀");
    let r = c
        .request(json!({"op": "tool_defs", "agent": "orchestrator"}))
        .unwrap();
    assert_eq!(r["defs"].as_array().unwrap().len(), 0);
    assert!(c.request(json!({"op": "bogus"})).is_err());
}
