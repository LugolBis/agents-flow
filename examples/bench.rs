//! Micro-benchmark of the tool layer on a large tree: `cargo run --release --example bench -- <workspace-dir>`
use agents_flow::config::Settings;
use agents_flow::security::runtime::{SecurityRuntime, ToolHost};
use serde_json::json;
use std::{collections::HashMap, sync::Arc, time::Instant};

fn main() {
    let ws = std::env::args().nth(1).expect("workspace dir");
    let env: HashMap<String, String> = [
        ("AGENTS_FLOW_WORKSPACE", ws.clone()),
        ("AGENTS_FLOW_AUDIT_LOG", "/tmp/bench-audit.jsonl".into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let cfg = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config");
    let rt = SecurityRuntime::new(
        Arc::new(Settings::load(Some(&cfg), Some(&env), false).unwrap()),
        None,
    )
    .unwrap();
    let run = |label: &str, agent: &str, tool: &str, args: serde_json::Value| {
        let t = Instant::now();
        let out = rt.call(agent, tool, &args);
        println!(
            "{label:<34} {:>8.1} ms   ok={} ({} chars)",
            t.elapsed().as_secs_f64() * 1000.0,
            out.is_ok(),
            out.text().len()
        );
    };
    run(
        "search_in_files (20k files, hit)",
        "file_editor",
        "search_in_files",
        json!({"query": "NEEDLE_TOKEN", "max_results": 200}),
    );
    run(
        "search_in_files (20k files, miss)",
        "file_editor",
        "search_in_files",
        json!({"query": "zzz_not_there", "ignore_case": true}),
    );
    run(
        "scan_project (20k files)",
        "architecture_explorer",
        "scan_project",
        json!({"path": "."}),
    );
    run(
        "python_import_graph (20k modules cap)",
        "architecture_explorer",
        "python_import_graph",
        json!({"path": "."}),
    );
    run(
        "shell: find . -name 'f7.py'",
        "shell_inspector",
        "shell_inspect",
        json!({"command": "find . -name 'f7.py' -maxdepth 3"}),
    );
    run(
        "shell: ls -la d0/sub",
        "shell_inspector",
        "shell_inspect",
        json!({"command": "ls -la d0/sub"}),
    );
    let t = Instant::now();
    for _ in 0..2000 {
        let _ = rt.call(
            "file_editor",
            "read_file",
            &json!({"path": "d0/sub/f1.py", "max_lines": 50}),
        );
    }
    println!(
        "{:<34} {:>8.1} µs/call (policy+validate+resolve+read+audit)",
        "read_file x2000",
        t.elapsed().as_secs_f64() * 1e6 / 2000.0
    );
}
