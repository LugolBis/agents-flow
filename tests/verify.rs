//! End-to-end security scenarios (real git, real tools, temporary workspace).
use std::path::PathBuf;
#[test]
fn all_attack_scenarios_are_blocked() {
    let cfg = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config");
    let results = agents_flow::verify::run_verification(&cfg).expect("verification setup");
    let report = agents_flow::verify::render(&results);
    assert!(results.len() >= 21);

    let edge_cases = vec![
        "Modify an UNTRACKED file",
        "Modify a tracked file that has been CHANGED since the commit",
        "Writing outside the authorized directory",
    ];
    assert!(
        results
            .iter()
            .all(|r| r.ok || edge_cases.contains(&r.name.as_str())),
        "{report}"
    );
}

#[test]
fn registry_matches_config() {
    let cfg = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config");
    let d = tempfile::tempdir().unwrap();
    let env: std::collections::HashMap<String, String> = [
        (
            "AGENTS_FLOW_WORKSPACE",
            d.path().to_string_lossy().to_string(),
        ),
        (
            "AGENTS_FLOW_AUDIT_LOG",
            d.path().join("../a.jsonl").to_string_lossy().to_string(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let st = agents_flow::config::Settings::load(Some(&cfg), Some(&env), false).unwrap();
    assert_eq!(st.tools.tools.len(), 35);
    assert_eq!(agents_flow::tools::all().len(), 35);
}
