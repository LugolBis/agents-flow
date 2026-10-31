//! Agent engine + orchestrator against a scripted LLM (no network): proves the loop, the plan validation, the guardrails and the
//! «second barrier» without any model.
use agents_flow::config::Settings;
use agents_flow::engine::{core::Agent, models::TaskInput};
use agents_flow::llm::{
    core::{Completion, Llm, ToolCall},
    mock::ScriptedLlm,
};
use agents_flow::security::runtime::SecurityRuntime;
use agents_flow::team::orchestrator::Orchestrator;
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

fn setup() -> (tempfile::TempDir, Arc<SecurityRuntime>, Arc<Settings>) {
    let d = tempfile::tempdir().unwrap();
    let ws = d.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let env: HashMap<String, String> = [
        ("AGENTS_FLOW_WORKSPACE", ws.to_string_lossy().to_string()),
        (
            "AGENTS_FLOW_AUDIT_LOG",
            d.path().join("audit.jsonl").to_string_lossy().to_string(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let cfg = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config");
    let st = Arc::new(Settings::load(Some(&cfg), Some(&env), false).unwrap());
    let rt = Arc::new(SecurityRuntime::new(st.clone(), None).unwrap());
    (d, rt, st)
}

fn text(s: &str) -> Completion {
    Completion {
        content: s.into(),
        tool_calls: vec![],
    }
}

fn call(name: &str, args: serde_json::Value) -> Completion {
    Completion {
        content: String::new(),
        tool_calls: vec![ToolCall {
            id: "c1".into(),
            name: name.into(),
            arguments: args,
        }],
    }
}

fn task() -> TaskInput {
    TaskInput {
        description: "do it".into(),
        expected: "something".into(),
        context: vec![],
    }
}

#[test]
fn plan_mode_end_to_end_with_native_tool_calls() {
    let (d, rt, _) = setup();
    let plan = json!({"goal": "Créer un fichier", "steps": [{"id": "s1", "agent": "file_editor", "instruction": "Crée hello.txt contenant hi", "expected_output": "chemin du fichier", "depends_on": []}]});
    let llm = Arc::new(ScriptedLlm::new(
        true,
        vec![
            text(&format!("Voici le plan :\n```json\n{plan}\n```")),
            call("create_file", json!({"path": "hello.txt", "content": "hi"})),
            text("Fichier créé : hello.txt (2 octets), aucun refus rencontré."),
            text("Synthèse : le fichier hello.txt a été créé avec succès par file_editor."),
        ],
    ));
    let orch = Orchestrator::new(rt.clone(), Some(llm.clone() as Arc<dyn Llm>)).unwrap();
    let report = orch.run_plan("Crée hello.txt");
    assert!(report.ok(), "{:?}", report.error);
    assert_eq!(
        std::fs::read_to_string(d.path().join("ws/hello.txt")).unwrap(),
        "hi"
    );
    assert!(
        report.final_text.contains("Synthèse")
            && report.audit.get("allow").copied().unwrap_or(0) >= 1
    );
    // the step's agent must have seen the tool result
    let seen = llm.seen.lock().unwrap();
    assert!(seen[2]
        .iter()
        .any(|m| m.role == "tool" && m.content.contains("file created")));
}

#[test]
fn invalid_plans_are_never_executed() {
    let (d, rt, _) = setup();
    let bad = json!({"goal": "x y z", "steps": [{"id": "s1", "agent": "root_shell", "instruction": "rm -rf everything", "expected_output": "nothing"}]});
    let llm = Arc::new(ScriptedLlm::new(
        true,
        vec![text(&bad.to_string()), text(&bad.to_string())],
    ));
    let orch = Orchestrator::new(rt.clone(), Some(llm as Arc<dyn Llm>)).unwrap();
    let report = orch.run_plan("do bad things");
    assert!(
        report
            .error
            .as_deref()
            .unwrap_or("")
            .contains("invalid plan")
            && report.step_results.is_empty()
    );
    assert!(std::fs::read_dir(d.path().join("ws"))
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn ungranted_tool_is_blocked_by_the_second_barrier() {
    let (d, rt, st) = setup();
    let llm = Arc::new(ScriptedLlm::new(
        true,
        vec![
            call("create_file", json!({"path": "x.txt", "content": "x"})),
            text("J'ai tenté d'écrire mais l'outil m'a été refusé, rien n'a été écrit."),
        ],
    ));
    let agent = Agent::new(
        rt.as_ref(),
        &st,
        "translator_fr_en",
        llm.clone() as Arc<dyn Llm>,
        false,
    )
    .unwrap();
    assert_eq!(
        agent
            .tools
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>(),
        vec!["read_file"]
    );
    let out = agent.run(rt.as_ref(), &task(), None, 0, None).unwrap();
    assert!(out.contains("refusé"));
    assert!(!d.path().join("ws/x.txt").exists());
    assert!(rt
        .audit
        .denials()
        .iter()
        .any(|e| e["code"] == "tool_not_granted"));
    assert!(llm.seen.lock().unwrap()[1]
        .iter()
        .any(|m| { m.role == "tool" && m.content.to_uppercase().contains("REFUSED") }));
}

#[test]
fn react_protocol_and_guardrail_retry() {
    let (d, rt, st) = setup();
    std::fs::write(d.path().join("ws/a.txt"), "contenu\n").unwrap();
    let llm = Arc::new(ScriptedLlm::new(
        false,
        vec![
            text("Thought: lire\nAction: read_file\nAction Input: {\"path\": \"a.txt\"}"),
            text("Final Answer: ok"), // too short -> guardrail rejects
            text("Final Answer: Le fichier a.txt contient la ligne « contenu »."), // corrected
        ],
    ));
    let agent = Agent::new(
        rt.as_ref(),
        &st,
        "file_editor",
        llm.clone() as Arc<dyn Llm>,
        false,
    )
    .unwrap();
    let guard = agents_flow::team::guardrails::non_empty(20);
    let out = agent
        .run(rt.as_ref(), &task(), Some(&guard), 1, None)
        .unwrap();
    assert!(out.contains("contenu"));
    let seen = llm.seen.lock().unwrap();
    assert!(
        seen[1].last().unwrap().content.starts_with("Observation:")
            && seen[1].last().unwrap().content.contains("contenu")
    );
    assert!(seen[2].last().unwrap().content.contains("rejected"));
    // guardrail exhausted -> the task fails, never passes silently
    let llm2 = Arc::new(ScriptedLlm::new(true, vec![text("ok"), text("ok")]));
    let a2 = Agent::new(rt.as_ref(), &st, "file_editor", llm2 as Arc<dyn Llm>, false).unwrap();
    assert!(a2.run(rt.as_ref(), &task(), Some(&guard), 1, None).is_err());
}

#[test]
fn hierarchical_delegation_respects_allowed_coworkers() {
    let (_d, rt, _) = setup();
    let llm = Arc::new(ScriptedLlm::new(
        true,
        vec![
            call(
                "delegate_work_to_coworker",
                json!({"coworker": "ghost", "task": "t", "context": "c"}),
            ),
            text("Délégation refusée : l'agent demandé n'existe pas, aucun travail effectué."),
        ],
    ));
    let orch = Orchestrator::new(rt.clone(), Some(llm.clone() as Arc<dyn Llm>)).unwrap();
    let r = orch.run_hierarchical("fais quelque chose");
    assert!(r.ok(), "{:?}", r.error);
    assert!(r.denials.iter().any(|e| e["code"] == "delegation_denied"));
}
