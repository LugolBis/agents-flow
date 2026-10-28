use agents_flow::{team::orchestrator::RunReport, util::clip};

pub fn print_report(report: &RunReport) {
    println!("=== mode : {} ===\n{}\n", report.mode, report.request);

    if let Some(plan) = &report.plan {
        println!("Plan : {}", plan.goal);

        for step in &plan.steps {
            println!(
                "  [{}] {} ← {:?}\n      {}",
                step.id,
                step.agent,
                step.depends_on,
                clip(&step.instruction, 160)
            );
        }
        println!();
    }

    for (id, text) in &report.step_results {
        println!("--- step {id} ---\n{}\n", clip(text, 1500));
    }

    if !report.final_text.is_empty() {
        println!("--- Final result ---\n{}\n", report.final_text);
    }

    for warning in &report.warnings {
        println!("[ WARNING ] {warning}");
    }

    println!(
        "Audit : {}",
        if report.audit.is_empty() {
            "(no event)".to_string()
        } else {
            report
                .audit
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(" ")
        }
    );

    for denial in &report.denials {
        println!(
            "  REFUSAL {} / {} : {}",
            denial
                .get("agent")
                .and_then(|value| value.as_str())
                .unwrap_or("?"),
            denial
                .get("tool")
                .and_then(|value| value.as_str())
                .unwrap_or("?"),
            denial
                .get("code")
                .and_then(|value| value.as_str())
                .unwrap_or("?")
        );
    }

    if let Some(err) = &report.error {
        println!("\n✘ ERROR : {err}");
    }
}
