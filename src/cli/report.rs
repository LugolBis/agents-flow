use agents_flow::{team::orchestrator::RunReport, util::clip};

fn print_report(report: &RunReport) {
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
        let shown = report
            .step_json
            .iter()
            .find(|(id_, _)| id_ == id)
            .map(|(_, value_)| serde_json::to_string_pretty(value_).unwrap_or_default())
            .unwrap_or_else(|| text.clone());
        println!("--- step {id} ---\n{}\n", clip(&shown, 1500));
    }

    if let Some(value_) = &report.final_json {
        println!(
            "--- Final result (JSON conforming to the schema) ---\n{}\n",
            serde_json::to_string_pretty(value_).unwrap_or_default()
        );
    } else if !report.final_text.is_empty() {
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

pub fn emit(report: &RunReport, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report.to_json()).unwrap_or_default()
        );
    } else {
        print_report(report);
    }
}
