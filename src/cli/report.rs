use agents_flow::{team::orchestrator::RunReport, util::clip};
use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write as _};

fn render_report(report: &RunReport) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== Mode : {} ===\n{}\n", report.mode, report.request);

    if let Some(plan) = &report.plan {
        let _ = writeln!(out, "Plan : {}", plan.goal);

        for step in &plan.steps {
            let _ = writeln!(
                out,
                "  [{}] {} ← {:?}\n      {}",
                step.id,
                step.agent,
                step.depends_on,
                clip(&step.instruction, 160)
            );
        }
        let _ = writeln!(out, "\n");
    }

    for (id, text) in &report.step_results {
        let shown = report
            .step_json
            .iter()
            .find(|(id_, _)| id_ == id)
            .map(|(_, value_)| serde_json::to_string_pretty(value_).unwrap_or_default())
            .unwrap_or_else(|| text.clone());
        let _ = writeln!(out, "--- step {id} ---\n{}\n", clip(&shown, 1500));
    }

    if let Some(value_) = &report.final_json {
        let _ = writeln!(
            out,
            "--- Final result (JSON conforming to the schema) ---\n{}\n",
            serde_json::to_string_pretty(value_).unwrap_or_default()
        );
    } else if !report.final_text.is_empty() {
        let _ = writeln!(out, "--- Final result ---\n{}\n", report.final_text);
    }

    for warning in &report.warnings {
        let _ = writeln!(out, "[ WARNING ] {warning}");
    }

    let _ = writeln!(
        out,
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
        let _ = writeln!(
            out,
            "REFUSAL {} / {} : {}",
            denial.get("agent").and_then(|v| v.as_str()).unwrap_or("?"),
            denial.get("tool").and_then(|v| v.as_str()).unwrap_or("?"),
            denial.get("code").and_then(|v| v.as_str()).unwrap_or("?")
        );
    }

    if let Some(err) = &report.error {
        let _ = writeln!(out, "\n✘ ERROR : {err}");
    }

    out
}

fn write_output(raw_text: &str) {
    let mut stdout = io::stdout();
    if stdout.is_terminal() {
        let normalized = raw_text.replace("\r\n", "\n").replace('\n', "\r\n");
        let _ = stdout.write_all(normalized.as_bytes());
    } else {
        let _ = stdout.write_all(raw_text.as_bytes());
    }
    let _ = stdout.flush();
}

pub fn emit(report: &RunReport, json: bool) {
    let output = if json {
        format!(
            "{}\n",
            serde_json::to_string_pretty(&report.to_json()).unwrap_or_default()
        )
    } else {
        render_report(report)
    };
    write_output(&output);
}
