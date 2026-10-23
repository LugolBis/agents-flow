use std::sync::Arc;

pub type Guardrail = Arc<dyn Fn(&str) -> std::result::Result<(), String> + Send + Sync>;
pub const ASK_QUESTION: &str = "ask_question_to_coworker";

/// First balanced JSON object in `raw` (models often wrap JSON in fences or prose).
pub fn extract_json(raw: &str) -> String {
    let text = raw.trim();
    let Some(start) = text.find('{') else {
        return text.to_string();
    };

    let (mut depth, mut in_str, mut esc) = (0i32, false, false);
    for (index, character) in text[start..].char_indices() {
        if in_str {
            if esc {
                esc = false
            } else if character == '\\' {
                esc = true
            } else if character == '"' {
                in_str = false
            }
            continue;
        }

        match character {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return text[start..start + index + 1].to_string();
                }
            }
            _ => {}
        }
    }
    text[start..].to_string()
}
