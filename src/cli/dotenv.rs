use std::fs;

/// Minimal `.env` loader (current directory only; never overrides the real environment).
pub fn load() {
    let Ok(text) = fs::read_to_string(".env") else {
        return;
    };

    for line in text.lines() {
        let line_cleaned = line.trim().trim_start_matches("export ").trim();

        if line_cleaned.is_empty() || line_cleaned.starts_with('#') {
            continue;
        }

        if let Some((key, env_var)) = line_cleaned.split_once('=') {
            if std::env::var_os(key.trim()).is_none() {
                std::env::set_var(key.trim(), env_var.trim().trim_matches(['"', '\'']));
            }
        }
    }
}
