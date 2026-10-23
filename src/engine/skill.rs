use crate::error::{Error, Result};
use std::fs::{read_dir, read_to_string};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub instructions: String,
}

/// Loads ONLY the named skills (`<skills_dir>/<name>/SKILL.md`, optional `---` front-matter with `name:`), at «instructions» level.
pub fn load_skills(dir: &Path, names: &[String]) -> Result<Vec<Skill>> {
    let mut out = Vec::new();

    for name in names {
        let mut found = None;

        if let Ok(directory) = read_dir(dir) {
            for entry in directory.flatten() {
                let Ok(text) = read_to_string(entry.path().join("SKILL.md")) else {
                    continue;
                };

                let (front, body) = match text
                    .strip_prefix("---")
                    .and_then(|content| content.split_once("\n---"))
                {
                    Some((front_, body_)) => (
                        front_.to_string(),
                        body_.trim_start_matches(['-', '\n', '\r']).to_string(),
                    ),
                    None => (String::new(), text.clone()),
                };

                let file_name = front
                    .lines()
                    .find_map(|l| l.strip_prefix("name:"))
                    .map(|v| v.trim().trim_matches(['"', '\'']).to_string())
                    .unwrap_or_else(|| entry.file_name().to_string_lossy().to_string());

                if file_name == *name {
                    found = Some(Skill {
                        name: file_name,
                        instructions: body.trim().to_string(),
                    });
                    break;
                }
            }
        }

        out.push(found.ok_or_else(|| {
            Error::config(format!(
                "Failed to find the skill '{name}' in {}.",
                dir.display()
            ))
        })?);
    }
    Ok(out)
}
