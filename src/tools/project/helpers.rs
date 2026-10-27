use super::constants::{DEP_SPLIT, IGNORED, MAX_FILES};
use crate::tools::ToolContext;
use crate::util::splitlines;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn dep_name(name: &str) -> String {
    DEP_SPLIT
        .split(name.trim())
        .next()
        .unwrap_or("")
        .to_string()
}

pub(super) fn suffix(name: &str) -> String {
    match name.rfind('.') {
        Some(index) if index > 0 && index < name.len() - 1 => name[index..].to_lowercase(),
        _ => String::new(),
    }
}

pub(super) struct F {
    pub(super) rel: Vec<String>,
    pub(super) full: PathBuf,
}

impl F {
    pub(super) fn name(&self) -> &str {
        self.rel.last().map(String::as_str).unwrap_or("")
    }

    pub(super) fn joined(&self) -> String {
        self.rel.join("/")
    }
}

pub(super) fn iter_files(
    ctx: &ToolContext,
    base: &crate::security::path_guard::resolved::ResolvedPath,
) -> Vec<F> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, Vec<String>)> = vec![(base.real.clone(), vec![])];

    while let Some((directory, rel)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&directory) else {
            continue;
        };
        let (mut files, mut dirs) = (Vec::<String>::new(), Vec::<String>::new());

        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            match entry.file_type() {
                Ok(file_type) if file_type.is_dir() => {
                    if !IGNORED.contains(&name.as_str()) {
                        dirs.push(name)
                    }
                }
                Ok(file_type) if file_type.is_file() => files.push(name),
                _ => {}
            }
        }
        files.sort();
        dirs.sort();

        for file in files {
            let mut parts = rel.clone();
            parts.push(file.clone());

            if ctx.rt.paths.check_discovered(base, &parts).is_err() {
                continue;
            }

            if out.len() >= MAX_FILES {
                return out;
            }

            out.push(F {
                full: directory.join(&file),
                rel: parts,
            });
        }

        for dir in dirs.into_iter().rev() {
            let mut path = rel.clone();
            path.push(dir.clone());
            stack.push((directory.join(&dir), path));
        }
    }
    out
}

pub(super) fn read_small(path: &Path) -> Option<String> {
    let meta_data = fs::metadata(path).ok()?;

    if meta_data.len() > 1_000_000 {
        return None;
    }

    fs::read(path)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

pub(super) fn take_keys(val_opt: Option<&Value>, len: usize) -> Vec<String> {
    val_opt
        .and_then(Value::as_object)
        .map(|map| map.keys().take(len).cloned().collect())
        .unwrap_or_default()
}

pub(super) fn parse_manifest(
    name: &str,
    full: &Path,
    deps: &mut BTreeSet<String>,
    entry: &mut Vec<String>,
) -> Value {
    let Some(text) = read_small(full) else {
        return json!({"unreadable": true});
    };

    let toml_err = json!({"parse_error": "TOMLDecodeError"});
    match name {
        "pyproject.toml" => {
            let Ok(d) = toml::from_str::<toml::Value>(&text) else {
                return toml_err;
            };

            let d = serde_json::to_value(&d).unwrap_or(Value::Null);
            let proj = d.get("project").cloned().unwrap_or(json!({}));

            let dl: Vec<String> = proj
                .get("dependencies")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            deps.extend(dl.iter().map(|x| dep_name(x)));

            if let Some(sc) = proj.get("scripts").and_then(Value::as_object) {
                entry.extend(
                    sc.iter()
                        .map(|(k, v)| format!("script:{k} -> {}", v.as_str().unwrap_or(""))),
                );
            }

            json!({"name": proj.get("name"), "requires_python": proj.get("requires-python"), "scripts": proj.get("scripts").cloned().unwrap_or(json!({})),
                   "dependencies": dl.iter().take(40).collect::<Vec<_>>(), "optional_groups": take_keys(proj.get("optional-dependencies"), usize::MAX)})
        }
        "package.json" => {
            let Ok(d) = serde_json::from_str::<Value>(&text) else {
                return json!({"parse_error": "JSONDecodeError"});
            };

            let mut names = take_keys(d.get("dependencies"), usize::MAX);
            for key in take_keys(d.get("devDependencies"), usize::MAX) {
                if !names.contains(&key) {
                    names.push(key);
                }
            }

            let names: Vec<String> = names.into_iter().take(40).collect();
            deps.extend(names.iter().cloned());

            if let Some(m) = d.get("main").and_then(Value::as_str) {
                entry.push(format!("main:{m}"));
            }

            json!({"name": d.get("name"), "main": d.get("main"), "bin": d.get("bin"), "scripts": d.get("scripts").cloned().unwrap_or(json!({})), "dependencies": names})
        }
        "requirements.txt" => {
            let names: Vec<String> = text
                .lines()
                .filter(|line| {
                    !line.trim().is_empty() && !line.starts_with('#') && !line.starts_with('-')
                })
                .map(dep_name)
                .collect();

            deps.extend(names.iter().cloned());
            json!({"packages": names.iter().take(60).collect::<Vec<_>>()})
        }
        "go.mod" => {
            json!({"module": Regex::new(r"(?m)^module\s+(\S+)").unwrap().captures(&text).map(|capture| capture[1].to_string())})
        }
        "Cargo.toml" => {
            let Ok(d) = toml::from_str::<toml::Value>(&text) else {
                return toml_err;
            };

            let d = serde_json::to_value(&d).unwrap_or(Value::Null);
            let dn = take_keys(d.get("dependencies"), usize::MAX);

            deps.extend(dn.iter().cloned());
            json!({"name": d.get("package").and_then(|p| p.get("name")), "dependencies": dn.iter().take(40).collect::<Vec<_>>()})
        }
        _ => json!({"present": true, "lines": splitlines(&text).len()}),
    }
}
