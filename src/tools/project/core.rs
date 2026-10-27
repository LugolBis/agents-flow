//! STATIC project analysis: no project code is ever imported or executed.
//! `scan_project`: tree, languages, manifests, dependencies, entry points, tests, config. `python_import_graph`: internal import graph of a
//! Python project. Outputs contain OBSERVED FACTS only. Difference from the Python original: imports are found with a lexical scanner
//! (docstrings and comments skipped) instead of the `ast` module, so syntax errors are not reported.
use super::{
    constants::{FRAMEWORKS, LANGS, MANIFESTS, MAX_FILES, TEST_RE},
    helpers::{iter_files, parse_manifest, read_small, suffix, F},
    python::{cycles, scan_py},
};

use crate::error::{Error, Result, SecurityError};
use crate::tools::{
    github::json_indent1,
    schema::{ArgSchema, Field},
    Tool,
};

use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

tool!(ScanProjectTool, "scan_project", "agents_flow.tools.project.ScanProjectTool", ["fs.read"],
    "Static analysis of a project (nothing is executed): directory structure, languages, manifests and dependencies, frameworks, entry points, tests, and configuration files. Returns a JSON object containing the observed facts.",
    ArgSchema(vec![Field::str("path", 1024).default(json!("."))]),
    |ctx, a| {
        let rp = ctx.rt.paths.resolve(a.str("path"), "read", None)?;
        
        if !rp.real.is_dir() {
            return Err(Error::Security(SecurityError::path("not_a_directory", "it isn't a directory")));
        }

        let files = iter_files(ctx, &rp);
        let mut langs: Vec<(String, usize)> = Vec::new();
        
        for file in &files {
            if let Some((_, lang)) = LANGS.iter().find(|(e, _)| *e == suffix(file.name())) {
                match langs.iter_mut().find(|(n, _)| n == lang) { Some(x) => x.1 += 1, None => langs.push((lang.to_string(), 1)) }
            }
        }
        
        langs.sort_by(|a, b| b.1.cmp(&a.1));
        let mut top: BTreeMap<String, usize> = BTreeMap::new();

        for f in files.iter().filter(|f| f.rel.len() > 1) {
            *top.entry(f.rel[0].clone()).or_default() += 1;
        }
        
        let (mut manifests, mut deps, mut entry) = (Map::new(), BTreeSet::<String>::new(), Vec::<String>::new());
        for file in &files {
            if MANIFESTS.contains(&file.name()) && file.rel.len() <= 3 {
                manifests.insert(file.joined(), parse_manifest(file.name(), &file.full, &mut deps, &mut entry));
            }
        }
        
        for file in &files {
            if ["__main__.py", "main.py", "app.py", "manage.py", "index.js", "main.go", "cli.py", "server.py"].contains(&file.name()) && file.rel.len() <= 4 {
                entry.push(file.joined());
            }
        }

        let parent = |f: &F| if f.rel.len() > 1 { f.rel[..f.rel.len() - 1].join("/") } else { ".".to_string() };
        let tests: Vec<String> = files.iter()
            .filter(|f| TEST_RE.is_match(f.name()) || ["tests", "test", "__tests__"]
            .contains(&f.rel[0].as_str())).map(parent)
            .collect::<BTreeSet<_>>().into_iter().take(15).collect();

        let configs: Vec<String> = files.iter()
            .filter(|f| [".jsonc", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg"]
            .contains(&suffix(f.name()).as_str()) && f.rel.len() <= 3)
            .map(F::joined).take(40).collect();

        let ci: Vec<String> = files.iter()
            .map(F::joined).filter(|p| p.starts_with(".github/workflows/")).collect();
        let lowered: BTreeSet<String> = deps.iter()
            .map(|d| d.to_lowercase().split('[').next().unwrap_or("").trim().to_string()).collect();

        let frameworks: BTreeSet<&str> = FRAMEWORKS.iter()
            .filter(|(k, _)| lowered.contains(*k)).map(|(_, v)| *v).collect();
        let entry_set: BTreeSet<String> = entry.into_iter().collect();
        
        let mut root_files: Vec<String> = files.iter()
            .filter(|f| f.rel.len() == 1).map(|f| f.name().to_string()).collect();
        root_files.sort(); root_files.truncate(60);

        let has = |p: &str| files.iter().any(|f| f.name().to_lowercase().starts_with(p));
        let data = json!({
            "root": rp.rel_str(), "file_count": files.len(), "truncated": files.len() >= MAX_FILES,
            "languages_by_file_count": Value::Object(langs.iter().map(|(k, v)| (k.clone(), json!(v))).collect()),
            "top_level_entries": top, "root_files": root_files, "manifests": manifests, "dependencies": deps.iter().take(80).collect::<Vec<_>>(),
            "frameworks_detected_from_dependencies": frameworks, "entry_points_observed": entry_set.iter().take(20).collect::<Vec<_>>(), "test_locations": tests,
            "config_files": configs, "ci_workflows": ci, "has_readme": has("readme"), "has_license": has("licen"),
        });
        Ok(ctx.untrusted(&json_indent1(&data), &format!("scan:{}", rp.rel_str())))
    });

tool!(PythonImportGraphTool, "python_import_graph", "agents_flow.tools.project.PythonImportGraphTool", ["fs.read"],
    "Graph of internal imports in a Python project (lexical analysis, no execution): modules, dependencies, cycles, and orphaned modules.",
    ArgSchema(vec![Field::str("path", 1024).default(json!("."))]),
    |ctx, a| {
        let rp = ctx.rt.paths.resolve(a.str("path"), "read", None)?;
        if !rp.real.is_dir() { return Err(Error::Security(SecurityError::path("not_a_directory", "this isn't a directory"))); }
        
        let mut mods: Vec<(String, PathBuf, bool)> = Vec::new();
        for file in iter_files(ctx, &rp) {
            if file.name().ends_with(".py") && mods.len() < 800 {
                let mut parts: Vec<String> = file.rel.clone();
                let last = parts.pop().unwrap_or_default();
                let stem = last.trim_end_matches(".py").to_string();
                let is_pkg = stem == "__init__";
                if !is_pkg { parts.push(stem); }
                if parts.first().map(String::as_str) == Some("src") { parts.remove(0); }
                if !parts.is_empty() { mods.push((parts.join("."), file.full.clone(), is_pkg)); }
            }
        }

        let names: BTreeSet<&str> = mods.iter().map(|(m, _, _)| m.as_str()).collect();
        let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut defs = Map::new();

        for (m, full, is_pkg) in &mods {
            let Some(src) = read_small(full) else { continue };
            let info = scan_py(&src);
            defs.insert(m.clone(), json!({"classes": info.classes, "functions": info.functions}));

            for (level, module, imported) in &info.imports {
                let mut targets: Vec<String> = Vec::new();

                if *level == 0 && module.is_empty() {
                    targets = imported.clone();
                }
                else {
                    let mut base = module.clone();

                    if *level > 0 {
                        let mut pkg: Vec<&str> = m.split('.').collect();
                        if !*is_pkg { pkg.pop(); }
                        if *level > 1 { pkg.truncate(pkg.len().saturating_sub(level - 1)); }
                        base = if base.is_empty() { pkg.join(".") } else { pkg.iter().copied().chain(std::iter::once(base.as_str())).collect::<Vec<_>>().join(".") };
                    }
                    targets.push(base.clone());
                    targets.extend(imported.iter().map(|n| format!("{base}.{n}")));
                }

                for target in targets {
                    let parts: Vec<&str> = target.split('.').collect();
                    
                    for index in (1..=parts.len()).rev() {
                        let cand = parts[..index].join(".");
                        if names.contains(cand.as_str()) && cand != *m { edges.entry(m.clone()).or_default().insert(cand); break; }
                    }
                }
            }
        }

        let mut inbound: BTreeMap<&str, usize> = BTreeMap::new();

        for ts in edges.values() {
            for t in ts {
                *inbound.entry(t.as_str()).or_default() += 1;
            }
        }

        let mut most: Vec<(&str, usize)> = inbound.iter().map(|(k, v)| (*k, *v)).collect();
        most.sort_by(|a, b| b.1.cmp(&a.1));
        
        let orphans: Vec<&str> = names.iter().copied().filter(|m| !inbound.contains_key(m) && !edges.contains_key(*m)).take(30).collect();
        let data = json!({"modules": mods.len(), "syntax_errors": Vec::<String>::new(), "definitions": defs,
            "edges": edges.iter().map(|(k, v)| (k.clone(), v.iter().cloned().collect::<Vec<_>>())).collect::<BTreeMap<_, _>>(), "cycles": cycles(&edges),
            "most_imported": most.iter().take(8).map(|(k, v)| json!([k, v])).collect::<Vec<_>>(), "isolated_modules": orphans});
        Ok(ctx.untrusted(&json_indent1(&data), &format!("imports:{}", rp.rel_str())))
    });

pub fn tools() -> Vec<Box<dyn Tool>> {
    vec![Box::new(ScanProjectTool), Box::new(PythonImportGraphTool)]
}

#[allow(dead_code)]
fn _u(_: Result<()>) {}
