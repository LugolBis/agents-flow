//! Project test execution — DISABLED by default. Running a project's tests executes ITS code: no in-process guard can truly isolate it.
//! This tool is only a launcher for an argv fixed by the administrator (never by the LLM), without a shell, with a timeout and an
//! output cap. Real isolation must come from the container/sandbox referenced in `test_runner.argv`, e.g.
//! `["docker","run","--rm","--network=none","--read-only","--cap-drop=ALL","-v","{repo}:/work:ro","-w","/work","python:3.12-slim","python","-m","pytest","-q"]`.
//! Requires `test_runner.enabled=true` AND `tools.jsonc: run_tests.enabled=true` AND a non-empty argv. NOT tested here (no Docker).
use super::schema::{ArgSchema, Field};
use super::Tool;
use crate::error::SecurityError;
use crate::security::runner::{run_limited, RunOpts};
use crate::security::secrets::clean_env;
use crate::util::{realpath, which_in};
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;

tool!(RunTestsTool, "run_tests", "agents_flow.tools.tests_runner.RunTestsTool", ["exec.tests"],
    "Executes the test command configured by the administrator on a repository within the scope (sandbox required). No free-form arguments.",
    ArgSchema(vec![Field::str("path", 1024).default(json!(".")).desc("Root of the repository to be tested.")]),
    |ctx, a| {
        let cfg = &ctx.rt.settings.permissions.test_runner;
        if !cfg.enabled || cfg.argv.is_empty() { return Err(SecurityError::command("tests_disabled", "test execution is disabled by the configuration").into()); }
        let repo = ctx.rt.git_reader.open(a.str("path"))?;
        let argv: Vec<String> = cfg.argv.iter().map(|x| x.replace("{repo}", &repo.top.to_string_lossy())).collect();
        let mut dirs = ctx.rt.settings.permissions.shell.trusted_dirs();
        if !cfg!(windows) { dirs.push(PathBuf::from("/usr/local/bin")); }
        let exe = which_in(&argv[0], &dirs).ok_or_else(|| SecurityError::command("runner_missing", format!("executable not found: {}", argv[0])))?;
        let mut full = vec![realpath(&exe).to_string_lossy().to_string()];
        full.extend(argv[1..].iter().cloned());
        let path_dirs: Vec<String> = dirs.iter().map(|d| d.to_string_lossy().to_string()).collect();
        let res = run_limited(&full, &RunOpts { cwd: &repo.top, env: clean_env(&[("PYTHONDONTWRITEBYTECODE", "1")], &path_dirs), timeout: Duration::from_secs_f64(cfg.timeout_s),
            max_output: cfg.max_output_bytes, cpu_s: cfg.timeout_s as u64, memory_mb: 4096, fsize: Some(cfg.max_output_bytes as u64 + 1) })?;
        let tail = if res.timed_out { "\n[elay exceeded]" } else { "" };
        Ok(ctx.untrusted(&format!("exit status code {}\n{}{}{tail}", res.returncode, res.stdout, res.stderr), "tests"))
    });

pub fn tools() -> Vec<Box<dyn Tool>> {
    vec![Box::new(RunTestsTool)]
}
