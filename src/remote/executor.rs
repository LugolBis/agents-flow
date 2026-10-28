//! Executor side (runs where the tools live, typically Linux/WSL): `agwo executor --serve`.
//! stdout carries ONLY protocol lines; every diagnostic goes to stderr.
use super::protocol::*;
use crate::config::Settings;
use crate::error::Result;
use crate::security::runtime::{SecurityRuntime, ToolHost, ToolOutcome};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use std::{fs, result};

/// `KEY=VALUE` lines (comments and `export` allowed). Secrets (GitHub token…) live HERE, not in the Windows-side environment.
/// On Unix the file must not be readable by group/others.
pub fn load_env_file(path: &Path) -> Result<()> {
    let Ok(meta_data) = fs::metadata(path) else {
        return Ok(());
    };

    #[cfg(unix)]
    {
        use crate::error::Error;
        use std::os::unix::fs::PermissionsExt;
        if md.permissions().mode() & 0o077 != 0 {
            return Err(Error::config(format!(
                "{} doit être en mode 600 (secrets)",
                path.display()
            )));
        }
    }
    let _ = meta_data;

    for line in fs::read_to_string(path)?.lines() {
        let line_cleaned = line.trim().trim_start_matches("export ").trim();

        if line_cleaned.is_empty() || line_cleaned.starts_with('#') {
            continue;
        }

        if let Some((key, val)) = line_cleaned.split_once('=') {
            std::env::set_var(key.trim(), val.trim().trim_matches(['"', '\'']));
        }
    }
    Ok(())
}

fn outcome_json(tool_outcome: &ToolOutcome) -> Value {
    match tool_outcome {
        ToolOutcome::Ok(text) => json!({"ok": true, "text": text}),
        ToolOutcome::Failure { message, code } => {
            json!({"ok": false, "message": message, "code": code})
        }
    }
}

pub fn handle(sec_runtime: &SecurityRuntime, cfg_hash: &str, req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let fn_ks = |key: &str| {
        req.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };

    let body: result::Result<Value, String> =
        match req.get("op").and_then(Value::as_str).unwrap_or("") {
            "hello" => Ok(json!(
                {"protocol": PROTOCOL_VERSION, "config_sha256": cfg_hash, "arch": std::env::consts::ARCH, "os": std::env::consts::OS, "version": env!("CARGO_PKG_VERSION"),
                "git": sec_runtime.git_exec.git_bin.as_ref().map(|p| p.to_string_lossy().to_string())}
            )),
            "tool_defs" => sec_runtime.tool_defs(&fn_ks("agent"))
                .map(|defs| json!({"defs": defs.iter().map(|tool| json!({"name": tool.name, "description": tool.description, "schema": tool.schema})).collect::<Vec<_>>()}))
                .map_err(|err| err.to_string()),
            "tool" => {
                let start = sec_runtime.audit.len();
                let out = sec_runtime.call(
                    &fn_ks("agent"), 
                    &fn_ks("tool"), 
                    req.get("args").unwrap_or(&Value::Null)
                );
                let sess = sec_runtime.session();
                Ok(json!({"outcome": outcome_json(&out), "audit": sec_runtime.audit.events_since(start), "session": {"seen_urls": sess.seen_urls, "created_files": sess.created_files}}))
            }
            "read_text" => sec_runtime.read_text(&fn_ks("path")).map(|text| json!({"text": text}))
                .map_err(|err| err.to_string()),
            "diagnose" => Ok(json!({"arch": std::env::consts::ARCH, "os": std::env::consts::OS, "roots": sec_runtime.paths.roots.iter().map(|root| json!({"name": root.name, "path": root.path.to_string_lossy(), "write": root.write})).collect::<Vec<_>>(),
                                    "git": sec_runtime.git_exec.git_bin.as_ref().map(|p| p.to_string_lossy().to_string()), "shell_commands": sec_runtime.commands.enabled})),
            "ping" => Ok(json!({})),
            other => Err(format!("unknown operation : {other}")),
    };

    match body {
        Ok(mut value) => {
            value["ok"] = json!(true);
            value["id"] = id;
            value
        }
        Err(err) => json!({"ok": false, "id": id, "error": err}),
    }
}

pub fn serve(config_dir: &Path, env_file: Option<&Path>, max_bytes: usize) -> Result<()> {
    if let Some(file_path) = env_file {
        load_env_file(file_path)?;
    }

    let settings = Arc::new(Settings::load(Some(config_dir), None, false)?);
    let hash = config_hash(&settings);
    let sec_runtime = SecurityRuntime::new(settings, None)?;
    sec_runtime.verify_registry()?;

    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();

    eprintln!(
        "agwo executor is ready ({} {})",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    loop {
        let Some(line) = read_line_limited(&mut input, max_bytes)? else {
            return Ok(());
        };

        if line.trim().is_empty() {
            continue;
        }

        let req = match decode(&line) {
            Ok(req_) => req_,
            Err(_) => {
                let mut stdout_lock = stdout.lock();
                stdout_lock.write_all(
                    encode(&json!({"ok": false, "error": "illegible request"})).as_bytes(),
                )?;

                stdout_lock.flush()?;
                continue;
            }
        };

        if req.get("op").and_then(Value::as_str) == Some("shutdown") {
            return Ok(());
        }

        let resp = handle(&sec_runtime, &hash, &req);
        let mut stdout_lock = stdout.lock();
        stdout_lock.write_all(encode(&resp).as_bytes())?;
        stdout_lock.flush()?;
    }
}

#[allow(dead_code)]
fn _u(_: &dyn BufRead) {}
