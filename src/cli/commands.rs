use super::args::{Cli, Cmd, WslCmd};
use super::report::emit;
use agents_flow::config::Settings;
use agents_flow::error::{Error, Result};
use agents_flow::llm::core::{build_llm, Message};
use agents_flow::remote::client::WslHost;
use agents_flow::remote::wsl::Wsl;
use agents_flow::remote::{doctor, executor};
use agents_flow::security::runtime::{PermissionPolicy, SecurityRuntime, ToolHost};
use agents_flow::team::orchestrator::Orchestrator;
use agents_flow::util::{clip, expanduser};
use agents_flow::verify::{self, run_verification};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

/// Execute the requested sub-command.
pub fn execute(cli: Cli) -> Result<ExitCode> {
    let Cli { config, cmd } = cli;
    let cfg = config.as_deref();

    match cmd {
        Cmd::Executor {
            serve,
            env_file,
            max_bytes,
        } => executor(cfg, serve, env_file.as_deref(), max_bytes),
        Cmd::Verify => verify(cfg),
        Cmd::Permissions => permissions(cfg),
        Cmd::Doctor => doctor(cfg),
        Cmd::Audit { tail, denials } => audit(cfg, tail, denials),
        Cmd::LlmCheck { profile } => llm_check(cfg, profile.as_deref()),
        Cmd::Wsl(WslCmd::Sync { binary }) => wsl_sync(cfg, &binary),
        Cmd::Run {
            request,
            mode,
            json,
        } => run(cfg, &request, &mode, json),
        Cmd::Pipeline { name, params, json } => pipeline(cfg, &name, params, json),
    }
}

fn exit_code(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn make_host(settings: &Arc<Settings>) -> Result<Arc<dyn ToolHost>> {
    if settings.deployment.backend == "wsl" {
        Ok(Arc::new(WslHost::connect(settings.clone())?))
    } else {
        Ok(Arc::new(SecurityRuntime::new(settings.clone(), None)?))
    }
}

fn executor(
    cfg: Option<&Path>,
    serve: bool,
    env_file: Option<&Path>,
    max_bytes: usize,
) -> Result<ExitCode> {
    if !serve {
        return Err(Error::config("use --serve"));
    }

    let dir = cfg
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config"));

    executor::serve(&dir, env_file, max_bytes)?;
    Ok(ExitCode::SUCCESS)
}

fn verify(cfg: Option<&Path>) -> Result<ExitCode> {
    let directory = cfg
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("AGENTS_FLOW_CONFIG_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("config"));

    let vresults = run_verification(&directory)?;

    println!("{}", verify::render(&vresults));
    Ok(exit_code(vresults.iter().all(|vresult| vresult.ok)))
}

fn permissions(cfg: Option<&Path>) -> Result<ExitCode> {
    let settings = Settings::load(cfg, None, false)?;
    let policy = PermissionPolicy::new(&settings);

    for (agent, caps, tools, deny) in policy.matrix() {
        println!(
            "{agent}\n  capacities : {}\n  outils    : {}{}",
            if caps.is_empty() {
                "(none)".into()
            } else {
                caps.join(", ")
            },
            if tools.is_empty() {
                "none)".into()
            } else {
                tools.join(", ")
            },
            if deny.is_empty() {
                String::new()
            } else {
                format!("\n  prohibited : {}", deny.join(", "))
            }
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn doctor(cfg: Option<&Path>) -> Result<ExitCode> {
    let settings = Settings::load(cfg, None, true)?;
    let checks = doctor::run(&settings);

    for check in &checks {
        println!("[{:^6}] {:<14} {}", check.status, check.name, check.detail);
    }

    Ok(exit_code(
        !checks.iter().any(|check| check.status == "FAILURE"),
    ))
}

fn audit(cfg: Option<&Path>, tail: usize, denials: bool) -> Result<ExitCode> {
    let settings = Settings::load(cfg, None, true)?;

    let path = expanduser(if settings.deployment.backend == "wsl" {
        &settings.deployment.client_audit_path
    } else {
        &settings.permissions.audit.path
    });

    let text = fs::read_to_string(&path).map_err(|err| {
        Error::config(format!("unreadable audit log ({}): {err}", path.display()))
    })?;

    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !denials || line.contains("\"decision\":\"deny\""))
        .collect();

    for line in lines.iter().skip(lines.len().saturating_sub(tail)) {
        println!("{line}");
    }

    Ok(ExitCode::SUCCESS)
}

fn llm_check(cfg: Option<&Path>, profile: Option<&str>) -> Result<ExitCode> {
    let settings = Settings::load(cfg, None, true)?;
    let llm = build_llm(&settings, profile)?;

    println!("LLM : {}", llm.describe());
    match llm.complete(&[Message::user("Respond only with the word: OK")], &[], &[]) {
        Ok(completion) => {
            println!("answer : {}", clip(completion.content.trim(), 200));
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            println!("✘ {err}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn wsl_sync(cfg: Option<&Path>, binary: &Path) -> Result<ExitCode> {
    let settings = Settings::load(cfg, None, true)?;
    println!("{}", Wsl::new(&settings).sync(&settings, binary)?);
    Ok(ExitCode::SUCCESS)
}

fn run(cfg: Option<&Path>, request: &str, mode: &str, json: bool) -> Result<ExitCode> {
    let settings = Arc::new(Settings::load(cfg, None, true)?);
    let host = make_host(&settings)?;

    if !json {
        println!("backend : {}", host.backend_name());
    }
    let orch = Orchestrator::new(host, None)?;

    let report = if mode == "hierarchical" {
        orch.run_hierarchical(request)
    } else {
        orch.run_plan(request)
    };

    emit(&report, json);
    Ok(exit_code(report.ok()))
}

fn pipeline(
    cfg: Option<&Path>,
    name: &str,
    params: Vec<(String, String)>,
    json: bool,
) -> Result<ExitCode> {
    let settings = Arc::new(Settings::load(cfg, None, true)?);
    let host = make_host(&settings)?;

    let orch = Orchestrator::new(host, None)?;
    let report = orch.run_pipeline(name, &params.into_iter().collect::<HashMap<_, _>>())?;

    emit(&report, json);
    Ok(exit_code(report.ok()))
}
