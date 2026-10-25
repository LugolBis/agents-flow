//! `agwo doctor`: environment checks, readable by a human. Also tells whether this binary runs natively or under x64 emulation
//! on a Windows ARM64 machine (a common, silent performance loss).
use crate::{config::Settings, remote::wsl::Wsl, security::runtime::SecurityRuntime};
use std::{sync::Arc, time::Duration};

pub struct Check {
    pub name: String,
    pub status: &'static str,
    pub detail: String,
}

fn check(name: &str, ok: Option<bool>, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status: match ok {
            Some(true) => "OK",
            Some(false) => "FAILURE",
            None => "WARNING",
        },
        detail: detail.into(),
    }
}

pub fn platform_check() -> Check {
    let built = std::env::consts::ARCH;
    let host = std::env::var("PROCESSOR_ARCHITEW6432")
        .or_else(|_| std::env::var("PROCESSOR_ARCHITECTURE"))
        .unwrap_or_default()
        .to_uppercase();

    if cfg!(windows) && host == "ARM64" && built != "aarch64" {
        return check("plateforme", None, format!("binary {built} executed on Windows ARM64 with emulation : recompile it for aarch64-pc-windows-msvc"));
    }

    if cfg!(windows) && host == "ARM64" {
        return check(
            "plateforme",
            Some(true),
            "Windows 11 ARM64, native aarch64 binary",
        );
    }

    check(
        "plateforme",
        Some(true),
        format!("{} {built}", std::env::consts::OS),
    )
}

pub fn run(settings: &Settings) -> Vec<Check> {
    let mut out = vec![platform_check()];
    let dep = &settings.deployment;

    out.push(check("backend", Some(true), dep.backend.clone()));
    out.push(check(
        "configuration",
        Some(true),
        format!(
            "{} agents, {} outils",
            settings.agents.agents.len(),
            settings.tools.tools.len()
        ),
    ));

    if dep.backend == "wsl" {
        let wsl = Wsl::new(settings);
        let distros = wsl.list_distros();

        out.push(check(
            "wsl",
            Some(distros.iter().any(|d| *d == dep.wsl.distro)),
            format!(
                "distributions : {}",
                if distros.is_empty() {
                    "(wsl.exe not found)".into()
                } else {
                    distros.join(", ")
                }
            ),
        ));
    } else {
        match SecurityRuntime::new(Arc::new(settings.clone()), None) {
            Ok(sec_runtime) => out.push(check(
                "git",
                Some(sec_runtime.git_exec.git_bin.is_some()),
                sec_runtime
                    .git_exec
                    .git_bin
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or(
                        "git not found in the trusted folders (git status/commit unavailable)"
                            .into(),
                    ),
            )),
            Err(err) => out.push(check("runtime", Some(false), err.to_string())),
        }
    }

    for (pname, llm_profile) in dep.llm.profiles.iter() {
        let url = format!("{}/models", llm_profile.base_url.trim_end_matches('/'));
        let req = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(5)))
            .http_status_as_error(false)
            .proxy(None)
            .build();

        let ok = ureq::Agent::new_with_config(req)
            .get(&url)
            .header("Authorization", format!("Bearer {}", llm_profile.api_key))
            .call()
            .map(|resp| resp.status().as_u16() == 200)
            .unwrap_or(false);

        out.push(check(
            &format!("llm:{pname}"),
            Some(ok),
            format!(
                "{} (ctx {}, function_calling={})",
                llm_profile.base_url, llm_profile.context_window, llm_profile.function_calling
            ),
        ));
    }
    out
}
