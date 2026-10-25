use crate::config::models::permissions::ShellCfg;
use crate::error::{Result, SecResult, SecurityError};
use crate::security::builtins::{api::run_builtin, context::Ctx};
use crate::security::commands::builders::{self, build, BuildCtx};
use crate::security::commands::names::{self, resolve_enabled};
use crate::security::commands::tokenizer::gate;
use crate::security::commands::{git_cmd, split_command, CommandOutput};
use crate::security::git_guard::reader::GitReader;
use crate::security::path_guard::guard::PathGuard;
use crate::security::secrets::SecretRedactor;
use crate::util::clip;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct CommandPolicy {
    cfg: ShellCfg,
    paths: Arc<PathGuard>,
    git: Option<Arc<GitReader>>,
    red: Arc<SecretRedactor>,
    pub enabled: Vec<String>,
}

impl CommandPolicy {
    pub fn new(
        cfg: &ShellCfg,
        paths: Arc<PathGuard>,
        git: Option<Arc<GitReader>>,
        red: Arc<SecretRedactor>,
    ) -> Result<Self> {
        let git_available = git.as_ref().map(|g| g.available()).unwrap_or(false);
        let enabled = resolve_enabled(cfg, git_available)?;

        Ok(CommandPolicy {
            cfg: cfg.clone(),
            paths,
            git,
            red,
            enabled,
        })
    }

    pub fn run(&self, command: &str, cwd: Option<&str>) -> SecResult<CommandOutput> {
        let (name, tokens, base) = self.parse(command, cwd)?;

        if name == "git" {
            let git_r = self.git.as_ref().ok_or_else(|| {
                SecurityError::command("command_not_allowlisted", "git unavailable")
            })?;
            return git_cmd::run(git_r, &base, &tokens);
        }

        let bctx = BuildCtx::new(&self.cfg, &self.paths);
        let argv = build(&bctx, &name, &tokens, &base)?;

        let ctx = Ctx {
            guard: &self.paths,
            deadline: Instant::now() + Duration::from_secs_f64(self.cfg.timeout_s),
            max_out: self.cfg.max_output_bytes,
            max_depth: self.cfg.find_max_depth,
        };

        let out = run_builtin(&name, &argv, &base, &ctx);
        let mut text = self.red.redact(&out.text).into_owned();

        if !out.err.trim().is_empty() {
            text.push_str("\n[stderr] ");
            text.push_str(&self.red.redact(&clip(out.err.trim(), 2000)));
        }

        if out.timed_out {
            text.push_str("\n[interrupted : delay exceeded]");
        }

        if out.truncated {
            text.push_str("\n[truncated output]");
        }

        Ok(CommandOutput {
            text,
            exit_code: out.exit,
            truncated: out.truncated,
            timed_out: out.timed_out,
        })
    }

    /// Validates without executing; returns the canonical argv (tests).
    pub fn validate(&self, command: &str, cwd: Option<&str>) -> SecResult<Vec<String>> {
        let (name, tokens, base) = self.parse(command, cwd)?;

        if name == "git" {
            let git_r = self.git.as_ref().ok_or(SecurityError::command(
                "command_not_allowlisted",
                "git unavailable",
            ))?;
            return git_cmd::validate(git_r, &base, &tokens);
        }

        let bctx = BuildCtx::new(&self.cfg, &self.paths);
        let mut vec = vec![name.clone()];
        vec.extend(builders::build(&bctx, &name, &tokens, &base)?);

        Ok(vec)
    }

    fn parse(&self, command: &str, cwd: Option<&str>) -> SecResult<(String, Vec<String>, PathBuf)> {
        gate(command)?;

        let tokens = split_command(command).ok_or(SecurityError::command(
            "unparseable",
            "unbalanced quotation marks",
        ))?;

        let (name, rest) = tokens
            .split_first()
            .ok_or(SecurityError::command("empty_command", "empty command"))?;

        if name.contains('/') {
            return Err(SecurityError::command(
                "command_path_not_allowed",
                "the command name shouldn't contains path",
            ));
        }

        if !self.enabled.contains(name) {
            if names::is_forbidden(name) {
                return Err(SecurityError::command(
                    "forbidden_command",
                    &format!("forbidden command : {name}"),
                ));
            }

            return Err(SecurityError::command(
                "command_not_allowlisted",
                &format!("command missing from the allowlist : {}", clip(name, 30)),
            ));
        }

        let base = self.base(cwd)?;
        Ok((name.clone(), rest.to_vec(), base))
    }

    fn base(&self, cwd: Option<&str>) -> SecResult<PathBuf> {
        let base = match cwd {
            Some(c) => self.paths.resolve(c, "read", None)?.real,
            None => self.paths.default_root().path.clone(),
        };

        if !base.is_dir() {
            return Err(SecurityError::command(
                "cwd_not_directory",
                "the working directory is not a folder",
            ));
        }

        Ok(base)
    }
}
