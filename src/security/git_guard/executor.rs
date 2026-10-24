use crate::config::models::permissions::GitCfg;
use crate::error::SecResult;
use crate::security::git_guard::core::Repo;
use crate::security::git_guard::helpers::{denied, sv, REV_RE, UNSAFE_KEYS};
use crate::security::path_guard::{guard::PathGuard, root::Root};
use crate::security::runner::{run_limited, RunOpts, RunResult};
use crate::security::secrets::clean_env;
use crate::util::{clip, realpath, rel_posix, which_in, NULL_DEVICE, PATH_LIST_SEP};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub struct GitExec {
    pub cfg: GitCfg,
    pub paths: Arc<PathGuard>,
    pub git_bin: Option<PathBuf>,
    ceilings: String,
}

impl GitExec {
    pub fn new(cfg: &GitCfg, paths: Arc<PathGuard>, trusted_dirs: &[PathBuf]) -> GitExec {
        let defaults: Vec<PathBuf> = ["/usr/bin", "/bin", "/usr/local/bin"]
            .iter()
            .map(PathBuf::from)
            .collect();

        let dirs: Vec<PathBuf> = if trusted_dirs.is_empty() {
            defaults
        } else {
            trusted_dirs.to_vec()
        };

        let ceilings: BTreeSet<String> = paths
            .roots
            .iter()
            .filter_map(|root| {
                root.path
                    .parent()
                    .map(|path| path.to_string_lossy().to_string())
            })
            .collect();

        GitExec {
            cfg: cfg.clone(),
            paths,
            git_bin: which_in("git", &dirs),
            ceilings: ceilings.into_iter().collect::<Vec<_>>().join(PATH_LIST_SEP),
        }
    }

    pub fn run(
        &self,
        cwd: &Path,
        args: &[String],
        write: bool,
        literal_pathspecs: bool,
        identity: bool,
    ) -> SecResult<RunResult> {
        let bin = self.git_bin.as_ref().ok_or_else(|| {
            denied(
                "git_unavailable",
                "failed to find the git binary in the trusted directories",
            )
        })?;

        let mut extra: Vec<(&str, String)> = vec![
            ("GIT_CONFIG_NOSYSTEM", "1".into()),
            ("GIT_CONFIG_GLOBAL", NULL_DEVICE.into()),
            ("GIT_TERMINAL_PROMPT", "0".into()),
            ("GIT_PAGER", "cat".into()),
            ("GIT_ATTR_NOSYSTEM", "1".into()),
            ("GIT_CEILING_DIRECTORIES", self.ceilings.clone()),
        ];

        if !cfg!(windows) {
            extra.push(("GIT_ASKPASS", "/bin/false".into()));
        }

        if !write {
            extra.push(("GIT_OPTIONAL_LOCKS", "0".into()));
        }

        if literal_pathspecs {
            extra.push(("GIT_LITERAL_PATHSPECS", "1".into()));
        }

        let nd = NULL_DEVICE;
        let mut argv: Vec<String> = vec![bin.to_string_lossy().to_string()];

        for kv in [
            format!("core.hooksPath={nd}"),
            "core.fsmonitor=false".into(),
            "protocol.allow=never".into(),
            "credential.helper=".into(),
            "core.askPass=".into(),
            "gc.auto=0".into(),
            "maintenance.auto=false".into(),
            "commit.gpgsign=false".into(),
            format!("core.attributesFile={nd}"),
            format!("core.excludesFile={nd}"),
        ] {
            argv.push("-c".into());
            argv.push(kv);
        }

        if identity {
            argv.extend([
                "-c".into(),
                format!("user.name={}", self.cfg.author_name),
                "-c".into(),
                format!("user.email={}", self.cfg.author_email),
            ]);
        }

        argv.extend(args.iter().cloned());

        let extras: Vec<(&str, &str)> = extra.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let git_dir = bin
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .into_iter()
            .collect::<Vec<_>>();

        let env = clean_env(&extras, if cfg!(windows) { &git_dir } else { &[] });

        run_limited(
            &argv,
            &RunOpts {
                cwd,
                env,
                timeout: Duration::from_secs_f64(self.cfg.timeout_s),
                max_output: self.cfg.max_output_bytes,
                cpu_s: 30,
                memory_mb: 4096,
                fsize: write.then_some(512 * 1024 * 1024),
            },
        )
        .map_err(|e| denied("git_error", format!("execution of git is impossible ({e})")))
    }

    pub fn run_r(&self, cwd: &Path, args: &[&str]) -> SecResult<RunResult> {
        self.run(cwd, &sv(args), false, false, false)
    }

    pub fn open_repo(&self, start: &Path, _root: &Root) -> SecResult<Repo> {
        let d = if start.is_dir() {
            start
        } else {
            start.parent().unwrap_or(start)
        };

        let res = self.run_r(d, &["rev-parse", "--show-toplevel"])?;
        if res.returncode != 0 || res.stdout.trim().is_empty() {
            return Err(denied(
                "not_a_git_repo",
                "there isn't any Git repository detected at this location",
            ));
        }

        let top = realpath(Path::new(res.stdout.trim()));
        let top_root = self.paths.root_of(&top).cloned().ok_or_else(|| {
            denied(
                "repo_outside_roots",
                "the repository is out from the authorized repositories",
            )
        })?;

        let keys = self.run_r(&top, &["config", "--local", "--name-only", "--list"])?;
        for key in keys.stdout.to_lowercase().lines() {
            if UNSAFE_KEYS.iter().any(|regex| regex.is_match(key.trim())) {
                return Err(denied(
                    "unsafe_repo_config",
                    format!(
                        "the local repository configuration define a key with risks ({})",
                        clip(key.trim(), 60)
                    ),
                ));
            }
        }

        Ok(Repo {
            top,
            root: top_root,
        })
    }
}

pub(super) fn check_rev(rev: &str) -> SecResult<String> {
    if REV_RE.is_match(rev) {
        Ok(rev.to_string())
    } else {
        Err(denied(
            "bad_revision",
            format!("invalid revision : '{}'", clip(rev, 30)),
        ))
    }
}

pub(super) fn truncate_note(r: &RunResult) -> &'static str {
    if r.truncated {
        "\n[truncated output]"
    } else {
        ""
    }
}

pub(super) fn rel_in(repo: &Repo, real: &Path) -> String {
    if real == repo.top {
        ".".into()
    } else {
        rel_posix(real, &repo.top).join("/")
    }
}
