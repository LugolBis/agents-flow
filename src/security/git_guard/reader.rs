use crate::error::{SecResult, SecurityError};
use crate::security::git_guard::core::{build_git_read_argv, Repo};
use crate::security::git_guard::executor::{check_rev, rel_in, truncate_note, GitExec};
use crate::security::git_guard::helpers::{denied, sv};
use crate::security::path_guard::guard::PathGuard;
use crate::security::secrets::SecretRedactor;
use crate::util::is_under;
use std::sync::Arc;

pub struct GitReader {
    exec: Arc<GitExec>,
    paths: Arc<PathGuard>,
    red: Arc<SecretRedactor>,
}

impl GitReader {
    pub fn new(exec: Arc<GitExec>, paths: Arc<PathGuard>, red: Arc<SecretRedactor>) -> Self {
        GitReader { exec, paths, red }
    }

    pub fn available(&self) -> bool {
        self.exec.git_bin.is_some()
    }

    pub fn open(&self, path: &str) -> SecResult<Repo> {
        let rp = self.paths.resolve(path, "read", None)?;
        self.exec.open_repo(&rp.real, &rp.root)
    }

    pub fn check_path(&self, repo: &Repo, token: &str) -> SecResult<String> {
        if token.starts_with(':') {
            return Err(SecurityError::path(
                "pathspec_magic",
                "the magic pathspecs (:...) are forbidden",
            ));
        }

        let rp = self.paths.resolve(token, "read", Some(&repo.top))?;
        if !is_under(&rp.real, &repo.top) {
            return Err(SecurityError::path("outside_repo", "chemin hors du dépôt"));
        }

        Ok(rel_in(repo, &rp.real))
    }

    pub fn argv_for(&self, repo: &Repo, sub: &str, tokens: &[String]) -> SecResult<Vec<String>> {
        build_git_read_argv(
            sub,
            tokens,
            &|token| self.check_path(repo, token),
            self.paths.deny_globs(),
        )
    }

    pub fn run_read(&self, repo: &Repo, sub: &str, tokens: &[String]) -> SecResult<String> {
        let argv = self.argv_for(repo, sub, tokens)?;
        let res = self.exec.run(&repo.top, &argv, false, false, false)?;

        if ![0, 1].contains(&res.returncode)
            || (res.returncode == 1 && !res.stderr.trim().is_empty())
        {
            let msg = crate::util::clip(res.stderr.trim(), 300);
            return Err(denied(
                "git_error",
                self.red
                    .redact(if msg.is_empty() { "git failure" } else { &msg })
                    .into_owned(),
            ));
        }

        Ok(format!(
            "{}{}",
            self.red.redact(&res.stdout),
            truncate_note(&res)
        ))
    }

    fn rd(&self, repo: &Repo, tokens: &[&str], sub: &str) -> SecResult<String> {
        self.run_read(repo, sub, &sv(tokens))
    }

    pub fn info(&self, path: &str) -> SecResult<String> {
        let repo = self.open(path)?;
        let fn_exec = |a: &[&str]| {
            self.exec
                .run_r(&repo.top, a)
                .map(|run_res| run_res.stdout.trim().to_string())
        };

        let branch = Some(fn_exec(&["symbolic-ref", "--short", "-q", "HEAD"])?)
            .filter(|text| !text.is_empty())
            .unwrap_or("(detached HEAD)".into());

        let head = Some(fn_exec(&["rev-parse", "--short", "HEAD"])?)
            .filter(|text| !text.is_empty())
            .unwrap_or("(no commits)".into());

        let urls = fn_exec(&["config", "--local", "--get-regexp", r"^remote\..*\.url$"])?;

        Ok(self
            .red
            .redact(&format!(
                "root: {}\nbranch: {branch}\nHEAD: {head}\nremotes (local config):\n{}",
                repo.top.display(),
                if urls.is_empty() { "(none)" } else { &urls }
            ))
            .into_owned())
    }

    pub fn status(&self, path: &str) -> SecResult<String> {
        let repo = self.open(path)?;
        self.rd(&repo, &["--porcelain=v1", "-b"], "status")
    }

    pub fn log(
        &self,
        path: &str,
        rev: &str,
        max_count: i64,
        file_opt: Option<&str>,
    ) -> SecResult<String> {
        let repo = self.open(path)?;
        let mut tokens = sv(&["--format=%H %an %ad %s", "--date=short"]);
        tokens.push(format!("--max-count={max_count}"));
        tokens.push(check_rev(rev)?);

        if let Some(file) = file_opt {
            tokens.push("--".into());
            tokens.push(file.into());
        }
        self.run_read(&repo, "log", &tokens)
    }

    pub fn diff(
        &self,
        path: &str,
        rev_a: Option<&str>,
        rev_b: Option<&str>,
        cached: bool,
        stat_only: bool,
        file_opt: Option<&str>,
    ) -> SecResult<String> {
        let repo = self.open(path)?;
        let mut tokens = Vec::new();

        if cached {
            tokens.push("--cached".to_string());
        }

        if stat_only {
            tokens.push("--stat".to_string());
        }

        for rev in [rev_a, rev_b].into_iter().flatten() {
            tokens.push(check_rev(rev)?);
        }

        if let Some(file) = file_opt {
            tokens.push("--".into());
            tokens.push(file.into());
        }

        self.run_read(&repo, "diff", &tokens)
    }

    pub fn show_commit(&self, path: &str, rev: &str, stat_only: bool) -> SecResult<String> {
        let repo = self.open(path)?;
        let mut tokens = if stat_only { sv(&["--stat"]) } else { vec![] };

        tokens.push(check_rev(rev)?);
        self.run_read(&repo, "show", &tokens)
    }

    /// File content at a revision (`git show rev:file`); deny globs apply through PathGuard.
    pub fn show_file(&self, path: &str, rev: &str, file: &str) -> SecResult<String> {
        let repo = self.open(path)?;
        let rp = self.paths.resolve(file, "read", Some(&repo.top))?;

        if !is_under(&rp.real, &repo.top) {
            return Err(SecurityError::path(
                "outside_repo",
                "path outside the repository",
            ));
        }

        let rel = rel_in(&repo, &rp.real);
        let res = self.exec.run(
            &repo.top,
            &[
                "show".into(),
                "--no-textconv".into(),
                format!("{}:{rel}", check_rev(rev)?),
            ],
            false,
            true,
            false,
        )?;

        if res.returncode != 0 {
            return Err(denied("git_error", "file or revision not found"));
        }

        Ok(format!(
            "{}{}",
            self.red.redact(&res.stdout),
            truncate_note(&res)
        ))
    }

    pub fn ls_files(&self, path: &str, subpath: Option<&str>) -> SecResult<String> {
        let repo = self.open(path)?;
        self.run_read(
            &repo,
            "ls-files",
            &subpath.map(|text| sv(&["--", text])).unwrap_or_default(),
        )
    }

    pub fn branches(&self, path: &str) -> SecResult<String> {
        let repo = self.open(path)?;
        let res = self.exec.run_r(
            &repo.top,
            &[
                "for-each-ref",
                "--format=%(refname:short) %(objectname:short)",
                "refs/heads",
            ],
        )?;

        Ok(self.red.redact(&res.stdout).into_owned())
    }
}
