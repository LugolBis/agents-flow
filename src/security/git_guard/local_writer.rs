use crate::config::models::permissions::GitCfg;
use crate::error::{SecResult, SecurityError};
use crate::security::git_guard::core::Repo;
use crate::security::git_guard::executor::{check_rev, GitExec};
use crate::security::git_guard::helpers::{denied, sv, BRANCH_RE, BUSY_MARKERS};
use crate::security::path_guard::guard::PathGuard;
use crate::security::runner::RunResult;
use crate::security::secrets::{scan_for_secrets, SecretRedactor};
use crate::util::{clip, is_under, rel_posix};
use std::collections::BTreeSet;
use std::fs::symlink_metadata;
use std::path::Path;
use std::sync::Arc;

/// The only allowed Git writes: local branch, local switch, local commit.
pub struct GitLocalWriter {
    exec: Arc<GitExec>,
    paths: Arc<PathGuard>,
    cfg: GitCfg,
    red: Arc<SecretRedactor>,
}

impl GitLocalWriter {
    pub fn new(
        exec: Arc<GitExec>,
        paths: Arc<PathGuard>,
        cfg: &GitCfg,
        red: Arc<SecretRedactor>,
    ) -> Self {
        GitLocalWriter {
            exec,
            paths,
            cfg: cfg.clone(),
            red,
        }
    }

    fn repo(&self, path: &str) -> SecResult<Repo> {
        let rp = self.paths.resolve(path, "write", None)?;
        let repo = self.exec.open_repo(&rp.real, &rp.root)?;
        if !repo.root.write {
            return Err(denied(
                "root_read_only",
                "repository root is in read-only mode",
            ));
        }
        Ok(repo)
    }

    pub fn check_branch_name(name: &str) -> SecResult<()> {
        let bad = !BRANCH_RE.is_match(name)
            || name.contains("..")
            || name.contains("//")
            || name.contains("@{")
            || [".lock", "/", "."].iter().any(|s| name.ends_with(s))
            || name == "HEAD";

        if bad {
            Err(denied("bad_branch_name", "invalid branch name"))
        } else {
            Ok(())
        }
    }

    fn git(&self, repo: &Repo, args: &[&str], identity: bool) -> SecResult<RunResult> {
        self.exec.run(&repo.top, &sv(args), true, true, identity)
    }

    fn git_v(&self, repo: &Repo, args: &[String], identity: bool) -> SecResult<RunResult> {
        self.exec.run(&repo.top, args, true, true, identity)
    }

    fn err_of(&self, run_res: &RunResult) -> SecurityError {
        denied(
            "git_error",
            self.red
                .redact(&clip(run_res.stderr.trim(), 300))
                .into_owned(),
        )
    }

    pub fn create_branch(&self, path: &str, name: &str, start: &str) -> SecResult<String> {
        let repo = self.repo(path)?;
        Self::check_branch_name(name)?;
        check_rev(start)?;

        if self
            .git(&repo, &["check-ref-format", "--branch", name], false)?
            .returncode
            != 0
        {
            return Err(denied("bad_branch_name", "branch name refused by git"));
        }

        let res = self.git(&repo, &["branch", "--no-track", name, start], false)?;
        if res.returncode != 0 {
            return Err(self.err_of(&res));
        }

        Ok(format!(
            "local branch '{name}' created based on the branch {start}"
        ))
    }

    pub fn switch_branch(&self, path: &str, name: &str) -> SecResult<String> {
        let repo = self.repo(path)?;
        Self::check_branch_name(name)?;

        if self
            .git(
                &repo,
                &[
                    "show-ref",
                    "--verify",
                    "--quiet",
                    &format!("refs/heads/{name}"),
                ],
                false,
            )?
            .returncode
            != 0
        {
            return Err(denied(
                "branch_not_found",
                "the local branch doesn't exist (no implicit creation or remote tracking)",
            ));
        }

        let dirty = self.exec.run_r(
            &repo.top,
            &["status", "--porcelain=v1", "--untracked-files=no"],
        )?;

        if !dirty.stdout.trim().is_empty() {
            return Err(denied(
                "dirty_worktree",
                "uncomitted changes : switch refused",
            ));
        }

        let res = self.git(&repo, &["switch", "--no-guess", "-q", name], false)?;
        if res.returncode != 0 {
            return Err(self.err_of(&res));
        }

        Ok(format!("switch on the local branch '{name}'"))
    }

    pub fn commit(&self, path: &str, message: &str, files: &[String]) -> SecResult<String> {
        let repo = self.repo(path)?;
        let msg = message.trim();

        if msg.is_empty() || msg.chars().count() > 2000 || msg.contains('\0') {
            return Err(denied(
                "bad_commit_message",
                "empty, too long or invalid commit message",
            ));
        }

        if !scan_for_secrets(msg).is_empty() {
            return Err(denied(
                "secret_in_message",
                "the commit message seems to contains a secret",
            ));
        }

        if files.is_empty() || files.len() > self.cfg.max_commit_files {
            return Err(denied(
                "bad_file_list",
                format!(
                    "1 to {} files required (never 'all')",
                    self.cfg.max_commit_files
                ),
            ));
        }

        let branch = self
            .git(&repo, &["symbolic-ref", "--short", "-q", "HEAD"], false)?
            .stdout
            .trim()
            .to_string();

        if branch.is_empty() {
            return Err(denied("detached_head", "commit refused on detached HEAD"));
        }

        if self.cfg.protected_branches.contains(&branch) {
            return Err(denied(
                "protected_branch",
                format!("commit forbidden on the protected branch '{branch}'"),
            ));
        }

        let git_dir = self
            .git(&repo, &["rev-parse", "--absolute-git-dir"], false)?
            .stdout
            .trim()
            .to_string();

        if BUSY_MARKERS
            .iter()
            .any(|m| Path::new(&git_dir).join(m).exists())
        {
            return Err(denied("repo_busy", "Git operation is running"));
        }

        if self
            .git(&repo, &["diff", "--cached", "--quiet"], false)?
            .returncode
            != 0
        {
            return Err(denied(
                "index_not_clean",
                "the index already contains changes : commit refused",
            ));
        }

        let mut rels: Vec<String> = Vec::new();
        for file in files {
            let rp = self.paths.resolve(file, "write", Some(&repo.top))?;

            if !is_under(&rp.real, &repo.top) {
                return Err(SecurityError::path(
                    "outside_repo",
                    "file outside the repository",
                ));
            }

            match symlink_metadata(&rp.lexical) {
                Err(_) => {
                    return Err(denied(
                        "not_found",
                        format!("file not found : {}", clip(file, 80)),
                    ))
                }
                Ok(meta_data) if !meta_data.file_type().is_file() => {
                    return Err(denied(
                        "not_regular_file",
                        "only regular files could be committed",
                    ))
                }
                _ => {}
            }
            rels.push(rel_posix(&rp.real, &repo.top).join("/"));
        }

        let mut add = sv(&["add", "--"]);
        add.extend(rels.iter().cloned());

        let run_res = self.git_v(&repo, &add, false)?;
        if run_res.returncode != 0 {
            return Err(self.err_of(&run_res));
        }

        let inner = || -> SecResult<()> {
            let staged: BTreeSet<String> = self
                .git(&repo, &["diff", "--cached", "--name-only", "-z"], false)?
                .stdout
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();

            if staged.is_empty() {
                return Err(denied(
                    "nothing_to_commit",
                    "there isn't any changes to commit for these files",
                ));
            }

            if staged != rels.iter().cloned().collect::<BTreeSet<_>>() {
                return Err(denied(
                    "unexpected_staged_files",
                    "the index differs from the requested list",
                ));
            }

            let patch = self
                .git(
                    &repo,
                    &["diff", "--cached", "--no-ext-diff", "--no-textconv", "-U0"],
                    false,
                )?
                .stdout;

            let added: Vec<&str> = patch
                .lines()
                .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
                .map(|line| &line[1..])
                .collect();

            if !scan_for_secrets(&added.join("\n")).is_empty() {
                return Err(denied(
                    "secret_in_diff",
                    "the diff indexed contains a secret : commit refused",
                ));
            }

            let res = self.git_v(
                &repo,
                &[
                    "commit".to_string(),
                    "--no-verify".into(),
                    "--no-gpg-sign".into(),
                    "-q".into(),
                    "-m".into(),
                    msg.to_string(),
                ],
                true,
            )?;

            if res.returncode != 0 {
                let text = if res.stderr.is_empty() {
                    &res.stdout
                } else {
                    &res.stderr
                };
                return Err(denied(
                    "git_error",
                    self.red.redact(&clip(text.trim(), 300)).into_owned(),
                ));
            }
            Ok(())
        };

        if let Err(err) = inner() {
            let mut reset = sv(&["reset", "-q", "--"]);
            reset.extend(rels.iter().cloned());
            let _ = self.git_v(&repo, &reset, false); // unstage: the working tree is untouched
            return Err(err);
        }

        let sha = self
            .git(&repo, &["rev-parse", "--short", "HEAD"], false)?
            .stdout
            .trim()
            .to_string();

        Ok(format!(
            "Successfully create the local commit {sha} on the branch '{branch}' ({} file(s))",
            rels.len()
        ))
    }
}
