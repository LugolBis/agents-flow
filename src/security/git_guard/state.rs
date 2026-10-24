use crate::error::SecurityError;
use crate::security::git_guard::{
    core::{Repo, Verdict},
    executor::GitExec,
    helpers::{sv, BUSY_MARKERS, ODD_NAME_RE},
};
use crate::security::path_guard::resolved::ResolvedPath;
use crate::util::rel_posix;
use std::{fs::symlink_metadata, path::Path, sync::Arc};

/// Checks the 5 conditions before modifying an EXISTING file: (1) recognised local repo; (2) tracked file; (3) current version committed
/// locally; (4) no uncommitted change; (5) explicitly allowed perimeter. Done by code, never on the agent's say-so.
pub struct GitFileState {
    exec: Arc<GitExec>,
}

impl GitFileState {
    pub fn new(exec: Arc<GitExec>) -> Self {
        GitFileState { exec }
    }

    fn no(code: &str, reason: &str, repo: Option<&Repo>, rel: Option<&str>) -> Verdict {
        Verdict {
            allowed: false,
            code: code.into(),
            reason: reason.into(),
            repo: repo.cloned(),
            rel: rel.map(String::from),
        }
    }

    pub fn check_modifiable(&self, rp: &ResolvedPath) -> Verdict {
        if !rp.root.write {
            return Self::no("root_read_only", "root is in read-only mode", None, None);
        }

        match symlink_metadata(&rp.lexical) {
            Err(_) => return Self::no("not_found", "file not found", None, None),
            Ok(meta_data) if !meta_data.file_type().is_file() => {
                return Self::no(
                    "not_regular_file",
                    "only regular files could be modified",
                    None,
                    None,
                )
            }
            _ => {}
        }

        let repo = match self
            .exec
            .open_repo(rp.real.parent().unwrap_or(&rp.real), &rp.root)
        {
            Ok(r) => r,
            Err(err) => return Self::no(&err.code, &err.reason, None, None),
        };

        if !repo.root.write {
            return Self::no(
                "root_read_only",
                "root of the repository is in read-only mode",
                Some(&repo),
                None,
            );
        }

        let rel = rel_posix(&rp.real, &repo.top).join("/");
        let rel_opt = Some(rel.as_str());

        if ODD_NAME_RE.is_match(&rel) || rel.starts_with('-') {
            return Self::no(
                "unusual_filename",
                "file name contains motif characters",
                Some(&repo),
                rel_opt,
            );
        }

        let git = |args: &[&str], literal: bool| {
            self.exec.run(&repo.top, &sv(args), false, literal, false)
        };

        let fail = |err: SecurityError| Self::no(&err.code, &err.reason, Some(&repo), rel_opt);
        let git_dir = match git(&["rev-parse", "--absolute-git-dir"], true) {
            Ok(run_res) => run_res.stdout.trim().to_string(),
            Err(err) => return fail(err),
        };

        if !git_dir.is_empty()
            && BUSY_MARKERS
                .iter()
                .any(|marker| Path::new(&git_dir).join(marker).exists())
        {
            return Self::no(
                "repo_busy",
                "Git operation is runing (merge/rebase/...)",
                Some(&repo),
                rel_opt,
            );
        }

        let ls = match git(
            &["ls-files", "-v", "-z", "--error-unmatch", "--", &rel],
            true,
        ) {
            Ok(run_res) => run_res,
            Err(err) => return fail(err),
        };

        if ls.returncode != 0 || ls.stdout.is_empty() {
            return Self::no(
                "not_tracked",
                "the file isn't tracked by Git",
                Some(&repo),
                rel_opt,
            );
        }

        let tag = &ls.stdout[..1];
        if tag != "H" {
            return Self::no(
                "index_flags",
                &format!(
                    "non standard index state ('{tag}') : assume-unchanged/skip-worktree/conflit"
                ),
                Some(&repo),
                rel_opt,
            );
        }

        // check-ignore does not accept GIT_LITERAL_PATHSPECS; the name has no pattern character (checked above)
        match git(&["check-ignore", "--no-index", "-q", "--", &rel], false) {
            Ok(run_res) if run_res.returncode == 1 => {}
            Ok(_) => {
                return Self::no(
                    "ignored_file",
                    "file ignored by .gitignore (or verification impossible)",
                    Some(&repo),
                    rel_opt,
                )
            }
            Err(e) => return fail(e),
        }

        let head = match git(
            &["rev-parse", "--verify", "-q", &format!("HEAD:{rel}")],
            true,
        ) {
            Ok(run_res) => run_res,
            Err(err) => return fail(err),
        };

        if head.returncode != 0 {
            return Self::no(
                "not_committed",
                "the current version wasn't committed locally",
                Some(&repo),
                rel_opt,
            );
        }

        let staged_out = match git(&["ls-files", "-s", "--", &rel], true) {
            Ok(run_res) => run_res.stdout,
            Err(err) => return fail(err),
        };

        let staged: Vec<&str> = staged_out.split_whitespace().collect();
        if staged.len() < 3 || staged[1] != head.stdout.trim() || staged[2] != "0" {
            return Self::no(
                "uncommitted_changes",
                "indexed changes uncommitted",
                Some(&repo),
                rel_opt,
            );
        }

        match git(
            &[
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=no",
                "--",
                &rel,
            ],
            true,
        ) {
            Ok(run_res)
                if run_res.returncode == 0 && run_res.stdout.trim_matches('\0').is_empty() => {}
            Ok(_) => {
                return Self::no(
                    "uncommitted_changes",
                    "uncomitted local changes",
                    Some(&repo),
                    rel_opt,
                )
            }
            Err(err) => return fail(err),
        }

        Verdict {
            allowed: true,
            code: "ok".into(),
            reason: "all conditions are satisfied".into(),
            repo: Some(repo.clone()),
            rel: Some(rel),
        }
    }
}
