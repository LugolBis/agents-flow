//! Git guards. Three DISTINCT interfaces share a hardened executor (`GitExec`):
//!  * `GitReader`      : read only (status, log, diff, show, ls-files, branches…);
//!  * `GitFileState`   : verifies the 5 conditions before an existing file may be modified;
//!  * `GitLocalWriter` : exactly 3 writes — create a local branch, switch to a local branch, create a local commit.
//! No code exists for push/fetch/pull/merge/rebase/reset --hard/branch -D/tag/remote add. Defence in depth: `-c protocol.allow=never`.
//! A repository's own config is NOT trusted: hooks disabled, no fsmonitor/external diff/textconv, minimal Git environment, and repositories
//! whose local config defines clean/smudge filters, diff/merge drivers, includes or `core.worktree` are refused.
use crate::error::{SecResult, SecurityError};
use crate::security::argspec::{int_between, parse_args, regex_value, Positional, Spec};
use crate::security::git_guard::helpers::REV_RE;
use crate::security::path_guard::root::Root;
use crate::util::clip;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::LazyLock;

const COMMON_DIFF: &[&str] = &[
    "--stat",
    "--name-only",
    "--name-status",
    "--no-color",
    "--shortstat",
    "--numstat",
    "--summary",
];

const DIFFISH: &[&str] = &["log", "diff", "show"];

#[derive(Debug, Clone)]
pub struct Repo {
    pub top: PathBuf,
    pub root: Root,
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub allowed: bool,
    pub code: String,
    pub reason: String,
    pub repo: Option<Repo>,
    pub rel: Option<String>,
}

pub static GIT_READ_SPECS: LazyLock<HashMap<&'static str, (Spec, Vec<&'static str>)>> =
    LazyLock::new(|| {
        let fmt = || regex_value(r"[%A-Za-z0-9 ,.:@<>()\[\]/_-]{1,120}", "format");
        let pretty = || regex_value(r"oneline|short|medium|fuller", "pretty");
        let mut map = HashMap::new();

        map.insert(
            "status",
            (
                Spec::new(Positional::Paths).flags(&[
                    "-s",
                    "--short",
                    "-b",
                    "--branch",
                    "--porcelain",
                    "--porcelain=v1",
                    "-uno",
                    "-unormal",
                    "--untracked-files=no",
                    "--untracked-files=normal",
                ]),
                vec![],
            ),
        );

        map.insert(
            "log",
            (
                Spec::new(Positional::RevsThenPaths)
                    .flags(COMMON_DIFF)
                    .flags(&[
                        "--oneline",
                        "--graph",
                        "--decorate",
                        "--no-merges",
                        "--merges",
                        "--first-parent",
                        "--abbrev-commit",
                        "--date=iso",
                        "--date=iso-strict",
                        "--date=short",
                        "--date=relative",
                        "-p",
                    ])
                    .valued("-n", int_between(1, 500, false))
                    .valued("--max-count", int_between(1, 500, false))
                    .valued("--format", fmt())
                    .valued("--pretty", pretty())
                    .numeric(int_between(1, 500, false))
                    .max(20),
                vec!["--no-ext-diff", "--no-textconv", "--no-color"],
            ),
        );

        map.insert(
            "diff",
            (
                Spec::new(Positional::RevsThenPaths)
                    .flags(COMMON_DIFF)
                    .flags(&["--cached", "--staged", "-w", "--ignore-all-space"])
                    .valued("-U", int_between(0, 100, false))
                    .valued("--unified", int_between(0, 100, false))
                    .max(20),
                vec!["--no-ext-diff", "--no-textconv", "--no-color"],
            ),
        );

        map.insert(
            "show",
            (
                Spec::new(Positional::RevsThenPaths)
                    .flags(COMMON_DIFF)
                    .flags(&["--oneline", "-s", "--no-patch", "--abbrev-commit"])
                    .valued("--format", fmt())
                    .valued("--pretty", pretty())
                    .max(5),
                vec!["--no-ext-diff", "--no-textconv", "--no-color"],
            ),
        );

        map.insert(
            "ls-files",
            (
                Spec::new(Positional::Paths)
                    .flags(&[
                        "-c",
                        "--cached",
                        "-m",
                        "--modified",
                        "-o",
                        "--others",
                        "--exclude-standard",
                        "-s",
                        "--stage",
                    ])
                    .max(20),
                vec![],
            ),
        );

        map.insert(
            "branch",
            (
                Spec::new(Positional::NoneAllowed).flags(&[
                    "-a",
                    "--all",
                    "-r",
                    "--remotes",
                    "-v",
                    "-vv",
                    "--list",
                    "--show-current",
                    "--no-color",
                ]),
                vec![],
            ),
        );

        map
    });

fn exclude_pathspecs(deny: &[String]) -> Vec<String> {
    let mut out = Vec::new();

    for pat in deny {
        if pat.contains('/') {
            out.push(format!(":(exclude,glob){pat}"));
        } else {
            out.push(format!(":(exclude,glob)**/{pat}"));
            out.push(format!(":(exclude,glob){pat}"));
        }
    }
    out
}

/// Validates `git <sub> <tokens>` and returns the arguments (without `git`).
pub fn build_git_read_argv(
    sub: &str,
    tokens: &[String],
    check_path: &dyn Fn(&str) -> SecResult<String>,
    deny_globs: &[String],
) -> SecResult<Vec<String>> {
    let (spec, extra) = GIT_READ_SPECS.get(sub).ok_or_else(|| {
        SecurityError::command(
            "git_subcommand_not_allowed",
            format!("unauthorized git sub-command : {}", clip(sub, 20)),
        )
    })?;

    let parsed = parse_args(spec, tokens, &format!("git {sub}"))?;
    for rev in &parsed.revs {
        if !REV_RE.is_match(rev) || rev.starts_with('-') {
            return Err(SecurityError::command(
                "bad_revision",
                format!("invalid revision : '{}'", crate::util::clip(rev, 30)),
            ));
        }
    }

    let paths: Vec<String> = parsed
        .paths
        .iter()
        .map(|p| check_path(p))
        .collect::<SecResult<_>>()?;

    let mut argv = vec![sub.to_string()];
    argv.extend(parsed.flags.iter().cloned());
    argv.extend(extra.iter().map(|s| s.to_string()));
    argv.extend(parsed.revs.iter().cloned());

    if !paths.is_empty() || DIFFISH.contains(&sub) {
        argv.push("--".into());
        argv.extend(paths);
        if DIFFISH.contains(&sub) {
            argv.extend(exclude_pathspecs(deny_globs));
        }
    }
    Ok(argv)
}
