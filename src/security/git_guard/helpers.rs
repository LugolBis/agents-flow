use crate::error::SecurityError;
use regex::Regex;
use std::sync::LazyLock;

pub static REV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_./~^@-]{0,199}$").unwrap());

pub static BRANCH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$").unwrap());

pub static ODD_NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[*?\[\\:]").unwrap());

pub static UNSAFE_KEYS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"^filter\..+\.(clean|smudge|process)$",
        r"^diff\..+\.(textconv|command)$",
        r"^diff\.external$",
        r"^merge\..+\.(driver|recursive)$",
        r"^include(if\..+)?\.path$",
        r"^core\.(worktree|fsmonitor|hookspath|sshcommand|gitproxy)$",
    ]
    .iter()
    .map(|pattern| Regex::new(pattern).unwrap())
    .collect()
});

pub const BUSY_MARKERS: &[&str] = &[
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "rebase-merge",
    "rebase-apply",
    "BISECT_LOG",
];

pub fn sv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

pub fn denied(code: &str, reason: impl Into<String>) -> SecurityError {
    SecurityError::git(code, reason)
}
