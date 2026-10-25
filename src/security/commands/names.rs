use crate::config::models::permissions::ShellCfg;
use crate::error::{Error, Result};

const FORBIDDEN_NAMES: &[&str] = &[
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "mv",
    "cp",
    "ln",
    "dd",
    "mkfs",
    "mkfs.ext4",
    "fdisk",
    "parted",
    "wipefs",
    "truncate",
    "chmod",
    "chown",
    "chgrp",
    "setfacl",
    "sudo",
    "su",
    "doas",
    "kill",
    "killall",
    "pkill",
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "ftp",
    "telnet",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "env",
    "xargs",
    "eval",
    "exec",
    "source",
    "alias",
    "nohup",
    "tee",
    "install",
    "touch",
    "mkdir",
    "mount",
    "umount",
    "crontab",
    "at",
    "sed",
    "awk",
    "tar",
    "zip",
    "unzip",
    "gzip",
    "gunzip",
    "make",
    "cmake",
    "gcc",
    "cc",
    "docker",
    "podman",
    "systemctl",
    "service",
    "powershell",
    "pwsh",
    "cmd",
    "del",
    "erase",
    "rd",
    "move",
    "copy",
    "reg",
    "wmic",
];

const KNOWN: &[&str] = &[
    "pwd", "ls", "find", "cat", "head", "tail", "file", "stat", "git",
];

pub(super) fn is_known(name: &str) -> bool {
    KNOWN.contains(&name)
}

pub(super) fn is_forbidden(name: &str) -> bool {
    FORBIDDEN_NAMES.contains(&name.to_lowercase().strip_suffix(".exe").unwrap_or(name))
}

/// Validates `cfg.enabled_commands` against `KNOWN`, then calculates the effective
/// list of permitted commands: sorted, deduplicated, with `git` included **only** if
/// the user has requested it *and* the `GitReader` is available.
///
/// Returns a configuration error if a requested command lacks a corresponding
/// validator (arbitrary commands cannot be executed).
pub(super) fn resolve_enabled(cfg: &ShellCfg, git_available: bool) -> Result<Vec<String>> {
    let unknown: Vec<&String> = cfg
        .enabled_commands
        .iter()
        .filter(|cmd| !is_known(cmd.as_str()))
        .collect();

    if !unknown.is_empty() {
        return Err(Error::config(format!(
            "command without coded validator (refused) : {unknown:?}"
        )));
    }

    let git_requested = cfg.enabled_commands.iter().any(|cmd| cmd == "git");
    let git_ok = git_requested && git_available;

    let mut enabled: Vec<String> = cfg
        .enabled_commands
        .iter()
        .filter(|cmd| cmd.as_str() != "git")
        .cloned()
        .collect();

    if git_ok {
        enabled.push("git".into());
    }

    enabled.sort();
    enabled.dedup();
    Ok(enabled)
}
