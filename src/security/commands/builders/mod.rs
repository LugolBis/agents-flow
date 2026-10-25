//! `argv` builders for allowlisted commands.
//!
//! Each builder produces a canonical `Vec<String>` (validated `argv`, resolved paths),
//! **without execution**. The [`build`] dispatcher selects the appropriate builder based on the command name.

pub(super) mod find;
pub(super) mod fsb;

use crate::config::models::permissions::ShellCfg;
use crate::error::{SecResult, SecurityError};
use crate::security::path_guard::guard::PathGuard;

use std::{fs, path::Path};

/// Context shared by all builders (config + path management).
pub(super) struct BuildCtx<'a> {
    pub cfg: &'a ShellCfg,
    pub paths: &'a PathGuard,
}

impl<'a> BuildCtx<'a> {
    pub fn new(cfg: &'a ShellCfg, paths: &'a PathGuard) -> Self {
        Self { cfg, paths }
    }

    /// Resolves `token` relative to `base`, for reading, and (optionally) requires a regular file.
    pub fn path(&self, token: &str, base: &Path, regular: bool) -> SecResult<String> {
        let rp = self.paths.resolve(token, "read", Some(base))?;
        if regular {
            let mtd = fs::metadata(&rp.real)
                .map_err(|_| SecurityError::command("not_found", "file not found"))?;
            if !mtd.is_file() {
                return Err(SecurityError::command(
                    "not_regular_file",
                    "only regular files are legible",
                ));
            }
        }
        Ok(rp.real.to_string_lossy().to_string())
    }
}

/// Dispatch : choose the correct builder based on the command name, already allowlisted
pub(super) fn build(
    ctx: &BuildCtx,
    name: &str,
    tokens: &[String],
    base: &Path,
) -> SecResult<Vec<String>> {
    match name {
        "pwd" => fsb::pwd(tokens),
        "ls" => fsb::ls(ctx, tokens, base),
        "cat" => fsb::cat(ctx, tokens, base),
        "head" | "tail" => fsb::head_tail(ctx, tokens, base, name),
        "file" => fsb::file(ctx, tokens, base),
        "stat" => fsb::stat(ctx, tokens, base),
        "find" => find::build(ctx, tokens, base),
        _ => Err(SecurityError::command(
            "command_not_allowlisted",
            "command not supported",
        )),
    }
}
