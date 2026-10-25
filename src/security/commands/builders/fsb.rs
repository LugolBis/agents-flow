//! Builders for filesystem inspection commands :
//! `pwd`, `ls`, `cat`, `head`, `tail`, `file`, `stat`.
use super::BuildCtx;

use crate::error::SecResult;
use crate::security::argspec::{int_between, parse_args, Parsed, Positional, Spec};

use std::path::Path;

/// Helper : concat `flags + "--" + resolved path`.
fn with_paths(
    ctx: &BuildCtx,
    parsed: Parsed,
    base: &Path,
    regular: bool,
) -> SecResult<Vec<String>> {
    let mut res = parsed.flags;
    res.push("--".into());
    for path in &parsed.paths {
        res.push(ctx.path(path, base, regular)?);
    }
    Ok(res)
}

pub(super) fn pwd(tokens: &[String]) -> SecResult<Vec<String>> {
    Ok(parse_args(
        &Spec::new(Positional::NoneAllowed).flags(&["-P"]),
        tokens,
        "pwd",
    )?
    .flags)
}

pub(super) fn ls(ctx: &BuildCtx, tokens: &[String], base: &Path) -> SecResult<Vec<String>> {
    let spec = Spec::new(Positional::Paths)
        .flags(&[
            "-l",
            "-a",
            "-h",
            "-1",
            "-R",
            "-t",
            "-S",
            "-r",
            "-d",
            "--color=never",
        ])
        .cluster("lahR1tSrd")
        .max(ctx.cfg.max_path_args);
    with_paths(ctx, parse_args(&spec, tokens, "ls")?, base, false)
}

pub(super) fn cat(ctx: &BuildCtx, tokens: &[String], base: &Path) -> SecResult<Vec<String>> {
    let spec = Spec::new(Positional::Paths)
        .flags(&["-n"])
        .min(1)
        .max(ctx.cfg.max_path_args);
    with_paths(ctx, parse_args(&spec, tokens, "cat")?, base, true)
}

pub(super) fn head_tail(
    ctx: &BuildCtx,
    tokens: &[String],
    base: &Path,
    name: &str,
) -> SecResult<Vec<String>> {
    let lines = || int_between(1, ctx.cfg.max_line_count as i64, true);
    let bytes = || int_between(1, ctx.cfg.max_output_bytes as i64, true);
    let spec = Spec::new(Positional::Paths)
        .flags(&["-q", "-v", "--quiet", "--verbose"])
        .valued("-n", lines())
        .valued("--lines", lines())
        .valued("-c", bytes())
        .valued("--bytes", bytes())
        .min(1)
        .max(ctx.cfg.max_path_args);
    with_paths(ctx, parse_args(&spec, tokens, name)?, base, true)
}

pub(super) fn file(ctx: &BuildCtx, tokens: &[String], base: &Path) -> SecResult<Vec<String>> {
    let spec = Spec::new(Positional::Paths)
        .flags(&[
            "-b",
            "--brief",
            "-i",
            "--mime",
            "--mime-type",
            "--mime-encoding",
        ])
        .min(1)
        .max(ctx.cfg.max_path_args);
    with_paths(ctx, parse_args(&spec, tokens, "file")?, base, false)
}

pub(super) fn stat(ctx: &BuildCtx, tokens: &[String], base: &Path) -> SecResult<Vec<String>> {
    let spec = Spec::new(Positional::Paths)
        .flags(&["--terse"])
        .min(1)
        .max(ctx.cfg.max_path_args);
    with_paths(ctx, parse_args(&spec, tokens, "stat")?, base, false)
}
