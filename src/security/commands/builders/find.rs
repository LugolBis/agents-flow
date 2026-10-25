//! Builder pour `find` : strict validation of predicates and
//! depths, without ever passing `-exec`, `-delete`, `-fprint*`, etc.
use super::BuildCtx;
use crate::error::{SecResult, SecurityError};
use crate::security::argspec::{int_between, regex_value, Validator};
use crate::util::clip;

use std::path::Path;

pub(super) fn build(ctx: &BuildCtx, tokens: &[String], base: &Path) -> SecResult<Vec<String>> {
    let shell_cfg = ctx.cfg;

    // 1) Starting path
    let (mut index, mut starts) = (0usize, Vec::new());
    while index < tokens.len() && !tokens[index].starts_with('-') && tokens[index] != "!" {
        starts.push(ctx.path(&tokens[index], base, false)?);
        index += 1;
        if starts.len() > shell_cfg.max_path_args {
            return Err(SecurityError::command(
                "too_many_arguments",
                "too many starting paths",
            ));
        }
    }

    if starts.is_empty() {
        starts.push(base.to_string_lossy().to_string());
    }

    // 2) Predicates authorized
    let simple = ["-print", "-empty", "-not", "!", "-o", "-or", "-a", "-and"];
    let pattern = regex_value(r"[^\x00]{1,200}", "motif");
    let dur = || regex_value(r"[+-]?[0-9]{1,6}", "durée");
    let valued: Vec<(&str, Validator)> = vec![
        ("-name", regex_value(r"[^\x00]{1,200}", "motif")),
        ("-iname", regex_value(r"[^\x00]{1,200}", "motif")),
        ("-path", regex_value(r"[^\x00]{1,200}", "motif")),
        ("-ipath", pattern),
        ("-type", regex_value(r"[fdl]", "type")),
        ("-size", regex_value(r"[+-]?[0-9]{1,9}[cwbkMG]?", "taille")),
        ("-mtime", dur()),
        ("-mmin", dur()),
        ("-atime", dur()),
        ("-ctime", dur()),
    ];

    let (mut maxd, mut mind, mut preds) = (
        shell_cfg.find_max_depth as i64,
        None::<i64>,
        Vec::<String>::new(),
    );

    while index < tokens.len() {
        let token = tokens[index].as_str();

        if simple.contains(&token) {
            preds.push(token.to_string());
        } else if token == "-maxdepth" || token == "-mindepth" {
            index += 1;
            let token_arg = tokens.get(index).ok_or(SecurityError::command(
                "missing_value",
                format!("find: missing value for {token}"),
            ))?;

            let n: i64 = int_between(0, shell_cfg.find_max_depth as i64, false)(token_arg)?
                .parse()
                .unwrap_or(0);

            if token == "-maxdepth" {
                maxd = maxd.min(n);
            } else {
                mind = Some(n);
            }
        } else if let Some((_, validator)) = valued.iter().find(|(n, _)| *n == token) {
            index += 1;

            let val = tokens.get(index).ok_or(SecurityError::command(
                "missing_value",
                format!("find: missing value for {token}"),
            ))?;

            preds.push(token.to_string());
            preds.push(validator(val)?);
        } else {
            // Refuse -exec, -execdir, -ok, -okdir, -delete, -fprint*, -fls, -L, -H, -D, -regex...
            return Err(SecurityError::command(
                "flag_not_allowed",
                format!("find: unauthorized expression {}", clip(token, 20)),
            ));
        }
        index += 1;
    }

    // 3) Canonical assembly.
    let mut argv = vec!["-P".to_string()];
    argv.extend(starts);
    argv.extend(["-maxdepth".to_string(), maxd.to_string()]);

    if let Some(m) = mind {
        argv.extend(["-mindepth".to_string(), m.to_string()]);
    }
    argv.extend(preds);
    Ok(argv)
}
