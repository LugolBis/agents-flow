//! In-process implementations of the allowlisted inspection commands (`pwd ls find cat head tail file stat`).
//! Why not exec the system tools: they do not exist on Windows, their flags/output differ across platforms (GNU/BSD/busybox) and every
//! fork costs. Builtins give identical, bounded output on Windows 11 ARM64 and Linux ARM64, need no external binary, honour the deny
//! globs for entries they DISCOVER (not only for arguments) and enforce a deadline and an output cap.
//! Arguments reaching this module were already validated by `argspec` and resolved by `PathGuard`.
use super::{
    context::Ctx,
    filesystem::{file_cmd, stat_cmd},
    find::find,
    ls::ls,
    system::Out,
    text::{cat, head_tail},
};

use std::path::Path;

/// `argv`: for find, the canonical `[-P, starts…, -maxdepth N, preds…]`; otherwise `[flags…, "--", paths…]`.
pub fn run_builtin(name: &str, argv: &[String], base: &Path, ctx: &Ctx) -> Out {
    let split = argv.iter().position(|a| a == "--");
    let (flags, paths) = match split {
        Some(i) => (&argv[..i], &argv[i + 1..]),
        None => (argv, &argv[argv.len()..]),
    };

    let mut out = match name {
        "pwd" => Out {
            text: format!("{}\n", base.display()),
            ..Default::default()
        },
        "ls" => ls(flags, paths, base, ctx),
        "find" => find(argv, ctx),
        "cat" => cat(flags, paths, ctx),
        "head" => head_tail(true, flags, paths, ctx),
        "tail" => head_tail(false, flags, paths, ctx),
        "file" => file_cmd(flags, paths),
        "stat" => stat_cmd(flags, paths),
        _ => Out {
            err: "command not supported\n".into(),
            exit: 2,
            ..Default::default()
        },
    };

    if out.text.len() > ctx.max_out {
        let mut c = ctx.max_out;
        while !out.text.is_char_boundary(c) {
            c -= 1;
        }

        out.text.truncate(c);
        out.truncated = true;
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::{
        config::models::permissions::{FsCfg, RootCfg},
        security::path_guard::guard::PathGuard,
    };
    use std::fs::{create_dir, write};

    fn setup() -> (tempfile::TempDir, PathGuard) {
        let d = tempfile::tempdir().unwrap();
        let cfg = FsCfg {
            roots: vec![RootCfg {
                name: "ws".into(),
                path: d.path().to_string_lossy().into(),
                write: true,
            }],
            deny_globs: vec![".env".into()],
            ..FsCfg::default()
        };
        let g = PathGuard::new(&cfg).unwrap();
        (d, g)
    }
    fn run(g: &PathGuard, base: &Path, name: &str, args: &[&str]) -> Out {
        let ctx = Ctx {
            guard: g,
            deadline: Instant::now() + std::time::Duration::from_secs(10),
            max_out: 100_000,
            max_depth: 6,
        };
        run_builtin(
            name,
            &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            base,
            &ctx,
        )
    }
    #[test]
    fn ls_find_cat_head_tail() {
        let (d, g) = setup();
        let b = g.default_root().path.clone();
        write(b.join("a.txt"), "1\n2\n3\n4\n5\n").unwrap();
        write(b.join(".env"), "SECRET").unwrap();
        create_dir(b.join("sub")).unwrap();
        write(b.join("sub/b.py"), "x").unwrap();
        let s = |p: &Path| p.to_string_lossy().to_string();
        let ls_out = run(&g, &b, "ls", &["-a", "--", &s(&b)]).text;
        assert!(
            ls_out.contains("a.txt") && ls_out.contains("sub") && !ls_out.contains(".env"),
            "{ls_out}"
        );
        let f = run(
            &g,
            &b,
            "find",
            &["-P", &s(&b), "-maxdepth", "3", "-name", "*.py"],
        )
        .text;
        assert_eq!(f.trim(), s(&b.join("sub/b.py")));
        let f = run(
            &g,
            &b,
            "find",
            &[
                "-P",
                &s(&b),
                "-maxdepth",
                "3",
                "-type",
                "f",
                "-not",
                "-name",
                "*.py",
            ],
        )
        .text;
        assert!(f.contains("a.txt") && !f.contains("b.py") && !f.contains(".env"));
        let f = run(
            &g,
            &b,
            "find",
            &[
                "-P",
                &s(&b),
                "-maxdepth",
                "3",
                "-name",
                "*.py",
                "-o",
                "-name",
                "a.txt",
            ],
        )
        .text;
        assert_eq!(f.lines().count(), 2);
        let a = s(&b.join("a.txt"));
        assert_eq!(
            run(&g, &b, "cat", &["-n", "--", &a])
                .text
                .lines()
                .nth(1)
                .unwrap(),
            "     2\t2"
        );
        assert_eq!(run(&g, &b, "head", &["-n", "2", "--", &a]).text, "1\n2\n");
        assert_eq!(run(&g, &b, "head", &["-n", "-3", "--", &a]).text, "1\n2\n");
        assert_eq!(run(&g, &b, "tail", &["-n", "2", "--", &a]).text, "4\n5\n");
        assert_eq!(run(&g, &b, "tail", &["-n", "+4", "--", &a]).text, "4\n5\n");
        assert_eq!(
            run(&g, &b, "head", &["-c", "3", "--", &a]).text,
            "1\n2\n".trim_end().to_string() + "\n"
        );
        assert!(run(&g, &b, "file", &["--", &a]).text.contains("ASCII text"));
        assert!(run(&g, &b, "stat", &["--terse", "--", &a])
            .text
            .contains(" 10 "));
        drop(d);
    }
    #[test]
    fn find_rejects_bad_expression() {
        let (_d, g) = setup();
        let b = g.default_root().path.clone();
        assert_eq!(
            run(
                &g,
                &b,
                "find",
                &["-P", &b.to_string_lossy(), "-maxdepth", "2", "-o"]
            )
            .exit,
            1
        );
    }
}
