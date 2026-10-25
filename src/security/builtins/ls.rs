use super::{
    context::Ctx,
    file_mtd::{ids, mode_string},
    system::{hidden, mtime, nope, Out},
};
use crate::util::fmt_ts;

use std::{
    cmp,
    fs::{read_dir, read_link, symlink_metadata, Metadata},
    path::{Path, PathBuf},
    time::Instant,
};

struct LsOpts {
    long: bool,
    all: bool,
    human: bool,
    recursive: bool,
    by_time: bool,
    by_size: bool,
    reverse: bool,
    dir_only: bool,
}

/// Convert numerical data as a human friendly string using units (_K, M, G, T_)
pub fn human(data: u64) -> String {
    if data < 1024 {
        return data.to_string();
    }

    let (mut value, mut len) = (data as f64, 0);
    while value >= 1024.0 && len < 4 {
        value /= 1024.0;
        len += 1;
    }

    let unit = ["", "K", "M", "G", "T"][len];
    if value < 10.0 {
        format!("{:.1}{unit}", (value * 10.0).ceil() / 10.0)
    } else {
        format!("{}{unit}", value.ceil() as u64)
    }
}

fn ls_line(options: &LsOpts, name: &str, path: &Path, meta_data: &Metadata) -> String {
    if !options.long {
        return name.to_string();
    }

    let (uid, gid, nlink) = ids(meta_data);
    let size = if options.human {
        human(meta_data.len())
    } else {
        meta_data.len().to_string()
    };

    let target = if meta_data.file_type().is_symlink() {
        read_link(path)
            .map(|p| format!(" -> {}", p.display()))
            .unwrap_or_default()
    } else {
        String::new()
    };

    format!(
        "{} {nlink:>2} {uid} {gid} {size:>8} {} {name}{target}",
        mode_string(meta_data),
        &fmt_ts(mtime(meta_data))[..16]
    )
}

pub fn ls(flags: &[String], paths: &[String], base: &Path, ctx: &Ctx) -> Out {
    let letters: String = flags
        .iter()
        .filter(|flag| flag.starts_with('-') && !flag.starts_with("--"))
        .flat_map(|flag| flag[1..].chars())
        .collect();

    let has = |char_: char| letters.contains(char_);
    let options = LsOpts {
        long: has('l'),
        all: has('a'),
        human: has('h'),
        recursive: has('R'),
        by_time: has('t'),
        by_size: has('S'),
        reverse: has('r'),
        dir_only: has('d'),
    };

    let mut out = Out::default();
    let targets: Vec<PathBuf> = if paths.is_empty() {
        vec![base.to_path_buf()]
    } else {
        paths.iter().map(PathBuf::from).collect()
    };

    let headers = targets.len() > 1 || options.recursive;
    let mut first = true;

    for target in &targets {
        let meta_data = match symlink_metadata(target) {
            Ok(mtd) => mtd,
            Err(err) => {
                out.fail(format!(
                    "ls: cannot access '{}': {}",
                    target.display(),
                    nope(&err)
                ));
                continue;
            }
        };

        if options.dir_only || !meta_data.is_dir() {
            let line = ls_line(&options, &target.to_string_lossy(), target, &meta_data);
            out.push(ctx.max_out, &line);
            continue;
        }

        let mut stack = vec![(target.clone(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            if Instant::now() > ctx.deadline {
                out.timed_out = true;
                out.exit = 1;
                return out;
            }

            if headers {
                if !first {
                    out.push(ctx.max_out, "");
                }
                out.push(ctx.max_out, &format!("{}:", dir.display()));
            }

            first = false;
            let mut entries: Vec<(String, PathBuf, Metadata)> = Vec::new();

            match read_dir(&dir) {
                Ok(directory) => {
                    for entry in directory.flatten() {
                        let name = entry.file_name().to_string_lossy().to_string();

                        if !options.all && name.starts_with('.') {
                            continue;
                        }

                        let path = entry.path();

                        if hidden(ctx, &path) {
                            continue;
                        }

                        if let Ok(meta_data) = symlink_metadata(&path) {
                            entries.push((name, path, meta_data));
                        }
                    }
                }
                Err(err) => {
                    out.fail(format!(
                        "ls: cannot open directory '{}': {}",
                        dir.display(),
                        nope(&err)
                    ));
                    continue;
                }
            }

            entries.sort_by(|a, b| {
                let ord = if options.by_time {
                    mtime(&b.2).cmp(&mtime(&a.2))
                } else if options.by_size {
                    b.2.len().cmp(&a.2.len())
                } else {
                    cmp::Ordering::Equal
                };
                ord.then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
            });

            if options.reverse {
                entries.reverse();
            }

            if options.all {
                let dmd = symlink_metadata(&dir).ok();

                if let Some(mtd) = dmd {
                    out.push(ctx.max_out, &ls_line(&options, ".", &dir, &mtd));
                }

                if let Some(parent) = dir.parent() {
                    if let Ok(mtd) = symlink_metadata(parent) {
                        out.push(ctx.max_out, &ls_line(&options, "..", parent, &mtd));
                    }
                }
            }

            let mut subdirs = Vec::new();
            for (name, path, mtd) in &entries {
                if !out.push(ctx.max_out, &ls_line(&options, name, path, mtd)) {
                    out.exit = out.exit.max(0);
                    return out;
                }

                if options.recursive && mtd.is_dir() && depth < ctx.max_depth {
                    subdirs.push((path.clone(), depth + 1));
                }
            }
            stack.extend(subdirs.into_iter().rev());
        }
    }
    out
}
