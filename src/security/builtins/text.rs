use super::{
    context::Ctx,
    system::{nope, Out},
};

use std::fs::File;
use std::io::{Read, Result, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

pub const LINE_BUF: u64 = 8 << 20;

pub fn read_prefix(path: &Path, n: u64) -> Result<(Vec<u8>, bool)> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();

    file.by_ref().take(n + 1).read_to_end(&mut buffer)?;

    let more = buffer.len() as u64 > n;
    buffer.truncate(n as usize);

    Ok((buffer, more))
}

fn read_suffix(path: &Path, n: u64) -> Result<(Vec<u8>, bool)> {
    let mut file = File::open(path)?;

    let len = file.metadata()?.len();
    let skip = len.saturating_sub(n);

    file.seek(SeekFrom::Start(skip))?;

    let mut buffer = Vec::new();
    file.take(n).read_to_end(&mut buffer)?;

    Ok((buffer, skip > 0))
}

fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut buffers: Vec<&[u8]> = bytes.split_inclusive(|char_| *char_ == b'\n').collect();

    if buffers.is_empty() && !bytes.is_empty() {
        buffers.push(bytes);
    }

    buffers
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn emit_text(out: &mut Out, cap: usize, text: &str) {
    for line in text.split_inclusive('\n') {
        if !out.push(cap, line.trim_end_matches('\n')) {
            return;
        }
    }
}

pub fn cat(flags: &[String], paths: &[String], ctx: &Ctx) -> Out {
    let number = flags.iter().any(|flag| flag == "-n");
    let mut out = Out::default();
    let mut n = 0usize;

    for path in paths {
        match read_prefix(Path::new(path), ctx.max_out as u64 + 1) {
            Ok((data, _)) => {
                for line in split_lines(&data) {
                    n += 1;
                    let l = lossy(line);
                    let l = l.trim_end_matches('\n');

                    if !out.push(
                        ctx.max_out,
                        &if number {
                            format!("{n:>6}\t{l}")
                        } else {
                            l.to_string()
                        },
                    ) {
                        return out;
                    }
                }
            }
            Err(e) => out.fail(format!("cat: {path}: {}", nope(&e))),
        }
    }
    out
}

pub fn head_tail(is_head: bool, flags: &[String], paths: &[String], ctx: &Ctx) -> Out {
    let (mut mode_bytes, mut count, mut quiet, mut verbose) =
        (false, "10".to_string(), false, false);

    let mut index = 0;
    while index < flags.len() {
        let f = flags[index].as_str();

        match f {
            "-q" | "--quiet" => quiet = true,
            "-v" | "--verbose" => verbose = true,
            "-n" => {
                count = flags[index + 1].clone();
                mode_bytes = false;
                index += 1;
            }
            "-c" => {
                count = flags[index + 1].clone();
                mode_bytes = true;
                index += 1;
            }
            _ if f.starts_with("--lines=") => {
                count = f[8..].to_string();
                mode_bytes = false;
            }
            _ if f.starts_with("--bytes=") => {
                count = f[8..].to_string();
                mode_bytes = true;
            }
            _ => {}
        }
        index += 1;
    }

    let (sign, n) = (
        count
            .chars()
            .next()
            .filter(|char_| *char_ == '+' || *char_ == '-'),
        count
            .trim_start_matches(['+', '-'])
            .parse::<usize>()
            .unwrap_or(10),
    );

    let mut out = Out::default();
    let show_headers = (paths.len() > 1 && !quiet) || verbose;

    for (index, path) in paths.iter().enumerate() {
        if Instant::now() > ctx.deadline {
            out.timed_out = true;
            out.exit = 1;
            return out;
        }

        let want = if mode_bytes {
            ctx.max_out as u64 + 1
        } else {
            LINE_BUF
        };

        let read = if is_head {
            read_prefix(Path::new(path), want)
        } else {
            read_suffix(Path::new(path), want)
        };

        let (data, _partial) = match read {
            Ok(value) => value,
            Err(err) => {
                out.fail(format!(
                    "{}: cannot open '{path}' for reading: {}",
                    if is_head { "head" } else { "tail" },
                    nope(&err)
                ));
                continue;
            }
        };

        if show_headers {
            if index > 0 {
                out.push(ctx.max_out, "");
            }

            if !out.push(ctx.max_out, &format!("==> {path} <==")) {
                return out;
            }
        }

        let slice: &[u8] = if mode_bytes {
            let len = data.len();

            match (is_head, sign) {
                (true, Some('-')) => &data[..len.saturating_sub(n)],
                (true, _) => &data[..n.min(len)],
                (false, Some('+')) => &data[(n.saturating_sub(1)).min(len)..],
                (false, _) => &data[len.saturating_sub(n)..],
            }
        } else {
            let lines = split_lines(&data);
            let total = lines.len();

            let (a, b) = match (is_head, sign) {
                (true, Some('-')) => (0, total.saturating_sub(n)),
                (true, _) => (0, n.min(total)),
                (false, Some('+')) => (n.saturating_sub(1).min(total), total),
                (false, _) => (total.saturating_sub(n), total),
            };

            let mut text = String::new();
            for line in &lines[a..b] {
                text.push_str(&lossy(line));
            }

            emit_text(&mut out, ctx.max_out, &text);

            if out.truncated {
                return out;
            }
            continue;
        };

        emit_text(&mut out, ctx.max_out, &lossy(slice));

        if out.truncated {
            return out;
        }
    }
    out
}
