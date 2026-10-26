//! Cross-platform helpers (Windows 11 ARM64 / Linux ARM64 / x86-64): paths, time, text, randomness.
use regex::Regex;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// Null device for git config values (`core.hooksPath`, `GIT_CONFIG_GLOBAL`…).
pub const NULL_DEVICE: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };
pub const PATH_LIST_SEP: &str = if cfg!(windows) { ";" } else { ":" };

/// File systems are case-insensitive by default on Windows and macOS: policy globs must match accordingly.
pub fn case_insensitive_fs() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM-DD HH:MM:SS` (UTC).
pub fn fmt_ts(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Audit timestamp: ISO-8601, UTC, numeric offset (same shape as Python's `%Y-%m-%dT%H:%M:%S%z`).
pub fn now_iso() -> String {
    fmt_ts(unix_now()).replacen(' ', "T", 1) + "+0000"
}

pub fn char_len(text: &str) -> usize {
    text.chars().count()
}

/// First `n` characters of `text`.
pub fn clip(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

pub fn hex_token(nbytes: usize) -> String {
    let mut bytes = vec![0u8; nbytes];
    getrandom::getrandom(&mut bytes).expect("system RNG unavailable");
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut it) = (0usize, text.char_indices().peekable());

    while let Some((index, char_)) = it.next() {
        let is_break = matches!(
            char_,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );

        if !is_break {
            continue;
        }

        out.push(&text[start..index]);
        let mut end = index + char_.len_utf8();

        if char_ == '\r' {
            if let Some(&(index_skip, '\n')) = it.peek() {
                it.next();
                end = index_skip + 1;
            }
        }
        start = end;
    }

    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

/// fnmatch(3)-style translation (`*`, `?`, `[seq]`, `[!seq]`); case-insensitive on Windows/macOS like Python's `fnmatch.fnmatch`.
pub fn fnmatch_regex(pat: &str) -> Regex {
    fnmatch_regex_ci(pat, case_insensitive_fs())
}

pub fn fnmatch_regex_ci(pat: &str, ci: bool) -> Regex {
    let chars: Vec<char> = pat.chars().collect();
    let mut out = String::from(if ci { "(?is)^" } else { "(?s)^" });
    let mut index = 0;

    while index < chars.len() {
        let char_ = chars[index];
        index += 1;
        match char_ {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            '[' => {
                let mut index_skip = index;

                if index_skip < chars.len() && chars[index_skip] == '!' {
                    index_skip += 1;
                }

                if index_skip < chars.len() && chars[index_skip] == ']' {
                    index_skip += 1;
                }

                while index_skip < chars.len() && chars[index_skip] != ']' {
                    index_skip += 1;
                }

                if index_skip >= chars.len() {
                    out.push_str("\\[");
                } else {
                    let mut body: String = chars[index..index_skip]
                        .iter()
                        .collect::<String>()
                        .replace('\\', "\\\\");

                    if body.starts_with('!') {
                        body = format!("^{}", &body[1..]);
                    } else if body.starts_with('^') {
                        body = format!("\\{body}");
                    }

                    out.push('[');
                    out.push_str(&body);
                    out.push(']');

                    index = index_skip + 1;
                }
            }
            _ => out.push_str(&regex::escape(&char_.to_string())),
        }
    }

    out.push('$');
    Regex::new(&out).unwrap_or_else(|_| Regex::new("^$").unwrap())
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|var| !var.is_empty())
        .map(PathBuf::from)
}

/// `~` and `~/x` only (no `~user`).
pub fn expanduser(path: &str) -> PathBuf {
    if path == "~" || path.starts_with("~/") || (cfg!(windows) && path.starts_with("~\\")) {
        if let Some(home) = home_dir() {
            return if path.len() > 2 {
                home.join(&path[2..])
            } else {
                home
            };
        }
    }
    PathBuf::from(path)
}

pub fn abspath(path: &Path) -> PathBuf {
    std::path::absolute(path)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().join(path))
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Windows: drop the `\\?\` verbatim prefix produced by `canonicalize` (`\\?\C:\x` -> `C:\x`, `\\?\UNC\s\x` -> `\\s\x`).
pub fn simplify_path(path: PathBuf) -> PathBuf {
    if !cfg!(windows) {
        return path;
    }

    let path_utf8 = path.to_string_lossy().to_string();
    if let Some(rest) = path_utf8.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }

    if let Some(rest) = path_utf8.strip_prefix(r"\\?\") {
        let bytes = rest.as_bytes();

        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
        {
            return PathBuf::from(rest);
        }
    }
    path
}

/// Non-strict `realpath`: resolves symlinks of the longest existing prefix, follows dangling symlinks, never fails.
pub fn realpath(path: &Path) -> PathBuf {
    resolve_real(abspath(path), 0)
}

fn resolve_real(path: PathBuf, depth: u32) -> PathBuf {
    if depth > 40 {
        return path;
    }

    if let Ok(path_canonical) = fs::canonicalize(&path) {
        return simplify_path(path_canonical);
    }

    if let Ok(meta_data) = fs::symlink_metadata(&path) {
        if meta_data.file_type().is_symlink() {
            if let Ok(file_path) = fs::read_link(&path) {
                let parent = resolve_real(
                    path.parent().map(Path::to_path_buf).unwrap_or_default(),
                    depth + 1,
                );

                let next = if file_path.is_absolute() {
                    file_path
                } else {
                    parent.join(file_path)
                };

                return resolve_real(normalize_lexical(&next), depth + 1);
            }
        }
    }

    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            resolve_real(parent.to_path_buf(), depth + 1).join(name)
        }
        _ => path,
    }
}

pub fn is_under(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

pub fn rel_posix(path: &Path, root: &Path) -> Vec<String> {
    path.strip_prefix(root)
        .map(|r| {
            r.components()
                .filter_map(|component| match component {
                    Component::Normal(os_text) => Some(os_text.to_string_lossy().to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Looks `name` up in trusted directories only (never in the inherited PATH).
pub fn which_in(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    let extensions: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };

    for directory in dirs {
        for extension in extensions {
            let candidate = directory.join(format!("{name}{extension}"));

            if let Ok(meta_data) = fs::metadata(&candidate) {
                #[cfg(unix)]
                let exec = {
                    use std::os::unix::fs::PermissionsExt;
                    meta_data.permissions().mode() & 0o111 != 0
                };
                #[cfg(not(unix))]
                let exec = true;
                if meta_data.is_file() && exec {
                    return Some(realpath(&candidate));
                }
            }
        }
    }
    None
}

/// Reads at most `limit` bytes.
pub fn read_up_to(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    fs::File::open(path)?.take(limit).read_to_end(&mut buffer)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn splitlines_matches_python() {
        assert_eq!(splitlines("a\nb\r\nc\rd"), vec!["a", "b", "c", "d"]);
        assert_eq!(splitlines("a\n"), vec!["a"]);
        assert_eq!(splitlines(""), Vec::<&str>::new());
        assert_eq!(splitlines("a\u{2028}b\x0cc"), vec!["a", "b", "c"]);
        assert_eq!(splitlines("\n\n"), vec!["", ""]);
    }
    #[test]
    fn time_format() {
        assert_eq!(fmt_ts(0), "1970-01-01 00:00:00");
        assert_eq!(fmt_ts(1_800_000_000), "2027-01-15 08:00:00");
    }
    #[test]
    fn fnmatch() {
        assert!(fnmatch_regex("*.py").is_match("a.py"));
        assert!(!fnmatch_regex("*.py").is_match("a.pyc"));
        assert!(fnmatch_regex("[!a]b").is_match("cb"));
        assert!(!fnmatch_regex("[!a]b").is_match("ab"));
    }
    #[test]
    fn realpath_dangling_and_missing() {
        let d = tempfile::tempdir().unwrap();
        let r = realpath(&d.path().join("x/y/z.txt"));
        assert!(r.ends_with("x/y/z.txt"));
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(outside.path().join("new.txt"), d.path().join("lnk"))
                .unwrap();
            let r = realpath(&d.path().join("lnk"));
            assert!(
                r.starts_with(realpath(outside.path())),
                "dangling symlink must resolve to its target: {r:?}"
            );
        }
    }
}
