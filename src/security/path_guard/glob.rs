//! PathGuard: the filesystem boundary. Every read/write goes through `PathGuard::resolve`; no string from an LLM is trusted:
//! NUL/control chars/huge paths refused; any `..` refused (no silent normalisation); real path resolved THEN checked against allowed roots
//! (a symlink leaving the perimeter is refused); deny globs tested on lexical AND real path; writes need a writable root and no symlink
//! below it; the hard-coded invariant «no `.git` component» cannot be disabled by configuration.
//! Windows hardening: backslashes, drive-relative paths (`C:x`), alternate data streams (`a:b`), reserved device names (NUL, COM1…) and
//! trailing dots/spaces are refused, and globs are matched case-insensitively.
use crate::{security::path_guard::rel::Rel, util::case_insensitive_fs};
use regex::Regex;

#[derive(Debug, Clone)]
enum Kind {
    Name,
    Anchored,
    Suffix,
}

#[derive(Debug, Clone)]
pub struct Glob {
    pub pattern: String,
    kind: Kind,
    literal: Option<String>,
    regex: Regex,
}

/// Compiled once at startup (the Python original recompiled per call).
#[derive(Debug, Clone, Default)]
pub struct GlobSet {
    globs: Vec<Glob>,
    patterns: Vec<String>,
}

/// `**` crosses directories, `*` and `?` do not.
pub fn glob_to_regex(pattern: &str) -> Regex {
    let chars: Vec<char> = pattern.chars().collect();

    let mut out = String::from(if case_insensitive_fs() {
        "(?is)^"
    } else {
        "(?s)^"
    });

    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '*' if chars.get(index + 1) == Some(&'*') => {
                index += 2;

                if chars.get(index) == Some(&'/') {
                    index += 1;
                    out.push_str("(?:.*/)?");
                } else {
                    out.push_str(".*");
                }
                continue;
            }
            '*' => out.push_str("[^/]*"),
            '?' => out.push_str("[^/]"),
            char_ => out.push_str(&regex::escape(&char_.to_string())),
        }
        index += 1;
    }

    out.push('$');
    Regex::new(&out).expect("glob regex")
}

impl Glob {
    pub fn new(pattern: &str) -> Glob {
        let kind = if !pattern.contains('/') {
            Kind::Name
        } else if pattern.starts_with('/') {
            Kind::Anchored
        } else {
            Kind::Suffix
        };

        let body = if matches!(kind, Kind::Anchored) {
            &pattern[1..]
        } else {
            pattern
        };

        let literal = (!body.contains(['*', '?'])).then(|| {
            if case_insensitive_fs() {
                body.to_lowercase()
            } else {
                body.to_string()
            }
        });

        Glob {
            pattern: pattern.to_string(),
            kind,
            literal,
            regex: glob_to_regex(body),
        }
    }

    fn is(&self, text: &str) -> bool {
        match &self.literal {
            Some(literal) => {
                if case_insensitive_fs() {
                    text.to_lowercase() == *literal
                } else {
                    text == literal
                }
            }
            None => self.regex.is_match(text),
        }
    }

    pub fn matches(&self, parts: &[String]) -> bool {
        match self.kind {
            Kind::Name => parts.iter().any(|part| self.is(part)),
            Kind::Anchored => self.is(&if parts.is_empty() {
                ".".to_string()
            } else {
                parts.join("/")
            }),
            Kind::Suffix => (0..parts.len()).any(|index| self.is(&parts[index..].join("/"))),
        }
    }
}

impl GlobSet {
    pub fn new(patterns: &[String]) -> GlobSet {
        GlobSet {
            globs: patterns.iter().map(|pattern| Glob::new(pattern)).collect(),
            patterns: patterns.to_vec(),
        }
    }

    pub fn first_match(&self, rel: &Rel) -> Option<&str> {
        self.globs
            .iter()
            .find(|glob| glob.matches(rel.parts()))
            .map(|glob| glob.pattern.as_str())
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::{
        config::{models::permissions::RootCfg, permissions::FsCfg},
        error::SecResult,
        security::path_guard::{
            guard::PathGuard, resolved::ResolvedPath, windows::windows_path_check,
        },
    };
    fn guard(dir: &Path) -> PathGuard {
        let cfg = FsCfg {
            roots: vec![RootCfg {
                name: "ws".into(),
                path: dir.to_string_lossy().into(),
                write: true,
            }],
            deny_globs: vec![
                ".env".into(),
                ".env.*".into(),
                "id_rsa".into(),
                "*.pem".into(),
                "secrets/**".into(),
            ],
            deny_exceptions: vec![".env.example".into()],
            write_deny_globs: vec![".github/workflows/**".into()],
            ..FsCfg::default()
        };
        PathGuard::new(&cfg).unwrap()
    }
    fn code(r: SecResult<ResolvedPath>) -> String {
        r.err().map(|e| e.code).unwrap_or_else(|| "ok".into())
    }
    #[test]
    fn globs() {
        let g = GlobSet::new(&[
            ".github/workflows/**".into(),
            "*.pem".into(),
            "/top.txt".into(),
        ]);
        let r = |s: &str| Rel(s.split('/').map(String::from).collect());
        assert!(g.first_match(&r("proj/.github/workflows/ci.yml")).is_some());
        assert!(g.first_match(&r("a/b/key.pem")).is_some());
        assert!(g.first_match(&r("top.txt")).is_some());
        assert!(g.first_match(&r("a/top.txt")).is_none());
    }
    #[test]
    fn resolve_rules() {
        let d = tempfile::tempdir().unwrap();
        let g = guard(d.path());
        std::fs::write(d.path().join(".env"), "x").unwrap();
        std::fs::write(d.path().join(".env.example"), "x").unwrap();
        std::fs::create_dir(d.path().join(".git")).unwrap();
        assert_eq!(code(g.read("a.txt")), "ok");
        assert_eq!(code(g.read("../x")), "path_traversal");
        assert_eq!(code(g.read("a\\b")), "backslash");
        assert_eq!(code(g.read("")), "empty_path");
        assert_eq!(code(g.read("a\u{0}b")), "control_chars");
        assert_eq!(code(g.read(".env")), "denied_by_pattern");
        assert_eq!(code(g.read(".env.example")), "ok");
        assert_eq!(code(g.read(".git/config")), "git_internal_path");
        assert_eq!(code(g.read("/etc/passwd")), "outside_allowed_roots");
        assert_eq!(
            code(g.write("p/.github/workflows/ci.yml")),
            "write_denied_by_pattern"
        );
    }
    #[cfg(unix)]
    #[test]
    fn symlink_rules() {
        let d = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("victim.txt"), "keep").unwrap();
        std::fs::write(d.path().join(".env"), "k").unwrap();
        std::os::unix::fs::symlink(out.path().join("victim.txt"), d.path().join("to_out")).unwrap();
        std::os::unix::fs::symlink(d.path().join(".env"), d.path().join("notes.txt")).unwrap();
        let g = guard(d.path());
        assert_eq!(code(g.read("to_out")), "outside_allowed_roots");
        assert_eq!(
            code(g.read("notes.txt")),
            "denied_by_pattern",
            "a link to a secret is refused via the real path"
        );
    }
    #[test]
    fn windows_checks() {
        assert!(windows_path_check("C:/ws/a.txt").is_ok());
        for bad in ["a/b:stream", "NUL", "a/com1.txt", "x/.git.", "a/b "] {
            assert!(windows_path_check(bad).is_err(), "{bad}");
        }
    }
}
