//! Secret protection: (1) `SecretRedactor` masks known secrets (values of sensitive env vars + common token patterns) in every tool output
//! and in the audit; (2) `clean_env` gives sub-processes a minimal environment; (3) tools read their own tokens.
//! Pattern detection is heuristic: the real protection is not giving access to secrets (deny globs, minimal env, dedicated tools).
use crate::config::jsonc::EnvMap;
use crate::util::PATH_LIST_SEP;
use regex::{Captures, Regex, RegexSet};
use std::borrow::Cow;
use std::sync::LazyLock;

pub const REDACTED: &str = "[REDACTED]";

const PLAIN: &[&str] = &[
    r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)",
    r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
    r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{20,}\b",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    r"\bAIza[0-9A-Za-z_\-]{30,}\b",
    r"(?i)\bbearer\s+[A-Za-z0-9._\-~+/]{16,}=*",
];

const USER_INFO: &str = r"://([^/\s:@]+:[^/\s@]+)@";
const ENV_ASSIGN: &str = r#"(?im)^\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=(\s*)(['"]?\S{12,})"#;

#[derive(Clone, Copy)]
enum Kind {
    Plain,
    UserInfo,
    EnvAssign,
}

struct Pattern {
    kind: Kind,
    regex: Regex,
}

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    let mut patterns: Vec<Pattern> = PLAIN
        .iter()
        .map(|p| Pattern {
            kind: Kind::Plain,
            regex: Regex::new(p).unwrap(),
        })
        .collect();

    patterns.push(Pattern {
        kind: Kind::UserInfo,
        regex: Regex::new(USER_INFO).unwrap(),
    });

    patterns.push(Pattern {
        kind: Kind::EnvAssign,
        regex: Regex::new(ENV_ASSIGN).unwrap(),
    });

    patterns
});

/// One pass over the text: if no pattern can match, none of the regexes above is run.
static PREFILTER: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new(PATTERNS.iter().map(|p| p.regex.as_str())).unwrap());

static SENSITIVE_ENV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(secret|token|passw(?:or)?d|api_?key|private_?key|credential|auth)").unwrap()
});

const SAFE_ENV_NAMES: &[&str] = &[
    "AGENTS_FLOW_AUDIT_LOG",
    "AGENTS_FLOW_CONFIG_DIR",
    "AGENTS_FLOW_WORKSPACE",
];

fn numeric_line(text: &str, start: usize) -> bool {
    let rest = &text[start..];
    let digits = rest
        .chars()
        .take_while(|char_| char_.is_numeric())
        .map(char::len_utf8)
        .sum::<usize>();

    if digits == 0 {
        return false;
    }

    let mut tail = rest[digits..].chars().peekable();
    loop {
        match tail.peek() {
            None | Some('\n') => return true,
            Some(char_) if char_.is_whitespace() => {
                tail.next();
            }
            _ => return false,
        }
    }
}

fn pattern_matches(pattern: &Pattern, text: &str) -> bool {
    match pattern.kind {
        Kind::EnvAssign => pattern
            .regex
            .captures_iter(text)
            .any(|matched| !numeric_line(text, matched.get(2).unwrap().start())),
        _ => pattern.regex.is_match(text),
    }
}

pub struct SecretRedactor {
    literals: Vec<String>,
}

impl SecretRedactor {
    /// `environ`: explicit map, or the process environment.
    pub fn new(environ: Option<&EnvMap>) -> Self {
        let pairs: Vec<(String, String)> = match environ {
            Some(map) => map
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            None => std::env::vars().collect(),
        };

        let mut lits: Vec<String> = pairs
            .into_iter()
            .filter(|(key, value)| {
                value.len() >= 8
                    && !SAFE_ENV_NAMES.contains(&key.as_str())
                    && SENSITIVE_ENV.is_match(key)
            })
            .map(|(_, value)| value)
            .collect();

        lits.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        lits.dedup();
        SecretRedactor { literals: lits }
    }

    pub fn contains_secret(&self, text: &str) -> bool {
        self.literals
            .iter()
            .any(|literal| text.contains(literal.as_str()))
            || (PREFILTER.is_match(text)
                && PATTERNS
                    .iter()
                    .any(|pattern| pattern_matches(pattern, text)))
    }

    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut cur: Cow<'a, str> = Cow::Borrowed(text);
        for literal in &self.literals {
            if cur.contains(literal.as_str()) {
                cur = Cow::Owned(cur.replace(literal.as_str(), REDACTED));
            }
        }

        if !PREFILTER.is_match(&cur) {
            return cur;
        }

        for pattern in PATTERNS.iter() {
            let replaced = match pattern.kind {
                Kind::Plain => {
                    let regex = pattern.regex.replace_all(&cur, REDACTED);
                    if matches!(regex, Cow::Borrowed(_)) {
                        None
                    } else {
                        Some(regex.into_owned())
                    }
                }
                Kind::UserInfo => {
                    let regex = pattern
                        .regex
                        .replace_all(&cur, format!("://{REDACTED}@").as_str());
                    if matches!(regex, Cow::Borrowed(_)) {
                        None
                    } else {
                        Some(regex.into_owned())
                    }
                }
                Kind::EnvAssign => {
                    let content: &str = &cur;
                    let res = pattern.regex.replace_all(content, |matched: &Captures| {
                        if numeric_line(content, matched.get(2).unwrap().start()) {
                            matched[0].to_string()
                        } else {
                            REDACTED.to_string()
                        }
                    });

                    if matches!(res, Cow::Borrowed(_)) {
                        None
                    } else {
                        Some(res.into_owned())
                    }
                }
            };

            if let Some(content) = replaced {
                cur = Cow::Owned(content);
            }
        }
        cur
    }
}

/// Indices of detected patterns; used before a commit or a write.
pub fn scan_for_secrets(text: &str) -> Vec<String> {
    if !PREFILTER.is_match(text) {
        return vec![];
    }

    PATTERNS
        .iter()
        .enumerate()
        .filter(|(_, pattern)| pattern_matches(pattern, text))
        .map(|(index, _)| index.to_string())
        .collect()
}

/// Minimal environment for a sub-process. No inherited secret. `extra` entries win.
pub fn clean_env(extra: &[(&str, &str)], path_dirs: &[String]) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();

    let default_dirs: Vec<String> = if cfg!(windows) {
        vec![]
    } else {
        vec!["/usr/bin".into(), "/bin".into()]
    };

    let dirs = if path_dirs.is_empty() {
        &default_dirs
    } else {
        path_dirs
    };

    env.push(("PATH".into(), dirs.join(PATH_LIST_SEP)));
    if cfg!(windows) {
        for key in [
            "SystemRoot",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "ComSpec",
        ] {
            if let Ok(val) = std::env::var(key) {
                env.push((key.into(), val));
            }
        }
        env.push(("HOME".into(), r"C:\nonexistent".into()));
    } else {
        env.extend(
            [
                ("LANG", "C.UTF-8"),
                ("LC_ALL", "C.UTF-8"),
                ("HOME", "/nonexistent"),
                ("TMPDIR", "/tmp"),
            ]
            .map(|(key, val)| (key.to_string(), val.to_string())),
        );
    }

    for (key, val) in extra {
        env.retain(|(n, _)| n != key);
        env.push((key.to_string(), val.to_string()));
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    fn red() -> SecretRedactor {
        SecretRedactor::new(Some(&EnvMap::new()))
    }
    #[test]
    fn patterns() {
        let r = red();
        for s in [
            "ghp_abcdefghijklmnopqrstuvwxyz0123",
            "sk-ant-abcdefghijklmnopqrstuvwxyz",
            "AKIAABCDEFGHIJKLMNOP",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
            "API_KEY=abcdefghijklmnopqrstuvwxyz0123",
        ] {
            assert!(r.contains_secret(s), "{s}");
            assert!(r.redact(s).contains(REDACTED), "{s}");
        }
        assert!(!r.contains_secret("MAX_TOKENS=4096"));
        assert!(!r.contains_secret("TOKEN_LIMIT=123456789012345"));
        assert!(!r.contains_secret("plain text with nothing"));
        let url = r.redact("see https://user:hunter2@example.com/x");
        assert!(
            !url.contains("hunter2") && url.contains("@example.com"),
            "{url}"
        );
        assert_eq!(
            scan_for_secrets("x ghp_abcdefghijklmnopqrstuvwxyz0123 y").len(),
            1
        );
    }
    #[test]
    fn env_literals_redacted() {
        let env: EnvMap = [
            ("MY_TOKEN".to_string(), "s3cr3t-value-xyz".to_string()),
            (
                "AGENTS_FLOW_AUDIT_LOG".to_string(),
                "/tmp/audit-xyz".to_string(),
            ),
        ]
        .into();
        let r = SecretRedactor::new(Some(&env));
        assert_eq!(r.redact("a s3cr3t-value-xyz b"), "a [REDACTED] b");
        assert_eq!(r.redact("/tmp/audit-xyz"), "/tmp/audit-xyz");
    }
    #[test]
    fn clean_env_has_no_inherited_secret() {
        std::env::set_var("VERIFY_DEMO_TOKEN", "should-not-leak-1234");
        assert!(!clean_env(&[], &[])
            .iter()
            .any(|(k, _)| k == "VERIFY_DEMO_TOKEN"));
    }
}
