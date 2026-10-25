use crate::error::SecResult;
use crate::security::argspec::deny;

use regex::Regex;
use std::sync::LazyLock;

pub const MAX_COMMAND_LEN: usize = 1000;
static META_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[;&|<>`$(){}\n\r\\\x00]").unwrap());

/// POSIX-like split. Backslash, `$` and backtick were already rejected, so only quotes remain to be handled.
pub fn split_command(cmd: &str) -> Option<Vec<String>> {
    let (mut out, mut cursor, mut in_tok, mut quote) =
        (Vec::new(), String::new(), false, None::<char>);

    for char_ in cmd.chars() {
        match quote {
            Some(q) => {
                if char_ == q {
                    quote = None
                } else {
                    cursor.push(char_)
                }
            }
            None => match char_ {
                '\'' | '"' => {
                    quote = Some(char_);
                    in_tok = true;
                }
                cw if cw.is_whitespace() => {
                    if in_tok {
                        out.push(std::mem::take(&mut cursor));
                        in_tok = false;
                    }
                }
                other => {
                    cursor.push(other);
                    in_tok = true;
                }
            },
        }
    }

    if quote.is_some() {
        return None;
    }

    if in_tok {
        out.push(cursor);
    }
    Some(out)
}

pub(super) fn gate(command: &str) -> SecResult<()> {
    if command.trim().is_empty() {
        return Err(deny("empty_command", "empty command".to_string()));
    }

    if command.chars().count() > MAX_COMMAND_LEN {
        return Err(deny("command_too_long", "too long command".to_string()));
    }

    if META_RE.is_match(command) {
        return Err(deny("shell_metacharacters", "composition, redirection, substitution, or escaping prohibited (a single, simple command)".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokenizer() {
        assert_eq!(
            split_command("find . -name '*.py' -maxdepth 3").unwrap(),
            vec!["find", ".", "-name", "*.py", "-maxdepth", "3"]
        );
        assert_eq!(split_command("a \"b c\" ''").unwrap(), vec!["a", "b c", ""]);
        assert!(split_command("a 'b").is_none());
    }
    #[test]
    fn metachar_gate() {
        for bad in [
            "ls; rm x",
            "ls | cat",
            "ls > f",
            "echo $(id)",
            "ls `id`",
            "ls && ls",
            "ls \\n",
            "ls $HOME",
            "cat {a,b}",
        ] {
            assert!(META_RE.is_match(bad), "{bad}");
        }
        assert!(!META_RE.is_match("find . -name '*.py' -mtime -3"));
    }
}
