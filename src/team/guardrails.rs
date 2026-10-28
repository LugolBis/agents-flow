//! Task guardrails: DETERMINISTIC validations of results. `Err(message)` is sent back to the agent for a correction (bounded retries),
//! then the task fails — it never passes silently. They complement (never replace) the checks done inside the tools: a guardrail checks
//! the QUALITY and FIDELITY of a result, never a permission.
use crate::engine::protocol::Guardrail;
use crate::error::{Error, Result};
use crate::security::runtime::ToolHost;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};

static URL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"https?://[^\s<>"')\]]+"#).unwrap());
static INLINE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`([^`\n]+)`").unwrap());

pub fn non_empty(min_chars: usize) -> Guardrail {
    Arc::new(move |text: &str| {
        if text.trim().chars().count() < min_chars {
            Err(format!("Result is empty or too short (< {min_chars} characters). Provide a complete result or explain precisely what went wrong."))
        } else {
            Ok(())
        }
    })
}

pub fn no_secrets(host: Arc<dyn ToolHost>) -> Guardrail {
    Arc::new(move |text: &str| {
        if host.contains_secret(text.trim()) {
            Err("The result contains what looks like a secret (token, key, password). Remove it and try again.".into())
        } else {
            Ok(())
        }
    })
}

fn norm(url: &str) -> String {
    url.trim()
        .trim_end_matches(['.', ',', ';', ':'])
        .split('#')
        .next()
        .unwrap_or("")
        .trim_end_matches('/')
        .to_lowercase()
}

/// At least one cited URL, and NO URL that was not returned by a tool (anti-hallucination of sources).
pub fn sources_cited(host: Arc<dyn ToolHost>) -> Guardrail {
    Arc::new(move |text: &str| {
        let cited: BTreeSet<String> = URL_RE
            .find_iter(text.trim())
            .map(|mat| norm(mat.as_str()))
            .collect();

        if cited.is_empty() {
            return Err(
                "No sources cited. Cite the URLs you actually consulted using your tools.".into(),
            );
        }

        let known: BTreeSet<String> = host.session().seen_urls.iter().map(|u| norm(u)).collect();
        let invented: Vec<&String> = cited.iter().filter(|u| !known.contains(*u)).collect();

        if !invented.is_empty() {
            return Err(format!("These URLs were not returned by any tool (sources either invented or not consulted): {}. Only cite URLs that have actually been retrieved, or consult them first.", invented.iter().take(5).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
        }
        Ok(())
    })
}

pub fn max_length(n: usize) -> Guardrail {
    Arc::new(move |text: &str| {
        let len = text.trim().chars().count();

        if len > n {
            Err(format!(
                "Result too long ({len} > {n} characters). Summarize."
            ))
        } else {
            Ok(())
        }
    })
}

/// Fenced code blocks (``` or ~~~): returns (bodies, text with the blocks removed). A closing fence is the same marker alone on its line.
fn fences(text: &str) -> (Vec<String>, String) {
    let (mut bodies, mut rest) = (Vec::new(), String::new());
    let lines: Vec<&str> = text.split_inclusive('\n').collect();

    let mut index = 0;
    while index < lines.len() {
        let marker = ["```", "~~~"]
            .into_iter()
            .find(|mark| lines[index].starts_with(mark));

        if let Some(mark) = marker {
            if let Some(close) = (index + 1..lines.len()).find(|&index_| {
                lines[index_].starts_with(mark) && lines[index_][3..].trim().is_empty()
            }) {
                bodies.push(lines[index + 1..close].concat());
                index = close + 1;
                continue;
            }
        }

        rest.push_str(lines[index]);
        index += 1;
    }
    (bodies, rest)
}

fn count(text: &str, pattern: &str) -> usize {
    Regex::new(pattern).unwrap().find_iter(text).count()
}

/// Translation: identical code blocks, same headings/table rows, inline code and URLs preserved.
pub fn markdown_preserved(source: &str) -> Guardrail {
    let (src_blocks, src_rest) = fences(source);
    let src_inline: BTreeSet<String> = INLINE_RE
        .captures_iter(&src_rest)
        .map(|capture| capture[1].to_string())
        .collect();

    let src_urls: BTreeSet<String> = URL_RE
        .find_iter(source)
        .map(|mat| mat.as_str().to_string())
        .collect();

    let (h_src, t_src) = (
        count(source, r"(?m)^#{1,6}\s"),
        count(source, r"(?m)^\s*\|"),
    );

    Arc::new(move |raw: &str| {
        let text_trim = raw.trim();
        let mut problems: Vec<String> = Vec::new();

        if fences(text_trim).0 != src_blocks {
            problems.push(
                "The code blocks must remain strictly identical (same number, same content)."
                    .into(),
            );
        }

        if count(text_trim, r"(?m)^#{1,6}\s") != h_src {
            problems.push("the number of Markdown headings has changed".into());
        }

        if count(text_trim, r"(?m)^\s*\|") != t_src {
            problems.push("the number of table rows has changed".into());
        }

        let missing: Vec<&String> = src_inline
            .iter()
            .filter(|index| !text_trim.contains(&format!("`{index}`")))
            .take(5)
            .collect();

        if !missing.is_empty() {
            problems.push(format!(
                "`inline` elements to be kept as is: {}",
                missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        let got: BTreeSet<String> = URL_RE
            .find_iter(text_trim)
            .map(|mat| mat.as_str().to_string())
            .collect();

        let lost: Vec<&String> = src_urls.difference(&got).take(3).collect();
        if !lost.is_empty() {
            problems.push(format!(
                "lost URL : {}",
                lost.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "The translation did not preserve the structure: {}.",
                problems.join(" ; ")
            ))
        }
    })
}

pub fn compose(fns: Vec<Guardrail>) -> Guardrail {
    Arc::new(move |text: &str| {
        for func in &fns {
            func(text)?;
        }
        Ok(())
    })
}

/// The structure guardrail applies to the translation alone, without the trailing ambiguities section.
pub fn strip_ambiguities(inner: Guardrail) -> Guardrail {
    Arc::new(move |text: &str| inner(text.split("---AMBIGUITIES---").next().unwrap_or("")))
}

pub fn build_guardrail(ids: &[String], host: &Arc<dyn ToolHost>) -> Result<Option<Guardrail>> {
    let mut fns = Vec::new();
    for index in ids {
        fns.push(match index.as_str() {
            "non_empty" => non_empty(20),
            "no_secrets" => no_secrets(host.clone()),
            "sources_cited" => sources_cited(host.clone()),
            "max_length" => max_length(30000),
            other => return Err(Error::config(format!("unknown guardrail : {other}"))),
        });
    }

    Ok(if fns.is_empty() {
        None
    } else {
        Some(compose(fns))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translation_structure() {
        let src = "# Titre\n\nTexte avec `code` et https://ex.com/a\n\n```python\nprint(1)\n```\n\n| a | b |\n|---|---|\n| 1 | 2 |\n";
        let fn_guardrail = markdown_preserved(src);
        let good = "# Title\n\nText with `code` and https://ex.com/a\n\n```python\nprint(1)\n```\n\n| a | b |\n|---|---|\n| 1 | 2 |\n";

        assert!(fn_guardrail(good).is_ok());
        assert!(fn_guardrail(&good.replace("print(1)", "print(2)"))
            .unwrap_err()
            .contains("code block"));

        assert!(fn_guardrail(&good.replace("# Title\n", ""))
            .unwrap_err()
            .contains("The translation did not preserve the structure: the number of Markdown headings has changed."));

        assert!(fn_guardrail(&good.replace("`code`", "code"))
            .unwrap_err()
            .contains("inline"));

        assert!(fn_guardrail(&good.replace("https://ex.com/a", ""))
            .unwrap_err()
            .contains("lost URL"));

        assert!(
            strip_ambiguities(fn_guardrail)(&format!("{good}---AMBIGUITIES---\n- a doubt")).is_ok()
        );
    }

    #[test]
    fn simple_guardrails() {
        assert!(non_empty(20)("short").is_err() && non_empty(5)("long enough").is_ok());
        assert!(max_length(5)("abcdefg").is_err());
        assert_eq!(norm("HTTPS://Ex.com/A/#frag."), "https://ex.com/a");
    }
}
