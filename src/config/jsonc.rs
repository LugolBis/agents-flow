//! JSONC loader: strips `//` and `/* */` comments and trailing commas (outside strings), then expands
//! `${VAR}` / `${VAR:-default}` inside string values.

use crate::error::{Error, Result};
use regex::{Captures, Regex};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

pub type EnvMap = HashMap<String, String>;

static ENV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").unwrap());

pub fn strip_jsonc(text: &str) -> Result<String> {
    let bytes: &[u8] = text.as_bytes();
    let (mut out, mut index, mut in_str) = (Vec::with_capacity(bytes.len()), 0usize, false);

    while index < bytes.len() {
        let byte = bytes[index];

        if in_str {
            out.push(byte);

            if byte == b'\\' && index + 1 < bytes.len() {
                out.push(bytes[index + 1]);
                index += 2;
                continue;
            }

            if byte == b'"' {
                in_str = false;
            }

            index += 1;
        } else if byte == b'"' {
            in_str = true;
            out.push(byte);
            index += 1;
        } else if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            match text[index + 2..].find("*/") {
                Some(e) => index = index + 2 + e + 2,
                None => return Err(Error::config("commentaire /* non terminé dans le JSONC")),
            }
        } else {
            out.push(byte);
            index += 1;
        }
    }
    Ok(strip_trailing_commas(&out))
}

fn strip_trailing_commas(bytes: &[u8]) -> String {
    let (mut out, mut in_str, mut index) = (Vec::with_capacity(bytes.len()), false, 0usize);

    while index < bytes.len() {
        let byte = bytes[index];

        if in_str {
            out.push(byte);

            if byte == b'\\' && index + 1 < bytes.len() {
                out.push(bytes[index + 1]);
                index += 2;
                continue;
            }

            if byte == b'"' {
                in_str = false;
            }

            index += 1;
            continue;
        }

        if byte == b'"' {
            in_str = true;
        } else if byte == b',' {
            let mut index_skip = index + 1;

            while index_skip < bytes.len()
                && matches!(bytes[index_skip], b' ' | b'\t' | b'\r' | b'\n')
            {
                index_skip += 1;
            }

            if index_skip < bytes.len() && matches!(bytes[index_skip], b']' | b'}') {
                index += 1;
                continue;
            }
        }

        out.push(byte);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn lookup(env: Option<&EnvMap>, name: &str) -> Option<String> {
    match env {
        Some(map) => map.get(name).cloned(),
        None => std::env::var(name).ok(),
    }
}

pub fn expand_str(text: &str, env: Option<&EnvMap>) -> Result<String> {
    let mut err_opt = None;

    let out = ENV_RE.replace_all(text, |rep: &Captures| {
        let name = &rep[1];

        if let Some(val) = lookup(env, name) {
            return val;
        }

        if let Some(d) = rep.get(2) {
            return d.as_str().to_string();
        }

        err_opt = Some(Error::config(format!(
            "variable d'environnement requise absente : {name}"
        )));
        String::new()
    });

    match err_opt {
        Some(err) => Err(err),
        None => Ok(out.into_owned()),
    }
}

pub fn expand_env(val: Value, env: Option<&EnvMap>) -> Result<Value> {
    Ok(match val {
        Value::String(text) => Value::String(expand_str(&text, env)?),
        Value::Array(array) => Value::Array(
            array
                .into_iter()
                .map(|x| expand_env(x, env))
                .collect::<Result<_>>()?,
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| Ok((k, expand_env(v, env)?)))
                .collect::<Result<_>>()?,
        ),
        other => other,
    })
}

pub fn loads_jsonc(text: &str, env: Option<&EnvMap>) -> Result<Value> {
    let val: Value = serde_json::from_str(&strip_jsonc(text)?)
        .map_err(|err| Error::config(format!("JSONC invalide : {err}")))?;
    expand_env(val, env)
}

pub fn load_jsonc(path: &Path, env: Option<&EnvMap>) -> Result<Value> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        Error::config(format!("lecture impossible de {} : {err}", path.display()))
    })?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    loads_jsonc(text, env).map_err(|err| Error::config(format!("{}: {err}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comments_and_commas_outside_strings_only() {
        let v = loads_jsonc(
            "{ // c\n \"a\": \"x // not a comment\", /* b */ \"b\": [1,2,], }",
            None,
        )
        .unwrap();
        assert_eq!(v["a"], "x // not a comment");
        assert_eq!(v["b"][1], 2);
    }
    #[test]
    fn env_expansion() {
        let env: EnvMap = [("A".to_string(), "1".to_string())].into();
        let v = loads_jsonc(r#"{"x":"${A}-${B:-def}"}"#, Some(&env)).unwrap();
        assert_eq!(v["x"], "1-def");
        assert!(loads_jsonc(r#"{"x":"${MISSING_VAR_X}"}"#, Some(&env)).is_err());
    }
    #[test]
    fn unterminated_comment_fails_closed() {
        assert!(strip_jsonc("{} /* oops").is_err());
    }
}
