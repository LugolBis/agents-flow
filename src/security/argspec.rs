//! Allowlist argument validation. A `Spec` describes EXACTLY what a command accepts (plain flags, valued flags with validators,
//! letter clusters, positional nature). Anything not listed is refused: there is no flag blacklist.
use crate::{
    error::{SecResult, SecurityError},
    util::clip,
};
use regex::Regex;
use std::collections::{HashMap, HashSet};

pub type Validator = Box<dyn Fn(&str) -> SecResult<String> + Send + Sync>;

fn deny(code: &str, reason: String) -> SecurityError {
    SecurityError::command(code, reason)
}

pub fn int_between(lower_bound: i64, higher_bound: i64, signed: bool) -> Validator {
    let regex = Regex::new(if signed {
        r"^[+-]?[0-9]{1,9}$"
    } else {
        r"^[0-9]{1,9}$"
    })
    .unwrap();

    Box::new(move |value: &str| {
        if !regex.is_match(value) {
            return Err(deny(
                "bad_argument",
                format!("expected an integer, got {:?}", clip(value, 20)),
            ));
        }

        let n = value.parse::<i64>().map(i64::abs).unwrap_or(i64::MAX);
        if n < lower_bound || n > higher_bound {
            return Err(deny(
                "argument_out_of_range",
                format!("value out of the bound limits [{lower_bound}, {higher_bound}]"),
            ));
        }

        Ok(value.to_string())
    })
}

pub fn regex_value(pattern: &str, what: &str) -> Validator {
    let regex = Regex::new(&format!("^(?:{pattern})$")).unwrap();
    let what = what.to_string();

    Box::new(move |value: &str| {
        if regex.is_match(value) {
            Ok(value.to_string())
        } else {
            Err(deny("bad_argument", format!("{what} is invalid")))
        }
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Positional {
    Paths,
    RevsThenPaths,
    NoneAllowed,
}

pub struct Spec {
    pub flags: HashSet<String>,
    pub cluster: HashSet<char>,
    pub valued: HashMap<String, Validator>,
    pub numeric_short: Option<Validator>,
    pub positional: Positional,
    pub min_positional: usize,
    pub max_positional: usize,
}

impl Spec {
    pub fn new(positional: Positional) -> Spec {
        Spec {
            flags: HashSet::new(),
            cluster: HashSet::new(),
            valued: HashMap::new(),
            numeric_short: None,
            positional,
            min_positional: 0,
            max_positional: 50,
        }
    }

    pub fn flags(mut self, flags: &[&str]) -> Self {
        self.flags.extend(flags.iter().map(|flag| flag.to_string()));
        self
    }

    pub fn cluster(mut self, letters: &str) -> Self {
        self.cluster.extend(letters.chars());
        self
    }

    pub fn valued(mut self, name: &str, validator: Validator) -> Self {
        self.valued.insert(name.to_string(), validator);
        self
    }

    pub fn numeric(mut self, validator: Validator) -> Self {
        self.numeric_short = Some(validator);
        self
    }

    pub fn min(mut self, n: usize) -> Self {
        self.min_positional = n;
        self
    }

    pub fn max(mut self, n: usize) -> Self {
        self.max_positional = n;
        self
    }
}

#[derive(Debug, Default, Clone)]
pub struct Parsed {
    pub flags: Vec<String>,
    pub revs: Vec<String>,
    pub paths: Vec<String>,
    pub saw_double_dash: bool,
}

pub fn parse_args(spec: &Spec, tokens: &[String], cmd: &str) -> SecResult<Parsed> {
    let mut out = Parsed::default();

    let (mut index, n, mut after_dd) = (0usize, tokens.len(), false);
    while index < n {
        let token = tokens[index].as_str();

        if after_dd {
            out.paths.push(token.to_string());
            index += 1;
            continue;
        }

        if token == "--" {
            after_dd = true;
            out.saw_double_dash = true;
            index += 1;
            continue;
        }

        if token.starts_with("--") {
            let (name, eq, val) = match token.find('=') {
                Some(p) => (&token[..p], true, &token[p + 1..]),
                None => (token, false, ""),
            };

            if spec.flags.contains(token) {
                out.flags.push(token.to_string());
            } else if let Some(v) = spec.valued.get(name) {
                let val = if eq {
                    val.to_string()
                } else {
                    index += 1;

                    if index >= n {
                        return Err(deny(
                            "missing_value",
                            format!("{cmd}: missing value for {name}"),
                        ));
                    }

                    tokens[index].clone()
                };
                out.flags.push(format!("{name}={}", v(&val)?));
            } else {
                return Err(deny(
                    "flag_not_allowed",
                    format!("{cmd}: unauthorized option {name}"),
                ));
            }
        } else if token.starts_with('-') && token.len() > 1 {
            let rest = &token[1..];
            let first = format!("-{}", rest.chars().next().unwrap());

            if spec.flags.contains(token) {
                out.flags.push(token.to_string());
            } else if let Some(v) = spec.valued.get(token) {
                index += 1;

                if index >= n {
                    return Err(deny(
                        "missing_value",
                        format!("{cmd}: missing value for {token}"),
                    ));
                }

                out.flags.push(token.to_string());
                out.flags.push(v(&tokens[index])?);
            } else if spec.numeric_short.is_some() && rest.chars().all(|c| c.is_ascii_digit()) {
                out.flags.push(format!(
                    "-{}",
                    (spec.numeric_short.as_ref().unwrap())(rest)?
                ));
            } else if token.chars().count() > 2
                && spec.valued.contains_key(&first)
                && !rest.chars().all(|c| c.is_ascii_digit())
            {
                let fn_val = &spec.valued[&first];
                let attached: String = rest.chars().skip(1).collect();
                out.flags.push(first.clone());
                out.flags.push(fn_val(&attached)?);
            } else if !rest.is_empty() && rest.chars().all(|c| spec.cluster.contains(&c)) {
                out.flags.push(token.to_string());
            } else {
                return Err(deny(
                    "flag_not_allowed",
                    format!(
                        "{cmd}: unauthorized option {}",
                        crate::util::clip(token, 20)
                    ),
                ));
            }
        } else {
            match spec.positional {
                Positional::NoneAllowed => {
                    return Err(deny(
                        "positional_not_allowed",
                        format!("{cmd}: not expected argument"),
                    ))
                }
                Positional::RevsThenPaths => out.revs.push(token.to_string()),
                Positional::Paths => out.paths.push(token.to_string()),
            }
        }
        index += 1;
    }

    let count = out.paths.len() + out.revs.len();

    if count < spec.min_positional {
        return Err(deny(
            "missing_argument",
            format!(
                "{cmd}: at least {} argument(s) required",
                spec.min_positional
            ),
        ));
    }

    if count > spec.max_positional {
        return Err(deny(
            "too_many_arguments",
            format!("{cmd}: too much arguments (max {})", spec.max_positional),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn t(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }
    fn ls() -> Spec {
        Spec::new(Positional::Paths)
            .flags(&["-l", "-a", "--color=never"])
            .cluster("lahR")
            .max(3)
    }
    #[test]
    fn clusters_and_unknown_flags() {
        assert_eq!(
            parse_args(&ls(), &t("-la src"), "ls").unwrap().flags,
            vec!["-la"]
        );
        assert_eq!(
            parse_args(&ls(), &t("-lz"), "ls").unwrap_err().code,
            "flag_not_allowed"
        );
        assert_eq!(
            parse_args(&ls(), &t("--delete"), "ls").unwrap_err().code,
            "flag_not_allowed"
        );
        assert_eq!(
            parse_args(&ls(), &t("a b c d"), "ls").unwrap_err().code,
            "too_many_arguments"
        );
    }
    #[test]
    fn valued_flags() {
        let s = Spec::new(Positional::Paths)
            .valued("-n", int_between(1, 100, true))
            .valued("--lines", int_between(1, 100, true))
            .numeric(int_between(1, 100, false));
        assert_eq!(
            parse_args(&s, &t("-n 5 f"), "head").unwrap().flags,
            vec!["-n", "5"]
        );
        assert_eq!(
            parse_args(&s, &t("-n5 f"), "head").unwrap().flags,
            vec!["-n", "5"]
        );
        assert_eq!(
            parse_args(&s, &t("--lines=7"), "head").unwrap().flags,
            vec!["--lines=7"]
        );
        assert_eq!(parse_args(&s, &t("-5"), "log").unwrap().flags, vec!["-5"]);
        assert_eq!(
            parse_args(&s, &t("-n 101"), "head").unwrap_err().code,
            "argument_out_of_range"
        );
        assert_eq!(
            parse_args(&s, &t("-n"), "head").unwrap_err().code,
            "missing_value"
        );
        assert_eq!(
            parse_args(&s, &t("-n abc"), "head").unwrap_err().code,
            "bad_argument"
        );
    }
}
