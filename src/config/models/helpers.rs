use crate::config::models::tools::*;
use crate::error::{Error, Result};
use regex::Regex;
use serde::{Deserialize, Deserializer};
use std::collections::BTreeSet;
use std::fmt::Display;
use std::str::FromStr;

pub fn bad(field: &str, why: &str) -> Error {
    Error::config(format!("invalid configuration : {field} {why}"))
}

pub fn ge(field: &str, val: i64, lower_bound: i64) -> Result<()> {
    if val < lower_bound {
        Err(bad(
            field,
            &format!("should be ≥ {lower_bound} (received {val})"),
        ))
    } else {
        Ok(())
    }
}

pub fn between(field: &str, val: i64, lower_bound: i64, higher_bound: i64) -> Result<()> {
    if val < lower_bound || val > higher_bound {
        Err(bad(
            field,
            &format!("should be between {lower_bound} and {higher_bound} (received {val})"),
        ))
    } else {
        Ok(())
    }
}

pub fn gt_le(field: &str, val: f64, higher_bound: f64) -> Result<()> {
    if !(val > 0.0 && val <= higher_bound) {
        Err(bad(
            field,
            &format!("should be in the interval ]0, {higher_bound}] (received {val})"),
        ))
    } else {
        Ok(())
    }
}

pub fn lit(field: &str, val: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&val) {
        Ok(())
    } else {
        Err(bad(
            field,
            &format!("set of accepted values {allowed:?} (received '{val}')"),
        ))
    }
}

pub fn pat(field: &str, val: &str, regex: &str) -> Result<()> {
    if Regex::new(regex).unwrap().is_match(val) {
        Ok(())
    } else {
        Err(bad(field, &format!("don't respect the regex {regex}")))
    }
}

pub fn unknown_caps(field: &str, caps: &[String]) -> Result<()> {
    let unknown_caps: BTreeSet<&String> = caps
        .iter()
        .filter(|c| !CAPABILITIES.contains(&c.as_str()))
        .collect();
    if unknown_caps.is_empty() {
        Ok(())
    } else {
        Err(bad(field, &format!("unknown capacity : {unknown_caps:?}")))
    }
}

pub fn lm_url() -> String {
    "http://127.0.0.1:1234/v1".into()
}

pub fn so_auto() -> String {
    "auto".into()
}

pub fn lm_key() -> String {
    "lm-studio".into()
}

pub fn temp() -> f64 {
    0.2
}

pub fn tmo() -> f64 {
    300.0
}

pub fn ctx() -> usize {
    8192
}

pub fn one() -> u32 {
    1
}

pub fn deserialize_from_string_or_number<'de, D, T>(
    deserializer: D,
) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    let value = serde_json::Value::deserialize(deserializer)?;

    let text = match value {
        serde_json::Value::String(s) => s,
        serde_json::Value::Number(n) => n.to_string(),
        _ => {
            return Err(serde::de::Error::custom("expected a string or a number"));
        }
    };

    text.parse::<T>().map_err(serde::de::Error::custom)
}

pub fn deserialize_string_or_bool<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;

    match value {
        serde_json::Value::String(text) => text.parse::<bool>().map_err(serde::de::Error::custom),
        serde_json::Value::Bool(byte) => Ok(byte),
        _ => Err(serde::de::Error::custom("expected a string or a boolean")),
    }
}
