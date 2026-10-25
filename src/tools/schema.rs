//! Declarative argument schemas: one definition drives BOTH validation (unknown keys refused, lengths/ranges enforced, lax coercions
//! like the Pydantic original) AND the JSON Schema sent to the LLM for native tool calling.
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::util::clip;

#[derive(Clone)]
pub enum Kind {
    Str {
        min: usize,
        max: usize,
        pattern: Option<Regex>,
    },
    Int {
        min: i64,
        max: i64,
    },
    Bool,
    StrList {
        max_items: usize,
        item_max: usize,
    },
    StrMap {
        max_items: usize,
        key_max: usize,
        val_max: usize,
    },
    Objects {
        fields: Vec<Field>,
        min: usize,
        max: usize,
    },
}

#[derive(Clone)]
pub struct Field {
    pub name: &'static str,
    pub kind: Kind,
    pub required: bool,
    pub default: Option<Value>,
    pub desc: &'static str,
}

#[derive(Clone, Default)]
pub struct ArgSchema(pub Vec<Field>);

/// Validated arguments (defaults applied).
#[derive(Debug, Clone, Default)]
pub struct Args(pub Map<String, Value>);

impl Field {
    fn new(name: &'static str, kind: Kind) -> Field {
        Field {
            name,
            kind,
            required: true,
            default: None,
            desc: "",
        }
    }

    pub fn str(name: &'static str, max: usize) -> Field {
        Self::new(
            name,
            Kind::Str {
                min: 0,
                max,
                pattern: None,
            },
        )
    }

    pub fn int(name: &'static str, min: i64, max: i64) -> Field {
        Self::new(name, Kind::Int { min, max })
    }

    pub fn bool(name: &'static str) -> Field {
        Self::new(name, Kind::Bool)
    }

    pub fn list(name: &'static str, max_items: usize, item_max: usize) -> Field {
        Self::new(
            name,
            Kind::StrList {
                max_items,
                item_max,
            },
        )
    }

    pub fn map(name: &'static str, max_items: usize, key_max: usize, val_max: usize) -> Field {
        Self::new(
            name,
            Kind::StrMap {
                max_items,
                key_max,
                val_max,
            },
        )
    }

    pub fn objects(name: &'static str, fields: Vec<Field>, min: usize, max: usize) -> Field {
        Self::new(name, Kind::Objects { fields, min, max })
    }

    pub fn min(mut self, n: usize) -> Field {
        if let Kind::Str { min, .. } = &mut self.kind {
            *min = n;
        }
        self
    }

    pub fn pattern(mut self, rx: &str) -> Field {
        if let Kind::Str { pattern, .. } = &mut self.kind {
            *pattern = Some(Regex::new(rx).expect("schema regex"));
        }
        self
    }

    pub fn desc(mut self, d: &'static str) -> Field {
        self.desc = d;
        self
    }

    pub fn opt(mut self) -> Field {
        self.required = false;
        self
    }

    pub fn default(mut self, v: Value) -> Field {
        self.required = false;
        self.default = Some(v);
        self
    }
}

impl Args {
    pub fn opt_str(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(Value::as_str)
    }

    pub fn str(&self, key: &str) -> &str {
        self.opt_str(key).unwrap_or("")
    }

    pub fn opt_int(&self, key: &str) -> Option<i64> {
        self.0.get(key).and_then(Value::as_i64)
    }

    pub fn int(&self, key: &str) -> i64 {
        self.opt_int(key).unwrap_or(0)
    }

    pub fn bool(&self, key: &str) -> bool {
        self.0.get(key).and_then(Value::as_bool).unwrap_or(false)
    }

    pub fn list(&self, key: &str) -> Vec<String> {
        self.0
            .get(key)
            .and_then(Value::as_array)
            .map(|array| {
                array
                    .iter()
                    .filter_map(|value| value.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn map(&self, key: &str) -> Vec<(String, String)> {
        self.0
            .get(key)
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn objects(&self, key: &str) -> Vec<&Map<String, Value>> {
        self.0
            .get(key)
            .and_then(Value::as_array)
            .map(|array| array.iter().filter_map(Value::as_object).collect())
            .unwrap_or_default()
    }
}

fn coerce_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64().or_else(|| {
            number
                .as_f64()
                .filter(|float| float.fract() == 0.0 && float.abs() < 9e15)
                .map(|float| float as i64)
        }),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn check_kind(name: &str, kind: &Kind, value: &Value) -> Result<Value, String> {
    match kind {
        Kind::Str { min, max, pattern } => {
            let text = value.as_str().ok_or(format!("{name}: expected string"))?;
            let len = text.chars().count();

            if len < *min || len > *max {
                return Err(format!(
                    "{name}: len {len} is out of the bound limits [{min}, {max}]"
                ));
            }

            if let Some(regex) = pattern {
                if !regex.is_match(text) {
                    return Err(format!("{name}: invalid format"));
                }
            }

            Ok(value.clone())
        }
        Kind::Int { min, max } => {
            let number = coerce_int(value).ok_or(format!("{name}: expected an integer"))?;

            if number < *min || number > *max {
                return Err(format!(
                    "{name}: {number} is out of the bounds [{min}, {max}]"
                ));
            }

            Ok(json!(number))
        }
        Kind::Bool => match value {
            Value::Bool(_) => Ok(value.clone()),
            Value::String(text) if matches!(text.to_lowercase().as_str(), "true" | "1" | "yes") => {
                Ok(json!(true))
            }
            Value::String(text) if matches!(text.to_lowercase().as_str(), "false" | "0" | "no") => {
                Ok(json!(false))
            }
            Value::Number(number) if number.as_i64() == Some(0) || number.as_i64() == Some(1) => {
                Ok(json!(number.as_i64() == Some(1)))
            }
            _ => Err(format!("{name}: expected a boolean")),
        },
        Kind::StrList {
            max_items,
            item_max,
        } => {
            let array = value.as_array().ok_or(format!("{name}: expected a list"))?;

            if array.len() > *max_items {
                return Err(format!("{name}: too much elements (max {max_items})"));
            }

            for val in array {
                let text = val.as_str().ok_or(format!("{name}: expected a string"))?;
                if text.chars().count() > *item_max {
                    return Err(format!("{name}: content too long (max {item_max})"));
                }
            }
            Ok(value.clone())
        }
        Kind::StrMap {
            max_items,
            key_max,
            val_max,
        } => {
            let map = value
                .as_object()
                .ok_or(format!("{name}: expected an object"))?;

            if map.len() > *max_items {
                return Err(format!("{name}: too much inputs (max {max_items})"));
            }

            for (key, val) in map {
                let text = val.as_str().ok_or(format!("{name}: expected a string"))?;
                if key.chars().count() > *key_max || text.chars().count() > *val_max {
                    return Err(format!("{name}: input too long"));
                }
            }
            Ok(value.clone())
        }
        Kind::Objects { fields, min, max } => {
            let array = value.as_array().ok_or(format!("{name}: expected a list"))?;

            if array.len() < *min || array.len() > *max {
                return Err(format!(
                    "{name}: {} element(s), expected between {min} and {max}",
                    array.len()
                ));
            }

            let sub = ArgSchema(fields.clone());
            let mut out = Vec::new();

            for (index, val) in array.iter().enumerate() {
                out.push(Value::Object(
                    sub.validate(val)
                        .map_err(|err| format!("{name}[{index}].{err}"))?
                        .0,
                ));
            }
            Ok(Value::Array(out))
        }
    }
}

impl ArgSchema {
    pub fn validate(&self, value: &Value) -> Result<Args, String> {
        let obj = value.as_object().ok_or("JSON object expected")?;

        if let Some(key) = obj
            .keys()
            .find(|k| !self.0.iter().any(|field| field.name == k.as_str()))
        {
            return Err(format!("unknwon field : {}", clip(key, 40)));
        }

        let mut out = Map::new();
        for field in &self.0 {
            match obj.get(field.name) {
                None | Some(Value::Null) => {
                    if field.required {
                        return Err(format!("{}: field required", field.name));
                    }
                    out.insert(
                        field.name.to_string(),
                        field.default.clone().unwrap_or(Value::Null),
                    );
                }
                Some(val) => {
                    out.insert(
                        field.name.to_string(),
                        check_kind(field.name, &field.kind, val)?,
                    );
                }
            }
        }
        Ok(Args(out))
    }

    pub fn json_schema(&self) -> Value {
        let mut props = Map::new();
        let mut required = Vec::new();

        for field in &self.0 {
            let mut value = match &field.kind {
                Kind::Str { min, max, .. } => {
                    json!({"type": "string", "minLength": min, "maxLength": max})
                }
                Kind::Int { min, max } => {
                    json!({"type": "integer", "minimum": min, "maximum": max})
                }
                Kind::Bool => json!({"type": "boolean"}),
                Kind::StrList { max_items, .. } => {
                    json!({"type": "array", "items": {"type": "string"}, "maxItems": max_items})
                }
                Kind::StrMap { max_items, .. } => {
                    json!({"type": "object", "additionalProperties": {"type": "string"}, "maxProperties": max_items})
                }
                Kind::Objects { fields, min, max } => {
                    let val = ArgSchema(fields.clone()).json_schema();
                    json!({"type": "array", "items": val, "minItems": min, "maxItems": max})
                }
            };

            if !field.desc.is_empty() {
                value["description"] = json!(field.desc);
            }

            if let Some(d) = &field.default {
                value["default"] = d.clone();
            }

            props.insert(field.name.to_string(), value);
            if field.required {
                required.push(json!(field.name));
            }
        }
        json!({"type": "object", "properties": props, "required": required, "additionalProperties": false})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s() -> ArgSchema {
        ArgSchema(vec![
            Field::str("path", 10).min(1),
            Field::int("n", 1, 5).default(json!(2)),
            Field::bool("b").opt(),
            Field::list("l", 2, 3).opt(),
        ])
    }
    #[test]
    fn validation() {
        let a = s().validate(&json!({"path": "x", "n": "3"})).unwrap();
        assert_eq!((a.str("path"), a.int("n"), a.bool("b")), ("x", 3, false));
        assert_eq!(s().validate(&json!({"path": "x"})).unwrap().int("n"), 2);
        assert!(
            s().validate(&json!({"path": "x", "evil": 1})).is_err(),
            "extra keys forbidden"
        );
        assert!(s().validate(&json!({})).is_err());
        assert!(s().validate(&json!({"path": "x", "n": 9})).is_err());
        assert!(s().validate(&json!({"path": "x".repeat(11)})).is_err());
        assert!(s()
            .validate(&json!({"path": "x", "l": ["a", "b", "c"]}))
            .is_err());
        let js = s().json_schema();
        assert_eq!(js["required"], json!(["path"]));
        assert_eq!(js["additionalProperties"], json!(false));
    }
}
