//! Validation schemas. Unknown keys are rejected everywhere (`deny_unknown_fields`): a typo in a security policy must fail at startup.
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::marker::PhantomData;

/// Insertion-ordered string-keyed map (JSON object order is meaningful for display and for planning).
#[derive(Debug, Clone)]
pub struct OMap<T>(pub Vec<(String, T)>);

impl<T> Default for OMap<T> {
    fn default() -> Self {
        OMap(Vec::new())
    }
}

impl<T> OMap<T> {
    pub fn get(&self, k: &str) -> Option<&T> {
        self.0.iter().find(|(n, _)| n == k).map(|(_, v)| v)
    }
    pub fn contains_key(&self, k: &str) -> bool {
        self.get(k).is_some()
    }
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.iter().map(|(k, _)| k)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&String, &T)> {
        self.0.iter().map(|(k, v)| (k, v))
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OMap<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = OMap<T>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<OMap<T>, A::Error> {
                let mut v = Vec::new();
                while let Some((k, x)) = a.next_entry::<String, T>()? {
                    v.push((k, x));
                }
                Ok(OMap(v))
            }
        }
        d.deserialize_map(V(PhantomData))
    }
}
