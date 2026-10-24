//! JSONL audit log (one line = one security decision or operation). Values are clipped and passed through the redactor;
//! file CONTENT is never logged. Timestamps are UTC.
use crate::util::now_iso;

use super::secrets::SecretRedactor;
use serde_json::{Map, Value};
use std::fs::create_dir_all;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub type Event = Map<String, Value>;

pub struct AuditLogger {
    path: Option<PathBuf>,
    redactor: Arc<SecretRedactor>,
    max: usize,
    events: Mutex<Vec<Event>>,
}

#[derive(Default)]
pub struct Rec<'a> {
    pub agent: &'a str,
    pub tool: &'a str,
    pub decision: &'a str,
    pub resource: Option<&'a str>,
    pub code: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub result: Option<&'a str>,
    pub extra: Option<Event>,
}

impl AuditLogger {
    pub fn new(
        path: Option<PathBuf>,
        redactor: Arc<SecretRedactor>,
        max_field_chars: usize,
    ) -> Self {
        if let Some(p) = &path {
            if let Some(parent_dir) = p.parent() {
                let _ = create_dir_all(parent_dir);
            }
        }

        AuditLogger {
            path,
            redactor,
            max: max_field_chars,
            events: Mutex::new(Vec::new()),
        }
    }

    fn clip(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => {
                let text_ = self.redactor.redact(text);
                Value::String(if text_.chars().count() <= self.max {
                    text_.into_owned()
                } else {
                    format!("{}...[truncated]", crate::util::clip(&text_, self.max))
                })
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, val)| (key.clone(), self.clip(val)))
                    .collect(),
            ),
            Value::Array(array) => {
                Value::Array(array.iter().take(20).map(|elem| self.clip(elem)).collect())
            }
            other => other.clone(),
        }
    }

    fn append(&self, event: &Event) {
        let Some(path) = &self.path else { return };
        let mut line = serde_json::to_string(event).unwrap_or_default();
        line.push('\n');

        let mut opener = std::fs::OpenOptions::new();
        opener.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opener.mode(0o600);
        }

        if let Ok(mut file) = opener.open(path) {
            let _ = file.write_all(line.as_bytes());
        }
    }

    pub fn record(&self, rec: Rec) -> Event {
        let mut events = Event::new();
        events.insert("ts".into(), Value::String(now_iso()));
        events.insert("agent".into(), rec.agent.into());
        events.insert("tool".into(), rec.tool.into());
        events.insert("decision".into(), rec.decision.into());

        for (key, val_opt) in [
            ("resource", rec.resource),
            ("code", rec.code),
            ("reason", rec.reason),
            ("result", rec.result),
        ] {
            if let Some(value) = val_opt {
                events.insert(key.into(), value.into());
            }
        }

        if let Some(extra_map) = rec.extra {
            for (key, value) in extra_map {
                events.insert(key, value);
            }
        }

        let events_clipped: Event = events
            .iter()
            .map(|(key, value)| (key.clone(), self.clip(value)))
            .collect();

        let mut guard = self.events.lock().unwrap();
        guard.push(events_clipped.clone());
        self.append(&events_clipped);
        events_clipped
    }

    pub fn simple(
        &self,
        agent: &str,
        tool: &str,
        decision: &str,
        resource: Option<&str>,
        code: Option<&str>,
        reason: Option<&str>,
    ) {
        self.record(Rec {
            agent,
            tool,
            decision,
            resource,
            code,
            reason,
            ..Default::default()
        });
    }

    /// Adds an event produced elsewhere (WSL executor), already redacted there; redacted again locally to be safe.
    pub fn ingest(&self, event: &Event, origin: &str) {
        let mut event_cl = event.clone();
        event_cl.insert("origin".into(), origin.into());

        let event_clipped: Event = event_cl
            .iter()
            .map(|(key, value)| (key.clone(), self.clip(value)))
            .collect();

        self.events.lock().unwrap().push(event_clipped.clone());
        self.append(&event_clipped);
    }

    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn events_since(&self, start: usize) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .skip(start)
            .cloned()
            .collect()
    }

    pub fn denials(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.get("decision").and_then(Value::as_str) == Some("deny"))
            .cloned()
            .collect()
    }
}
