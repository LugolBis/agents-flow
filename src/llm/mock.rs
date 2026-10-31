use crate::llm::core::{Completion, Llm, LlmError, Message};
use crate::schema::OutputSchema;
use crate::security::runtime::ToolDef;

use std::collections::VecDeque;
use std::result;
use std::sync::Mutex;

/// Deterministic LLM for tests: pops scripted completions.
pub struct ScriptedLlm {
    pub script: Mutex<VecDeque<Completion>>,
    pub native: bool,
    pub seen: Mutex<Vec<Vec<Message>>>,
    /// Answers for `complete_structured` (when empty, falls back to `script` like the trait default); `structured_seen` records schema names.
    pub structured: Mutex<VecDeque<Completion>>,
    pub structured_seen: Mutex<Vec<String>>,
}

impl ScriptedLlm {
    pub fn new(native: bool, script: Vec<Completion>) -> Self {
        Self {
            script: Mutex::new(script.into()),
            native,
            seen: Mutex::new(vec![]),
            structured: Mutex::new(VecDeque::new()),
            structured_seen: Mutex::new(vec![]),
        }
    }

    pub fn with_structured(self, answers: Vec<Completion>) -> Self {
        *self.structured.lock().unwrap() = answers.into();
        self
    }
}

impl Llm for ScriptedLlm {
    fn complete(
        &self,
        msgs: &[Message],
        _t: &[ToolDef],
        _s: &[&str],
    ) -> result::Result<Completion, LlmError> {
        self.seen.lock().unwrap().push(msgs.to_vec());
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| LlmError::Fatal("LLM script exhausted".into()))
    }

    fn complete_structured(
        &self,
        msgs: &[Message],
        schema: &OutputSchema,
    ) -> result::Result<Completion, LlmError> {
        self.structured_seen
            .lock()
            .unwrap()
            .push(schema.name.clone());
        self.seen.lock().unwrap().push(msgs.to_vec());

        match self.structured.lock().unwrap().pop_front() {
            Some(completion) => Ok(completion),
            None => self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| LlmError::Fatal("LLM script exhausted".into())),
        }
    }

    fn native_tools(&self) -> bool {
        self.native
    }

    fn context_tokens(&self) -> usize {
        100_000
    }

    fn describe(&self) -> String {
        "scripted".into()
    }
}
