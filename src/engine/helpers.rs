use crate::engine::protocol::{extract_json, ASK_QUESTION};
use crate::security::runtime::ToolDef;
use crate::util::clip;
use crate::{engine::models::Step, llm::Message};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const DELEGATE_WORK: &str = "delegate_work_to_coworker";
pub type Delegate<'a> = &'a dyn Fn(&str, &str, &str, &str) -> String;

static ACTION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)Action:\s*([^\n]+?)\s*\n\s*Action Input:\s*(.*)").unwrap());

static FINAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)Final Answer:\s*(.*)").unwrap());

pub fn parse_react(text: &str) -> Step {
    let (action_opt, final_regex) = (ACTION_RE.find(text), FINAL_RE.find(text));

    if let Some(action_regex) = action_opt {
        if final_regex
            .map(|regex| action_regex.start() < regex.start())
            .unwrap_or(true)
        {
            let matched = ACTION_RE.captures(text).unwrap();
            let name = matched[1]
                .trim()
                .trim_matches(['`', '"', '\'', '*'])
                .to_string();

            let raw = extract_json(&matched[2]);
            return Step::Action {
                name,
                input: serde_json::from_str(&raw).unwrap_or(Value::String(raw)),
            };
        }
    }

    match FINAL_RE.captures(text) {
        Some(matched) => Step::Final(matched[1].trim().to_string()),
        None => Step::Final(text.trim().to_string()),
    }
}

pub fn tokens_count(messages: &[Message]) -> usize {
    messages
        .iter()
        .map(|message| {
            message.content.chars().count() / 4
                + 6
                + message
                    .tool_calls
                    .iter()
                    .map(|tool_call| tool_call.arguments.to_string().len() / 4 + 8)
                    .sum::<usize>()
        })
        .sum()
}

/// Keeps the conversation under the context budget: clip old observations, then drop the oldest exchange groups.
pub fn fit_context(messages: &mut Vec<Message>, budget: usize) {
    if tokens_count(messages) <= budget {
        return;
    }

    let msgs_len = messages.len();
    for message in messages.iter_mut().take(msgs_len.saturating_sub(4)).skip(2) {
        if (message.role == "tool" || message.role == "user")
            && message.content.chars().count() > 600
        {
            message.content = format!(
                "{}\n[... truncated observation to respect the context]",
                clip(&message.content, 500)
            );
        }
    }

    let mut dropped = 0;
    while tokens_count(messages) > budget && messages.len() > 8 {
        let mut end = 3;
        if messages[2].role == "assistant" {
            while end < messages.len() - 4 && messages[end].role == "tool" {
                end += 1;
            }
        }
        messages.drain(2..end);
        dropped += 1;
    }
    if dropped > 0 {
        messages.insert(2, Message::user("[... earlier exchanges have been removed to stay within the context size limit; please resume from the remaining information]"));
    }
}

pub fn delegation_defs() -> Vec<ToolDef> {
    let common = |what: &str| json!({"type": "object", "properties": {"coworker": {"type": "string", "description": "Identifier of the agent."}, what: {"type": "string"}, "context": {"type": "string", "description": "All relevant context (the agent sees nothing else)."}}, "required": ["coworker", what, "context"], "additionalProperties": false});
    vec![
        ToolDef {
            name: DELEGATE_WORK.into(),
            description: "Delegates a complete task to a work agent and returns its result.".into(),
            schema: common("task"),
        },
        ToolDef {
            name: ASK_QUESTION.into(),
            description: "Ask a specific question to a work agent and return their response."
                .into(),
            schema: common("question"),
        },
    ]
}
