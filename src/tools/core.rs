//! Shared types, register and entrypoint for tools call.
use crate::error::{Error, Result};
use crate::security::audit::Rec;
use crate::security::runtime::{SecurityRuntime, ToolOutcome};
use crate::security::untrusted::wrap_untrusted;
use crate::tools::schema::{ArgSchema, Args};
use crate::util::clip;
use serde_json::Value;
use std::panic;
use std::sync::LazyLock;

pub const MAX_OUTPUT_CHARS: usize = 60_000;

pub trait Tool: Send + Sync {
    fn id(&self) -> &'static str;
    fn class_path(&self) -> &'static str;
    fn caps(&self) -> &'static [&'static str];
    fn description(&self) -> &'static str;
    fn schema(&self) -> ArgSchema;
    fn execute(&self, ctx: &ToolContext, args: &Args) -> Result<String>;
}

pub struct Entry {
    pub tool: Box<dyn Tool>,
    pub schema: ArgSchema,
}

pub struct ToolContext<'a> {
    pub agent_id: &'a str,
    pub tool_id: &'a str,
    pub rt: &'a SecurityRuntime,
}

impl ToolContext<'_> {
    /// Frames external content as data and audits a «flag» event when it looks like an injection attempt.
    pub fn untrusted(&self, content: &str, source: &str) -> String {
        let (wrapped, hits) = wrap_untrusted(content, source);
        if !hits.is_empty() {
            self.rt.audit.record(Rec {
                agent: self.agent_id,
                tool: self.tool_id,
                decision: "flag",
                resource: Some(source),
                code: Some("possible_prompt_injection"),
                reason: Some(&format!("{} index(s) in the external content", hits.len())),
                ..Default::default()
            });
        }
        wrapped
    }
}

static REGISTRY: LazyLock<Vec<Entry>> = LazyLock::new(|| {
    let mut tools: Vec<Box<dyn Tool>> = Vec::new();
    tools.extend(super::fs::tools());
    tools.extend(super::documents::tools());
    tools.extend(super::git_tools::tools());
    tools.extend(super::github::tools());
    tools.extend(super::project::core::tools());
    tools.extend(super::shell::tools());
    tools.extend(super::tests_runner::tools());
    tools.extend(super::web::tools());
    tools
        .into_iter()
        .map(|tool| {
            let schema = tool.schema();
            Entry { tool, schema }
        })
        .collect()
});

pub fn all() -> &'static [Entry] {
    &REGISTRY
}

pub fn find(id: &str) -> Option<&'static Entry> {
    REGISTRY.iter().find(|entry| entry.tool.id() == id)
}

/// Config <-> code consistency: id, class path, capabilities. Any divergence is an error (fail closed).
pub fn verify_registry(security_runtime: &SecurityRuntime) -> Result<()> {
    for (tool_id, spec) in security_runtime.settings.tools.tools.iter() {
        let entry = find(tool_id)
            .filter(|entry_| entry_.tool.class_path() == spec.class_path)
            .ok_or(Error::config(format!(
                "{tool_id}: class '{}' untraceable or divergent id",
                spec.class_path
            )))?;

        let (mut cfg, mut code): (Vec<&str>, Vec<&str>) = (
            spec.capabilities.iter().map(String::as_str).collect(),
            entry.tool.caps().to_vec(),
        );

        cfg.sort();
        code.sort();
        cfg.dedup();
        code.dedup();

        if cfg != code {
            return Err(Error::config(format!(
                "{tool_id}: divergent capacities (config {cfg:?} / code {code:?})"
            )));
        }
    }
    Ok(())
}

fn resource_of(tool_id: &str, args: &Value) -> Option<String> {
    if let (Some(owner), Some(repo)) = (
        args.get("owner").and_then(Value::as_str),
        args.get("repo").and_then(Value::as_str),
    ) {
        return Some(format!(
            "{owner}/{repo}{}",
            args.get("path")
                .and_then(Value::as_str)
                .filter(|path| !path.is_empty())
                .map(|path| format!(":{path}"))
                .unwrap_or_default()
        ));
    }

    let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
    match tool_id {
        "git_create_branch" | "git_switch_branch" => {
            return Some(format!(
                "{path}#{}",
                args.get("name").and_then(Value::as_str).unwrap_or("")
            ))
        }
        "git_commit" => {
            return Some(format!(
                "{path} ({} file(s))",
                args.get("files")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0)
            ))
        }
        _ => {}
    }

    if let (Some(a), Some(b)) = (
        args.get("path_a").and_then(Value::as_str),
        args.get("path_b").and_then(Value::as_str),
    ) {
        return Some(format!("{a} <> {b}"));
    }

    ["path", "url", "command", "query", "repo"]
        .iter()
        .find_map(|key| {
            args.get(key)
                .filter(|value| !value.is_null())
                .map(|value| match value {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                })
        })
}

pub fn call(
    sec_runtime: &SecurityRuntime,
    agent_id: &str,
    tool_id: &str,
    raw: &Value,
) -> ToolOutcome {
    let resource = resource_of(tool_id, raw);
    let res = resource.as_deref();

    let fn_deny = |code: &str, reason: &str, msg: String| {
        sec_runtime.audit.record(Rec {
            agent: agent_id,
            tool: tool_id,
            decision: "deny",
            resource: res,
            code: Some(code),
            reason: Some(reason),
            ..Default::default()
        });

        ToolOutcome::Failure {
            message: msg,
            code: code.to_string(),
        }
    };

    let Some(entry) = find(tool_id) else {
        return fn_deny(
            "unknown_tool",
            &format!("outil inconnu : {tool_id}"),
            format!("REJECTED by security policy: unknown tool: {tool_id}"),
        );
    };

    if let Err(err) = sec_runtime.policy.authorize(agent_id, tool_id) {
        return fn_deny(
            &err.code,
            &err.reason,
            format!("REJECTED by the security policy : {}", err.reason),
        );
    }

    let args = match entry.schema.validate(raw) {
        Ok(args_) => args_,
        Err(msg) => {
            return fn_deny(
                "invalid_arguments",
                &msg,
                format!("invalid arguments for this tool : {msg}"),
            )
        }
    };

    let ctx = ToolContext {
        agent_id,
        tool_id,
        rt: sec_runtime,
    };

    let outcome = panic::catch_unwind(panic::AssertUnwindSafe(|| entry.tool.execute(&ctx, &args)));

    let out = match outcome {
        Ok(res) => res,
        Err(_) => Err(Error::internal("Panic", "internal panic of the tool")),
    };

    match out {
        Err(Error::Security(err)) => fn_deny(
            &err.code,
            &err.reason,
            format!("REJECTED by the security policy : {}", err.reason),
        ),
        Err(Error::InvalidArgs(msg)) => fn_deny(
            "invalid_arguments",
            &msg,
            format!("invalid arguments for this tool : {msg}"),
        ),
        Err(err) => {
            let kind = match &err {
                Error::Internal { kind, .. } => kind.clone(),
                _ => "Error".into(),
            };
            sec_runtime.audit.record(Rec {
                agent: agent_id,
                tool: tool_id,
                decision: "error",
                resource: res,
                code: Some(&kind),
                ..Default::default()
            });
            ToolOutcome::Failure {
                message: format!("tool failure ({kind}) ; the operation was not successful"),
                code: "tool_error".into(),
            }
        }
        Ok(text) => {
            let text = sec_runtime.redactor.redact(&text).into_owned();
            let text = if text.chars().count() > MAX_OUTPUT_CHARS {
                format!("{}\n[truncated output]", clip(&text, MAX_OUTPUT_CHARS))
            } else {
                text
            };

            sec_runtime.audit.record(Rec {
                agent: agent_id,
                tool: tool_id,
                decision: "allow",
                resource: res,
                result: Some(&format!("{} chars", text.chars().count())),
                ..Default::default()
            });
            ToolOutcome::Ok(text)
        }
    }
}
