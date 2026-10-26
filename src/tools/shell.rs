//! Shell inspection tool: ONE tool backed by `CommandPolicy`. It is not a shell: no composition, redirection, substitution or command
//! outside the allowlist. Its permissions are independent of the developer agent's.
use crate::util::clip;

use super::schema::{ArgSchema, Field};
use super::Tool;

tool!(ShellInspectTool, "shell_inspect", "agents_flow.tools.shell.ShellInspectTool", ["shell.inspect"],
    "Read-only inspection. Permitted commands: pwd, ls, find (excluding -exec/-delete), cat, head, tail, file, stat, and git status|log|diff|show|ls-files|branch (listing). No command chaining or composition (using ;, |, &&, >, or $()) is allowed; no deletion or writing operations are permitted. Any other command will be rejected before execution.",
    ArgSchema(vec![Field::str("command", 1000).desc("A simple command, e.g., `ls -la`, `find . -name '*.py' -maxdepth 3`, `git log --oneline -5`."), Field::str("cwd", 1024).opt().desc("Working file within the authorized scope.")]),
    |ctx, a| {
        let res = ctx.rt.commands.run(a.str("command"), a.opt_str("cwd"))?;
        let mut body = if res.text.trim().is_empty() { "(no output)".to_string() } else { res.text.clone() };
        if res.exit_code != 0 && res.exit_code != 1 { body.push_str(&format!("\n[exit status code {}]", res.exit_code)); }
        Ok(ctx.untrusted(&body, &format!("shell:{}", clip(a.str("command"), 60))))
    });

pub fn tools() -> Vec<Box<dyn Tool>> {
    vec![Box::new(ShellInspectTool)]
}
