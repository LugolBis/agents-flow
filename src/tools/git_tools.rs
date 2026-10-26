//! Local Git tools. Read (`git.read`) and local write (`git.write_local`) are DISTINCT tools and capabilities backed by two distinct
//! classes (GitReader / GitLocalWriter). There is no push / fetch / merge / delete / reset tool. Returned content (commit messages,
//! diffs, files) is untrusted.
use super::schema::{ArgSchema, Field};
use super::Tool;
use serde_json::json;

fn path_f() -> Field {
    Field::str("path", 1024)
        .default(json!("."))
        .desc("Repository folder (or a file/folder within the repository).")
}

tool!(
    GitInfoTool,
    "git_info",
    "agents_flow.tools.git_tools.GitInfoTool",
    ["git.read"],
    "Root, current branch, HEAD, and remotes (local configuration) of a local repository.",
    ArgSchema(vec![path_f()]),
    |ctx, a| { Ok(ctx.rt.git_reader.info(a.str("path"))?) }
);

tool!(
    GitStatusTool,
    "git_status",
    "agents_flow.tools.git_tools.GitStatusTool",
    ["git.read"],
    "Status of the local repository (git status --porcelain).",
    ArgSchema(vec![path_f()]),
    |ctx, a| { Ok(ctx.rt.git_reader.status(a.str("path"))?) }
);

tool!(
    GitLogTool,
    "git_log",
    "agents_flow.tools.git_tools.GitLogTool",
    ["git.read"],
    "Commit history (hash, author, date, subject), optionally limited to a single file.",
    ArgSchema(vec![
        path_f(),
        Field::str("rev", 200).default(json!("HEAD")),
        Field::int("max_count", 1, 200).default(json!(20)),
        Field::str("file", 1024).opt()
    ]),
    |ctx, a| {
        let t = ctx.rt.git_reader.log(
            a.str("path"),
            a.str("rev"),
            a.int("max_count"),
            a.opt_str("file"),
        )?;
        Ok(ctx.untrusted(&t, &format!("git:{}", a.str("path"))))
    }
);

tool!(
    GitDiffTool,
    "git_diff",
    "agents_flow.tools.git_tools.GitDiffTool",
    ["git.read"],
    "Differences (working tree, index, or between two revisions). Secret files are excluded.",
    ArgSchema(vec![
        path_f(),
        Field::str("rev_a", 200).opt(),
        Field::str("rev_b", 200).opt(),
        Field::bool("cached").default(json!(false)),
        Field::bool("stat_only").default(json!(false)),
        Field::str("file", 1024).opt()
    ]),
    |ctx, a| {
        let t = ctx.rt.git_reader.diff(
            a.str("path"),
            a.opt_str("rev_a"),
            a.opt_str("rev_b"),
            a.bool("cached"),
            a.bool("stat_only"),
            a.opt_str("file"),
        )?;
        Ok(ctx.untrusted(&t, &format!("git:{}", a.str("path"))))
    }
);

tool!(
    GitShowTool,
    "git_show",
    "agents_flow.tools.git_tools.GitShowTool",
    ["git.read"],
    "Details of a commit (message, statistics, or full diff).",
    ArgSchema(vec![
        path_f(),
        Field::str("rev", 200).default(json!("HEAD")),
        Field::bool("stat_only").default(json!(true))
    ]),
    |ctx, a| {
        let t = ctx
            .rt
            .git_reader
            .show_commit(a.str("path"), a.str("rev"), a.bool("stat_only"))?;
        Ok(ctx.untrusted(&t, &format!("git:{}", a.str("path"))))
    }
);

tool!(
    GitShowFileTool,
    "git_show_file",
    "agents_flow.tools.git_tools.GitShowFileTool",
    ["git.read"],
    "Contents of a file at a given revision (git show rev:file).",
    ArgSchema(vec![
        path_f(),
        Field::str("rev", 200),
        Field::str("file", 1024)
    ]),
    |ctx, a| {
        let t = ctx
            .rt
            .git_reader
            .show_file(a.str("path"), a.str("rev"), a.str("file"))?;
        Ok(ctx.untrusted(
            &t,
            &format!("git:{}@{}:{}", a.str("path"), a.str("rev"), a.str("file")),
        ))
    }
);

tool!(
    GitLsFilesTool,
    "git_ls_files",
    "agents_flow.tools.git_tools.GitLsFilesTool",
    ["git.read"],
    "List the files tracked by Git.",
    ArgSchema(vec![path_f(), Field::str("subpath", 1024).opt()]),
    |ctx, a| {
        Ok(ctx
            .rt
            .git_reader
            .ls_files(a.str("path"), a.opt_str("subpath"))?)
    }
);

tool!(
    GitBranchesTool,
    "git_branches",
    "agents_flow.tools.git_tools.GitBranchesTool",
    ["git.read"],
    "List local branches.",
    ArgSchema(vec![path_f()]),
    |ctx, a| { Ok(ctx.rt.git_reader.branches(a.str("path"))?) }
);

// ------------------------------- LOCAL WRITES (3 only) -------------------------------
tool!(
    GitCreateBranchTool,
    "git_create_branch",
    "agents_flow.tools.git_tools.GitCreateBranchTool",
    ["git.write_local"],
    "Create a LOCAL branch (without remote tracking).",
    ArgSchema(vec![
        path_f(),
        Field::str("name", 100).desc("Name of the new local branch (letters, numbers, . _ / -)."),
        Field::str("start", 200).default(json!("HEAD"))
    ]),
    |ctx, a| {
        Ok(ctx
            .rt
            .git_writer
            .create_branch(a.str("path"), a.str("name"), a.str("start"))?)
    }
);

tool!(
    GitSwitchBranchTool,
    "git_switch_branch",
    "agents_flow.tools.git_tools.GitSwitchBranchTool",
    ["git.write_local"],
    "Switch to an existing LOCAL branch (rejected if any tracked changes are uncommitted).",
    ArgSchema(vec![path_f(), Field::str("name", 100)]),
    |ctx, a| {
        Ok(ctx
            .rt
            .git_writer
            .switch_branch(a.str("path"), a.str("name"))?)
    }
);

tool!(GitCommitTool, "git_commit", "agents_flow.tools.git_tools.GitCommitTool", ["git.write_local"],
    "Creates a LOCAL commit containing exactly the listed files. Operation is rejected on protected branches (main/master), in a detached HEAD state, if the index is not empty, or if a secret file—or a secret—is detected in the diff. No push is performed.",
    ArgSchema(vec![path_f(), Field::str("message", 2000).min(1), Field::list("files", 50, 1024).desc("Files to be committed, relative to the repository root. Never « everything ».")]),
    |ctx, a| { Ok(ctx.rt.git_writer.commit(a.str("path"), a.str("message"), &a.list("files"))?) });

pub fn tools() -> Vec<Box<dyn Tool>> {
    vec![
        Box::new(GitInfoTool),
        Box::new(GitStatusTool),
        Box::new(GitLogTool),
        Box::new(GitDiffTool),
        Box::new(GitShowTool),
        Box::new(GitShowFileTool),
        Box::new(GitLsFilesTool),
        Box::new(GitBranchesTool),
        Box::new(GitCreateBranchTool),
        Box::new(GitSwitchBranchTool),
        Box::new(GitCommitTool),
    ]
}
