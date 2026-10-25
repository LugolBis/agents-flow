//! The 35 agent tools. Every call goes through the same template, independent of the LLM:
//!  1. `authorize(agent, tool)` … (doc inchangée)

pub mod core;
pub use core::*;

pub mod schema;

#[macro_use]
mod macros {
    /// Declares a tool: id, capabilities, description, schema, body.
    macro_rules! tool {
        ($name:ident, $id:literal, $class:literal, [$($cap:literal),*], $desc:expr, $schema:expr, |$ctx:ident, $a:ident| $body:block) => {
            pub struct $name;
            impl $crate::tools::Tool for $name {
                fn id(&self) -> &'static str { $id }
                fn class_path(&self) -> &'static str { $class }
                fn caps(&self) -> &'static [&'static str] { &[$($cap),*] }
                fn description(&self) -> &'static str { $desc }
                fn schema(&self) -> $crate::tools::schema::ArgSchema { $schema }
                #[allow(unused_variables)]
                fn execute(&self, $ctx: &$crate::tools::ToolContext, $a: &$crate::tools::schema::Args) -> $crate::error::Result<String> $body
            }
        };
    }
}

pub mod documents;
pub mod extract;
pub mod fs;
pub mod git_tools;
pub mod github;
pub mod project;
pub mod shell;
pub mod tests_runner;
pub mod web;
pub mod xml;
