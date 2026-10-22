//! JSONC policy files: `permissions.jsonc`, `agents.jsonc`, `tools.jsonc`, optional `deployment.jsonc`.
pub mod jsonc;
pub mod loader;
pub mod models;
pub use loader::{Settings, ORCHESTRATOR_ID};
pub use models::*;
