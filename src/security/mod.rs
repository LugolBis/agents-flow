//! Guards: filesystem boundary, secrets, audit, command policy (no shell), Git, network (SSRF), runtime assembly.
pub mod argspec;
pub mod audit;
pub mod builtins;
pub mod commands;
pub mod git_guard;
pub mod network;
pub mod path_guard;
pub mod runner;
pub mod runtime;
pub mod safe_io;
pub mod secrets;
pub mod untrusted;
