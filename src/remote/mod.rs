//! Optional WSL backend: the agent loop runs on the host (e.g. native Windows 11 ARM64), ALL tools run in a Linux (WSL2) process — the Linux
//! build of this same binary started as `agwo executor --serve`. Wire format: one JSON object per line on stdin/stdout, ASCII-only.
//! The policy files must be identical on both sides (SHA-256 handshake). Native `local` execution on Windows does not need any of this.
pub mod client;
pub mod doctor;
pub mod executor;
pub mod protocol;
pub mod wsl;
