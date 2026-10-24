use std::path::PathBuf;

use super::{rel::Rel, root::Root};

#[derive(Debug, Clone)]
pub struct ResolvedPath {
    /// Real path: use it for all I/O.
    pub real: PathBuf,
    /// Absolute, unresolved path (to detect links).
    pub lexical: PathBuf,
    pub root: Root,
    pub rel: Rel,
}

impl ResolvedPath {
    pub fn rel_str(&self) -> String {
        self.rel.to_string()
    }
}
