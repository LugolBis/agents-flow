use std::fmt::{Display, Formatter, Result};
use std::path::Path;

use crate::util::rel_posix;

/// Path relative to a root, as POSIX components.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rel(pub Vec<String>);

impl Rel {
    pub fn from_path(path: &Path, root: &Path) -> Rel {
        Rel(rel_posix(path, root))
    }

    pub fn parts(&self) -> &[String] {
        &self.0
    }

    pub fn join(&self) -> String {
        self.0.join("/")
    }
}

impl Display for Rel {
    fn fmt(&self, formater: &mut Formatter<'_>) -> Result {
        if self.0.is_empty() {
            formater.write_str(".")
        } else {
            formater.write_str(&self.join())
        }
    }
}
