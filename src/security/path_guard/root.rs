use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Root {
    pub name: String,
    pub path: PathBuf,
    pub write: bool,
}
