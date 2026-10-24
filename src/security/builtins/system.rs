use super::context::Ctx;
use crate::security::path_guard::rel::Rel;

use std::fs::Metadata;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;
use std::time::SystemTime;

#[derive(Debug, Default, Clone)]
pub struct Out {
    pub text: String,
    pub err: String,
    pub exit: i32,
    pub truncated: bool,
    pub timed_out: bool,
}

impl Out {
    pub fn push(&mut self, cap: usize, line: &str) -> bool {
        if self.truncated {
            return false;
        }

        if self.text.len() + line.len() + 1 > cap {
            let room = cap.saturating_sub(self.text.len());
            let mut cut = room.min(line.len());

            while cut > 0 && !line.is_char_boundary(cut) {
                cut -= 1;
            }

            self.text.push_str(&line[..cut]);
            self.truncated = true;
            return false;
        }

        self.text.push_str(line);
        self.text.push('\n');
        true
    }

    pub fn fail(&mut self, message: String) {
        self.err.push_str(&message);
        self.err.push('\n');
        self.exit = 1;
    }
}

fn secs(res_time: Result<SystemTime>) -> i64 {
    res_time
        .ok()
        .and_then(|syst| syst.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub fn mtime(meta_data: &Metadata) -> i64 {
    secs(meta_data.modified())
}

pub fn atime(meta_data: &Metadata) -> i64 {
    secs(meta_data.accessed())
}

pub fn ctime(meta_data: &Metadata) -> i64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta_data.ctime()
    }
    #[cfg(not(unix))]
    {
        secs(meta_data.created())
    }
}

pub fn hidden(ctx: &Ctx, path: &Path) -> bool {
    match ctx.guard.root_of(path) {
        Some(root) => ctx
            .guard
            .denied_by_policy(&Rel::from_path(path, &root.path))
            .is_some(),
        None => true,
    }
}

pub fn nope(error: &Error) -> &'static str {
    match error.kind() {
        ErrorKind::NotFound => "No such file or directory",
        ErrorKind::PermissionDenied => "Permission denied",
        _ => "Input/output error",
    }
}
