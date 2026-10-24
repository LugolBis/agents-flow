use std::{path::Path, sync::LazyLock};

use regex::Regex;

use crate::error::{SecResult, SecurityError};

static WIN_DRIVE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/mnt/[a-zA-Z](/|$)").unwrap());

pub fn is_windows_drive_path(p: &Path) -> bool {
    WIN_DRIVE_RE.is_match(&p.to_string_lossy().replace('\\', "/"))
}

pub fn windows_path_check(raw: &str) -> SecResult<()> {
    for (index, comp) in raw.split('/').enumerate() {
        if comp.is_empty() {
            continue;
        }

        let drive = index == 0
            && comp.len() == 2
            && comp.as_bytes()[0].is_ascii_alphabetic()
            && comp.as_bytes()[1] == b':';

        if drive {
            continue;
        }

        if comp.contains(':') {
            return Err(SecurityError::path(
                "alternate_stream",
                "':' forbidden in a path component (alternate data stream)",
            ));
        }

        if comp != "." && (comp.ends_with('.') || comp.ends_with(' ')) {
            return Err(SecurityError::path(
                "bad_component",
                "component end by a point or space",
            ));
        }

        let stem = comp
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end()
            .to_ascii_uppercase();

        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && stem.as_bytes()[3].is_ascii_digit()
                && stem.as_bytes()[3] != b'0');

        if reserved {
            return Err(SecurityError::path(
                "reserved_name",
                "reserved Windows device name",
            ));
        }
    }
    Ok(())
}
