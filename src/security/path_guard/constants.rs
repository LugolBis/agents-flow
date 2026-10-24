use regex::Regex;
use std::sync::LazyLock;

pub const MAX_PATH_LEN: usize = 4096;
pub(super) static CTRL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\x00-\x1f\x7f]").unwrap());
