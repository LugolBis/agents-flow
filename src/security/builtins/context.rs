use std::time::Instant;

use crate::security::path_guard::guard::PathGuard;

pub struct Ctx<'a> {
    pub guard: &'a PathGuard,
    pub deadline: Instant,
    pub max_out: usize,
    pub max_depth: usize,
}
