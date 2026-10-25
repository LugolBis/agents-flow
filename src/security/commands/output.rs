#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub text: String,
    pub exit_code: i32,
    pub truncated: bool,
    pub timed_out: bool,
}
