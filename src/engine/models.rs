use serde_json::Value;

#[derive(Debug, Clone)]
pub struct TaskInput {
    pub description: String,
    pub expected: String,
    pub context: Vec<(String, String)>,
}

pub enum Step {
    Final(String),
    Action { name: String, input: Value },
}
