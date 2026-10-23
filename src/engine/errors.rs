#[derive(Debug)]
pub enum AgentError {
    Llm(String),
    Timeout,
    Guardrail(String),
}

impl AgentError {
    pub fn kind(&self) -> &'static str {
        match self {
            AgentError::Llm(_) => "LLMError",
            AgentError::Timeout => "AgentTimeout",
            AgentError::Guardrail(_) => "GuardrailFailed",
        }
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::Llm(m) => write!(f, "{m}"),
            AgentError::Timeout => write!(f, "runtime limit excedeed"),
            AgentError::Guardrail(m) => write!(
                f,
                "guardrails not respected, after the authorized retries : {m}"
            ),
        }
    }
}
