use crate::error::SecurityError;

pub fn net_denial(code: &str, reason: impl Into<String>) -> SecurityError {
    SecurityError::network(code, reason)
}

pub fn decode(body: &[u8], content_type_header: &str) -> String {
    let cs = content_type_header
        .to_lowercase()
        .split("charset=")
        .nth(1)
        .map(|content| {
            content
                .trim()
                .trim_matches('"')
                .split(';')
                .next()
                .unwrap_or("")
                .to_string()
        });

    match cs.as_deref() {
        Some("iso-8859-1") | Some("latin1") | Some("latin-1") | Some("windows-1252")
        | Some("cp1252") => body.iter().map(|b| *b as char).collect(),
        _ => String::from_utf8_lossy(body).into_owned(),
    }
}
