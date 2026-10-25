use crate::config::Settings;
use crate::error::{Error, Result};
use crate::util;

use serde_json::Value;
use std::io::BufRead;

pub const PROTOCOL_VERSION: u64 = 1;

/// One line of JSON with every non-ASCII character escaped (`ensure_ascii`): immune to console code pages and stream re-encoding.
pub fn encode(value: &Value) -> String {
    let raw = serde_json::to_string(value).unwrap_or_default();
    let mut out = String::with_capacity(raw.len() + 1);

    for char_ in raw.chars() {
        if char_.is_ascii() {
            out.push(char_);
        } else {
            let mut b = [0u16; 2];

            for u in char_.encode_utf16(&mut b) {
                out.push_str(&format!("\\u{:04x}", u));
            }
        }
    }

    out.push('\n');
    out
}

pub fn decode(line: &str) -> Result<Value> {
    serde_json::from_str(line.trim())
        .map_err(|_| Error::internal("ProtocolError", "invalid JSON line"))
}

/// Reads one line, refusing messages larger than `max` bytes (a hostile or runaway peer cannot exhaust memory).
pub fn read_line_limited(bf_reader: &mut impl BufRead, max: usize) -> Result<Option<String>> {
    let mut buf = Vec::new();

    loop {
        let chunk = bf_reader.fill_buf()?;

        if chunk.is_empty() {
            return Ok(if buf.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&buf).into_owned())
            });
        }

        match chunk.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                buf.extend_from_slice(&chunk[..index]);
                bf_reader.consume(index + 1);
                break;
            }
            None => {
                let n = chunk.len();
                buf.extend_from_slice(chunk);
                bf_reader.consume(n);
            }
        }

        if buf.len() > max {
            return Err(Error::internal("ProtocolError", "message too large"));
        }
    }

    if buf.len() > max {
        return Err(Error::internal("ProtocolError", "message too large"));
    }

    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// Hash of the three policy files (CRLF normalised): detects a Windows/WSL configuration drift.
pub fn config_hash(settings: &Settings) -> String {
    let mut data = Vec::new();

    for name in ["agents.jsonc", "permissions.jsonc", "tools.jsonc"] {
        let text = std::fs::read_to_string(settings.config_dir.join(name))
            .unwrap_or_default()
            .replace("\r\n", "\n");

        data.extend_from_slice(name.as_bytes());
        data.push(0);
        data.extend_from_slice(text.as_bytes());
        data.push(0);
    }

    util::sha256_hex(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ascii_roundtrip_and_limits() {
        let v = serde_json::json!({"t": "é😀\n\"x\""});
        let line = encode(&v);
        assert!(line.is_ascii() && line.ends_with('\n') && line.matches('\n').count() == 1);
        assert_eq!(decode(&line).unwrap(), v);
        let mut big = std::io::Cursor::new(vec![b'a'; 1000]);
        assert!(read_line_limited(&mut big, 100).is_err());
        let mut ok = std::io::Cursor::new(b"abc\ndef".to_vec());
        assert_eq!(read_line_limited(&mut ok, 100).unwrap().unwrap(), "abc");
        assert_eq!(read_line_limited(&mut ok, 100).unwrap().unwrap(), "def");
        assert!(read_line_limited(&mut ok, 100).unwrap().is_none());
    }
}
