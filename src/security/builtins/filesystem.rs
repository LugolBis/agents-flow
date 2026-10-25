use super::file_mtd::{ids, mode_string, octal_mode};
use super::system::{atime, ctime, mtime, nope, Out};
use super::text::read_prefix;
use crate::util::fmt_ts;

use std::fs::{read_link, symlink_metadata};
use std::path::Path;
use std::{self};

struct Kind {
    desc: &'static str,
    mime: &'static str,
}

fn sniff(head: &[u8]) -> Option<Kind> {
    let types: &[(&[u8], &str, &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "PNG image data", "image/png"),
        (b"\xff\xd8\xff", "JPEG image data", "image/jpeg"),
        (b"GIF8", "GIF image data", "image/gif"),
        (b"%PDF-", "PDF document", "application/pdf"),
        (b"PK\x03\x04", "Zip archive data", "application/zip"),
        (b"\x1f\x8b", "gzip compressed data", "application/gzip"),
        (b"\x7fELF", "ELF executable", "application/x-executable"),
        (
            b"MZ",
            "PE32 executable",
            "application/vnd.microsoft.portable-executable",
        ),
        (
            b"SQLite format 3\0",
            "SQLite 3.x database",
            "application/vnd.sqlite3",
        ),
    ];

    for (bytes, desc, mime) in types {
        if head.starts_with(bytes) {
            return Some(Kind { desc, mime });
        }
    }

    if head.len() > 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return Some(Kind {
            desc: "WebP image data",
            mime: "image/webp",
        });
    }
    None
}

fn describe(path: &Path, flags: &[String]) -> Result<String, String> {
    let meta_data = symlink_metadata(path).map_err(|err| nope(&err).to_string())?;

    let (brief_mime, mime_enc) = (
        flags
            .iter()
            .any(|flag| flag == "-i" || flag == "--mime" || flag == "--mime-type"),
        flags.iter().any(|flag| flag == "--mime-encoding"),
    );

    let with_charset = flags.iter().any(|flag| flag == "-i" || flag == "--mime");
    let mut text_enc = "binary";

    let (desc, mime): (String, String) = if meta_data.file_type().is_symlink() {
        (
            format!(
                "symbolic link to {}",
                read_link(path)
                    .map(|t| t.display().to_string())
                    .unwrap_or_default()
            ),
            "inode/symlink".into(),
        )
    } else if meta_data.is_dir() {
        ("directory".into(), "inode/directory".into())
    } else if meta_data.len() == 0 {
        ("empty".into(), "inode/x-empty".into())
    } else {
        let (head, _) = read_prefix(path, 8192).map_err(|err| nope(&err).to_string())?;

        if let Some(kind) = sniff(&head) {
            (kind.desc.to_string(), kind.mime.to_string())
        } else {
            let valid = match str::from_utf8(&head) {
                Ok(_) => true,
                Err(err) => err.error_len().is_none(),
            };

            if valid && !head.contains(&0) {
                let ascii = head.is_ascii();
                text_enc = if ascii { "us-ascii" } else { "utf-8" };
                let text = String::from_utf8_lossy(&head);

                let (kind, mime) = if text.trim_start().starts_with("<?xml") {
                    ("XML document text", "text/xml")
                } else if text
                    .trim_start()
                    .to_lowercase()
                    .starts_with("<!doctype html")
                    || text.to_lowercase().contains("<html")
                {
                    ("HTML document", "text/html")
                } else {
                    (
                        if ascii {
                            "ASCII text"
                        } else {
                            "Unicode text, UTF-8 text"
                        },
                        "text/plain",
                    )
                };

                let crlf = if text.contains("\r\n") {
                    ", with CRLF line terminators"
                } else {
                    ""
                };

                (format!("{kind}{crlf}"), mime.into())
            } else {
                ("data".into(), "application/octet-stream".into())
            }
        }
    };

    Ok(if mime_enc {
        text_enc.to_string()
    } else if brief_mime {
        if with_charset {
            format!("{mime}; charset={text_enc}")
        } else {
            mime
        }
    } else {
        desc
    })
}

pub fn file_cmd(flags: &[String], paths: &[String]) -> Out {
    let brief = flags.iter().any(|flag| flag == "-b" || flag == "--brief");
    let mut out = Out::default();

    for path in paths {
        match describe(Path::new(path), flags) {
            Ok(desc) => {
                out.text.push_str(&if brief {
                    format!("{desc}\n")
                } else {
                    format!("{path}: {desc}\n")
                });
            }
            Err(err) => {
                out.text.push_str(&format!("{path}: cannot open ({err})\n"));
                out.exit = 1;
            }
        }
    }
    out
}

pub fn stat_cmd(flags: &[String], paths: &[String]) -> Out {
    let terse = flags.iter().any(|flag| flag == "--terse");
    let mut out = Out::default();

    for path in paths {
        let meta_data = match symlink_metadata(path) {
            Ok(mtd) => mtd,
            Err(err) => {
                out.fail(format!("stat: cannot statx '{path}': {}", nope(&err)));
                continue;
            }
        };

        let (uid, gid, _) = ids(&meta_data);
        if terse {
            out.text.push_str(&format!(
                "{path} {} {:o} {uid} {gid} {} {} {}\n",
                meta_data.len(),
                octal_mode(&meta_data),
                mtime(&meta_data),
                atime(&meta_data),
                ctime(&meta_data)
            ));
            continue;
        }

        let ty = if meta_data.file_type().is_symlink() {
            "symbolic link"
        } else if meta_data.is_dir() {
            "directory"
        } else if meta_data.len() == 0 {
            "regular empty file"
        } else {
            "regular file"
        };

        out.text.push_str(&format!("  File: {path}\n  Size: {}\tType: {ty}\n  Mode: ({:04o}/{})  Uid: ({uid})  Gid: ({gid})\nAccess: {} +0000\nModify: {} +0000\nChange: {} +0000\n", meta_data.len(), octal_mode(&meta_data), mode_string(&meta_data), fmt_ts(atime(&meta_data)), fmt_ts(mtime(&meta_data)), fmt_ts(ctime(&meta_data))));
    }
    out
}
