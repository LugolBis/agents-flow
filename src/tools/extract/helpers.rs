use crate::config::models::permissions::DocsCfg;
use crate::error::Result;
use crate::tools::extract::constants::MAX_PART;
use crate::tools::extract::core::pd;
use crate::tools::xml::{self, Node, XmlError};
use std::io::Read;
use std::path::Path;

pub(super) fn open_zip(path: &Path, cfg: &DocsCfg) -> Result<zip::ZipArchive<std::fs::File>> {
    let mut zip_archive = zip::ZipArchive::new(std::fs::File::open(path)?)
        .map_err(|_| pd("corrupt_file", "invalid OOXML archive"))?;

    let (mut total, mut comp) = (0u64, 0u64);
    for index in 0..zip_archive.len() {
        let file = zip_archive
            .by_index_raw(index)
            .map_err(|_| pd("corrupt_file", "invalid OOXML archive"))?;
        total += file.size();
        comp += file.compressed_size();
    }

    if total > cfg.max_zip_uncompressed_mb * 1024 * 1024 {
        return Err(pd("zip_bomb", "unzipped content too large"));
    }

    if total / comp.max(1) > 200 && total > 10 * 1024 * 1024 {
        return Err(pd("zip_bomb", "suspicious compression rate"));
    }

    if zip_archive.len() > 5000 {
        return Err(pd("zip_bomb", "too many entries in the archive"));
    }
    Ok(zip_archive)
}

pub(super) fn part(
    zip_archive: &mut zip::ZipArchive<std::fs::File>,
    name: &str,
) -> Option<Result<Node>> {
    let file = zip_archive.by_name(name).ok()?;
    let mut buffer = Vec::new();

    if file.take(MAX_PART + 1).read_to_end(&mut buffer).is_err() {
        return Some(Err(pd("corrupt_file", "OOXML part is illegible")));
    }

    if buffer.len() as u64 > MAX_PART {
        return Some(Err(pd("zip_bomb", "OOXML part is too large")));
    }

    Some(xml::parse(&buffer).map_err(|e| match e {
        XmlError::Unsafe => pd(
            "unsafe_xml",
            "XML with DTD/entities rejected (XXE protection)",
        ),
        XmlError::Malformed(_) => pd("corrupt_file", "malformed OOXML part"),
    }))
}

pub(super) fn need(zip_archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Result<Node> {
    part(zip_archive, name).unwrap_or_else(|| Err(pd("corrupt_file", "OOXML missing part")))
}

pub(super) fn join_target(base_dir: &str, target: &str) -> String {
    let mut parts: Vec<&str> = if target.starts_with('/') {
        vec![]
    } else {
        base_dir.split('/').filter(|s| !s.is_empty()).collect()
    };

    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

pub(super) fn rels(
    zip_archive: &mut zip::ZipArchive<std::fs::File>,
    rel_part: &str,
) -> Vec<(String, String, String)> {
    match part(zip_archive, rel_part) {
        Some(Ok(node)) => node
            .kids("Relationship")
            .map(|relationship| {
                (
                    relationship.attr("Id").unwrap_or("").into(),
                    relationship.attr("Target").unwrap_or("").into(),
                    relationship.attr("Type").unwrap_or("").into(),
                )
            })
            .collect(),
        _ => vec![],
    }
}

pub(super) fn py_repr(vec: &[String]) -> String {
    format!(
        "[{}]",
        vec.iter()
            .map(|text| format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'")))
            .collect::<Vec<_>>()
            .join(", ")
    )
}
