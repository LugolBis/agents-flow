//! Static document extraction (no code or macro is ever executed).
//! Formats and LIMITS: text/code/config/Markdown/JSON: direct read (UTF-8, invalid bytes replaced) · CSV/TSV · XML (DTD with entities refused)
//! · HTML (scripts/styles/hidden text removed) · PDF (text layer via lopdf; encrypted PDFs refused; scanned PDFs flagged, no OCR) ·
//! DOCX (paragraphs, headings, tables; NOT headers/footers, comments, floating text boxes) · XLSX (cached values; dates appear as serial
//! numbers; never-computed formulas appear empty) · PPTX (text, tables, notes; NOT picture/SmartArt text) · images (metadata; OCR only if
//! enabled AND a `tesseract` binary exists in a trusted directory).
//! NOT supported (explicit message): .doc .xls .ppt .odt .ods .odp .rtf .pages .key .numbers, archives and unknown binaries.
//! Protections: max size, pages, characters, ZIP bomb (ratio, uncompressed size, entry count) for OOXML, max pixels for images.
use crate::config::models::permissions::DocsCfg;
use crate::error::{Error, Result, SecurityError};
use crate::security::{runner, secrets};
use crate::tools::extract::constants::{IMAGE_EXT, TEXT_EXT, UNSUPPORTED_EXT};
use crate::tools::extract::helpers::{open_zip, py_repr};
use crate::tools::extract::ooxml::{docx, pptx, xlsx};
use crate::tools::xml::{self, XmlError};
use crate::util::splitlines;
use scraper::{Html, Selector};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time;

#[derive(Debug, Clone)]
pub struct Section {
    pub location: String,
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct Extraction {
    pub fmt: String,
    pub sections: Vec<Section>,
    pub warnings: Vec<String>,
}

impl Extraction {
    pub(super) fn new(fmt: &str) -> Self {
        Extraction {
            fmt: fmt.into(),
            ..Default::default()
        }
    }

    pub(super) fn warn(mut self, w: &str) -> Self {
        self.warnings.push(w.into());
        self
    }

    pub fn render(&mut self, max_chars: usize) -> String {
        let (mut out, mut total, mut cut) = (Vec::new(), 0usize, false);
        for section in &self.sections {
            let chunk = format!("[{}]\n{}\n", section.location, section.text);
            let len = chunk.chars().count();

            if total + len > max_chars {
                out.push(format!(
                    "{}\n[truncated output]",
                    crate::util::clip(&chunk, max_chars.saturating_sub(total))
                ));

                cut = true;
                break;
            }

            out.push(chunk);
            total += len;
        }

        if cut {
            self.warnings
                .push(format!("output truncated at {max_chars} characters"));
        }
        out.join("\n")
    }

    pub fn flat_text(&self) -> String {
        self.sections
            .iter()
            .map(|section| format!("[{}] {}", section.location, section.text))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub(super) fn pd(code: &str, reason: &str) -> Error {
    SecurityError::path(code, reason).into()
}

fn lines_sections(text: &str, step: usize) -> Vec<Section> {
    let lines = splitlines(text);
    (0..lines.len().max(1))
        .step_by(step)
        .map(|index| Section {
            location: format!("lignes {}-{}", index + 1, (index + step).min(lines.len())),
            text: lines[index.min(lines.len())..(index + step).min(lines.len())].join("\n"),
        })
        .collect()
}

pub fn extract(path: &Path, cfg: &DocsCfg, ocr_dirs: &[PathBuf]) -> Result<Extraction> {
    let size = std::fs::metadata(path)?.len();
    if size > cfg.max_file_mb * 1024 * 1024 {
        return Err(pd(
            "file_too_large",
            &format!("file larger than {} Mo", cfg.max_file_mb),
        ));
    }

    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let name = path
        .file_name()
        .map(|fname| fname.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if UNSUPPORTED_EXT.contains(&extension.as_str()) {
        return Err(pd(
            "unsupported_format",
            &format!(
                "format .{extension} not supported : convert it into PDF/DOCX/XLSX/PPTX/texte"
            ),
        ));
    }

    match extension.as_str() {
        "docx" | "xlsx" | "pptx" => {
            let mut z = open_zip(path, cfg)?;
            return match extension.as_str() {
                "docx" => docx(&mut z),
                "xlsx" => xlsx(&mut z),
                _ => pptx(&mut z),
            };
        }
        "pdf" => return pdf(path, cfg),
        ext if IMAGE_EXT.contains(&ext) => return image(path, cfg, ocr_dirs),
        "html" | "htm" => return Ok(html_doc(&String::from_utf8_lossy(&std::fs::read(path)?))),
        "xml" | "xsd" | "svg" => return xml_doc(&String::from_utf8_lossy(&std::fs::read(path)?)),
        "csv" | "tsv" => {
            return Ok(csv_doc(
                &String::from_utf8_lossy(&std::fs::read(path)?),
                if extension == "tsv" { b'\t' } else { b',' },
            ))
        }
        _ => {}
    }

    let raw = std::fs::read(path)?;
    let decodes = std::str::from_utf8(&raw[..raw.len().min(20000)]).is_ok();

    if TEXT_EXT.contains(&extension.as_str())
        || ["dockerfile", "makefile", "readme", "license"].contains(&name.as_str())
        || (!raw[..raw.len().min(8000)].contains(&0) && decodes)
    {
        let mut extraction = Extraction::new(if extension.is_empty() {
            "texte"
        } else {
            &extension
        });

        extraction.sections = lines_sections(&String::from_utf8_lossy(&raw), 80);
        return Ok(extraction);
    }

    Err(pd(
        "unsupported_format",
        "unknown binary format : there isn't reliable extract available",
    ))
}

fn csv_doc(text: &str, delim: u8) -> Extraction {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .delimiter(delim)
        .from_reader(text.as_bytes());

    let rows: Vec<Vec<String>> = reader
        .records()
        .filter_map(|res| res.ok())
        .map(|record| record.iter().map(String::from).collect())
        .collect();

    let mut extraction = Extraction::new("csv");
    extraction.sections.push(Section {
        location: "summary".into(),
        text: format!(
            "{} line(s) ; columns : {}",
            rows.len(),
            rows.first()
                .map(|row| py_repr(row))
                .unwrap_or_else(|| "[]".into())
        ),
    });

    extraction.sections.extend(lines_sections(text, 100));
    extraction
}

/// Visible text nodes. `strict`: also drops iframes, svg and hidden elements (web pages).
pub fn visible_texts(doc: &Html, strict: bool) -> Vec<String> {
    use scraper::node::Node as N;

    fn hidden(element: &scraper::node::Element, strict: bool) -> bool {
        matches!(element.name(), "script" | "style" | "noscript" | "template")
            || (strict
                && (matches!(element.name(), "iframe" | "svg")
                    || element.attr("hidden").is_some()
                    || element.attr("aria-hidden") == Some("true")
                    || element
                        .attr("style")
                        .map(|s| s.contains("display:none") || s.contains("display: none"))
                        .unwrap_or(false)))
    }

    let mut out = Vec::new();
    for node in doc.tree.root().descendants() {
        if let N::Text(text) = node.value() {
            if node
                .ancestors()
                .any(|ancestor| matches!(ancestor.value(), N::Element(element) if hidden(element, strict)))
            {
                continue;
            }

            let text_clean = text.trim();
            if !text_clean.is_empty() {
                out.push(text_clean.to_string());
            }
        }
    }
    out
}

pub fn first_title(doc: &Html) -> String {
    let sel = Selector::parse("title").unwrap();
    doc.select(&sel)
        .next()
        .map(|element_ref| element_ref.text().collect::<String>().trim().to_string())
        .unwrap_or_default()
}

fn html_doc(text: &str) -> Extraction {
    let doc = Html::parse_document(text);
    let mut extraction = Extraction::new("html");

    extraction.sections.push(Section {
        location: "title".into(),
        text: first_title(&doc),
    });

    extraction
        .sections
        .extend(lines_sections(&visible_texts(&doc, false).join("\n"), 80));
    extraction
}

fn xml_doc(raw: &str) -> Result<Extraction> {
    match xml::parse(raw.as_bytes()) {
        Err(XmlError::Unsafe) => Err(pd(
            "unsafe_xml",
            "XML with DTD/entities rejected (XXE protection)",
        )),
        Err(XmlError::Malformed(malformed)) => Ok(Extraction {
            fmt: "xml".into(),
            sections: lines_sections(raw, 80),
            warnings: vec![format!("XML mal formé : {malformed}")],
        }),
        Ok(_) => Ok(Extraction {
            fmt: "xml".into(),
            sections: lines_sections(raw, 80),
            warnings: vec![],
        }),
    }
}

fn pdf(path: &Path, cfg: &DocsCfg) -> Result<Extraction> {
    let path = path.to_path_buf();
    let max_pages = cfg.max_pages;

    // lopdf may panic on hostile files: contain it.
    let res = std::panic::catch_unwind(
        move || -> std::result::Result<(Vec<String>, usize), String> {
            let doc = lopdf::Document::load(&path).map_err(|_| "corrupt".to_string())?;

            if doc.is_encrypted() {
                return Err("encrypted".into());
            }

            let pages: BTreeMap<u32, _> = doc.get_pages();
            let n = pages.len();

            Ok((
                pages
                    .keys()
                    .take(max_pages)
                    .map(|p| {
                        doc.extract_text(&[*p])
                            .unwrap_or_default()
                            .trim()
                            .to_string()
                    })
                    .collect(),
                n,
            ))
        },
    );

    let (texts, n) = match res {
        Ok(Ok(x)) => x,
        Ok(Err(e)) if e == "encrypted" => {
            return Err(pd("encrypted_pdf", "crypted PDF aren't supported"))
        }
        _ => return Err(pd("corrupt_file", "invalid or illegible PDF")),
    };

    let mut extraction = Extraction::new("pdf");
    if n > cfg.max_pages {
        extraction.warnings.push(format!(
            "{n} pages : only the {} first pages were readed",
            cfg.max_pages
        ));
    }

    let empty: Vec<usize> = texts
        .iter()
        .enumerate()
        .filter(|(_, text_)| text_.chars().count() < 20)
        .map(|(index, _)| index + 1)
        .collect();

    for (index, text_) in texts.into_iter().enumerate() {
        extraction.sections.push(Section {
            location: format!("page {}", index + 1),
            text: text_,
        });
    }

    if !empty.is_empty() && empty.len() >= (n / 2).max(1) {
        extraction.warnings.push(format!(
            "{} page(s) without text : PDF probably scanned",
            empty.len()
        ));

        extraction.warnings.push(
            if cfg.ocr_enabled {
                "PDF OCR not available in this version (no built-in rasterizer): convert pages to images".into()
            }
            else {
                "OCR disabled (documents.ocr_enabled=false): the text from these pages is not extracted".into()
            }
        );
    }
    Ok(extraction)
}

fn image(path: &Path, cfg: &DocsCfg, ocr_dirs: &[PathBuf]) -> Result<Extraction> {
    let size = imagesize::size(path)
        .map_err(|_| pd("corrupt_file", "illegible image or unknwon format"))?;

    if (size.width as u64) * (size.height as u64) > cfg.max_image_pixels {
        return Err(pd("image_too_large", "image too large"));
    }

    let fmt = std::fs::read(path)
        .ok()
        .and_then(|bytes| imagesize::image_type(&bytes[..bytes.len().min(512)]).ok())
        .map(|img_type| format!("{img_type:?}").to_uppercase())
        .unwrap_or_else(|| "IMAGE".into());

    let meta = Section {
        location: "ùeta data".into(),
        text: format!("{fmt} {}x{}", size.width, size.height),
    };

    if !cfg.ocr_enabled {
        return Ok(Extraction {
            fmt: "image".into(),
            sections: vec![meta],
            warnings: vec!["OCR deactivated : the text of the image isn't extracted".into()],
        });
    }

    let mut ex = Extraction {
        fmt: "image".into(),
        sections: vec![meta],
        warnings: vec![],
    };

    match crate::util::which_in("tesseract", ocr_dirs) {
        Some(bin) => {
            let env = secrets::clean_env(
                &[],
                &ocr_dirs
                    .iter()
                    .map(|d| d.to_string_lossy().to_string())
                    .collect::<Vec<_>>(),
            );

            let argv = vec![
                bin.to_string_lossy().to_string(),
                path.to_string_lossy().to_string(),
                "stdout".to_string(),
            ];

            let cwd = path.parent().unwrap_or(Path::new("."));
            match runner::run_limited(
                &argv,
                &runner::RunOpts {
                    cwd,
                    env,
                    timeout: time::Duration::from_secs(60),
                    max_output: 200_000,
                    cpu_s: 60,
                    memory_mb: 2048,
                    fsize: None,
                },
            ) {
                Ok(r) if r.returncode == 0 => ex.sections.push(Section {
                    location: "OCR".into(),
                    text: r.stdout,
                }),
                _ => ex.warnings.push("OCR is in failure".into()),
            }
        }
        None => ex
            .warnings
            .push("OCR unavailable: Tesseract binary not found in trusted directories".into()),
    }
    Ok(ex)
}
