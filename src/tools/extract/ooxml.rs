use crate::error::Result;
use crate::tools::extract::core::{pd, Extraction, Section};
use crate::tools::extract::helpers::{join_target, need, part, rels};
use crate::tools::xml::Node;
use std::collections::BTreeMap;

fn run_text(node: &Node) -> String {
    let mut buffer = String::new();

    for children in &node.children {
        match children.name.as_str() {
            "t" => buffer.push_str(&children.text),
            "tab" => buffer.push('\t'),
            "br" | "cr" => buffer.push('\n'),
            "noBreakHyphen" => buffer.push('-'),
            _ => {}
        }
    }
    buffer
}

fn para_text(node: &Node) -> String {
    let mut buffer = String::new();

    for children in &node.children {
        match children.name.as_str() {
            "r" => buffer.push_str(&run_text(children)),
            "hyperlink" | "ins" | "smartTag" | "fldSimple" => buffer.push_str(&para_text(children)),
            _ => {}
        }
    }
    buffer
}

pub(super) fn docx(zip_archive: &mut zip::ZipArchive<std::fs::File>) -> Result<Extraction> {
    let doc = need(zip_archive, "word/document.xml")?;
    let mut styles: BTreeMap<String, String> = BTreeMap::new();

    if let Some(Ok(st)) = part(zip_archive, "word/styles.xml") {
        for kid in st.kids("style") {
            if let (Some(id), Some(name)) = (
                kid.attr("w:styleId"),
                kid.child("name").and_then(|node_| node_.attr("w:val")),
            ) {
                styles.insert(id.into(), name.into());
            }
        }
    }

    let mut extraction = Extraction::new("docx")
        .warn("headers/footers, comments, and floating text boxes not extracted");

    let body = doc
        .child("body")
        .ok_or_else(|| pd("corrupt_file", "DOCX document without body"))?;

    for (index, kid_p) in body.kids("p").enumerate() {
        let text = para_text(kid_p);

        if text.trim().is_empty() {
            continue;
        }

        let sid = kid_p
            .child("pPr")
            .and_then(|pp| pp.child("pStyle"))
            .and_then(|s| s.attr("w:val"))
            .unwrap_or("");

        let mut style = styles.get(sid).cloned().unwrap_or_else(|| {
            if sid.is_empty() {
                "Normal".into()
            } else {
                sid.to_string()
            }
        });

        if style.starts_with("heading ") {
            style = format!("H{}", &style[1..]);
        }

        let style_lower = style.to_lowercase();
        let tag = if style_lower.starts_with("heading")
            || style_lower.starts_with("titre")
            || style_lower.starts_with("title")
        {
            format!(" [{style}]")
        } else {
            String::new()
        };

        extraction.sections.push(Section {
            location: format!("paragraph {}{tag}", index + 1),
            text,
        });
    }

    for (index, table) in body.kids("tbl").enumerate() {
        let rows: Vec<String> = table
            .kids("tr")
            .map(|kid_tr| {
                kid_tr
                    .kids("tc")
                    .map(|kid_tc| {
                        kid_tc
                            .kids("p")
                            .map(para_text)
                            .collect::<Vec<_>>()
                            .join("\n")
                            .trim()
                            .to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(" | ")
            })
            .collect();

        extraction.sections.push(Section {
            location: format!("table {}", index + 1),
            text: rows.join("\n"),
        });
    }
    Ok(extraction)
}

fn col_index(cell_ref: &str) -> usize {
    cell_ref
        .chars()
        .take_while(|char_| char_.is_ascii_alphabetic())
        .fold(0usize, |a, char_| {
            a * 26 + (char_.to_ascii_uppercase() as usize - 'A' as usize + 1)
        })
        .max(1)
        - 1
}

pub(super) fn xlsx(zip_archive: &mut zip::ZipArchive<std::fs::File>) -> Result<Extraction> {
    let shared: Vec<String> = match part(zip_archive, "xl/sharedStrings.xml") {
        Some(Ok(node)) => node
            .kids("si")
            .map(|kid_si| kid_si.text_of("t", &["rPh"]))
            .collect(),
        _ => vec![],
    };

    let wb = need(zip_archive, "xl/workbook.xml")?;
    let rel = rels(zip_archive, "xl/_rels/workbook.xml.rels");
    let mut extraction = Extraction::new("xlsx").warn("cached values: formulas that have never been calculated appear empty; dates are displayed as serial numbers");

    let sheets: Vec<(String, String)> = wb
        .child("sheets")
        .map(|child| {
            child
                .kids("sheet")
                .map(|kid_sht| {
                    (
                        kid_sht.attr("name").unwrap_or("").to_string(),
                        kid_sht.attr("r:id").unwrap_or("").to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    for (title, rid) in sheets {
        let Some((_, target, _)) = rel.iter().find(|(id, _, _)| *id == rid) else {
            continue;
        };

        let ws = need(zip_archive, &join_target("xl", target))?;
        let Some(data) = ws.child("sheetData") else {
            continue;
        };

        let mut grid: BTreeMap<usize, BTreeMap<usize, String>> = BTreeMap::new();
        let mut max_row = 0usize;

        for (index_row, kid_row) in data.kids("row").enumerate() {
            let atr_r: usize = kid_row
                .attr("r")
                .and_then(|v| v.parse().ok())
                .unwrap_or(index_row + 1);

            max_row = max_row.max(atr_r);
            if atr_r > 500 {
                continue;
            }

            for (index_c, kid_c) in kid_row.kids("c").enumerate() {
                let col = kid_c.attr("r").map(col_index).unwrap_or(index_c);
                let child_v = kid_c.child("v").map(|tag_v| tag_v.text.clone());

                let val = match kid_c.attr("t") {
                    Some("s") => child_v
                        .and_then(|i| i.trim().parse::<usize>().ok())
                        .and_then(|i| shared.get(i).cloned()),
                    Some("b") => child_v.map(|b| {
                        if b.trim() == "1" {
                            "True".to_string()
                        } else {
                            "False".to_string()
                        }
                    }),
                    Some("inlineStr") => kid_c.child("is").map(|i| i.text_of("t", &["rPh"])),
                    _ => child_v,
                };

                if let Some(val) = val {
                    grid.entry(atr_r).or_default().insert(col, val);
                }
            }
        }

        let ncols = grid
            .values()
            .flat_map(|r| r.keys())
            .max()
            .map(|m| m + 1)
            .unwrap_or(0)
            .min(40);

        let mut rows: Vec<String> = Vec::new();
        for index_row in 1..=max_row.min(500) {
            rows.push(format!(
                "{index_row}: {}",
                (0..ncols)
                    .map(|column| grid
                        .get(&index_row)
                        .and_then(|grp| grp.get(&column))
                        .cloned()
                        .unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join(" | ")
            ));
        }

        if max_row > 500 {
            extraction
                .warnings
                .push(format!("sheet '{title}' truncated to 500 rows"));
        }

        for index in (0..rows.len()).step_by(100) {
            extraction.sections.push(Section {
                location: format!(
                    "sheet '{title}' lines {}-{}",
                    index + 1,
                    (index + 100).min(rows.len())
                ),
                text: rows[index..(index + 100).min(rows.len())].join("\n"),
            });
        }
    }
    Ok(extraction)
}

fn a_para(node: &Node) -> String {
    let mut buffer = String::new();

    for children in &node.children {
        match children.name.as_str() {
            "r" | "fld" => buffer.push_str(&children.text_of("t", &[])),
            "br" => buffer.push('\u{b}'),
            _ => {}
        }
    }
    buffer
}

fn tx_text(tx: &Node) -> String {
    tx.kids("p").map(a_para).collect::<Vec<_>>().join("\n")
}

pub(super) fn pptx(zip_archive: &mut zip::ZipArchive<std::fs::File>) -> Result<Extraction> {
    let pres = need(zip_archive, "ppt/presentation.xml")?;
    let rel = rels(zip_archive, "ppt/_rels/presentation.xml.rels");
    let mut extraction = Extraction::new("pptx").warn("Text from images/SmartArt not extracted");

    let ids: Vec<String> = pres
        .child("sldIdLst")
        .map(|child_list| {
            child_list
                .kids("sldId")
                .filter_map(|kid_id| kid_id.attr("r:id").map(String::from))
                .collect()
        })
        .unwrap_or_default();

    for (index, rid) in ids.iter().enumerate() {
        let Some((_, target, _)) = rel.iter().find(|(id, _, _)| id == rid) else {
            continue;
        };

        let slide_path = join_target("ppt", target);
        let slide = need(zip_archive, &slide_path)?;
        let mut parts: Vec<String> = Vec::new();

        if let Some(tree) = slide
            .child("cSld")
            .and_then(|child_| child_.child("spTree"))
        {
            for shape in &tree.children {
                match shape.name.as_str() {
                    "sp" => {
                        if let Some(tx) = shape.child("txBody") {
                            let t = tx_text(tx);
                            if !t.trim().is_empty() {
                                parts.push(t.trim().to_string());
                            }
                        }
                    }
                    "graphicFrame" => {
                        let mut tables = Vec::new();
                        shape.descendants("tbl", &mut tables);

                        for table in tables {
                            for kid_tr in table.kids("tr") {
                                parts.push(
                                    kid_tr
                                        .kids("tc")
                                        .map(|kid_tc| {
                                            kid_tc
                                                .child("txBody")
                                                .map(tx_text)
                                                .unwrap_or_default()
                                                .trim()
                                                .to_string()
                                        })
                                        .collect::<Vec<_>>()
                                        .join(" | "),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let (dir, file) = slide_path.rsplit_once('/').unwrap_or(("", &slide_path));
        for (_, tgt, ty) in rels(zip_archive, &format!("{dir}/_rels/{file}.rels")) {
            if ty.ends_with("/notesSlide") {
                if let Some(Ok(notes)) = part(zip_archive, &join_target(dir, &tgt)) {
                    let mut sps = Vec::new();
                    notes.descendants("sp", &mut sps);

                    for sp in sps {
                        let mut phs = Vec::new();
                        sp.descendants("ph", &mut phs);

                        if phs.iter().any(|p| p.attr("type") == Some("body")) {
                            if let Some(tx) = sp.child("txBody") {
                                let t = tx_text(tx);
                                if !t.trim().is_empty() {
                                    parts.push(format!("[notes] {}", t.trim()));
                                }
                            }
                        }
                    }
                }
            }
        }

        extraction.sections.push(Section {
            location: format!("slide {}", index + 1),
            text: parts.join("\n"),
        });
    }
    Ok(extraction)
}
