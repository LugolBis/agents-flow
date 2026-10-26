//! Document tools: extraction, targeted search, comparison. They extract and LOCATE (page, sheet, slide, lines); summaries are produced by
//! the LLM from that content. The content is treated as untrusted DATA.
use super::extract::core::{extract, Extraction};
use super::schema::{ArgSchema, Field};
use super::{Tool, ToolContext};
use crate::error::{Error, Result, SecurityError};
use crate::util::{clip, splitlines};
use regex::RegexBuilder;
use serde_json::json;

fn load(ctx: &ToolContext, path: &str) -> Result<(Extraction, String)> {
    let rp = ctx.rt.paths.resolve(path, "read", None)?;

    if !rp.real.is_file() {
        return Err(Error::Security(SecurityError::path(
            "not_a_file",
            "file not found",
        )));
    }

    let dirs = ctx.rt.settings.permissions.shell.trusted_dirs();
    Ok((
        extract(&rp.real, &ctx.rt.settings.permissions.documents, &dirs)?,
        rp.rel_str(),
    ))
}

fn uniq(w: &[String]) -> Vec<String> {
    let mut o: Vec<String> = Vec::new();

    for x in w {
        if !o.contains(x) {
            o.push(x.clone());
        }
    }
    o
}

fn char_slice(s: &str, a: usize, b: usize) -> String {
    s.chars().skip(a).take(b.saturating_sub(a)).collect()
}

tool!(ReadDocumentTool, "read_document", "agents_flow.tools.documents.ReadDocumentTool", ["fs.read"],
    "Extracts text from a document (TXT, MD, CSV, JSON, XML, HTML, PDF, DOCX, XLSX, PPTX, images, code), including references [page / sheet / slide / lines] and warnings regarding extraction limitations.",
    ArgSchema(vec![Field::str("path", 1024), Field::int("max_chars", 500, 100_000).default(json!(12000))]),
    |ctx, a| {
        let (mut ex, rel) = load(ctx, a.str("path"))?;
        let cap = (a.int("max_chars") as usize).min(ctx.rt.settings.permissions.documents.max_chars);
        let body = ex.render(cap);
        let w = uniq(&ex.warnings);
        let warn = if w.is_empty() { String::new() } else { format!("\nLIMITES : {}", w.join(" ; ")) };
        let head = format!("format={} ; {} section(s){warn}\n", ex.fmt, ex.sections.len());
        Ok(ctx.untrusted(&format!("{head}{}", if body.is_empty() { "(no text extracted)" } else { &body }), &format!("doc:{rel}")))
    });

tool!(SearchInDocumentTool, "search_in_document", "agents_flow.tools.documents.SearchInDocumentTool", ["fs.read"],
    "Finds occurrences of text within a document and returns the excerpt along with its location (page, sheet, slide, lines).",
    ArgSchema(vec![Field::str("path", 1024), Field::str("query", 200).min(1).desc("Literal text (case-insensitive)."), Field::int("context_chars", 20, 600).default(json!(150)), Field::int("max_matches", 1, 50).default(json!(15))]),
    |ctx, a| {
        let (ex, rel) = load(ctx, a.str("path"))?;
        let rx = RegexBuilder::new(&regex::escape(a.str("query"))).case_insensitive(true).build().map_err(|e| Error::internal("RegexError", e.to_string()))?;
        
        let (ctxc, max) = (a.int("context_chars") as usize, a.int("max_matches") as usize);
        let mut found: Vec<String> = Vec::new();

        'outer: for s in &ex.sections {
            let total = s.text.chars().count();
            
            for m in rx.find_iter(&s.text) {
                let (cs, ce) = (s.text[..m.start()].chars().count(), s.text[..m.end()].chars().count());
                let (lo, hi) = (cs.saturating_sub(ctxc), (ce + ctxc).min(total));

                found.push(format!("[{}] …{}…", s.location, char_slice(&s.text, lo, hi).replace('\n', " ")));
                if found.len() >= max { break 'outer; }
            }
        }

        let w = uniq(&ex.warnings);
        let note = if w.is_empty() { String::new() } else { format!("\nLIMITS : {}", w.join(" ; ")) };

        Ok(ctx.untrusted(&format!("{}{note}", if found.is_empty() { "(no occurrences)".to_string() } else { found.join("\n") }), &format!("doc:{rel}")))
    });

tool!(CompareDocumentsTool, "compare_documents", "agents_flow.tools.documents.CompareDocumentsTool", ["fs.read"],
    "Compare two documents: similarity rate and line-by-line differences (unified diff), with references.",
    ArgSchema(vec![Field::str("path_a", 1024), Field::str("path_b", 1024), Field::int("max_chars", 500, 60_000).default(json!(10000))]),
    |ctx, a| {
        let ((ea, ra), (eb, rb)) = (load(ctx, a.str("path_a"))?, load(ctx, a.str("path_b"))?);
        let (fa, fb) = (ea.flat_text(), eb.flat_text());
        
        let (la, lb): (Vec<&str>, Vec<&str>) = (splitlines(&fa), splitlines(&fb));
        let diff_ = similar::TextDiff::from_slices(&la, &lb);
        let ratio = diff_.ratio() as f64;

        let diff = diff_.unified_diff().context_radius(1).missing_newline_hint(false).header(&ra, &rb).to_string();
        let diff = diff.trim_end_matches('\n').to_string();
        let max = a.int("max_chars") as usize;
        
        let mut text = format!("similarity (lines) : {:.0}%\n{}", ratio * 100.0, if diff.is_empty() { "(identical documents)".to_string() } else { clip(&diff, max) });
        if diff.chars().count() > max { text.push_str("\n[diff tronqué]"); }
        
        let warns = uniq(&[ea.warnings, eb.warnings].concat());
        if !warns.is_empty() { text.push_str(&format!("\nLIMITS : {}", warns.join(" ; "))); }
        
        Ok(ctx.untrusted(&text, &format!("compare:{ra}|{rb}")))
    });

pub fn tools() -> Vec<Box<dyn Tool>> {
    vec![
        Box::new(ReadDocumentTool),
        Box::new(SearchInDocumentTool),
        Box::new(CompareDocumentsTool),
    ]
}
