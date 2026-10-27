use super::constants::{RE_CLASS, RE_DEF, RE_FROM, RE_IMPORT};

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    mem,
};

#[derive(Default)]
pub(super) struct PyInfo {
    pub(super) classes: usize,
    pub(super) functions: usize,
    pub(super) imports: Vec<(usize, String, Vec<String>)>,
}

/// Logical lines of a Python source with comments, string-only continuation and triple-quoted blocks removed.
fn py_logical_lines(src: &str) -> Vec<String> {
    let (mut out, mut triple, mut pending, mut depth) =
        (Vec::new(), None::<&str>, String::new(), 0i32);

    for raw in crate::util::splitlines(src) {
        let mut line = String::new();
        let mut rest = raw;

        loop {
            if let Some(q) = triple {
                match rest.find(q) {
                    Some(index) => {
                        rest = &rest[index + 3..];
                        triple = None;
                    }
                    None => {
                        rest = "";
                        break;
                    }
                }
            } else {
                break;
            }
        }

        let mut chars = rest.char_indices().peekable();
        let mut in_str: Option<char> = None;

        while let Some((index, char_)) = chars.next() {
            if let Some(q) = in_str {
                if char_ == '\\' {
                    chars.next();
                } else if char_ == q {
                    in_str = None;
                }
                continue;
            }

            match char_ {
                '#' => break,
                '\'' | '"' => {
                    if rest[index..].starts_with(&char_.to_string().repeat(3)) {
                        let q: &'static str = if char_ == '"' { "\"\"\"" } else { "'''" };
                        match rest[index + 3..].find(q) {
                            Some(j) => {
                                for _ in 0..(j + 5) {
                                    chars.next();
                                }
                            }
                            None => {
                                triple = Some(q);
                                break;
                            }
                        }
                    } else {
                        in_str = Some(char_);
                    }
                }
                '(' | '[' | '{' => {
                    depth += 1;
                    line.push(char_);
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    line.push(char_);
                }
                _ => line.push(char_),
            }
        }

        if pending.is_empty() {
            pending = line.clone();
        } else {
            pending.push(' ');
            pending.push_str(line.trim());
        }

        if pending.trim_end().ends_with('\\') {
            pending = pending.trim_end().trim_end_matches('\\').to_string();
            continue;
        }

        if depth > 0 {
            continue;
        }
        depth = 0;
        out.push(mem::take(&mut pending));
    }

    if !pending.is_empty() {
        out.push(pending);
    }
    out
}

pub(super) fn scan_py(src: &str) -> PyInfo {
    let mut info = PyInfo::default();

    for line in py_logical_lines(src) {
        for stmt in line.split(';') {
            if RE_CLASS.is_match(stmt) {
                info.classes += 1;
            }

            if RE_DEF.is_match(stmt) {
                info.functions += 1;
            }

            if let Some(capture) = RE_IMPORT.captures(stmt) {
                let names = capture[1]
                    .split(',')
                    .map(|name| name.split_whitespace().next().unwrap_or("").to_string())
                    .filter(|name| !name.is_empty())
                    .collect();

                info.imports.push((0, String::new(), names));
            } else if let Some(capture) = RE_FROM.captures(stmt) {
                let names = capture[3]
                    .replace(['(', ')'], " ")
                    .split(',')
                    .map(|n| n.split_whitespace().next().unwrap_or("").to_string())
                    .filter(|n| !n.is_empty())
                    .collect();

                info.imports.push((
                    capture[1].len(),
                    capture
                        .get(2)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default(),
                    names,
                ));
            }
        }
    }
    info
}

pub(super) fn cycles(edges: &BTreeMap<String, BTreeSet<String>>) -> Vec<Vec<String>> {
    fn dfs(
        n: &str,
        edges: &BTreeMap<String, BTreeSet<String>>,
        state: &mut HashMap<String, u8>,
        stack: &mut Vec<String>,
        found: &mut Vec<Vec<String>>,
    ) {
        state.insert(n.to_string(), 1);
        stack.push(n.to_string());

        for edge in edges.get(n).into_iter().flatten() {
            match state.get(edge) {
                Some(1) => {
                    let index = stack.iter().position(|s| s == edge).unwrap_or(0);
                    let mut cyc: Vec<String> = stack[index..].to_vec();
                    cyc.push(edge.clone());

                    if found.len() < 10 && !found.contains(&cyc) {
                        found.push(cyc);
                    }
                }
                None => dfs(edge, edges, state, stack, found),
                _ => {}
            }
        }
        stack.pop();
        state.insert(n.to_string(), 2);
    }

    let (mut found, mut state, mut stack) = (Vec::new(), HashMap::new(), Vec::new());
    for n in edges.keys() {
        if !state.contains_key(n) {
            dfs(n, edges, &mut state, &mut stack, &mut found);
        }
    }
    found
}
