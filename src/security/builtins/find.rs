use super::{
    context::Ctx,
    system::{atime, ctime, hidden, mtime, nope, Out},
};
use crate::util::{fnmatch_regex_ci, unix_now};

use regex::Regex;
use std::{
    fs::{self, read_dir, Metadata},
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Debug, Clone)]
enum Pred {
    Name(Regex),
    Path(Regex),
    Type(char),
    Size(char, i64, i64),
    Time(char, char, i64, bool),
    Empty,
    Print,
}

#[derive(Debug, Clone)]
enum Node {
    P(Pred),
    Not(Box<Node>),
    And(Vec<Node>),
    Or(Vec<Node>),
}

struct Parser {
    tokens: Vec<String>,
    index: usize,
}

fn parse_cmp(value: &str) -> (char, i64) {
    match value.as_bytes().first() {
        Some(b'+') => ('+', value[1..].parse().unwrap_or(0)),
        Some(b'-') => ('-', value[1..].parse().unwrap_or(0)),
        _ => ('=', value.parse().unwrap_or(0)),
    }
}

impl Parser {
    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.index).map(String::as_str)
    }

    fn or(&mut self) -> Result<Node, String> {
        let mut nodes = vec![self.and()?];

        while matches!(self.peek(), Some("-o" | "-or")) {
            self.index += 1;
            nodes.push(self.and()?);
        }

        Ok(if nodes.len() == 1 {
            nodes.pop().unwrap()
        } else {
            Node::Or(nodes)
        })
    }

    fn and(&mut self) -> Result<Node, String> {
        let mut nodes = vec![self.unary()?];

        while let Some(token) = self.peek() {
            if matches!(token, "-o" | "-or") {
                break;
            }

            if matches!(token, "-a" | "-and") {
                self.index += 1;
            }
            nodes.push(self.unary()?);
        }

        Ok(if nodes.len() == 1 {
            nodes.pop().unwrap()
        } else {
            Node::And(nodes)
        })
    }

    fn unary(&mut self) -> Result<Node, String> {
        let token = self.peek().ok_or("incomplete expression")?.to_string();
        self.index += 1;

        if token == "!" || token == "-not" {
            return Ok(Node::Not(Box::new(self.unary()?)));
        }

        let mut fn_match_toks = || -> Result<String, String> {
            let res = self
                .tokens
                .get(self.index)
                .cloned()
                .ok_or("missing value")?;
            self.index += 1;
            Ok(res)
        };

        Ok(Node::P(match token.as_str() {
            "-print" => Pred::Print,
            "-empty" => Pred::Empty,
            "-name" => Pred::Name(fnmatch_regex_ci(&fn_match_toks()?, false)),
            "-iname" => Pred::Name(fnmatch_regex_ci(&fn_match_toks()?, true)),
            "-path" => Pred::Path(fnmatch_regex_ci(&fn_match_toks()?, false)),
            "-ipath" => Pred::Path(fnmatch_regex_ci(&fn_match_toks()?, true)),
            "-type" => Pred::Type(fn_match_toks()?.chars().next().unwrap_or('f')),
            "-size" => {
                let value = fn_match_toks()?;
                let (unit, digits) = match value.chars().last() {
                    Some(c) if "cwbkMG".contains(c) => (c, &value[..value.len() - 1]),
                    _ => ('b', value.as_str()),
                };

                let (cmp, n) = parse_cmp(digits);
                let mult = match unit {
                    'c' => 1,
                    'w' => 2,
                    'k' => 1024,
                    'M' => 1 << 20,
                    'G' => 1 << 30,
                    _ => 512,
                };

                Pred::Size(cmp, n, mult)
            }
            "-mtime" | "-atime" | "-ctime" | "-mmin" => {
                let (c, n) = parse_cmp(&fn_match_toks()?);
                Pred::Time(token.chars().nth(1).unwrap(), c, n, token == "-mmin")
            }
            other => return Err(format!("unknown predicate {other}")),
        }))
    }
}

fn cmp_ok(target_char: char, got: i64, want: i64) -> bool {
    match target_char {
        '+' => got > want,
        '-' => got < want,
        _ => got == want,
    }
}

fn eval(node: &Node, path: &Path, name: &str, meta_data: &Metadata, now: i64) -> bool {
    match node {
        Node::Not(node_ref) => !eval(node_ref, path, name, meta_data, now),
        Node::And(nodes) => nodes
            .iter()
            .all(|node_| eval(node_, path, name, meta_data, now)),
        Node::Or(nodes) => nodes
            .iter()
            .any(|node_| eval(node_, path, name, meta_data, now)),
        Node::P(pred) => match pred {
            Pred::Print => true,
            Pred::Name(regex) => regex.is_match(name),
            Pred::Path(regex) => regex.is_match(&path.to_string_lossy()),
            Pred::Type(char_) => {
                let file_type = meta_data.file_type();
                match char_ {
                    'f' => file_type.is_file(),
                    'd' => file_type.is_dir(),
                    'l' => file_type.is_symlink(),
                    _ => false,
                }
            }
            Pred::Size(char_, n, mult) => {
                cmp_ok(*char_, (meta_data.len() as i64 + mult - 1) / mult, *n)
            }
            Pred::Empty => {
                if meta_data.is_dir() {
                    read_dir(path)
                        .map(|mut dir| dir.next().is_none())
                        .unwrap_or(false)
                } else {
                    meta_data.is_file() && meta_data.len() == 0
                }
            }
            Pred::Time(kind, char_, n, minutes) => {
                let time = match kind {
                    'a' => atime(meta_data),
                    'c' => ctime(meta_data),
                    _ => mtime(meta_data),
                };

                let age = (now - time).max(0);
                cmp_ok(
                    *char_,
                    if *minutes {
                        (age + 59) / 60
                    } else {
                        age / 86_400
                    },
                    *n,
                )
            }
        },
    }
}

pub fn find(argv: &[String], ctx: &Ctx) -> Out {
    let mut out = Out::default();
    let mut index = 0;

    if argv.first().map(String::as_str) == Some("-P") {
        index = 1;
    }

    let mut starts = Vec::new();
    while index < argv.len() && !argv[index].starts_with('-') {
        starts.push(PathBuf::from(&argv[index]));
        index += 1;
    }

    let (mut maxd, mut mind) = (ctx.max_depth, 0usize);
    loop {
        match argv.get(index).map(String::as_str) {
            Some("-maxdepth") => {
                maxd = argv[index + 1].parse().unwrap_or(maxd);
                index += 2;
            }
            Some("-mindepth") => {
                mind = argv[index + 1].parse().unwrap_or(0);
                index += 2;
            }
            _ => break,
        }
    }

    let expr = if index < argv.len() {
        match (Parser {
            tokens: argv[index..].to_vec(),
            index: 0,
        })
        .run()
        {
            Ok(n) => Some(n),
            Err(e) => {
                out.fail(format!("find: invalid expression : {e}"));
                out.exit = 1;
                return out;
            }
        }
    } else {
        None
    };

    let now = unix_now();
    for start in &starts {
        let mut stack = vec![(start.clone(), 0usize)];

        while let Some((path, depth)) = stack.pop() {
            if Instant::now() > ctx.deadline {
                out.timed_out = true;
                out.exit = 1;
                return out;
            }

            let meta_data = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    out.fail(format!("find: '{}': {}", path.display(), nope(&e)));
                    continue;
                }
            };

            if depth > 0 && hidden(ctx, &path) {
                continue;
            }

            let name = if depth == 0 {
                path.to_string_lossy().to_string()
            } else {
                path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default()
            };

            if depth >= mind
                && expr
                    .as_ref()
                    .map(|node| eval(node, &path, &name, &meta_data, now))
                    .unwrap_or(true)
            {
                if !out.push(ctx.max_out, &path.to_string_lossy()) {
                    return out;
                }
            }

            if meta_data.is_dir() && depth < maxd {
                if let Ok(rd) = fs::read_dir(&path) {
                    let mut kids: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                    kids.sort_by(|a, b| b.as_os_str().cmp(a.as_os_str())); // popped in ascending order
                    stack.extend(kids.into_iter().map(|k| (k, depth + 1)));
                }
            }
        }
    }
    out
}

impl Parser {
    fn run(mut self) -> Result<Node, String> {
        let n = self.or()?;
        if self.index < self.tokens.len() {
            return Err(format!("unexpected token {}", self.tokens[self.index]));
        }
        Ok(n)
    }
}
