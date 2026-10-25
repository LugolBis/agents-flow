//! Minimal XML DOM on top of quick-xml (used for OOXML parts and XML documents). Local names only for elements, qualified names for
//! attributes. A DOCTYPE declaring entities is refused (XXE / «billion laughs»): quick-xml never expands custom entities anyway.
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

const MAX_DEPTH: usize = 256;

#[derive(Debug, Default, Clone)]
pub struct Node {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
    pub text: String,
}

#[derive(Debug)]
pub enum XmlError {
    Unsafe,
    Malformed(String),
}

fn local(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.rsplit(':').next().unwrap_or("").to_string()
}

fn attrs_of(element: &BytesStart) -> Result<Vec<(String, String)>, XmlError> {
    let mut tags = Vec::new();
    for attribute_res in element.attributes() {
        let attribute = attribute_res.map_err(|err| XmlError::Malformed(err.to_string()))?;
        let val = attribute
            .unescape_value()
            .map_err(|err| XmlError::Malformed(err.to_string()))?
            .into_owned();

        tags.push((
            String::from_utf8_lossy(attribute.key.as_ref()).into_owned(),
            val,
        ));
    }
    Ok(tags)
}

pub fn parse(bytes: &[u8]) -> Result<Node, XmlError> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);

    let mut stack: Vec<Node> = vec![Node::default()];
    loop {
        match reader
            .read_event()
            .map_err(|err| XmlError::Malformed(err.to_string()))?
        {
            Event::Start(element) => {
                if stack.len() > MAX_DEPTH {
                    return Err(XmlError::Malformed("max depth excedeed".into()));
                }

                stack.push(Node {
                    name: local(element.name().as_ref()),
                    attrs: attrs_of(&element)?,
                    ..Default::default()
                });
            }
            Event::Empty(element) => {
                let node = Node {
                    name: local(element.name().as_ref()),
                    attrs: attrs_of(&element)?,
                    ..Default::default()
                };
                stack.last_mut().unwrap().children.push(node);
            }
            Event::End(_) => {
                if stack.len() < 2 {
                    return Err(XmlError::Malformed("unexpected closen tag".into()));
                }
                let node = stack.pop().unwrap();
                stack.last_mut().unwrap().children.push(node);
            }
            Event::Text(btext) => {
                let text = btext
                    .unescape()
                    .map_err(|err| XmlError::Malformed(err.to_string()))?;
                stack.last_mut().unwrap().text.push_str(&text);
            }
            Event::CData(bcd) => stack
                .last_mut()
                .unwrap()
                .text
                .push_str(&String::from_utf8_lossy(&bcd.into_inner())),
            Event::DocType(btext) => {
                if String::from_utf8_lossy(&btext)
                    .to_uppercase()
                    .contains("<!ENTITY")
                {
                    return Err(XmlError::Unsafe);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if stack.len() != 1 {
        return Err(XmlError::Malformed("not finished document".into()));
    }

    stack
        .pop()
        .unwrap()
        .children
        .into_iter()
        .next()
        .ok_or_else(|| XmlError::Malformed("empty document".into()))
}

impl Node {
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|child| child.name == name)
    }

    pub fn kids<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }

    pub fn descendants<'a>(&'a self, name: &str, out: &mut Vec<&'a Node>) {
        for child in &self.children {
            if child.name == name {
                out.push(child);
            }
            child.descendants(name, out);
        }
    }

    /// Concatenated text of all `name` descendants, skipping subtrees named in `skip`.
    pub fn text_of(&self, name: &str, skip: &[&str]) -> String {
        let mut buffer = String::new();

        fn go(node: &Node, name: &str, skip: &[&str], text: &mut String) {
            for child in &node.children {
                if skip.contains(&child.name.as_str()) {
                    continue;
                }
                if child.name == name {
                    text.push_str(&child.text);
                }
                go(child, name, skip, text);
            }
        }

        go(self, name, skip, &mut buffer);
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_and_refuses_entities() {
        let n = parse(
            br#"<?xml version="1.0"?><w:a xmlns:w="x"><w:b k="1">hi &amp; bye</w:b><w:b/></w:a>"#,
        )
        .unwrap();
        assert_eq!(n.name, "a");
        assert_eq!(n.kids("b").count(), 2);
        assert_eq!(n.child("b").unwrap().text, "hi & bye");
        assert!(matches!(
            parse(b"<!DOCTYPE x [<!ENTITY a \"b\">]><x>&a;</x>"),
            Err(XmlError::Unsafe)
        ));
        assert!(matches!(parse(b"<a><b></a>"), Err(XmlError::Malformed(_))));
    }
}
