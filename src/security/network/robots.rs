use regex::Regex;

struct Group {
    agents: Vec<String>,
    rules: Vec<(bool, Regex, usize)>,
}

pub struct Robots {
    groups: Vec<Group>,
    disallow_all: bool,
}

impl Robots {
    pub fn allow_all() -> Self {
        Robots {
            groups: vec![],
            disallow_all: false,
        }
    }

    pub fn deny_all() -> Self {
        Robots {
            groups: vec![],
            disallow_all: true,
        }
    }

    pub fn parse(text: &str) -> Self {
        let mut groups: Vec<Group> = Vec::new();
        let mut last_was_agent = false;

        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };

            let (key, value) = (key.trim().to_lowercase(), value.trim());
            match key.as_str() {
                "user-agent" => {
                    if !last_was_agent || groups.is_empty() {
                        groups.push(Group {
                            agents: vec![],
                            rules: vec![],
                        });
                    }

                    groups.last_mut().unwrap().agents.push(value.to_lowercase());
                    last_was_agent = true;
                }
                "allow" | "disallow" => {
                    last_was_agent = false;
                    let Some(group) = groups.last_mut() else {
                        continue;
                    };

                    if value.is_empty() {
                        continue;
                    } // empty Disallow = allow all

                    let anchored_end = value.ends_with('$');
                    let body = value.trim_end_matches('$');

                    let regex = format!(
                        "^{}{}",
                        body.split('*')
                            .map(regex::escape)
                            .collect::<Vec<_>>()
                            .join(".*"),
                        if anchored_end { "$" } else { "" }
                    );

                    if let Ok(regex_) = Regex::new(&regex) {
                        group.rules.push((key == "allow", regex_, value.len()));
                    }
                }
                _ => {
                    last_was_agent = false;
                }
            }
        }

        Robots {
            groups,
            disallow_all: false,
        }
    }

    /// RFC 9309: most specific group, then longest matching rule, Allow wins ties.
    pub fn can_fetch(&self, user_agent: &str, path_and_query: &str) -> bool {
        if self.disallow_all {
            return false;
        }

        let token = user_agent.split('/').next().unwrap_or("").to_lowercase();
        let specific: Vec<&Group> = self
            .groups
            .iter()
            .filter(|grp| {
                grp.agents
                    .iter()
                    .any(|agt| agt != "*" && token.contains(agt.as_str()))
            })
            .collect();

        let chosen = if !specific.is_empty() {
            specific
        } else {
            self.groups
                .iter()
                .filter(|grp| grp.agents.iter().any(|agt| agt == "*"))
                .collect()
        };

        let mut best: Option<(usize, bool)> = None;
        for group in chosen {
            for (allow, regex, len) in &group.rules {
                if regex.is_match(path_and_query)
                    && best
                        .map(|(size, alw)| *len > size || (*len == size && *allow && !alw))
                        .unwrap_or(true)
                {
                    best = Some((*len, *allow));
                }
            }
        }

        best.map(|(_, a)| a).unwrap_or(true)
    }
}
