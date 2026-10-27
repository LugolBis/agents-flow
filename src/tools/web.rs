//! Web tools. ALL traffic goes through `SafeFetcher` (SSRF, robots.txt, rate limit, size). Web content is ALWAYS framed as untrusted data.
//! No authentication is presented and no access protection is bypassed. `browser_fetch` needs a JavaScript browser (Playwright in the
//! Python original): not available in this build, the tool id is kept so configurations stay valid and it answers `browser_unavailable`.
use super::extract::core::{first_title, visible_texts};
use super::github::json_indent1;
use super::schema::{ArgSchema, Field};
use super::{Tool, ToolContext};
use crate::error::{Category, Error, Result, SecurityError};
use crate::security::network::transport::{HttpRequest, Transport, UreqTransport};
use crate::util::{clip, sha256_hex};
use regex::Regex;
use scraper::{Html, Selector};
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use url::Url;

static NL3: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n{3,}").unwrap());

const META_KEYS: &[&str] = &[
    "description",
    "author",
    "keywords",
    "og:title",
    "og:description",
    "og:type",
    "article:published_time",
];

fn sel(s: &str) -> Selector {
    Selector::parse(s).expect("static selector")
}

fn text_sep(e: scraper::ElementRef, strip_n: usize) -> String {
    clip(
        &e.text()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
        strip_n,
    )
}

pub struct Page {
    pub title: String,
    pub meta: Map<String, Value>,
    pub canonical: Option<String>,
    pub headings: Vec<String>,
    pub json_ld: Vec<Value>,
    pub links: Vec<(String, String)>,
    pub text: String,
}

pub fn parse_html(html: &str, base_url: &str) -> Page {
    let doc = Html::parse_document(html);
    let base = Url::parse(base_url).ok();
    let join = |h: &str| base.as_ref().and_then(|b| b.join(h).ok());

    let mut meta = Map::new();
    for elem_meta in doc.select(&sel("meta")) {
        let key = elem_meta
            .value()
            .attr("name")
            .or_else(|| elem_meta.value().attr("property"));

        if let (Some(key), Some(content)) = (key, elem_meta.value().attr("content")) {
            if !content.is_empty() && META_KEYS.contains(&key.to_lowercase().as_str()) {
                meta.insert(key.to_lowercase(), json!(crate::util::clip(content, 300)));
            }
        }
    }

    let canonical = doc
        .select(&sel("link[rel~=canonical]"))
        .filter_map(|elem| elem.value().attr("href"))
        .find_map(|href| join(href))
        .map(|url| url.to_string());

    let json_ld: Vec<Value> = doc
        .select(&sel("script[type=\"application/ld+json\"]"))
        .filter_map(|elem| serde_json::from_str(&elem.text().collect::<String>()).ok())
        .take(5)
        .collect();

    let mut links = Vec::new();
    for elem_a in doc.select(&sel("a[href]")) {
        if let Some(mut url) = join(elem_a.value().attr("href").unwrap_or("")) {
            url.set_fragment(None);

            if url.scheme() == "http" || url.scheme() == "https" {
                links.push((url.to_string(), text_sep(elem_a, 100)));
            }
        }
    }

    let headings: Vec<String> = doc
        .select(&sel("h1, h2, h3"))
        .map(|elem_h| text_sep(elem_h, 150))
        .take(30)
        .collect();

    let text = NL3
        .replace_all(&visible_texts(&doc, true).join("\n"), "\n\n")
        .into_owned();

    let title = clip(first_title(&doc).trim(), 200);
    Page {
        title,
        meta,
        canonical,
        headings,
        json_ld,
        links,
        text,
    }
}

fn dedupe(links: &[(String, String)]) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    links
        .iter()
        .filter(|(url, _)| seen.insert(url.clone()))
        .map(|(url, content)| json!({"url": url, "text": content}))
        .collect()
}

fn deny(code: &str, reason: &str) -> Error {
    SecurityError::network(code, reason).into()
}

fn host_of(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|url_| url_.host_str().map(String::from))
}

fn http_url(url: &str) -> bool {
    Url::parse(url)
        .map(|url_| url_.scheme() == "http" || url_.scheme() == "https")
        .unwrap_or(false)
}

tool!(WebSearchTool, "web_search", "agents_flow.tools.web.WebSearchTool", ["net.read"],
    "Web search via the configured provider (Brave or SearXNG). Returns titles, URLs, and snippets (unreliable).",
    ArgSchema(vec![Field::str("query", 300).min(2), Field::int("max_results", 1, 10).default(json!(8))]),
    |ctx, a| {
        let rt = ctx.rt;
        let cfg = &rt.settings.permissions.network;
        if cfg.search_provider == "none" {
            return Err(deny("search_disabled", "no search provider configured (network.search_provider); use fetch_page on a known URL"));
        }
        
        let transport: Arc<dyn Transport> = rt.search_transport.clone().unwrap_or_else(|| Arc::new(UreqTransport));
        let (query, n) = (a.str("query"), a.int("max_results"));
        
        let (mut url, mut headers, list_key, snip_key) = if cfg.search_provider == "brave" {
            let key = std::env::var(&cfg.search_api_key_env).ok().filter(|k| !k.is_empty()).ok_or_else(|| deny("search_key_missing", &format!("missing variable {}", cfg.search_api_key_env)))?;
            (Url::parse("https://api.search.brave.com/res/v1/web/search").unwrap(), vec![("X-Subscription-Token".to_string(), key), ("Accept".into(), "application/json".into())], "web.results", "description")
        } else {
            let b = cfg.search_base_url.as_deref().ok_or_else(|| deny("search_unconfigured", "network.search_base_url requis pour searxng"))?;
            (Url::parse(&format!("{}/search", b.trim_end_matches('/'))).map_err(|_| deny("search_unconfigured", "network.search_base_url invalide"))?, vec![], "results", "content")
        };

        headers.push(("User-Agent".into(), cfg.user_agent.clone()));
        if cfg.search_provider == "brave" {
            url.query_pairs_mut().append_pair("q", query).append_pair("count", &n.to_string());
        } else {
            url.query_pairs_mut().append_pair("q", query).append_pair("format", "json");
        }
        
        let resp = transport.get(&HttpRequest { url: url.to_string(), headers, pinned: vec![], timeout: Duration::from_secs_f64(cfg.timeout_s), max_bytes: 2_000_000 }).map_err(|e| deny("http_error", &format!("Network error ({e})")))?;
        
        if resp.status >= 400 { return Err(deny("http_error", &format!("search provider: HTTP {}", resp.status))); }
        
        let data: Value = serde_json::from_slice(&resp.body).map_err(|_| Error::internal("JSONDecodeError", "invalid search response"))?;
        let mut node = &data;

        for k in list_key.split('.') {
            node = node.get(k).unwrap_or(&Value::Null);
        }

        let items: Vec<Value> = node.as_array().cloned().unwrap_or_default().iter()
            .map(|x| json!({"title": x.get("title"), "url": x.get("url"), "snippet": x.get(snip_key)}))
            .filter(|i| i["url"].as_str().map(http_url).unwrap_or(false)).take(n as usize).collect();
        
        for i in &items {
            let u = i["url"].as_str().unwrap_or("").to_string();
            rt.fetcher.fetched_urls.lock().unwrap().insert(u.clone());
            rt.session.lock().unwrap().seen_urls.insert(u);
        }
        
        Ok(ctx.untrusted(&json_indent1(&Value::Array(items)), &format!("search:{}", crate::util::clip(query, 60))))
    });

fn seen(ctx: &ToolContext, urls: &[&str]) {
    let mut s = ctx.rt.session.lock().unwrap();
    for u in urls {
        s.seen_urls.insert((*u).to_string());
    }
}

tool!(FetchPageTool, "fetch_page", "agents_flow.tools.web.FetchPageTool", ["net.read"],
    "Downloads a page (public http/https only; respects robots.txt) and returns a JSON object containing the title, metadata, headings, text, JSON-LD, and—if requested—fields extracted via CSS selectors.",
    ArgSchema(vec![Field::str("url", 2048), Field::int("max_chars", 500, 40_000).default(json!(8000)), Field::bool("include_links").default(json!(false)),
                   Field::map("css_selectors", 10, 100, 300).opt().desc("Structured extraction: {name: CSS selector}.")]),
    |ctx, a| {
        let res = ctx.rt.fetcher.fetch(a.str("url"))?;

        seen(ctx, &[a.str("url"), &res.final_url]);
        let max = a.int("max_chars") as usize;

        let data = if res.content_type.contains("json") {
            json!({"url": res.final_url, "status": res.status, "json_text": clip(&res.text, max)})
        } else {
            let page = parse_html(&res.text, &res.final_url);
            let mut d = json!({"url": res.final_url, "status": res.status, "content_type": res.content_type, "title": page.title, "meta": page.meta, "canonical": page.canonical,
                "headings": page.headings, "json_ld": page.json_ld, "text": clip(&page.text, max), "text_truncated": page.text.chars().count() > max || res.truncated});
            
            if a.bool("include_links") {
                d["links"] = Value::Array(dedupe(&page.links).into_iter().take(50).collect());
            }

            let selectors = a.map("css_selectors");
            
            if !selectors.is_empty() {
                let doc = Html::parse_document(&res.text);
                let mut ex = Map::new();

                for (k, s) in selectors {
                    let sl = Selector::parse(&s).map_err(|_| Error::internal("SelectorError", "invalid CSS selector"))?;
                    ex.insert(k, Value::Array(doc.select(&sl).take(20).map(|e| json!(text_sep(e, 300))).collect()));
                }
                d["extracted"] = Value::Object(ex);
            }
            d
        };
        Ok(ctx.untrusted(&json_indent1(&data), &res.final_url))
    });

tool!(
    ExtractLinksTool,
    "extract_links",
    "agents_flow.tools.web.ExtractLinksTool",
    ["net.read"],
    "Lists the links on a page (deduplicated), optionally limited to the same domain.",
    ArgSchema(vec![
        Field::str("url", 2048),
        Field::bool("same_domain_only").default(json!(true)),
        Field::int("max_links", 1, 100).default(json!(40))
    ]),
    |ctx, a| {
        let res = ctx.rt.fetcher.fetch(a.str("url"))?;
        seen(ctx, &[a.str("url"), &res.final_url]);
        let mut links = dedupe(&parse_html(&res.text, &res.final_url).links);
        
        if a.bool("same_domain_only") {
            let h = host_of(&res.final_url);
            links.retain(|l| host_of(l["url"].as_str().unwrap_or("")) == h);
        }
        
        links.truncate(a.int("max_links") as usize);
        Ok(ctx.untrusted(&json_indent1(&Value::Array(links)), &res.final_url))
    }
);

tool!(CrawlSiteTool, "crawl_site", "agents_flow.tools.web.CrawlSiteTool", ["net.read"],
    "Explores multiple pages within the SAME domain, starting from a given URL (breadth-first search), with limits on the number of pages and crawl depth. Detects and ignores duplicates (both URLs and content). Respects robots.txt and rate limits.",
    ArgSchema(vec![Field::str("start_url", 2048), Field::int("max_pages", 1, 50).default(json!(5)), Field::int("max_depth", 0, 5).default(json!(1)), Field::int("chars_per_page", 200, 5000).default(json!(1500))]),
    |ctx, a| {
        let cfg = &ctx.rt.settings.permissions.network;
        let (max_pages, max_depth) = ((a.int("max_pages") as usize).min(cfg.max_crawl_pages), (a.int("max_depth") as usize).min(cfg.max_crawl_depth));
        let cpp = a.int("chars_per_page") as usize;
        let host = host_of(a.str("start_url"));
        
        let mut queue: VecDeque<(String, usize)> = VecDeque::from([(a.str("start_url").to_string(), 0)]);
        let (mut seen_urls, mut seen_hash, mut pages, mut skipped) = (BTreeSet::new(), BTreeSet::new(), Vec::<Value>::new(), Vec::<Value>::new());
        
        while let (Some((url, depth)), true) = (queue.pop_front(), pages.len() < max_pages) {
            let norm = url.split('#').next().unwrap_or("").trim_end_matches('/').to_string();
            
            if !seen_urls.insert(norm) { continue; }
            
            let res = match ctx.rt.fetcher.fetch(&url) {
                Ok(r) => r,
                Err(e) if e.category == Category::Network => {
                    skipped.push(json!({"url": url, "reason": e.code}));
                    continue;
                }
                Err(e) => return Err(e.into())
            };
            
            seen(ctx, &[&url, &res.final_url]);
            
            let page = parse_html(&res.text, &res.final_url);
            
            if !seen_hash.insert(sha256_hex(page.text.as_bytes())) {
                skipped.push(json!({"url": res.final_url, "reason": "duplicate content"}));
                continue;
            }
            
            pages.push(json!({"url": res.final_url, "depth": depth, "title": page.title, "text": clip(&page.text, cpp)}));
            if depth < max_depth {
                for l in dedupe(&page.links) {
                    let u = l["url"].as_str().unwrap_or("").to_string();

                    if host_of(&u) == host {
                        queue.push_back((u, depth + 1));
                    }
                }
            }
        }

        skipped.truncate(20);
        Ok(ctx.untrusted(&json_indent1(&json!({"pages": pages, "skipped": skipped})), &format!("crawl:{}", host.unwrap_or_default())))
    });

tool!(BrowserFetchTool, "browser_fetch", "agents_flow.tools.web.BrowserFetchTool", ["net.read"],
    "Loads a page using a headless browser (with JavaScript executed) and returns its visible text.",
    ArgSchema(vec![Field::str("url", 2048), Field::int("max_chars", 500, 40_000).default(json!(8000)), Field::bool("include_links").default(json!(false)),
                   Field::map("css_selectors", 10, 100, 300).opt().desc("Structured extraction: {name: CSS selector}.")]),
    |ctx, a| {
        Err::<String, Error>(deny("browser_unavailable", "Automated browser unavailable in this version (use fetch_page; pages that rely on JavaScript are not supported)"))
    });

pub fn tools() -> Vec<Box<dyn Tool>> {
    vec![
        Box::new(WebSearchTool),
        Box::new(FetchPageTool),
        Box::new(ExtractLinksTool),
        Box::new(CrawlSiteTool),
        Box::new(BrowserFetchTool),
    ]
}
#[allow(dead_code)]
fn _u(_: Result<()>) {}
