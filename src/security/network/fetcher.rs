use crate::config::models::permissions::NetCfg;
use crate::error::SecResult;
use crate::security::network::core::{CheckedUrl, FetchResult, UrlPolicy};
use crate::security::network::helpers::{decode, net_denial};
use crate::security::network::robots::Robots;
use crate::security::network::transport::{HttpRequest, Transport, UreqTransport};
use crate::util::clip;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

type UrlFilter = Box<dyn Fn(&str) -> SecResult<()> + Send + Sync>;

pub struct SafeFetcher {
    pub cfg: NetCfg,
    pub policy: UrlPolicy,
    transport: Arc<dyn Transport>,
    sleep: Box<dyn Fn(Duration) + Send + Sync>,
    clock: Box<dyn Fn() -> f64 + Send + Sync>,
    last_hit: Mutex<HashMap<String, f64>>,
    robots: Mutex<HashMap<String, Arc<Robots>>>,
    /// Feeds the «cited sources» guardrail.
    pub fetched_urls: Mutex<BTreeSet<String>>,
    /// Anti-exfiltration filter (set by the runtime): refuses a URL that would carry a secret.
    url_filter: Option<UrlFilter>,
}

impl SafeFetcher {
    pub fn new(
        cfg: &NetCfg,
        policy: Option<UrlPolicy>,
        transport: Option<Arc<dyn Transport>>,
    ) -> Self {
        let start = std::time::Instant::now();
        SafeFetcher {
            cfg: cfg.clone(),
            policy: policy.unwrap_or_else(|| UrlPolicy::new(cfg, None)),
            transport: transport.unwrap_or_else(|| Arc::new(UreqTransport)),
            sleep: Box::new(std::thread::sleep),
            clock: Box::new(move || start.elapsed().as_secs_f64()),
            last_hit: Mutex::new(HashMap::new()),
            robots: Mutex::new(HashMap::new()),
            fetched_urls: Mutex::new(BTreeSet::new()),
            url_filter: None,
        }
    }

    pub fn with_url_filter(mut self, filter: UrlFilter) -> Self {
        self.url_filter = Some(filter);
        self
    }

    pub fn with_clock(
        mut self,
        sleep: Box<dyn Fn(Duration) + Send + Sync>,
        clock: Box<dyn Fn() -> f64 + Send + Sync>,
    ) -> Self {
        self.sleep = sleep;
        self.clock = clock;
        self
    }

    fn throttle(&self, host: &str) {
        let mut hits = self.last_hit.lock().unwrap();
        if let Some(last) = hits.get(host) {
            if self.cfg.min_interval_s > 0.0 {
                let wait = self.cfg.min_interval_s - ((self.clock)() - last);
                if wait > 0.0 {
                    (self.sleep)(Duration::from_secs_f64(wait.min(30.0)));
                }
            }
        }
        hits.insert(host.to_string(), (self.clock)());
    }

    fn robots_allows(&self, url_chk: &CheckedUrl) -> bool {
        let origin = format!("{}://{}:{}", url_chk.scheme, url_chk.host, url_chk.port);
        let cached = self.robots.lock().unwrap().get(&origin).cloned();

        let rp = match cached {
            Some(robot) => robot,
            None => {
                let robots_url = format!(
                    "{}://{}{}/robots.txt",
                    url_chk.scheme,
                    url_chk.host,
                    if url_chk.port == 80 || url_chk.port == 443 {
                        String::new()
                    } else {
                        format!(":{}", url_chk.port)
                    }
                );
                let robot = match self.fetch_once(&robots_url, 500_000, false, false) {
                    Ok(res) if res.status == 200 => Robots::parse(&res.text),
                    Ok(res) if (400..500).contains(&res.status) => Robots::allow_all(),
                    _ => Robots::deny_all(), // cautious: unreachable => forbidden
                };
                let robot_ = Arc::new(robot);
                self.robots.lock().unwrap().insert(origin, robot_.clone());
                robot_
            }
        };

        let url_opt = Url::parse(&url_chk.url).ok();
        let pq = url_opt
            .map(|u| {
                format!(
                    "{}{}",
                    u.path(),
                    u.query().map(|q| format!("?{q}")).unwrap_or_default()
                )
            })
            .unwrap_or_else(|| "/".into());

        rp.can_fetch(&self.cfg.user_agent, &pq)
    }

    fn fetch_once(
        &self,
        url: &str,
        max_bytes: usize,
        check_type: bool,
        robots: bool,
    ) -> SecResult<FetchResult> {
        if let Some(fn_filter) = &self.url_filter {
            fn_filter(url)?;
        }

        let checked = self.policy.check(url)?;
        if robots && self.cfg.respect_robots && !self.robots_allows(&checked) {
            return Err(net_denial(
                "robots_disallowed",
                "robots.txt disallows access to this resource",
            ));
        }

        self.throttle(&checked.host);
        let req = HttpRequest {
            url: checked.url.clone(),
            pinned: checked.addrs.clone(),
            timeout: Duration::from_secs_f64(self.cfg.timeout_s),
            max_bytes,
            headers: vec![
                ("User-Agent".into(), self.cfg.user_agent.clone()),
                (
                    "Accept".into(),
                    "text/html,application/xhtml+xml,application/json,text/plain;q=0.8".into(),
                ),
            ],
        };

        let resp = self
            .transport
            .get(&req)
            .map_err(|err| net_denial("http_error", format!("Network error ({err})")))?;

        if matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
            let loc = resp.header("location").unwrap_or("");
            let target = Url::parse(&checked.url)
                .ok()
                .and_then(|b| b.join(loc).ok())
                .map(|u| u.to_string())
                .unwrap_or_default();

            return Ok(FetchResult {
                url: checked.url.clone(),
                final_url: target,
                status: resp.status,
                content_type: String::new(),
                text: String::new(),
                truncated: false,
                redirects: 0,
            });
        }

        let ct_header = resp
            .header("content-type")
            .unwrap_or("text/plain")
            .to_string();

        let ctype = ct_header
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();

        if check_type && resp.status == 200 && !self.cfg.allowed_content_types.contains(&ctype) {
            return Err(net_denial(
                "content_type_not_allowed",
                format!("unauthorized content type : {}", clip(&ctype, 40)),
            ));
        }

        Ok(FetchResult {
            url: checked.url.clone(),
            final_url: checked.url,
            status: resp.status,
            content_type: ctype,
            text: decode(&resp.body, &ct_header),
            truncated: resp.truncated,
            redirects: 0,
        })
    }

    pub fn fetch(&self, url: &str) -> SecResult<FetchResult> {
        let (mut current, mut hops) = (url.to_string(), 0u32);
        loop {
            let res = self.fetch_once(&current, self.cfg.max_bytes, true, true)?;

            if matches!(res.status, 301 | 302 | 303 | 307 | 308) {
                hops += 1;

                if hops > self.cfg.max_redirects {
                    return Err(net_denial("too_many_redirects", "too many redirects"));
                }

                if res.final_url.is_empty() || res.final_url == current {
                    return Err(net_denial("bad_redirect", "invalid redirection"));
                }

                current = res.final_url; // re-validated next turn (SSRF, domain, robots)
                continue;
            }

            if matches!(res.status, 401 | 403 | 407) {
                return Err(net_denial(
                    "access_restricted",
                    format!(
                        "restricted access (HTTP {}): no bypass attempted",
                        res.status
                    ),
                ));
            }

            if res.status == 429 {
                return Err(net_denial(
                    "rate_limited",
                    "HTTP 429: site rate limit, please try again later",
                ));
            }

            {
                let mut fetched_guard = self.fetched_urls.lock().unwrap();
                fetched_guard.insert(url.to_string());
                fetched_guard.insert(res.url.clone());
            }

            return Ok(FetchResult {
                url: url.to_string(),
                final_url: res.url,
                status: res.status,
                content_type: res.content_type,
                text: res.text,
                truncated: res.truncated,
                redirects: hops,
            });
        }
    }
}
