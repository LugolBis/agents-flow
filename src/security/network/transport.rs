use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use ureq::unversioned::{
    resolver::{ResolvedSocketAddrs, Resolver},
    transport::{DefaultConnector, NextTimeout},
};
use ureq::{config::Config, http::Uri, Agent, Error};

pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub pinned: Vec<IpAddr>,
    pub timeout: Duration,
    pub max_bytes: usize,
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub truncated: bool,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub trait Transport: Send + Sync {
    fn get(&self, req: &HttpRequest) -> Result<HttpResponse, String>;
}

#[derive(Debug)]
struct Pinned(Vec<IpAddr>);
impl Resolver for Pinned {
    fn resolve(
        &self,
        uri: &Uri,
        _c: &Config,
        _t: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, Error> {
        let port = uri
            .port_u16()
            .or_else(|| {
                uri.scheme()
                    .and_then(|s| s.as_str().eq("https").then_some(443).or(Some(80)))
            })
            .unwrap_or(80);

        let mut array = self.empty();
        for ip in self.0.iter().take(16) {
            array.push(SocketAddr::new(*ip, port));
        }

        if self.0.is_empty() {
            return Err(Error::HostNotFound);
        }

        Ok(array)
    }
}

/// rustls (ring) transport: pure Rust, no OpenSSL, builds on Windows ARM64 and Linux ARM64.
pub struct UreqTransport;

impl Transport for UreqTransport {
    fn get(&self, req: &HttpRequest) -> Result<HttpResponse, String> {
        let cfg = Agent::config_builder()
            .timeout_global(Some(req.timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            .proxy(None)
            .build();

        let agent = if req.pinned.is_empty() {
            Agent::new_with_config(cfg)
        } else {
            Agent::with_parts(cfg, DefaultConnector::new(), Pinned(req.pinned.clone()))
        };

        let mut req_build = agent.get(&req.url);
        for (key, val) in &req.headers {
            req_build = req_build.header(key.as_str(), val.as_str());
        }

        let mut resp = req_build.call().map_err(|err| {
            format!("{err:?}")
                .split('(')
                .next()
                .unwrap_or("Error")
                .to_string()
        })?;

        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(key, value)| {
                (
                    key.as_str().to_string(),
                    value.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();

        if (300..400).contains(&status) {
            return Ok(HttpResponse {
                status,
                headers,
                body: vec![],
                truncated: false,
            });
        }

        let mut body = Vec::new();
        let mut reader = resp.body_mut().as_reader().take(req.max_bytes as u64 + 1);
        let _ = reader.read_to_end(&mut body);
        let truncated = body.len() > req.max_bytes;

        body.truncate(req.max_bytes);

        Ok(HttpResponse {
            status,
            headers,
            body,
            truncated,
        })
    }
}
