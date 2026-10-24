//! Controlled web access for the research agent.
//!  * http/https only, no credentials in the URL, allowed ports only;
//!  * SSRF protection: ALL resolved addresses must be public (loopback, private, link-local, cloud metadata, CGNAT… refused);
//!  * redirects followed MANUALLY: every hop is re-validated;
//!  * robots.txt honoured (configurable), per-host rate limit;
//!  * 401/403: stop (no authentication or protection bypass);
//!  * size capped AFTER decompression, MIME allowlist, global timeout;
//!  * no cookie, no environment proxy, no auth header.
//! Improvement over the Python original: the validated addresses are PINNED into the connection (custom resolver), which closes the
//! DNS-rebinding window between the check and the connect.
use crate::config::models::permissions::NetCfg;
use crate::error::SecResult;
use crate::security::network::helpers::net_denial;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;
use url::Url;

pub const MAX_URL_LEN: usize = 2048;

pub type Resolver = Arc<dyn Fn(&str) -> SecResult<Vec<IpAddr>> + Send + Sync>;

pub fn default_resolver(host: &str) -> SecResult<Vec<IpAddr>> {
    let it = (host, 0u16)
        .to_socket_addrs()
        .map_err(|_| net_denial("dns_failure", "DNS resolution failed"))?;
    let set: BTreeSet<IpAddr> = it.map(|a| a.ip()).collect();
    Ok(set.into_iter().collect())
}

fn v4_public(a: Ipv4Addr) -> bool {
    let oct = a.octets();
    !(oct[0] == 0
        || oct[0] == 10
        || (oct[0] == 100 && (64..128).contains(&oct[1]))
        || oct[0] == 127
        || (oct[0] == 169 && oct[1] == 254)
        || (oct[0] == 172 && (16..32).contains(&oct[1]))
        || (oct[0] == 192 && oct[1] == 0 && oct[2] == 0 && !(oct[3] == 9 || oct[3] == 10))
        || (oct[0] == 192 && oct[1] == 0 && oct[2] == 2)
        || (oct[0] == 192 && oct[1] == 88 && oct[2] == 99)
        || (oct[0] == 192 && oct[1] == 168)
        || (oct[0] == 198 && (oct[1] == 18 || oct[1] == 19))
        || (oct[0] == 198 && oct[1] == 51 && oct[2] == 100)
        || (oct[0] == 203 && oct[1] == 0 && oct[2] == 113)
        || oct[0] >= 224)
}

/// Equivalent of Python's `ip.is_global and not ip.is_multicast`, fail-closed for exotic IPv6 ranges.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(adr) => v4_public(adr),
        IpAddr::V6(adr) => {
            if let Some(mapped) = adr.to_ipv4_mapped() {
                return v4_public(mapped);
            }
            let segts = adr.segments();

            if adr.is_unspecified() || adr.is_loopback() || adr.is_multicast() {
                return false;
            }

            if segts[0] & 0xfe00 == 0xfc00
                || segts[0] & 0xffc0 == 0xfe80
                || segts[0] & 0xffc0 == 0xfec0
            {
                return false;
            } // ULA, link-local, site-local

            if segts[0] == 0x2001 && segts[1] == 0x0db8 {
                return false;
            } // documentation

            if segts[0] == 0x2001 && segts[1] < 0x0200 {
                // 2001::/23 IETF protocol assignments, minus the explicitly global sub-ranges
                let global = matches!((segts[1], segts[2]), (1, 1) | (1, 2) | (3, _))
                    && segts[1] != 0
                    || (segts[1] == 4 && segts[2] == 0x112)
                    || (0x20..0x40).contains(&segts[1]);

                if !global {
                    return false;
                }
            }

            if segts[0] == 0x2002
                || (segts[0] == 0x0100 && segts[1] == 0 && segts[2] == 0 && segts[3] == 0)
            {
                return false;
            } // 6to4, discard-only

            if segts[0] == 0x0064 && segts[1] == 0xff9b && segts[2] == 1 {
                return false;
            } // local-use NAT64

            if segts[0] == 0x0064 && segts[1] == 0xff9b && segts[2..6] == [0, 0, 0, 0] {
                // well-known NAT64: judge the embedded IPv4
                return v4_public(Ipv4Addr::new(
                    (segts[6] >> 8) as u8,
                    segts[6] as u8,
                    (segts[7] >> 8) as u8,
                    segts[7] as u8,
                ));
            }

            if segts[..6] == [0; 6] {
                return false;
            } // IPv4-compatible / reserved ::/96
            true
        }
    }
}

#[derive(Debug, Clone)]
pub struct CheckedUrl {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub addrs: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct FetchResult {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub content_type: String,
    pub text: String,
    pub truncated: bool,
    pub redirects: u32,
}

fn domain_match(host: &str, domains: &[String]) -> bool {
    domains.iter().any(|domain| {
        let d = domain.to_lowercase();
        host == d || host.ends_with(&format!(".{d}"))
    })
}

pub struct UrlPolicy {
    pub cfg: NetCfg,
    resolve: Resolver,
}

impl UrlPolicy {
    pub fn new(cfg: &NetCfg, resolver: Option<Resolver>) -> Self {
        UrlPolicy {
            cfg: cfg.clone(),
            resolve: resolver.unwrap_or_else(|| Arc::new(default_resolver)),
        }
    }

    pub fn check(&self, raw: &str) -> SecResult<CheckedUrl> {
        if raw.is_empty() || raw.len() > MAX_URL_LEN {
            return Err(net_denial("bad_url", "empty or too long URL"));
        }

        if raw.chars().any(|c| (c as u32) < 33 || c as u32 == 127) {
            return Err(net_denial("bad_url", "invalid characters in the URL"));
        }

        let url = Url::parse(raw).map_err(|_| net_denial("bad_url", "invalid URL"))?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(net_denial(
                "scheme_not_allowed",
                "only 'http' or 'https' are authorized",
            ));
        }

        if !url.username().is_empty() || url.password().is_some() {
            return Err(net_denial(
                "credentials_in_url",
                "forbidden identifier in the URL",
            ));
        }

        let host = url
            .host_str()
            .unwrap_or("")
            .to_lowercase()
            .trim_end_matches('.')
            .trim_matches(['[', ']'])
            .to_string();

        if host.is_empty() {
            return Err(net_denial("bad_url", "host missing"));
        }

        let port = url.port_or_known_default().unwrap_or(0);
        if !self.cfg.allowed_ports.contains(&port) {
            return Err(net_denial(
                "port_not_allowed",
                format!("port {port} not authorized"),
            ));
        }

        if domain_match(&host, &self.cfg.deny_domains) {
            return Err(net_denial(
                "domain_denied",
                "domain forbidden by the policy",
            ));
        }

        if !self.cfg.allow_domains.is_empty() && !domain_match(&host, &self.cfg.allow_domains) {
            return Err(net_denial(
                "domain_not_allowed",
                "domain missing from the authorized list",
            ));
        }

        // the `url` crate already applied IDNA/punycode and normalised numeric IPv4 forms (0x7f.1, 2130706433…)
        let addrs: Vec<IpAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => (self.resolve)(&host)?,
        };

        if addrs.is_empty() {
            return Err(net_denial("dns_failure", "no adress resolved"));
        }

        if addrs.iter().any(|a| !is_public_ip(*a)) {
            return Err(net_denial(
                "private_address",
                "no public adress (SSRF) refused",
            ));
        }

        let mut clean = url.clone();
        clean.set_fragment(None);

        Ok(CheckedUrl {
            url: clean.to_string(),
            host,
            port,
            scheme: url.scheme().to_string(),
            addrs,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use crate::security::network::{
        fetcher::SafeFetcher,
        robots::Robots,
        transport::{HttpRequest, HttpResponse, Transport},
    };

    use super::*;
    fn cfg() -> NetCfg {
        NetCfg {
            min_interval_s: 0.0,
            ..NetCfg::default()
        }
    }
    fn resolver(map: &'static [(&'static str, &'static str)]) -> Resolver {
        Arc::new(move |h: &str| {
            map.iter()
                .filter(|(n, _)| *n == h)
                .map(|(_, ip)| ip.parse().unwrap())
                .collect::<Vec<IpAddr>>()
                .into_iter()
                .map(Ok)
                .collect::<SecResult<Vec<_>>>()
        })
    }
    fn code(r: SecResult<CheckedUrl>) -> String {
        r.err().map(|e| e.code).unwrap_or_else(|| "ok".into())
    }
    #[test]
    fn public_ip_classification() {
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "2002::1",
            "2001:db8::1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn url_policy() {
        let p = UrlPolicy::new(
            &cfg(),
            Some(resolver(&[
                ("example.com", "93.184.216.34"),
                ("evil.test", "10.0.0.5"),
                ("mixed.test", "93.184.216.34"),
                ("mixed.test", "127.0.0.1"),
            ])),
        );
        assert_eq!(code(p.check("https://example.com/a?b=1#frag")), "ok");
        assert_eq!(code(p.check("ftp://example.com/")), "scheme_not_allowed");
        assert_eq!(
            code(p.check("https://user:pw@example.com/")),
            "credentials_in_url"
        );
        assert_eq!(
            code(p.check("https://example.com:8080/")),
            "port_not_allowed"
        );
        assert_eq!(code(p.check("http://127.0.0.1/")), "private_address");
        assert_eq!(code(p.check("http://2130706433/")), "private_address");
        assert_eq!(code(p.check("http://0x7f.1/")), "private_address");
        assert_eq!(code(p.check("http://[::1]/")), "private_address");
        assert_eq!(
            code(p.check("http://169.254.169.254/latest/meta-data")),
            "private_address"
        );
        assert_eq!(code(p.check("https://evil.test/")), "private_address");
        assert_eq!(code(p.check("https://mixed.test/")), "private_address");
        assert_eq!(code(p.check("https://exa mple.com/")), "bad_url");
        assert!(!p
            .check("https://example.com/p#x")
            .unwrap()
            .url
            .contains('#'));
    }
    #[test]
    fn robots_rules() {
        let r = Robots::parse("User-agent: *\nDisallow: /private\nAllow: /private/ok\nDisallow: /*.pdf$\n\nUser-agent: agwo-research\nDisallow: /nope\n");
        let ua = "agwo-research/0.1 (+x)";
        assert!(!r.can_fetch(ua, "/nope/x"));
        assert!(r.can_fetch(ua, "/private/x"), "specific group replaces '*'");
        let r2 = Robots::parse(
            "User-agent: *\nDisallow: /private\nAllow: /private/ok\nDisallow: /*.pdf$",
        );
        assert!(
            !r2.can_fetch("bot", "/private/x")
                && r2.can_fetch("bot", "/private/ok/y")
                && !r2.can_fetch("bot", "/a/b.pdf")
                && r2.can_fetch("bot", "/a/b.pdf?x")
        );
        assert!(
            Robots::allow_all().can_fetch("bot", "/x")
                && !Robots::deny_all().can_fetch("bot", "/x")
        );
    }
    struct Mock(
        Mutex<Vec<(String, u16, Vec<(String, String)>, String)>>,
        Mutex<Vec<String>>,
    );
    impl Transport for Mock {
        fn get(&self, r: &HttpRequest) -> Result<HttpResponse, String> {
            self.1.lock().unwrap().push(r.url.clone());
            let q = self.0.lock().unwrap();
            let (_, st, h, body) = q
                .iter()
                .find(|(u, ..)| *u == r.url)
                .ok_or("ConnectionRefused")?
                .clone();
            Ok(HttpResponse {
                status: st,
                headers: h,
                body: body.into_bytes(),
                truncated: false,
            })
        }
    }
    #[test]
    fn redirects_are_revalidated_and_status_mapped() {
        let h = |t: &str| vec![("content-type".to_string(), t.to_string())];
        let loc = |l: &str| vec![("location".to_string(), l.to_string())];
        let m = Arc::new(Mock(
            Mutex::new(vec![
                (
                    "https://example.com/a".into(),
                    302,
                    loc("http://evil.test/x"),
                    "".into(),
                ),
                (
                    "https://example.com/ok".into(),
                    200,
                    h("text/html; charset=utf-8"),
                    "<p>hi</p>".into(),
                ),
                ("https://example.com/r1".into(), 301, loc("/ok"), "".into()),
                (
                    "https://example.com/forbidden".into(),
                    403,
                    h("text/html"),
                    "".into(),
                ),
                (
                    "https://example.com/bin".into(),
                    200,
                    h("application/octet-stream"),
                    "x".into(),
                ),
            ]),
            Mutex::new(vec![]),
        ));
        let policy = UrlPolicy::new(
            &NetCfg {
                respect_robots: false,
                ..cfg()
            },
            Some(resolver(&[
                ("example.com", "93.184.216.34"),
                ("evil.test", "10.0.0.5"),
            ])),
        );
        let f = SafeFetcher::new(
            &NetCfg {
                respect_robots: false,
                ..cfg()
            },
            Some(policy),
            Some(m.clone()),
        );
        assert_eq!(
            f.fetch("https://example.com/a").unwrap_err().code,
            "private_address"
        );
        assert_eq!(
            m.1.lock().unwrap().len(),
            1,
            "the private hop must never be requested"
        );
        let r = f.fetch("https://example.com/r1").unwrap();
        assert_eq!(
            (r.status, r.redirects, r.final_url.as_str()),
            (200, 1, "https://example.com/ok")
        );
        assert_eq!(
            f.fetch("https://example.com/forbidden").unwrap_err().code,
            "access_restricted"
        );
        assert_eq!(
            f.fetch("https://example.com/bin").unwrap_err().code,
            "content_type_not_allowed"
        );
        assert!(f
            .fetched_urls
            .lock()
            .unwrap()
            .contains("https://example.com/ok"));
    }
}
