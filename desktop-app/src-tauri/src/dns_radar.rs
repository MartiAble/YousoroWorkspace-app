use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeSet, net::IpAddr, time::Duration};

const PROVIDER: &str = "https://bash.ws";

#[derive(Serialize)]
pub struct DnsReport {
    status: &'static str,
    tunnel_resolvers: usize,
    system_resolvers: usize,
}

fn outcome(tunnel: &BTreeSet<IpAddr>, system: &BTreeSet<IpAddr>) -> DnsReport {
    let status = if tunnel.is_empty() || system.is_empty() { "unavailable" }
        else if tunnel.is_disjoint(system) { "distinct" } else { "overlap" };
    DnsReport { status, tunnel_resolvers: tunnel.len(), system_resolvers: system.len() }
}

impl DnsReport {
    pub fn distinct(&self) -> bool { self.status == "distinct" }
}

fn valid_probe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|c| c.is_ascii_alphanumeric())
}

fn resolvers(collector: &reqwest::blocking::Client, route: &reqwest::blocking::Client) -> BTreeSet<IpAddr> {
    let lookup = || -> Option<BTreeSet<IpAddr>> {
        let id = collector.get(format!("{PROVIDER}/id")).send().ok()?.error_for_status().ok()?.text().ok()?;
        let id = id.trim();
        if !valid_probe_id(id) { return None; }
        std::thread::scope(|scope| {
            for index in 1..=3 {
                scope.spawn(move || {
                    // The observer needs DNS resolution only. TLS failure at the test hostname is expected.
                    let _ = route.get(format!("https://{index}.{id}.bash.ws/")).send();
                });
            }
        });
        let result: Vec<Value> = collector.get(format!("{PROVIDER}/dnsleak/test/{id}?json=2"))
            .send().ok()?.error_for_status().ok()?.json().ok()?;
        Some(result.iter().filter(|item| item["type"] == "dns").filter_map(|item| item["ip"].as_str()?.parse().ok()).collect())
    };
    lookup().unwrap_or_default()
}

pub fn check(port: u16) -> DnsReport {
    let direct = reqwest::blocking::Client::builder().no_proxy().timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none()).build();
    let tunneled = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).ok().and_then(|proxy|
        reqwest::blocking::Client::builder().proxy(proxy).timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none()).build().ok());
    if let (Ok(direct), Some(tunneled)) = (direct, tunneled) {
        return std::thread::scope(|scope| {
            let tunnel = scope.spawn(|| resolvers(&direct, &tunneled));
            let system = resolvers(&direct, &direct);
            outcome(&tunnel.join().unwrap_or_default(), &system)
        });
    }
    outcome(&BTreeSet::new(), &BTreeSet::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_alphanumeric_provider_ids_but_rejects_hostname_separators() {
        assert!(valid_probe_id("v0D0eeE4f3844a51"));
        assert!(!valid_probe_id("probe.example"));
        assert!(!valid_probe_id("probe/another"));
        assert!(!valid_probe_id(""));
    }

    #[test]
    fn requires_both_resolver_lists_and_reports_overlap_without_claiming_a_leak() {
        let local = BTreeSet::from(["1.1.1.1".parse().unwrap()]);
        let relay = BTreeSet::from(["8.8.8.8".parse().unwrap()]);
        assert!(outcome(&relay, &local).distinct());
        assert_eq!(outcome(&local, &local).status, "overlap");
        assert_eq!(outcome(&BTreeSet::new(), &local).status, "unavailable");
    }
}
