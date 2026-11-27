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
    pub fn measured(&self) -> bool { self.status != "unavailable" }

    pub fn distinct(&self) -> bool { self.status == "distinct" }
}

fn valid_probe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|c| c.is_ascii_alphanumeric())
}

fn request_id(collector: &reqwest::blocking::Client) -> Option<String> {
    let id = collector.get(format!("{PROVIDER}/id")).send().ok()?.error_for_status().ok()?.text().ok()?;
    let id = id.trim();
    valid_probe_id(id).then(|| id.to_owned())
}

fn collect(collector: &reqwest::blocking::Client, id: &str) -> BTreeSet<IpAddr> {
    let lookup = || -> Option<BTreeSet<IpAddr>> {
        let result: Vec<Value> = collector.get(format!("{PROVIDER}/dnsleak/test/{id}?json=2"))
            .send().ok()?.error_for_status().ok()?.json().ok()?;
        Some(result.iter().filter(|item| item["type"] == "dns").filter_map(|item| item["ip"].as_str()?.parse().ok()).collect())
    };
    lookup().unwrap_or_default()
}

fn resolvers(collector: &reqwest::blocking::Client, route: &reqwest::blocking::Client) -> BTreeSet<IpAddr> {
    let Some(id) = request_id(collector) else { return BTreeSet::new(); };
    std::thread::scope(|scope| {
        for index in 1..=3 {
            let id = &id;
            scope.spawn(move || {
                let _ = route.get(format!("https://{index}.{id}.bash.ws/")).send();
            });
        }
    });
    collect(collector, &id)
}

fn compare_browser(browser: &BTreeSet<IpAddr>, tunnel: &BTreeSet<IpAddr>, system: &BTreeSet<IpAddr>) -> &'static str {
    if browser.is_empty() || tunnel.is_empty() || system.is_empty() { return "unmeasured"; }
    if browser.is_subset(tunnel) && browser.is_disjoint(system) { return "tunnel"; }
    if browser.iter().any(|ip| system.contains(ip) && !tunnel.contains(ip)) { return "system_overlap"; }
    "unmeasured"
}

pub struct BrowserDns {
    pub id: String,
    collector: reqwest::blocking::Client,
    tunnel: BTreeSet<IpAddr>,
    system: BTreeSet<IpAddr>,
}

impl BrowserDns {
    pub fn start(port: u16) -> Option<Self> {
        let (collector, proxy) = clients(port)?;
        let (id, tunnel, system) = std::thread::scope(|scope| {
            let tunnel = scope.spawn(|| resolvers(&collector, &proxy));
            let system = scope.spawn(|| resolvers(&collector, &collector));
            (request_id(&collector), tunnel.join().unwrap_or_default(), system.join().unwrap_or_default())
        });
        Some(Self { id: id?, collector, tunnel, system })
    }

    pub fn finish(&self) -> &'static str {
        compare_browser(&collect(&self.collector, &self.id), &self.tunnel, &self.system)
    }
}

fn clients(port: u16) -> Option<(reqwest::blocking::Client, reqwest::blocking::Client)> {
    let direct = reqwest::blocking::Client::builder().no_proxy().timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none()).build();
    let tunneled = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).ok().and_then(|proxy|
        reqwest::blocking::Client::builder().proxy(proxy).timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none()).build().ok());
    direct.ok().zip(tunneled)
}

pub fn check(port: u16) -> DnsReport {
    if let Some((direct, tunneled)) = clients(port) {
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
    fn browser_resolver_comparison_requires_both_controls() {
        let system = BTreeSet::from(["1.1.1.1".parse().unwrap()]);
        let tunnel = BTreeSet::from(["8.8.8.8".parse().unwrap()]);
        assert_eq!(compare_browser(&tunnel, &tunnel, &system), "tunnel");
        assert_eq!(compare_browser(&system, &tunnel, &system), "system_overlap");
        assert_eq!(compare_browser(&tunnel, &tunnel, &tunnel), "unmeasured");
        assert_eq!(compare_browser(&tunnel, &BTreeSet::new(), &system), "unmeasured");
    }

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
