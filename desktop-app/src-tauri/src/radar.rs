use crate::{apps, dns_radar, launch, service};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs, io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream}, path::Path,
    sync::{Arc, Mutex}, time::{Duration, Instant},
};

const DIAGNOSTICS: &str = service::DIAGNOSTICS_ORIGIN;

#[derive(Clone, Serialize)]
pub struct Observation {
    pub ip: Ipv4Addr,
    latency_ms: u64,
}

fn public_ipv4(value: &str) -> Option<Ipv4Addr> {
    let ip: Ipv4Addr = value.parse().ok()?;
    let [a, b, c, _] = ip.octets();
    (!ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_documentation()
        && !ip.is_multicast() && a != 0 && a < 240 && !(a == 100 && (64..128).contains(&b))
        && !(a == 198 && (18..=19).contains(&b)) && !(a == 192 && b == 0 && c == 0)).then_some(ip)
}

fn client(port: u16) -> Result<reqwest::blocking::Client, String> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).map_err(|_| "Некорректный адрес прокси")?;
    reqwest::blocking::Client::builder().proxy(proxy).timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none()).build().map_err(|_| "Не удалось настроить диагностику".into())
}

fn parse_observation(result: &Value, latency_ms: u64) -> Result<Observation, String> {
    let ip = result["ip"].as_str().and_then(public_ipv4)
        .ok_or("Сервер диагностики не увидел публичный IPv4")?;
    Ok(Observation { ip, latency_ms })
}

fn observe(client: &reqwest::blocking::Client) -> Result<Observation, String> {
    let started = Instant::now();
    let result: Value = service::checked(client.get(format!("{DIAGNOSTICS}/api/network-observe")).send())?
        .json().map_err(|_| "Сервер не вернул адрес")?;
    parse_observation(&result, started.elapsed().as_millis() as u64)
}

fn parse_gateway(data: &Value) -> Option<(Ipv4Addr, bool)> {
    if data["known"] != true { return None; }
    Some((public_ipv4(data["gateway_ip"].as_str()?)?, data["via_gateway"].as_bool()?))
}

fn tunnel_check(client: &reqwest::blocking::Client, session: &service::Session) -> Option<((Ipv4Addr, bool), u64)> {
    let started = Instant::now();
    let request = session.authorize(client.get(format!("{DIAGNOSTICS}/api/tunnel-check")));
    let data: Value = service::checked(request.send()).ok()?.json().ok()?;
    Some((parse_gateway(&data)?, started.elapsed().as_millis() as u64))
}

fn reconcile(
    observation: Result<Observation, String>, gateway: Option<((Ipv4Addr, bool), u64)>,
) -> (Result<Observation, String>, Option<bool>) {
    match (observation, gateway) {
        (Ok(observation), Some(((ip, via_gateway), _))) => {
            let matched = via_gateway && observation.ip == ip;
            (Ok(observation), Some(matched))
        }
        (Err(_), Some(((ip, true), latency_ms))) => {
            // A match on this separate SOCKS request verifies the public address of that request.
            (Ok(Observation { ip, latency_ms }), Some(true))
        }
        (observation, _) => (observation, None),
    }
}

pub fn route_alive(port: u16, session: &service::Session, confirmed: &mut Option<Ipv4Addr>) -> bool {
    let observation = (|| {
        let probe = client(port).ok()?;
        let observation = observe(&probe).ok()?;
        if *confirmed == Some(observation.ip) { return Some(observation.ip); }
        let ((expected, via_gateway), _) = tunnel_check(&probe, session)?;
        (via_gateway && expected == observation.ip).then_some(expected)
    })();
    *confirmed = observation;
    confirmed.is_some()
}

pub fn observe_tunnel(port: u16) -> Result<Observation, String> {
    let client = client(port)?;
    let result = observe(&client);
    if result.is_ok() { return result; }
    let gateway = service::Session::restore().ok().and_then(|session| tunnel_check(&client, &session));
    reconcile(result, gateway).0
}

#[derive(Clone, Deserialize, Serialize)]
pub struct BrowserObservation {
    timezone: String,
    language: String,
    #[serde(default)]
    languages: Vec<String>,
    #[serde(default)]
    language_matches: Option<bool>,
    timezone_matches: Option<bool>,
}

#[derive(Default, Clone)]
pub struct BrowserProbe(Arc<Mutex<Option<(u16, String, u64, Option<BrowserObservation>)>>>);

pub struct ProbeEndpoint {
    pub url: String,
    pub port: u16,
}

impl BrowserProbe {
    pub fn start(&self, port: u16, region: &str, destination: &str, timezone: Option<&str>, language: Option<&str>, wait_for_timezone: bool) -> std::io::Result<ProbeEndpoint> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let local = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        use std::hash::{BuildHasher, RandomState};
        let token = RandomState::new().hash_one((Instant::now(), local));
        let path = format!("/{token:016x}");
        let host = format!("127.0.0.1:{local}");
        let url = format!("http://{host}{path}");
        let redirect = serde_json::to_string(destination).unwrap_or_else(|_| "\"about:blank\"".into());
        let expected = serde_json::to_string(&timezone).unwrap_or_else(|_| "null".into());
        let language = serde_json::to_string(&language).unwrap_or_else(|_| "null".into());
        let html = format!(r#"<!doctype html><meta charset="utf-8"><title>Yousoro Workspace</title>
<script>
const next = {redirect};
const expected = {expected};
function check(attempt = 0) {{
const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
let matches = null;
if (expected) {{
  try {{
    const clock = new Intl.DateTimeFormat('en', {{timeZone: expected, timeZoneName:'longOffset'}});
    const year = new Date().getUTCFullYear();
    matches = timezone === clock.resolvedOptions().timeZone && [0, 6].every(month => {{
      const date = new Date(Date.UTC(year,month,15,12));
      const label = clock.formatToParts(date).find(part => part.type === 'timeZoneName').value;
      const [, sign, hour, minute] = /GMT([+-])([0-9]{{2}}):([0-9]{{2}})/.exec(label) || [];
      const offset = sign ? (sign === '+' ? -1 : 1) * (+hour * 60 + +minute) : 0;
      return date.getTimezoneOffset() === offset;
    }});
  }} catch {{}}
}}
const expectedLanguage = {language};
const languages = [...navigator.languages].slice(0, 16);
const languageMatches = expectedLanguage ? languages[0]?.toLowerCase() === expectedLanguage.toLowerCase()
  && languages.every(value => !/^ru(?:-|$)/i.test(value)
      && [expectedLanguage.toLowerCase(), expectedLanguage.split("-")[0].toLowerCase()].includes(value.toLowerCase())) : null;
if ({wait_for_timezone} && expected && matches !== true && attempt < 96) {{
  setTimeout(() => check(attempt + 1), 125);
  return;
}}
const go = () => {{
  if ((!expected || matches === true) && (!expectedLanguage || languageMatches === true)) location.replace(next);
  else document.querySelector("p").textContent = "Рабочий сайт не открыт. Проверьте часовой пояс и язык рабочего профиля, затем откройте браузер заново.";
}};
setTimeout(go, 1500);
fetch(location.pathname, {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{
  timezone, language: navigator.language, languages, language_matches: languageMatches, timezone_matches: matches
}})}}).finally(go);
}}
check();
</script><p>Открываем рабочую страницу…</p>"#);
        let region = region.to_owned();
        let probe = self.clone();
        if let Ok(mut previous) = self.0.lock() { *previous = Some((port, region, token, None)); }
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(25);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Ok(Some(data)) = probe_request(stream, &path, &host, &html) {
                            if let Ok(mut value) = probe.0.lock() {
                                if let Some((_, _, current_token, observed)) = value.as_mut() {
                                    if *current_token == token { *observed = Some(data); }
                                }
                            }
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(40)),
                    Err(_) => break,
                }
            }
        });
        Ok(ProbeEndpoint { url, port: local })
    }

    fn observation(&self, port: u16, region: &str) -> Option<BrowserObservation> {
        let guard = self.0.lock().ok()?;
        let (observed_port, observed_region, _, value) = guard.as_ref()?;
        (*observed_port == port && observed_region == region).then(|| value.clone()).flatten()
    }
}

fn probe_request(mut stream: TcpStream, path: &str, host: &str, html: &str) -> std::io::Result<Option<BrowserObservation>> {
    stream.set_read_timeout(Some(Duration::from_millis(350)))?;
    stream.set_write_timeout(Some(Duration::from_millis(350)))?;
    let mut reader = BufReader::new(stream.try_clone()?.take(8192));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut words = line.split_whitespace();
    let method = words.next().unwrap_or("");
    if words.next() != Some(path) { return Ok(None); }
    let mut host_matches = false;
    let mut origin_matches = false;
    let mut length = 0;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header.trim().is_empty() { break; }
        if let Some((key, value)) = header.trim().split_once(':') {
            match key.to_ascii_lowercase().as_str() {
                "host" => host_matches = value.trim() == host,
                "origin" => origin_matches = value.trim() == format!("http://{host}"),
                "content-length" => length = value.trim().parse::<usize>().unwrap_or(0),
                _ => {}
            }
        }
    }
    if !host_matches { return Ok(None); }
    if method == "GET" {
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{html}", html.len())?;
    } else if method == "POST" && origin_matches && (1..=256).contains(&length) {
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        let value: Option<BrowserObservation> = serde_json::from_slice(&body).ok();
        if value.as_ref().is_some_and(|data| [data.timezone.as_str(), data.language.as_str()]
            .iter().all(|part| !part.is_empty() && part.len() < 64
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b"/+-_".contains(&b)))) {
            stream.write_all(b"HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n")?;
            return Ok(value);
        }
    }
    Ok(None)
}

#[derive(Serialize)]
struct Browser {
    running: Option<bool>,
    expected_timezone: Option<String>,
    expected_language: Option<String>,
    actual: Option<BrowserObservation>,
    launch_language: Option<String>,
    geolocation_blocked: Option<bool>,
    webrtc_protected: Option<bool>,
    quic_disabled: Option<bool>,
}

#[derive(Serialize)]
struct DeviceSlots {
    used: usize,
    limit: u64,
    desktop: usize,
    mobile: usize,
    current_pc: Option<bool>,
}

fn device_slots(bound: &service::Devices, device_id: Option<&str>) -> DeviceSlots {
    let desktop = bound.items.iter().filter(|device| matches!(device.os.as_str(), "windows" | "macos" | "linux")).count();
    let mobile = bound.items.iter().filter(|device| matches!(device.os.as_str(), "ios" | "android")).count();
    DeviceSlots {
        used: bound.items.len(),
        limit: bound.limit,
        desktop,
        mobile,
        current_pc: device_id.map(|id| bound.items.iter().any(|device| device.id == id)),
    }
}

#[derive(Serialize)]
struct HttpsTargets {
    claude: HttpsCheck,
    chatgpt: HttpsCheck,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum HttpsState { Available, Restricted, Unavailable }

#[derive(Serialize)]
struct HttpsCheck {
    state: HttpsState,
    status: Option<u16>,
}

fn classify_https(status: Option<u16>) -> HttpsCheck {
    let state = match status {
        Some(200..=399) => HttpsState::Available,
        Some(401 | 403 | 429) => HttpsState::Restricted,
        _ => HttpsState::Unavailable,
    };
    HttpsCheck { state, status }
}

#[derive(Serialize)]
struct NetworkProbes {
    ipv4: &'static str,
    ipv6: &'static str,
    dns: &'static str,
    udp: &'static str,
}

fn socks_udp_policy(port: u16) -> &'static str {
    fn check(port: u16) -> std::io::Result<&'static str> {
        let timeout = Duration::from_secs(1);
        let mut socket = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), timeout)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        socket.write_all(&[5, 1, 0])?;
        let mut reply = [0; 2];
        socket.read_exact(&mut reply)?;
        if reply != [5, 0] { return Ok("unmeasured"); }
        socket.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])?;
        match socket.read_exact(&mut reply) {
            Ok(()) if reply == [5, 0] => Ok("allowed"),
            Ok(()) if reply[0] == 5 => Ok("blocked"),
            Err(error) if matches!(error.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset) => Ok("blocked"),
            _ => Ok("unmeasured"),
        }
    }
    check(port).unwrap_or("unmeasured")
}

fn network_probes(matched: Option<bool>, check_dns: bool, dns: Option<&dns_radar::DnsReport>, udp: &'static str) -> NetworkProbes {
    NetworkProbes {
        ipv4: match matched { Some(true) => "confirmed", Some(false) => "mismatch", None => "unmeasured" },
        // This native observation compares IPv4 only.
        ipv6: "unmeasured",
        udp,
        dns: if !check_dns { "disabled" } else if dns.is_some_and(dns_radar::DnsReport::measured) {
            "confirmed"
        } else { "unmeasured" },
    }
}

#[derive(Serialize)]
pub struct Report {
    platform: &'static str,
    probes: NetworkProbes,
    pub network: Option<Observation>,
    network_error: Option<String>,
    pub matched: Option<bool>,
    dns: Option<dns_radar::DnsReport>,
    devices: Option<DeviceSlots>,
    browser: Browser,
    timezone: Option<String>,
    timezone_matches: Option<bool>,
    https: Option<HttpsTargets>,
    system_proxy: Option<bool>,
    apps: apps::InstalledApps,
    ready: usize,
    total: usize,
    hints: Vec<&'static str>,
}

pub fn timezone_matches(local: Option<&str>, expected: Option<&str>) -> Option<bool> {
    fn canonical(zone: &str) -> &str {
        match zone {
            "Turkey" | "Asia/Istanbul" => "Europe/Istanbul",
            "Etc/UTC" | "Etc/GMT" | "GMT" => "UTC",
            "Asia/Calcutta" => "Asia/Kolkata",
            _ => zone,
        }
    }
    local.zip(expected).map(|(local, expected)| canonical(local).eq_ignore_ascii_case(canonical(expected)))
}

fn system_timezone() -> Option<String> {
    #[cfg(windows)]
    { crate::native_windows::timezone() }
    #[cfg(not(windows))]
    {
        let link = fs::read_link("/etc/localtime").ok()?;
        link.to_str()?.split_once("zoneinfo/").map(|(_, zone)| zone.to_owned())
    }
}

fn https_probe(client: &reqwest::blocking::Client, url: &str) -> HttpsCheck {
    classify_https(client.head(url).send().ok().map(|response| response.status().as_u16()))
}

pub fn report(
    port: u16, region: &str, app_data: &Path, probe: &BrowserProbe,
    check_dns: bool, device_id: Option<&str>, environment: Option<&service::NodeEnvironment>, pac_active: bool, apps: apps::InstalledApps, progress: impl Fn(&'static str),
) -> Report {
    progress("network");
    let session = service::Session::restore().ok();
    let (network, network_error, matched, https, dns, devices, udp) = std::thread::scope(|scope| {
        let dns = scope.spawn(|| check_dns.then(|| dns_radar::check(port)));
        let udp = scope.spawn(|| socks_udp_policy(port));
        let devices = scope.spawn(|| session.as_ref().and_then(|session| service::account(session).ok())
            .map(|account| device_slots(&account.bound, device_id)));
        let (network, network_error, matched, https) = match client(port) {
        Ok(client) => {
            let (observation, gateway) = std::thread::scope(|scope| {
                let probe = scope.spawn(|| session.as_ref().and_then(|session| tunnel_check(&client, session)));
                (observe(&client), probe.join().ok().flatten())
            });
            let result = reconcile(observation, gateway);
            progress("services");
            let (claude, chatgpt) = std::thread::scope(|scope| {
                let claude = scope.spawn(|| https_probe(&client, "https://claude.ai/"));
                let chatgpt = scope.spawn(|| https_probe(&client, "https://chatgpt.com/"));
                (claude.join().unwrap_or_else(|_| classify_https(None)), chatgpt.join().unwrap_or_else(|_| classify_https(None)))
            });
            let https = Some(HttpsTargets { claude, chatgpt });
            match result {
                (Ok(observation), matched) => {
                    (Some(observation), None, matched, https)
                }
                (Err(error), _) => (None, Some(error), None, https),
            }
        }
        Err(error) => (None, Some(error), None, None),
        };
        (network, network_error, matched, https, dns.join().ok().flatten(), devices.join().ok().flatten(), udp.join().unwrap_or("unmeasured"))
    });

    progress("profile");
    let expected_timezone = environment.map(|node| node.timezone.clone());
    let expected_language = launch::browser_language(environment, crate::preferences::english_browser(app_data)).map(str::to_owned);
    let profile = launch::profile_path(app_data, region).ok();
    let process = profile.as_ref().and_then(|path| launch::browser_process(path).ok());
    let running = process.as_ref().map(Option::is_some);
    let command = process.as_ref().and_then(Option::as_deref);
    let launch_language = command.and_then(|command| command.split_whitespace().find_map(|arg|
        arg.trim_matches('"').strip_prefix("--lang=").map(str::to_owned)));
    let preferences = profile.and_then(|path| fs::read(path.join("Default/Preferences")).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let geolocation_blocked = preferences.as_ref().and_then(|value| value["profile"]["default_content_setting_values"]["geolocation"].as_u64())
        .map(|setting| setting == 2);
    let webrtc_protected = command.map(|command| command.split_whitespace().any(|flag|
        matches!(flag.trim_matches('"'),
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" | "--webrtc-ip-handling-policy=disable_non_proxied_udp")))
        .or_else(|| preferences.as_ref().and_then(|value| value["webrtc"]["ip_handling_policy"].as_str())
            .map(|setting| setting == "disable_non_proxied_udp"));
    let actual = (running == Some(true)).then(|| probe.observation(port, region)).flatten();
    let quic_disabled = command.map(|line| line.split_whitespace().any(|flag| flag == "--disable-quic"));
    let browser = Browser { running, expected_timezone, expected_language, actual, launch_language, geolocation_blocked, webrtc_protected, quic_disabled };

    let system_proxy = Some(pac_active);

    let timezone = system_timezone();
    let timezone_matches = timezone.as_deref().zip(environment).map(|(actual, expected)| {
        timezone_matches(Some(actual), Some(if cfg!(windows) { &expected.windows_timezone } else { &expected.timezone })).unwrap_or(false)
    });
    let checks = [
        (network.is_some(), "Проверьте, что туннель подключён и сервер диагностики доступен."),
        (https.as_ref().is_some_and(|target| target.claude.state == HttpsState::Available && target.chatgpt.state == HttpsState::Available), "Повторите HTTPS-проверку после переподключения."),
        (matched == Some(true), "Подождите, пока регион применится, затем переподключите туннель и повторите сверку узла."),
        (browser.actual.as_ref().is_some_and(|data| data.timezone_matches == Some(true) && data.language_matches == Some(true)),
            "Перезапустите рабочий браузер из Workspace. Если Windows сохраняет системный часовой пояс, сравните его с регионом."),
        (geolocation_blocked == Some(true), "Проверьте запрет геолокации в настройках рабочего профиля."),
        (webrtc_protected == Some(true), "Откройте браузер через Workspace, чтобы применить ограничение WebRTC."),
        (dns.as_ref().is_some_and(|result| result.distinct()), if check_dns {
            "Проверка DNS не подтвердила различие резолверов. Убедитесь, что проверочный сервис доступен через узел."
        } else { "Включите проверку DNS, чтобы сравнить резолверы." }),
        (devices.as_ref().is_some_and(|slots| slots.current_pc == Some(true)),
            "Текущий ПК не подтверждён в активных слотах. Обновите данные и проверьте устройства в кабинете."),
        (devices.as_ref().is_some_and(|slots| slots.mobile > 0),
            "Если вы используете Workspace на телефоне, подключите его через веб-кабинет."),
    ];
    let mut total = checks.len();
    let mut ready = checks.iter().filter(|(passed, _)| *passed).count();
    let mut hints: Vec<_> = checks.iter().filter_map(|(passed, hint)| (!passed).then_some(*hint)).collect();
    if apps.chatgpt.as_ref().is_some_and(|app| app.store) || apps.claude.as_ref().is_some_and(|app| app.store) {
        total += 1;
        if system_proxy == Some(true) { ready += 1; }
        else { hints.push("Включите системный прокси Windows для клиентов из Microsoft Store."); }
    }
    for app in [apps.claude.as_ref(), apps.chatgpt.as_ref()].into_iter().flatten() {
        if app.running {
            total += 1;
            if app.proxy != "unknown" { ready += 1; }
            else { hints.push("Проверьте маршрут запущенного клиента."); }
        }
    }
    if cfg!(windows) {
        total += 1;
        if timezone_matches == Some(true) { ready += 1; }
        else { hints.push("Сверьте часовой пояс Windows с выбранным узлом."); }
    }
    let probes = network_probes(matched, check_dns, dns.as_ref(), udp);
    Report { platform: std::env::consts::OS, probes, network, network_error, matched, dns, devices, browser, timezone, timezone_matches, https, system_proxy, apps, ready, total, hints }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_udp_probe_measures_the_response_to_associate() {
        for (response, expected) in [([5, 7], "blocked"), ([5, 0], "allowed")] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let (mut peer, _) = listener.accept().unwrap();
                    let mut greeting = [0; 3];
                    peer.read_exact(&mut greeting).unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    peer.write_all(&[5, 0]).unwrap();
                    let mut associate = [0; 10];
                    peer.read_exact(&mut associate).unwrap();
                    assert_eq!(&associate[..4], &[5, 3, 0, 1]);
                    peer.write_all(&response).unwrap();
                });
                assert_eq!(socks_udp_policy(port), expected);
            });
        }
    }

    #[test]
    fn separates_service_restrictions_from_success_and_failure() {
        for status in [200, 204, 302] {
            assert_eq!(classify_https(Some(status)).state, HttpsState::Available);
        }
        for status in [403, 429] {
            let result = classify_https(Some(status));
            assert_eq!(result.state, HttpsState::Restricted);
            assert_eq!(result.status, Some(status));
        }
        assert_eq!(classify_https(Some(503)).state, HttpsState::Unavailable);
        assert_eq!(classify_https(None).state, HttpsState::Unavailable);
    }

    #[test]
    fn rejects_loopback_and_private_gateway_addresses() {
        for address in ["127.0.0.1", "10.2.3.4", "172.16.1.1", "100.64.2.1", "::1", "203.0.113.5"] {
            assert_eq!(public_ipv4(address), None);
        }
        assert!(public_ipv4(&Ipv4Addr::new(192, 168, 1, 1).to_string()).is_none());
        assert!(public_ipv4(&Ipv4Addr::new(172, 31, 255, 255).to_string()).is_none());
        assert_eq!(public_ipv4("8.8.8.8"), Some(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn loopback_response_cannot_confirm_a_gateway_or_populate_the_status_bar() {
        let payload = serde_json::json!({"ip":"127.0.0.1"});
        let misleading_check = serde_json::json!({"known":true,"via_gateway":true,"gateway_ip":"127.0.0.1"});
        assert!(parse_observation(&payload, 979).is_err());
        assert!(parse_gateway(&misleading_check).is_none());
        let (result, matched) = reconcile(parse_observation(&payload, 979), None);
        assert!(result.is_err());
        assert_eq!(matched, None);
    }

    #[test]
    fn independent_gateway_check_requires_a_public_address_and_agreement() {
        let gateway = "8.8.8.8".parse().unwrap();
        let other = serde_json::json!({"ip":"1.1.1.1"});
        assert_eq!(reconcile(parse_observation(&other, 42), Some(((gateway, true), 57))).1, Some(false));
        let (result, matched) = reconcile(Err("address unavailable".into()), Some(((gateway, true), 57)));
        let observation = result.unwrap();
        assert_eq!(observation.ip, gateway);
        assert_eq!(observation.latency_ms, 57);
        assert_eq!(matched, Some(true));
        assert!(reconcile(Err("address unavailable".into()), Some(((gateway, false), 57))).0.is_err());
    }

    #[test]
    fn counts_desktop_and_mobile_and_matches_only_the_current_pc() {
        let devices: service::Devices = serde_json::from_value(serde_json::json!({"limit":3,"items":[
            {"id":"a","name":"PC","os":"windows"},{"id":"b","name":"Phone","os":"android"}
        ]})).unwrap();
        let slots = device_slots(&devices, Some("a"));
        assert_eq!((slots.used, slots.desktop, slots.mobile), (2, 1, 1));
        assert_eq!(slots.current_pc, Some(true));
        assert_eq!(device_slots(&devices, Some("revoked")).current_pc, Some(false));
    }

    #[test]
    fn report_keeps_unknown_distinct_from_failed_and_includes_readiness() {
        let report = Report {
            platform: "windows", probes: network_probes(Some(false), false, None, "unmeasured"),
            network: Some(Observation { ip: "8.8.8.8".parse().unwrap(), latency_ms: 123 }),
            network_error: None, matched: Some(false), dns: None, devices: None,
            browser: Browser { running: Some(true), expected_timezone: Some("Europe/Berlin".into()), expected_language: Some("de-DE".into()),
                actual: None, launch_language: Some("de-DE".into()), geolocation_blocked: Some(false), webrtc_protected: None, quic_disabled: None },
            timezone: None, timezone_matches: None, https: None, system_proxy: Some(false),
            apps: apps::InstalledApps::default(), ready: 1, total: 5, hints: vec!["hint"],
        };
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["network"]["ip"], "8.8.8.8");
        assert_eq!(json["network"]["latency_ms"], 123);
        assert_eq!(json["matched"], false);
        assert_eq!(json["probes"], serde_json::json!({"ipv4":"mismatch", "ipv6":"unmeasured", "dns":"disabled", "udp":"unmeasured"}));
        assert!(json["browser"]["actual"].is_null());
        assert_eq!(json["total"], 5);
    }
}

#[cfg(test)]
#[test]
fn compares_system_timezone_to_dedicated_exit() {
    assert_eq!(timezone_matches(Some("Turkey"), Some("Europe/Istanbul")), Some(true));
    assert_eq!(timezone_matches(Some("Europe/Moscow"), Some("Europe/Istanbul")), Some(false));
    assert_eq!(timezone_matches(Some("Europe/Istanbul"), None), None);
}
