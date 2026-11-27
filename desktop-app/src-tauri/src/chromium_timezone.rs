//! Windows Chromium keeps the system timezone even with TZ set in its environment.
use serde_json::{json, Value};
use std::{
    collections::VecDeque, ffi::c_void, io::{self, Read}, net::{Ipv4Addr, TcpListener},
    process::{Child, Command}, ptr::{null, null_mut}, sync::mpsc, thread,
    time::{Duration, Instant},
};

type Internet = *mut c_void;
const NO_PROXY: u32 = 1;
const DISABLE_FEATURE: u32 = 63;
const DISABLE_REDIRECTS: u32 = 2;
const UPGRADE_TO_WEBSOCKET: u32 = 114;
const UTF8_MESSAGE: u32 = 2;
const UTF8_FRAGMENT: u32 = 3;
const WINHTTP_TIMEOUT: u32 = 12002;

#[link(name = "winhttp")]
extern "system" {
    fn WinHttpOpen(agent: *const u16, access: u32, proxy: *const u16, bypass: *const u16, flags: u32) -> Internet;
    fn WinHttpConnect(session: Internet, host: *const u16, port: u16, reserved: u32) -> Internet;
    fn WinHttpOpenRequest(connection: Internet, method: *const u16, path: *const u16, version: *const u16,
        referer: *const u16, accept: *const *const u16, flags: u32) -> Internet;
    fn WinHttpSetOption(handle: Internet, option: u32, value: *const c_void, length: u32) -> i32;
    fn WinHttpSetTimeouts(handle: Internet, resolve: i32, connect: i32, send: i32, receive: i32) -> i32;
    fn WinHttpSendRequest(request: Internet, headers: *const u16, len: u32, data: *const c_void,
        data_len: u32, total_len: u32, context: usize) -> i32;
    fn WinHttpReceiveResponse(request: Internet, reserved: *mut c_void) -> i32;
    fn WinHttpWebSocketCompleteUpgrade(request: Internet, context: usize) -> Internet;
    fn WinHttpWebSocketSend(socket: Internet, kind: u32, data: *const u8, size: u32) -> u32;
    fn WinHttpWebSocketReceive(socket: Internet, data: *mut u8, size: u32, read: *mut u32, kind: *mut u32) -> u32;
    fn WinHttpCloseHandle(handle: Internet) -> i32;
}

struct Handle(Internet);
impl Handle {
    fn new(handle: Internet) -> io::Result<Self> {
        if handle.is_null() { Err(io::Error::last_os_error()) } else { Ok(Self(handle)) }
    }
}
impl Drop for Handle {
    fn drop(&mut self) { unsafe { WinHttpCloseHandle(self.0); } }
}

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }
fn win_ok(value: i32) -> io::Result<()> {
    if value == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
fn invalid() -> io::Error { io::Error::new(io::ErrorKind::InvalidData, "Chromium CDP") }
fn timeout() -> io::Error { io::ErrorKind::TimedOut.into() }

struct Cdp {
    socket: Handle,
    _connection: Handle,
    _agent: Handle,
    id: u64,
    queued: VecDeque<Value>,
    fragment: Vec<u8>,
}
impl Cdp {
    fn connect(port: u16, path: &str) -> io::Result<Self> {
        let (agent, connection, socket) = unsafe {
            let agent = Handle::new(WinHttpOpen(wide("Workspace").as_ptr(), NO_PROXY, null(), null(), 0))?;
            win_ok(WinHttpSetTimeouts(agent.0, 500, 500, 1000, 2000))?;
            let connection = Handle::new(WinHttpConnect(agent.0, wide("127.0.0.1").as_ptr(), port, 0))?;
            let request = Handle::new(WinHttpOpenRequest(connection.0, null(), wide(path).as_ptr(),
                null(), null(), null(), 0))?;
            win_ok(WinHttpSetOption(request.0, DISABLE_FEATURE, (&DISABLE_REDIRECTS as *const u32).cast(), 4))?;
            win_ok(WinHttpSetOption(request.0, UPGRADE_TO_WEBSOCKET, null(), 0))?;
            win_ok(WinHttpSendRequest(request.0, null(), 0, null(), 0, 0, 0))?;
            win_ok(WinHttpReceiveResponse(request.0, null_mut()))?;
            let socket = Handle::new(WinHttpWebSocketCompleteUpgrade(request.0, 0))?;
            (agent, connection, socket)
        };
        Ok(Self { socket, _connection: connection, _agent: agent, id: 0, queued: VecDeque::new(), fragment: Vec::new() })
    }

    fn receive(&mut self) -> io::Result<Option<Value>> {
        let mut buffer = [0; 4096];
        loop {
            let (mut read, mut kind) = (0, 0);
            match unsafe { WinHttpWebSocketReceive(self.socket.0, buffer.as_mut_ptr(), buffer.len() as u32, &mut read, &mut kind) } {
                0 => {}
                WINHTTP_TIMEOUT => return Ok(None),
                code => return Err(io::Error::from_raw_os_error(code as i32)),
            }
            if self.fragment.len() + read as usize > 256 * 1024 { return Err(invalid()); }
            self.fragment.extend_from_slice(&buffer[..read as usize]);
            match kind {
                UTF8_FRAGMENT => continue,
                UTF8_MESSAGE => return serde_json::from_slice(&std::mem::take(&mut self.fragment)).map(Some).map_err(|_| invalid()),
                _ => return Err(invalid()),
            }
        }
    }

    fn request(&mut self, method: &str, params: Value, session: Option<&str>) -> io::Result<()> {
        self.id += 1;
        let mut data = json!({ "id": self.id, "method": method, "params": params });
        if let Some(session) = session { data["sessionId"] = json!(session); }
        let data = data.to_string();
        let status = unsafe { WinHttpWebSocketSend(self.socket.0, UTF8_MESSAGE, data.as_ptr(), data.len() as u32) };
        if status != 0 { return Err(io::Error::from_raw_os_error(status as i32)); }
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            let Some(reply) = self.receive()? else { continue; };
            if reply["id"].as_u64() == Some(self.id) {
                return if reply.get("result").is_some() { Ok(()) } else {
                    if session.is_some() && reply["error"]["code"].as_i64() == Some(-32001) {
                        return Err(io::ErrorKind::NotFound.into());
                    }
                    #[cfg(test)]
                    eprintln!("{method}: {}", reply["error"]["message"]);
                    Err(invalid())
                };
            }
            if reply["method"] == "Target.attachedToTarget" { self.queued.push_back(reply); }
            if self.queued.len() > 256 { return Err(invalid()); }
        }
        Err(timeout())
    }

    fn attach(&mut self, session: Option<&str>, target: &str) -> io::Result<()> {
        let filter = match target {
            "browser" => json!([{ "type": "page" }, { "type": "webview" }, { "exclude": true }]),
            _ => json!([{ "type": "tab", "exclude": true }, { "type": "browser", "exclude": true }, {}]),
        };
        self.request("Target.setAutoAttach", json!({
            "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true, "filter": filter
        }), session)
    }

    fn apply(&mut self, event: Value, zone: &str) -> io::Result<bool> {
        let session = event["params"]["sessionId"].as_str().ok_or_else(invalid)?;
        let target = event["params"]["targetInfo"]["type"].as_str().ok_or_else(invalid)?;
        let renderer = matches!(target, "page" | "iframe" | "webview");

        if renderer {
            self.request("Emulation.setTimezoneOverride", json!({ "timezoneId": zone }), Some(session))?;
            self.attach(Some(session), target)?;
        }
        if event["params"]["waitingForDebugger"] == true {
            self.request("Runtime.runIfWaitingForDebugger", json!({}), Some(session))?;
        }
        Ok(renderer)
    }

    fn next_target(&mut self) -> io::Result<Option<Value>> {
        if let Some(event) = self.queued.pop_front() { return Ok(Some(event)); }
        Ok(self.receive()?.filter(|event| event["method"] == "Target.attachedToTarget"))
    }
}

fn endpoint(client: &reqwest::blocking::Client, port: u16) -> Option<String> {
    let mut bytes = Vec::new();
    client.get(format!("http://127.0.0.1:{port}/json/version")).send().ok()?.error_for_status().ok()?
        .take(16384).read_to_end(&mut bytes).ok()?;
    let data: Value = serde_json::from_slice(&bytes).ok()?;
    let url = reqwest::Url::parse(data["webSocketDebuggerUrl"].as_str()?).ok()?;
    let id = url.path().strip_prefix("/devtools/browser/")?;
    (url.scheme() == "ws" && url.host_str() == Some("127.0.0.1") && url.port() == Some(port)
        && id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'))
        .then(|| url.path().to_owned())
}

pub fn start(mut command: Command, zone: &str) -> io::Result<u32> {
    let bound = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = bound.local_addr()?.port();
    let (ready, outcome) = mpsc::sync_channel(1);
    let zone = zone.to_owned();
    thread::Builder::new().name("workspace-chromium-timezone".into()).spawn(move || {
        drop(bound);
        let mut child = match command.args([
            "--remote-debugging-address=127.0.0.1".into(), format!("--remote-debugging-port={port}")
        ]).spawn() {
            Ok(child) => child,
            Err(error) => { let _ = ready.send(Err(error)); return; }
        };
        let result = crate::native_windows::process_job(&child).and_then(|_job| {
            control(&mut child, port, &zone, &ready)
        });
        if let Err(error) = result {
            #[cfg(test)]
            eprintln!("controller stopped: {error:?}");
            let _ = child.kill();
            let _ = child.wait();
            let _ = ready.try_send(Err(error));
        }
    })?;
    outcome.recv().map_err(|_| invalid())?
}

fn control(child: &mut Child, port: u16, zone: &str, ready: &mpsc::SyncSender<io::Result<u32>>) -> io::Result<()> {
    let client = reqwest::blocking::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(300)).build().map_err(|_| invalid())?;
    let until = Instant::now() + Duration::from_secs(10);
    let path = loop {
        if child.try_wait()?.is_some() { return Err(io::Error::other("Chromium exited during startup")); }
        if Instant::now() >= until { return Err(timeout()); }
        if crate::native_windows::owns_loopback_listener(port, child.id()) {
            if let Some(path) = endpoint(&client, port) { break path; }
        }
        thread::sleep(Duration::from_millis(60));
    };
    let mut cdp = Cdp::connect(port, &path).map_err(|error| io::Error::new(error.kind(), format!("WebSocket upgrade: {error}")))?;
    cdp.attach(None, "browser")?;
    let until = Instant::now() + Duration::from_secs(8);
    let mut ready = Some(ready);
    while child.try_wait()?.is_none() {
        if ready.is_some() && Instant::now() > until { return Err(timeout()); }
        if let Some(event) = cdp.next_target()? {
            match cdp.apply(event, zone) {
                Ok(true) => {
                    if let Some(sender) = ready.take() { sender.send(Ok(child.id())).map_err(|_| invalid())?; }
                }
                Ok(false) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::{BufRead, BufReader, Write}, path::Path, process::Stdio};

    #[test]
    fn real_windows_chromium_overrides_timezone_in_new_targets() {
        let Some(browser) = std::env::var_os("WORKSPACE_CHROMIUM_TEST_BIN") else { return; };
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.scratch");
        let test = root.join(format!("timezone-cdp-{}", std::process::id()));
        fs::create_dir_all(&test).unwrap();
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        server.set_nonblocking(true).unwrap();
        let port = server.local_addr().unwrap().port();
        let (reports, results) = mpsc::channel();
        let http = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(35);
            while Instant::now() < deadline {
                match server.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                        let mut request = BufReader::new(&mut stream);
                        let mut line = String::new();
                        if request.read_line(&mut line).unwrap_or(0) == 0 { continue; }
                        let mut parts = line.split_whitespace();
                        let method = parts.next().unwrap_or("");
                        let path = parts.next().unwrap_or("").to_owned();
                        let mut length = 0;
                        loop {
                            let mut header = String::new();
                            if request.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" { break; }
                            if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                                length = value.trim().parse().unwrap_or(0);
                            }
                        }
                        let code = r#"({
                            tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
                            currentOffset: new Date().getTimezoneOffset(),
                            offsets: [0, 6].map(month => new Date(2026, month, 1, 12).getTimezoneOffset()),
                            languages: navigator.languages, webdriver: navigator.webdriver
                        })"#;
                        let (content_type, body) = match (method, path.as_str()) {
                            ("GET", "/worker.js") => ("text/javascript", format!("postMessage({code});")),
                            ("GET", "/baseline" | "/initial" | "/new" | "/frame") => {
                                let extra = if path == "/initial" {
                                    format!("setTimeout(()=>window.open('/new'), 4000); new Worker('/worker.js').onmessage=e=>report('/worker',e.data); const frame=document.createElement('iframe'); frame.src='http://localhost:{port}/frame'; document.documentElement.append(frame);")
                                } else { String::new() };
                                ("text/html", format!(r#"<script>
                                    const report=(path,data)=>fetch(path,{{method:'POST',body:JSON.stringify(data)}});
                                    report(location.pathname, {code}); {extra}
                                    </script>"#))
                            }
                            ("POST", _) if (1..4096).contains(&length) => {
                                let mut bytes = vec![0; length];
                                if request.read_exact(&mut bytes).is_ok() {
                                    if let Ok(body) = serde_json::from_slice::<Value>(&bytes) {
                                        let _ = reports.send((path, body));
                                    }
                                }
                                ("text/plain", String::new())
                            }
                            _ => ("text/plain", String::new()),
                        };
                        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(15)),
                    Err(_) => break,
                }
            }
        });
        let command = |name: &str, page: &str| {
            let profile = test.join(name);
            fs::create_dir_all(profile.join("Default")).unwrap();
            if !profile.join("Default/Preferences").exists() {
                fs::write(profile.join("Default/Preferences"), r#"{"intl":{"accept_languages":"en-US,en","selected_languages":"en-US,en"}}"#).unwrap();
            }
            let mut command = Command::new(&browser);
            command.args([
                format!("--user-data-dir={}", profile.display()), "--lang=en-US".into(), "--no-first-run".into(),
                "--disable-background-networking".into(), "--disable-popup-blocking".into(), "--no-proxy-server".into(),
                "--host-resolver-rules=MAP localhost 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1".into(),
                "--site-per-process".into(), page.into(),
            ]).stdout(Stdio::null()).stderr(Stdio::null());
            command
        };
        let mut baseline = command("baseline", &format!("http://127.0.0.1:{port}/baseline")).spawn().unwrap();
        let baseline_report = results.recv_timeout(Duration::from_secs(10));
        let _ = baseline.kill();
        let _ = baseline.wait();
        let (path, baseline) = baseline_report.expect("system baseline");
        assert_eq!(path, "/baseline");
        let zone = if baseline["tz"] == "America/New_York" { "Pacific/Honolulu" } else { "America/New_York" };
        eprintln!("system Chromium: {baseline}");

        let probe = crate::radar::BrowserProbe::default();
        let gate = probe.start(port, "test", &format!("http://127.0.0.1:{port}/initial"), Some(zone), Some("en-US"), true).unwrap();
        let pid = start(command("override", &gate.url), zone).expect("CDP controller");
        struct TestBrowser(u32);
        impl Drop for TestBrowser {
            fn drop(&mut self) {
                let _ = Command::new("taskkill.exe").args(["/pid", &self.0.to_string(), "/t", "/f"])
                    .stdout(Stdio::null()).stderr(Stdio::null()).status();
            }
        }
        let browser = TestBrowser(pid);

        let mut checked = std::collections::BTreeSet::new();
        let samples = (0..4).map(|_| results.recv_timeout(Duration::from_secs(10))).collect::<Vec<_>>();

        let expected_offsets = if zone == "America/New_York" { json!([300, 240]) } else { json!([600, 600]) };
        for sample in samples {
            let (path, result) = sample.expect("target report");
            eprintln!("{path}: {result}");
            assert_eq!(result["tz"], zone, "{path}");
            assert_eq!(result["offsets"], expected_offsets, "{path}");
            assert!(expected_offsets.as_array().unwrap().contains(&result["currentOffset"]), "{path}");
            if path != "/worker" {
                assert_eq!(result["webdriver"], false, "{path}");
            }
            assert!(result["languages"].as_array().is_some_and(|languages| !languages.is_empty() &&
                languages.iter().all(|item| !item.as_str().unwrap_or("ru").to_ascii_lowercase().starts_with("ru"))));
            checked.insert(path);
        }
        assert_eq!(checked, ["/initial".into(), "/new".into(), "/worker".into(), "/frame".into()].into_iter().collect());
        drop(browser);
        drop(http);
    }
}
