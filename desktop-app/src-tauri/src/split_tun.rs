use crate::killswitch::Core;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime},
};

const POLL: Duration = Duration::from_millis(100);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const JOURNAL: &str = "split-tun-session.json";
const ADAPTER_IP: &str = "172.19.0.1";
const INTERFACE: &str = if cfg!(target_os = "macos") {
    "utun233"
} else {
    "YousoroWorkspace"
};
const CORE: &str = if cfg!(windows) {
    "sing-box.exe"
} else {
    "sing-box"
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedEngine {
    #[default]
    Proxy,
    SplitTun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveEngine {
    Proxy,
    SplitTun,
    ProxyFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    #[cfg(any(test, windows))]
    UacCancelled,
    #[cfg(any(test, target_os = "macos"))]
    AuthorizationCancelled,
    ElevationFailed,
    ElevationTimeout,
    SidecarMissing,
    SidecarInvalid,
    TunInitFailed,
    RecoveryPending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Recovery {
    #[default]
    None,
    Recovered,
    Pending,
}

#[derive(Deserialize, Serialize)]
struct Journal {
    pid: Option<u32>,
    engine: RequestedEngine,
    interface_name: String,
    started_at: u64,
    config_path: String,
    socks_port: u16,
}

fn journal_write(path: &Path, journal: &Journal) -> io::Result<()> {
    let staged = path.with_extension("next");
    let mut file = fs::File::create(&staged)?;
    serde_json::to_writer(&mut file, journal)?;
    file.sync_all()?;
    drop(file);
    fs::rename(staged, path)
}

fn control_proof(role: &[u8], nonce: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(role);
    digest.update(nonce.as_bytes());
    digest.finalize().into()
}

fn adapter_present() -> bool {
    TcpListener::bind((ADAPTER_IP, 0)).is_ok()
}

pub fn recover(data: &Path) -> Recovery {
    recover_with(data, |port| adapter_present() || loopback_ready(port))
}

fn recover_with(data: &Path, occupied: impl Fn(u16) -> bool) -> Recovery {
    let file = data.join(JOURNAL);
    let contents = match fs::read(&file) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Recovery::None,
        Err(_) => return Recovery::Pending,
    };
    let Ok(journal) = serde_json::from_slice::<Journal>(&contents) else {
        return Recovery::Pending;
    };
    if journal.engine != RequestedEngine::SplitTun
        || journal.interface_name != INTERFACE
        || journal.config_path != "stdin"
    {
        return Recovery::Pending;
    }
    // The privileged supervisor owns the child and closes it when its launcher
    // socket closes. Never signal an arbitrary PID from a user-writable file.
    let deadline = Instant::now() + STOP_TIMEOUT;
    while occupied(journal.socks_port) {
        if Instant::now() >= deadline {
            return Recovery::Pending;
        }
        thread::sleep(POLL);
    }
    if fs::remove_file(file).is_ok() {
        Recovery::Recovered
    } else {
        Recovery::Pending
    }
}

fn system_config(port: u16, gate: u16, relay: Option<SocketAddrV4>) -> Value {
    let contract: Value = serde_json::from_str(include_str!("../../../ops/workspace_routing.json"))
        .expect("embedded workspace routing");
    assert_eq!(contract["version"], 3);
    let domains = contract["domains"].as_array().expect("routing domains");
    let mut full = vec!["workspace.yousoro-projects.ru"];
    let mut suffix = Vec::new();
    for domain in domains.iter().filter_map(Value::as_str) {
        if let Some(host) = domain.strip_prefix("full:") {
            full.push(host);
        }
        if let Some(host) = domain.strip_prefix("domain:") {
            suffix.push(host);
        }
    }
    let mut config = contract["desktop_split_tun"].clone();
    config["inbounds"][0]["interface_name"] = json!(INTERFACE);
    config["inbounds"][1]["listen_port"] = json!(port);
    for rule in config["dns"]["rules"].as_array_mut().expect("DNS rules") {
        rule["domain"] = json!(full);
        rule["domain_suffix"] = json!(suffix);
    }
    for rule in config["route"]["rules"]
        .as_array_mut()
        .expect("routing rules")
    {
        if rule.get("domain").is_some() {
            rule["domain"] = json!(full);
            rule["domain_suffix"] = json!(suffix);
        }
        if rule["outbound"] == "proxy" {
            rule["action"] = json!("route");
        }
    }
    if let Some(endpoint) = relay {
        // Match the Relay transport before TLS sniffing can classify its Reality SNI.
        config["route"]["rules"].as_array_mut().expect("routing rules").insert(0, json!({
            "inbound":"desktop-tun", "network":"tcp", "ip_cidr":[format!("{}/32", endpoint.ip())],
            "port":endpoint.port(), "action":"route", "outbound":"direct"
        }));
    }
    // Keep the routes installed across HOLD. The unprivileged gate closes all
    // existing connections and denies new ones until a fresh Relay is ready.
    config["outbounds"].as_array_mut().expect("routing outbounds")
        .push(json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":gate,"version":"5","network":"tcp"}));
    config
}

pub fn relay_endpoint(config: &Value) -> Option<SocketAddrV4> {
    let [remote] = config["outbounds"].as_array()?.as_slice() else {
        return None;
    };
    let [endpoint] = remote["settings"]["vnext"].as_array()?.as_slice() else {
        return None;
    };
    let address = endpoint["address"]
        .as_str()?
        .parse::<std::net::Ipv4Addr>()
        .ok()?;
    let port = u16::try_from(endpoint["port"].as_u64()?)
        .ok()
        .filter(|port| *port > 0)?;
    Some(SocketAddrV4::new(address, port))
}

fn relay_config(config: &Value, port: u16) -> Option<Value> {
    let [remote] = config["outbounds"].as_array()?.as_slice() else {
        return None;
    };
    let [endpoint] = remote["settings"]["vnext"].as_array()?.as_slice() else {
        return None;
    };
    let [user] = endpoint["users"].as_array()?.as_slice() else {
        return None;
    };
    let stream = &remote["streamSettings"];
    let reality = &stream["realitySettings"];
    let endpoint = relay_endpoint(config)?;
    if remote["tag"] != "proxy"
        || remote["protocol"] != "vless"
        || user["encryption"] != "none"
        || user["flow"] != "xtls-rprx-vision"
        || stream["security"] != "reality"
        || !matches!(stream["network"].as_str(), Some("tcp" | "raw"))
    {
        return None;
    }
    Some(json!({
        "log":{"level":"warn"},
        "inbounds":[{"type":"mixed","tag":"relay-loopback","listen":"127.0.0.1","listen_port":port}],
        "outbounds":[{
            "type":"vless","tag":"proxy","server":endpoint.ip().to_string(),"server_port":endpoint.port(),
            "uuid":user["id"].as_str()?,"flow":"xtls-rprx-vision","network":"tcp",
            "tls":{"enabled":true,"server_name":reality["serverName"].as_str()?,
                "utls":{"enabled":true,"fingerprint":reality["fingerprint"].as_str()?},
                "reality":{"enabled":true,"public_key":reality["password"].as_str().or_else(|| reality["publicKey"].as_str())?,
                    "short_id":reality["shortId"].as_str()?}}
        }],
        "route":{"final":"proxy","rules":[
            {"network":"udp","action":"reject"},{"ip_version":6,"action":"reject"}
        ]}
    }))
}

fn loopback_ready(port: u16) -> bool {
    let timeout = Duration::from_millis(200);
    let Ok(mut stream) = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), timeout) else {
        return false;
    };
    let mut greeting = [0; 2];
    stream.set_read_timeout(Some(timeout)).is_ok()
        && stream.set_write_timeout(Some(timeout)).is_ok()
        && stream.write_all(&[5, 1, 0]).is_ok()
        && stream.read_exact(&mut greeting).is_ok()
        && greeting == [5, 0]
}

struct SingBox {
    child: Child,
    port: u16,
    privileged: bool,
}
impl SingBox {
    fn spawn(binary: &Path, config: Value, port: u16, privileged: bool) -> io::Result<Self> {
        let mut command = Command::new(binary);
        command
            .args(["run", "-c", "stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if privileged {
            command
                .env_clear()
                .current_dir(binary.parent().expect("sidecar directory"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(if privileged { 0x00000200 } else { 0x08000000 });
        }
        let child = command.spawn()?;
        let mut core = Self {
            child,
            port,
            privileged,
        };
        core.child
            .stdin
            .take()
            .ok_or(io::ErrorKind::BrokenPipe)?
            .write_all(&serde_json::to_vec(&config)?)?;
        Ok(core)
    }
}

impl Core for SingBox {
    fn port(&self) -> u16 {
        self.port
    }
    fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for SingBox {
    fn drop(&mut self) {
        if self.privileged && self.running() {
            platform::interrupt(self.child.id());
            let deadline = Instant::now() + Duration::from_secs(3);
            while self.running() && Instant::now() < deadline {
                thread::sleep(POLL);
            }
        }
        if self.running() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

pub fn start_relay(binary: &Path, bootstrap: &Value) -> Option<impl Core> {
    let _verified = platform::verify(binary).ok()?;
    let reservation = TcpListener::bind(("127.0.0.1", 0)).ok()?;
    let port = reservation.local_addr().ok()?.port();
    let config = relay_config(bootstrap, port)?;
    drop(reservation);
    let mut core = SingBox::spawn(binary, config, port, false).ok()?;
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline && core.running() {
        if loopback_ready(port) {
            return Some(core);
        }
        thread::sleep(POLL);
    }
    None
}

pub struct Session {
    control: TcpStream,
    journal: PathBuf,
    socks_port: u16,
    stop_requested: bool,
}

impl Session {
    pub fn start(
        data: &Path,
        gate: u16,
        relay: Option<SocketAddrV4>,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self, Fallback> {
        let executable = std::env::current_exe().map_err(|_| Fallback::SidecarMissing)?;
        let binary = executable.with_file_name(CORE);
        let _verified = platform::verify(&binary)?;
        if adapter_present() {
            return Err(Fallback::TunInitFailed);
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| Fallback::TunInitFailed)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Fallback::TunInitFailed)?;
        let control_port = listener
            .local_addr()
            .map_err(|_| Fallback::TunInitFailed)?
            .port();
        let reservation =
            TcpListener::bind(("127.0.0.1", 0)).map_err(|_| Fallback::TunInitFailed)?;
        let socks_port = reservation
            .local_addr()
            .map_err(|_| Fallback::TunInitFailed)?
            .port();
        let mut seed = [0; 16];
        platform::random(&mut seed).map_err(|_| Fallback::ElevationFailed)?;
        let nonce: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut journal = Journal {
            pid: None,
            engine: RequestedEngine::SplitTun,
            interface_name: INTERFACE.into(),
            started_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            config_path: "stdin".into(),
            socks_port,
        };
        fs::create_dir_all(data).map_err(|_| Fallback::TunInitFailed)?;
        let journal_path = data.join(JOURNAL);
        if journal_path.exists() {
            return Err(Fallback::RecoveryPending);
        }
        journal_write(&journal_path, &journal).map_err(|_| Fallback::TunInitFailed)?;

        let (send, recv) = std::sync::mpsc::channel();
        let helper_nonce = nonce.clone();
        let requested = thread::Builder::new()
            .name("workspace-elevation".into())
            .spawn(move || {
                let _ = send.send(platform::elevate(
                    &executable,
                    control_port,
                    socks_port,
                    gate,
                    relay,
                    helper_nonce,
                ));
            });
        let control = (|| {
            requested.map_err(|_| Fallback::ElevationFailed)?;
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if let Ok(Err(reason)) = recv.try_recv() {
                    return Err(reason);
                }
                if cancelled() || Instant::now() >= deadline {
                    return Err(Fallback::ElevationTimeout);
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut presented = [0; 32];
                        if stream.set_nonblocking(false).is_ok()
                            && stream
                                .set_read_timeout(Some(Duration::from_millis(500)))
                                .is_ok()
                            && stream
                                .set_write_timeout(Some(Duration::from_millis(500)))
                                .is_ok()
                            && stream
                                .write_all(&control_proof(b"launcher", &nonce))
                                .is_ok()
                            && stream.read_exact(&mut presented).is_ok()
                            && presented == control_proof(b"helper", &nonce)
                        {
                            return Ok(stream);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
                    Err(_) => return Err(Fallback::ElevationFailed),
                }
            }
        })();
        let control = match control {
            Ok(control) => control,
            Err(error) => {
                let _ = fs::remove_file(&journal_path);
                return Err(error);
            }
        };
        drop(listener);
        drop(reservation);
        let mut session = Self {
            control,
            journal: journal_path,
            socks_port,
            stop_requested: false,
        };
        let failure = Fallback::TunInitFailed;
        session
            .control
            .set_read_timeout(Some(Duration::from_secs(8)))
            .map_err(|_| failure)?;
        session
            .control
            .set_write_timeout(Some(Duration::from_secs(1)))
            .map_err(|_| failure)?;
        session.control.write_all(&[1]).map_err(|_| failure)?;
        let mut pid = [0; 4];
        session.control.read_exact(&mut pid).map_err(|_| failure)?;
        journal.pid = Some(u32::from_be_bytes(pid));
        journal_write(&session.journal, &journal).map_err(|_| failure)?;
        let mut ready = [0];
        session
            .control
            .read_exact(&mut ready)
            .map_err(|_| failure)?;
        if ready != [1] || cancelled() {
            return Err(failure);
        }
        Ok(session)
    }

    pub fn healthy(&self) -> bool {
        if self
            .control
            .set_read_timeout(Some(Duration::from_millis(20)))
            .is_err()
        {
            return false;
        }
        let mut signal = [0];
        matches!(self.control.peek(&mut signal),
            Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock))
            && loopback_ready(self.socks_port)
            && adapter_present()
    }

    pub fn stop(&mut self) -> bool {
        self.stop_requested = true;
        let _ = self.control.shutdown(Shutdown::Write);
        let _ = self.control.set_read_timeout(Some(STOP_TIMEOUT));
        let mut complete = [0];
        let _ = self.control.read_exact(&mut complete);
        let deadline = Instant::now() + Duration::from_secs(1);
        while adapter_present() || loopback_ready(self.socks_port) {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(POLL);
        }
        complete == [2] && fs::remove_file(&self.journal).is_ok()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.stop_requested {
            self.stop();
        }
    }
}

// This branch starts before Tauri. Elevated code reads no launcher data,
// credentials or arbitrary config paths and accepts only loopback port numbers.
pub fn run_helper() -> Option<i32> {
    let mut args = std::env::args_os().skip(1);
    if args.next()?.to_str()? != "--workspace-split-tun-helper" {
        return None;
    }
    let result = (|| {
        let mut port = || {
            args.next()?
                .to_str()?
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
        };
        let (control, socks, gate) = (port()?, port()?, port()?);
        let relay = args.next()?.into_string().ok()?;
        let relay = if relay == "none" {
            None
        } else {
            Some(
                relay
                    .parse::<SocketAddrV4>()
                    .ok()
                    .filter(|endpoint| endpoint.port() != 0)?,
            )
        };
        let nonce = args.next()?.into_string().ok()?;
        if args.next().is_some()
            || control == socks
            || socks == gate
            || gate == control
            || nonce.len() != 32
            || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        supervise(control, socks, gate, relay, &nonce).ok()?;
        Some(0)
    })();
    Some(result.unwrap_or(1))
}

fn supervise(
    control: u16,
    socks: u16,
    gate: u16,
    relay: Option<SocketAddrV4>,
    nonce: &str,
) -> io::Result<()> {
    let mut owner =
        TcpStream::connect_timeout(&([127, 0, 0, 1], control).into(), Duration::from_secs(2))?;
    owner.set_write_timeout(Some(Duration::from_secs(1)))?;
    owner.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut presented = [0; 32];
    owner.read_exact(&mut presented)?;
    if presented != control_proof(b"launcher", nonce) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    owner.write_all(&control_proof(b"helper", nonce))?;
    let mut message = [0];
    owner.read_exact(&mut message)?;
    if message != [1] {
        return Err(io::ErrorKind::InvalidData.into());
    }
    owner.set_write_timeout(Some(Duration::from_secs(1)))?;
    owner.set_read_timeout(Some(POLL))?;
    let binary = std::env::current_exe()?.with_file_name(CORE);
    let _verified = platform::verify(&binary).map_err(|_| io::ErrorKind::NotFound)?;
    let _platform = platform::prepare()?;
    let mut core = SingBox::spawn(&binary, system_config(socks, gate, relay), socks, true)?;
    let _tracking = match platform::track(&core.child) {
        Ok(tracking) => tracking,
        Err(error) => {
            drop(core);
            return Err(error);
        }
    };
    let result = (|| -> io::Result<()> {
        owner.write_all(&core.child.id().to_be_bytes())?;
        let mut ready = false;
        let deadline = Instant::now() + Duration::from_secs(6);
        while core.running() {
            match owner.read(&mut message) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                _ => break,
            }
            if !ready {
                #[cfg(windows)]
                let owned = crate::native_windows::owns_loopback_listener(socks, core.child.id());
                #[cfg(not(windows))]
                let owned = true;
                if owned && loopback_ready(socks) && adapter_present() {
                    owner.write_all(&[1])?;
                    ready = true;
                } else if Instant::now() >= deadline {
                    break;
                }
            }
        }
        Ok(())
    })();
    drop(core);
    #[cfg(windows)]
    platform::cleanup_residual();
    result?;
    owner.write_all(&[2])
}

#[cfg(windows)]
#[path = "split_tun_windows.rs"]
mod platform;

#[cfg(target_os = "macos")]
#[path = "split_tun_macos.rs"]
mod platform;

#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use super::*;
    pub fn verify(_: &Path) -> Result<(), Fallback> {
        Err(Fallback::SidecarMissing)
    }
    pub fn random(_: &mut [u8; 16]) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    pub fn elevate(
        _: &Path,
        _: u16,
        _: u16,
        _: u16,
        _: Option<SocketAddrV4>,
        _: String,
    ) -> Result<(), Fallback> {
        Err(Fallback::ElevationFailed)
    }
    pub fn prepare() -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    pub fn track(_: &Child) -> io::Result<()> {
        Ok(())
    }
    pub fn interrupt(_: u32) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::killswitch::{Monitor, Proxy};

    fn check(binary: &Path, config: &Value) {
        let mut child = Command::new(binary)
            .args(["check", "-c", "stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(config).unwrap())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn checks_the_system_profile_and_relay_worker_with_pinned_sing_box() {
        let relay: SocketAddrV4 = "192.0.2.1:24443".parse().unwrap();
        let system = system_config(12123, 12124, Some(relay));
        assert_eq!(
            system["route"]["rules"][0]["ip_cidr"],
            json!(["192.0.2.1/32"])
        );
        assert_eq!(system["route"]["rules"][0]["outbound"], "direct");
        assert_eq!(system["route"]["final"], "direct");
        assert_eq!(system["inbounds"][0]["strict_route"], false);
        assert_eq!(system["outbounds"][1]["server"], "127.0.0.1");
        assert!(system["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule["inbound"] == "workspace-loopback"
                && rule["outbound"] == "proxy"
                && rule.get("domain").is_none()));
        assert!(system["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|outbound| outbound.get("uuid").is_none()));

        let bootstrap = json!({"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{
            "address":"192.0.2.1","port":24443,
            "users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none","flow":"xtls-rprx-vision"}]
        }]},"streamSettings":{"network":"raw","security":"reality","realitySettings":{
            "serverName":"www.microsoft.com","fingerprint":"chrome",
            "password":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","shortId":"abcd"
        }}}]});
        assert_eq!(relay_endpoint(&bootstrap), Some(relay));
        let worker = relay_config(&bootstrap, 12125).unwrap();
        assert_eq!(worker["route"]["final"], "proxy");
        if let Some(binary) = std::env::var_os("SING_BOX_TEST_BIN") {
            let binary = Path::new(&binary);
            check(binary, &system);
            check(binary, &system_config(12123, 12124, None));
            check(binary, &worker);
        }
    }

    #[test]
    fn leftover_session_waits_for_owned_adapter_then_clears_journal() {
        let data =
            std::env::temp_dir().join(format!("workspace-tun-recovery-{}", std::process::id()));
        fs::create_dir_all(&data).unwrap();
        let file = data.join(JOURNAL);
        let journal = Journal {
            pid: Some(42),
            engine: RequestedEngine::SplitTun,
            interface_name: INTERFACE.into(),
            started_at: 123,
            config_path: "stdin".into(),
            socks_port: 32101,
        };
        fs::write(&file, serde_json::to_vec(&journal).unwrap()).unwrap();
        let count = std::cell::Cell::new(0);
        assert_eq!(
            recover_with(&data, |port| {
                assert_eq!(port, journal.socks_port);
                count.set(count.get() + 1);
                count.get() < 3
            }),
            Recovery::Recovered
        );
        assert!(!file.exists());
        assert_eq!(
            recover_with(&data, |_| panic!("no previous session")),
            Recovery::None
        );
        fs::remove_dir(data).unwrap();
    }

    // Exercise the actual sing-box inbound and stable gate on loopback. Neither
    // the fixture nor the core can connect to an external IP in this test.
    #[test]
    fn windows_signals_reach_local_relay_and_hold_closes_the_same_gate() {
        let Some(binary) = std::env::var_os("SING_BOX_TEST_BIN") else {
            return;
        };
        let relay = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        let gate = Proxy::bind().unwrap();
        struct LocalRelay(u16);
        impl Core for LocalRelay {
            fn port(&self) -> u16 {
                self.0
            }
            fn running(&mut self) -> bool {
                true
            }
        }
        let _monitor = Monitor::start(
            &gate,
            move || Some(LocalRelay(relay_port)),
            |_| true,
            |_| {},
        )
        .unwrap();
        let local = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = local.local_addr().unwrap().port();
        let mut config = system_config(port, gate.port, None);
        config["inbounds"].as_array_mut().unwrap().remove(0);
        config["route"]["rules"]
            .as_array_mut()
            .unwrap()
            .retain(|rule| rule["inbound"] != "desktop-tun");
        drop(local);
        let mut process = SingBox::spawn(Path::new(&binary), config, port, false).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !(gate.ready() && loopback_ready(port)) {
            assert!(
                process.running() && Instant::now() < deadline,
                "SOCKS listener did not start"
            );
            thread::sleep(POLL);
        }
        let diagnostic = b"radar.example.invalid";
        let fixture = thread::spawn(move || {
            relay.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut conn = loop {
                match relay.accept() {
                    Ok((conn, _)) => break conn,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(POLL)
                    }
                    Err(error) => panic!("Relay fixture did not receive diagnostic host: {error}"),
                }
            };
            conn.set_nonblocking(false).unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut greeting = [0; 3];
            conn.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            conn.write_all(&[5, 0]).unwrap();
            let mut head = [0; 5];
            conn.read_exact(&mut head).unwrap();
            assert_eq!(head, [5, 1, 0, 3, diagnostic.len() as u8]);
            let mut host = vec![0; diagnostic.len() + 2];
            conn.read_exact(&mut host).unwrap();
            assert_eq!(&host[..diagnostic.len()], diagnostic);
            conn.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
            let mut payload = [0];
            conn.read_exact(&mut payload).unwrap();
            conn.write_all(&payload).unwrap();
            assert!(!matches!(conn.read(&mut payload), Ok(1)));
        });
        let connect = || {
            let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            conn.write_all(&[5, 1, 0]).unwrap();
            let mut greeting = [0; 2];
            conn.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 0]);
            let mut request = vec![5, 1, 0, 3, diagnostic.len() as u8];
            request.extend(diagnostic);
            request.extend(443u16.to_be_bytes());
            conn.write_all(&request).unwrap();
            conn
        };
        let mut active = connect();
        let mut reply = [0; 10];
        active.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0);
        active.write_all(b"X").unwrap();
        let mut echo = [0];
        active.read_exact(&mut echo).unwrap();
        assert_eq!(echo, *b"X");

        let mut quic = TcpStream::connect(("127.0.0.1", gate.port)).unwrap();
        quic.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        quic.write_all(&[5, 1, 0]).unwrap();
        let mut response = [0; 2];
        quic.read_exact(&mut response).unwrap();
        assert_eq!(response, [5, 0]);
        quic.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        quic.read_exact(&mut response).unwrap();
        assert_eq!(response, [5, 7]);

        gate.suspend();
        assert!(!gate.ready());
        assert!(!matches!(active.read(&mut echo), Ok(1)));
        let mut held = connect();
        let mut head = [0; 2];
        assert!(held.read_exact(&mut head).is_err() || head[1] != 0);
        fixture.join().unwrap();
        assert!(process.running());
    }
}
