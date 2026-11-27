use crate::killswitch::Core;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, net::{TcpListener, TcpStream}, path::Path, process::{Child, Command, Stdio}, thread, time::Duration};

pub struct Tunnel { child: Child, port: u16 }
impl Core for Tunnel {
    fn port(&self) -> u16 { self.port }
    fn running(&mut self) -> bool { matches!(self.child.try_wait(), Ok(None)) }
}
impl Drop for Tunnel {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}

fn local_config(mut config: Value, port: u16) -> Result<Value, String> {
    let outbounds = config["outbounds"].as_array_mut().ok_or("Нет выходов Xray")?;
    if outbounds.len() != 1 || outbounds[0]["protocol"] != "vless" || outbounds[0]["tag"] != "proxy" {
        return Err("Ожидается единственный выход через Relay".into());
    }
    outbounds.push(json!({"tag":"workspace-block","protocol":"blackhole","settings":{}}));
    let rules = config["routing"]["rules"].as_array_mut().ok_or("Нет правил маршрута Xray")?;
    if rules.iter().any(|rule| rule["outboundTag"] != "proxy" || rule.get("balancerTag").is_some()) {
        return Err("Конфиг Xray содержит альтернативный маршрут".into());
    }
    rules.splice(..0, [
        json!({"type":"field","network":"udp","outboundTag":"workspace-block"}),
        json!({"type":"field","ip":["::/0"],"outboundTag":"workspace-block"}),
    ]);
    config["inbounds"] = json!([{"listen":"127.0.0.1","port":port,"protocol":"mixed","settings":{"udp":false},
        "sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":true}}]);
    Ok(config)
}
pub fn verified(executable_dir: &Path, resources: &Path) -> Result<std::path::PathBuf, String> {
    let (name, checksum) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => ("xray", "xray-aarch64-apple-darwin.sha256"),
        ("macos", "x86_64") => ("xray", "xray-x86_64-apple-darwin.sha256"),
        ("windows", "x86_64") => ("xray.exe", "xray-x86_64-pc-windows-msvc.exe.sha256"),
        _ => return Err("Нет сборки Xray для этой системы".into()),
    };
    let path = executable_dir.join(name);
    if cfg!(target_os = "macos") && executable_dir.ends_with("Contents/MacOS") {
        // Bundling combines and re-signs the binaries, changing the staged SHA-256.
        let output = Command::new("/usr/bin/codesign").args(["--verify", "--strict", "--all-architectures"])
            .arg(&path).output().map_err(|_| "Не удалось проверить подпись Xray")?;
        if !output.status.success() {
            return Err("Подпись Xray отсутствует или недействительна".into());
        }
    } else {
        let hash = fs::read_to_string(resources.join(checksum))
            .map_err(|_| "В сборке отсутствует контрольная сумма Xray")?;
        let actual = format!("{:x}", Sha256::digest(fs::read(&path).map_err(|_| "В сборке отсутствует Xray")?));
        if hash.trim() != actual {
            return Err("Контрольная сумма Xray не совпадает".into());
        }
    }
    Ok(path)
}
pub fn start(path: &Path, config: Value) -> Result<Tunnel, String> {
    let reservation = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "Нет свободного локального порта")?;
    let port = reservation.local_addr().map_err(|_| "Не удалось получить локальный порт")?.port();
    let config = local_config(config, port)?;
    let payload = serde_json::to_vec(&config).map_err(|_| "Некорректный конфиг Xray")?;
    let mut cmd = Command::new(path);
    cmd.args(["run","-config","stdin:"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)] { use std::os::windows::process::CommandExt; cmd.creation_flags(0x08000000); }
    drop(reservation);
    let child = cmd.spawn().map_err(|_| "Не удалось запустить Xray")?;
    let mut tunnel = Tunnel { child, port };
    tunnel.child.stdin.take().ok_or("Нет stdin у Xray")?.write_all(&payload).map_err(|_| "Xray отклонил конфиг")?;
    for _ in 0..40 {
        if !tunnel.running() { break; }
        if let Ok(mut socket) = TcpStream::connect(("127.0.0.1", port)) {
            use std::io::Read;
            let _ = socket.set_read_timeout(Some(Duration::from_millis(250)));
            let mut response = [0u8; 2];
            if socket.write_all(&[5,1,0]).is_ok() && socket.read_exact(&mut response).is_ok() && response == [5,0] {
                return Ok(tunnel);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("Xray не открыл локальный SOCKS5-порт".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installed_xray_accepts_protected_desktop_config() {
        let Some(binary) = std::env::var_os("XRAY_TEST_BIN") else { return; };
        let config = local_config(json!({
            "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{
                "address":"192.0.2.1","port":443,
                "users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]
            }]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.invalid"}}}],
            "routing":{"domainStrategy":"AsIs","rules":[]}
        }), 12123).unwrap();
        let mut process = Command::new(binary).args(["run", "-test", "-config", "stdin:"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        process.stdin.take().unwrap().write_all(&serde_json::to_vec(&config).unwrap()).unwrap();
        let output = process.wait_with_output().unwrap();
        assert!(output.status.success(), "{:?}", output);
    }

    #[test]
    fn config_binds_loopback_and_retains_routes() {
        let config = local_config(json!({
            "outbounds":[{"tag":"proxy","protocol":"vless"}],
            "routing":{"rules":[{"outboundTag":"proxy"}]},
        }), 12123).unwrap();
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["port"], 12123);
        assert_eq!(config["inbounds"][0]["settings"]["udp"], false);
        assert_eq!(config["routing"]["rules"][0]["network"], "udp");
        assert_eq!(config["routing"]["rules"][1]["ip"], json!(["::/0"]));
        assert_eq!(config["routing"]["rules"][2]["outboundTag"], "proxy");
        assert!(local_config(json!({"outbounds":[{"tag":"proxy","protocol":"freedom"}]}), 12123).is_err());
    }
}
