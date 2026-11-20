use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, net::{TcpListener, TcpStream}, path::Path, process::{Child, Command, Stdio}, thread, time::Duration};

pub struct Tunnel { child: Child, pub port: u16, pub region: String }
impl Tunnel {
    pub fn running(&mut self) -> bool { matches!(self.child.try_wait(), Ok(None)) }
}
impl Drop for Tunnel {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}

fn local_config(mut config: Value, port: u16) -> Result<Value, String> {
    if !config.is_object() { return Err("Некорректный конфиг Xray".into()); }
    config["inbounds"] = json!([{"listen":"127.0.0.1","port":port,"protocol":"mixed","settings":{"udp":false},
        "sniffing":{"enabled":true,"destOverride":["http","tls"]}}]);
    Ok(config)
}
fn verified(executable_dir: &Path, resources: &Path) -> Result<std::path::PathBuf, String> {
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
pub fn start(executable_dir: &Path, resources: &Path, config: Value, region: String) -> Result<Tunnel, String> {
    let path = verified(executable_dir, resources)?;
    let reservation = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "Нет свободного локального порта")?;
    let port = reservation.local_addr().map_err(|_| "Не удалось получить локальный порт")?.port();
    let config = local_config(config, port)?;
    let payload = serde_json::to_vec(&config).map_err(|_| "Некорректный конфиг Xray")?;
    let mut cmd = Command::new(path);
    cmd.args(["run","-config","stdin:"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)] { use std::os::windows::process::CommandExt; cmd.creation_flags(0x08000000); }
    drop(reservation);
    let child = cmd.spawn().map_err(|_| "Не удалось запустить Xray")?;
    let mut tunnel = Tunnel { child, port, region };
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
    fn config_binds_loopback_and_retains_routes() {
        let config = local_config(json!({"routing":{"rules":[{"outboundTag":"proxy"}]}}), 12123).unwrap();
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["port"], 12123);
        assert_eq!(config["routing"]["rules"][0]["outboundTag"], "proxy");
    }
}
