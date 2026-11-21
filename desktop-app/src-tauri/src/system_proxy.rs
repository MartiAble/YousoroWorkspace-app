use serde::{Deserialize, Serialize};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, net::TcpListener, path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct Settings {
    enable: Option<u32>,
    server: Option<String>,
    bypass: Option<String>,
    pac: Option<String>,
}

impl Settings {
    fn with_pac(&self, url: String) -> Result<Self, String> {
        if self.enable.unwrap_or(0) != 0 || self.pac.as_deref().is_some_and(|url| !url.is_empty()) {
            return Err("Windows уже использует прокси или сторонний PAC. Настройки сети сохранены.".into());
        }
        Ok(Self { pac: Some(url), ..self.clone() })
    }

    fn restore(&self, expected: &Self, before: &Self) -> Self {
        Self {
            enable: if self.enable == expected.enable { before.enable } else { self.enable },
            server: restore_value(&self.server, &expected.server, &before.server),
            bypass: restore_value(&self.bypass, &expected.bypass, &before.bypass),
            pac: restore_value(&self.pac, &expected.pac, &before.pac),
        }
    }
}

fn restore_value(current: &Option<String>, expected: &Option<String>, before: &Option<String>) -> Option<String> {
    if current == expected { before.clone() } else { current.clone() }
}

const KEY: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings', $env:WORKSPACE_PROXY_WRITE -eq 'yes')
if (!$key) { throw 'Internet Settings unavailable' }
"#;

fn read_settings() -> Result<Settings, String> {
    let script = format!(r#"{KEY}
@{{ enable = $key.GetValue('ProxyEnable'); server = $key.GetValue('ProxyServer', $null, 'DoNotExpandEnvironmentNames');
    bypass = $key.GetValue('ProxyOverride', $null, 'DoNotExpandEnvironmentNames');
    pac = $key.GetValue('AutoConfigURL', $null, 'DoNotExpandEnvironmentNames') }} | ConvertTo-Json -Compress
"#);
    let output = crate::launch::powershell(&script).env_remove("WORKSPACE_PROXY_WRITE")
        .output().map_err(|_| "Не удалось прочитать системный прокси")?;
    if !output.status.success() { return Err("Не удалось прочитать системный прокси".into()); }
    serde_json::from_slice(&output.stdout).map_err(|_| "Не удалось разобрать настройки системного прокси".into())
}

fn write_settings(current: &Settings, settings: &Settings) -> Result<(), String> {
    let script = format!(r#"{KEY}
$settings = $env:WORKSPACE_PROXY_DATA | ConvertFrom-Json
$changes = $env:WORKSPACE_PROXY_FIELDS -split ","
foreach ($entry in @(
    @('ProxyServer', $settings.server, 'String'),
    @('ProxyOverride', $settings.bypass, 'String'),
    @('AutoConfigURL', $settings.pac, 'String'),
    @('ProxyEnable', $settings.enable, 'DWord')
)) {{
    if ($changes -notcontains $entry[0]) {{ continue }}
    if ($null -eq $entry[1]) {{ $key.DeleteValue($entry[0], $false) }}
    else {{ $key.SetValue($entry[0], $entry[1], $entry[2]) }}
}}
"#);
    let changes = [
        (current.enable != settings.enable, "ProxyEnable"),
        (current.server != settings.server, "ProxyServer"),
        (current.bypass != settings.bypass, "ProxyOverride"),
        (current.pac != settings.pac, "AutoConfigURL"),
    ].into_iter().filter_map(|(changed, name)| changed.then_some(name)).collect::<Vec<_>>();
    if changes.is_empty() { return Ok(()); }
    let data = serde_json::to_string(settings).map_err(|_| "Не удалось подготовить настройки системного прокси")?;
    let output = crate::launch::powershell(&script).env("WORKSPACE_PROXY_WRITE", "yes")
        .env("WORKSPACE_PROXY_DATA", data).env("WORKSPACE_PROXY_FIELDS", changes.join(",")).output().map_err(|_| "Не удалось изменить системный прокси")?;
    refresh();
    if !output.status.success() { return Err("Не удалось изменить системный прокси Windows".into()); }
    Ok(())
}

#[cfg(windows)]
fn refresh() {
    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(handle: *mut std::ffi::c_void, option: u32, buffer: *mut std::ffi::c_void, len: u32) -> i32;
    }
    // Notify WinINet clients of the per-user settings change.
    unsafe {
        InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0);
        InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0);
    }
}

#[cfg(not(windows))]
fn refresh() {}

#[derive(Serialize, Deserialize)]
struct Journal {
    before: Settings,
    expected: Settings,
}

pub struct Lease {
    journal: PathBuf,
    _lock: File,
    restored: bool,
    server: Option<PacServer>,
}

impl Lease {
    fn lock(directory: &Path) -> Result<Self, String> {
        fs::create_dir_all(directory).map_err(|_| "Нет каталога настроек системного прокси")?;
        let lock = OpenOptions::new().write(true).create(true).truncate(false)
            .open(directory.join("system-proxy.lock")).map_err(|_| "Нет доступа к блокировке системного прокси")?;
        lock.try_lock().map_err(|_| "Настройками системного прокси управляет другой экземпляр Workspace")?;
        Ok(Self { journal: directory.join("system-proxy.json"), _lock: lock, restored: true, server: None })
    }

    pub fn enable(directory: &Path, port: u16, domains: &[String]) -> Result<Self, String> {
        if !cfg!(windows) { return Err("Управление системным прокси доступно в Windows".into()); }
        let mut lease = Self::lock(directory)?;
        lease.restore()?;
        let before = read_settings()?;
        let server = PacServer::start(port, domains)?;
        let expected = before.with_pac(server.url.clone())?;
        let journal = Journal { before, expected };
        let serialized = serde_json::to_vec(&journal).map_err(|_| "Не удалось сохранить исходный прокси")?;
        let save = || -> std::io::Result<()> {
            let mut file = OpenOptions::new().write(true).create_new(true).open(&lease.journal)?;
            file.write_all(&serialized)?;
            file.sync_all()
        };
        save().map_err(|_| "Не удалось сохранить исходный прокси")?;
        lease.restored = false;
        lease.server = Some(server);
        write_settings(&journal.before, &journal.expected)?;
        Ok(lease)
    }

    pub fn recover(directory: &Path) -> Result<(), String> {
        if cfg!(windows) && directory.join("system-proxy.json").exists() {
            Self::lock(directory)?.restore()?;
        }
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), String> {
        let bytes = match fs::read(&self.journal) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("Не удалось открыть исходные настройки прокси".into()),
        };
        let journal: Journal = serde_json::from_slice(&bytes)
            .map_err(|_| "Не удалось прочитать исходные настройки прокси")?;
        let current = read_settings()?;
        let restored = current.restore(&journal.expected, &journal.before);
        write_settings(&current, &restored)?;
        fs::remove_file(&self.journal).map_err(|_| "Не удалось завершить восстановление прокси")?;
        self.restored = true;
        self.server = None;
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.restored { let _ = self.restore(); }
    }
}

pub fn active(lease: Option<&Lease>) -> bool {
    lease.and_then(|lease| lease.server.as_ref()).is_some_and(|server| {
        read_settings().is_ok_and(|settings| settings.enable.unwrap_or(0) == 0 && settings.pac.as_deref() == Some(server.url.as_str()))
    })
}

const PAC: &str = r#"
function FindProxyForURL(url, host) {
    host = host.toLowerCase().replace(/\.$/, "");
    if (url.indexOf("https:") !== 0 && url.indexOf("http:") !== 0) return "DIRECT";
    for (var i = 0; i < rules.length; i++) {
        var colon = rules[i].indexOf(":");
        var name = rules[i].substring(colon + 1);
        if (host === name || (rules[i].substring(0, colon) === "domain" &&
            host.length > name.length && host.slice(-name.length - 1) === "." + name)) return workspaceProxy;
    }
    return "DIRECT";
}
"#;

fn pac_script(port: u16, domains: &[String]) -> Result<String, String> {
    if domains.is_empty() || domains.len() > 512 || !domains.iter().all(|rule| {
        rule.split_once(':').is_some_and(|(kind, name)| {
            matches!(kind, "full" | "domain") && !name.is_empty() && name.len() <= 253
                && name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
        })
    }) { return Err("Сервер не выдал список доменов для Store-приложений".into()); }
    let rules = serde_json::to_string(domains).map_err(|_| "Не удалось сформировать список доменов PAC")?;
    let proxy = format!("PROXY 127.0.0.1:{port}");
    Ok(format!("var rules = {rules};\nvar workspaceProxy = {proxy:?};\n{PAC}"))
}

struct PacServer { url: String, stop: Arc<AtomicBool> }

impl PacServer {
    fn start(proxy_port: u16, domains: &[String]) -> Result<Self, String> {
        let script = pac_script(proxy_port, domains)?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "Не удалось открыть локальный сервер PAC")?;
        listener.set_nonblocking(true).map_err(|_| "Не удалось настроить локальный сервер PAC")?;
        let port = listener.local_addr().map_err(|_| "Не удалось получить порт PAC")?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        std::thread::spawn(move || {
            let host = format!("Host: 127.0.0.1:{port}");
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let timeout = Some(Duration::from_millis(350));
                        let _ = stream.set_read_timeout(timeout);
                        let _ = stream.set_write_timeout(timeout);
                        let mut request = [0u8; 4096];
                        let Ok(size) = stream.read(&mut request) else { continue };
                        let Ok(text) = std::str::from_utf8(&request[..size]) else { continue };
                        if text.lines().next().is_some_and(|line| line.starts_with("GET /workspace.pac HTTP/"))
                            && text.lines().any(|line| line.eq_ignore_ascii_case(&host)) {
                            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{script}", script.len());
                        } else {
                            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(40)),
                    Err(_) => break,
                }
            }
        });
        Ok(Self { url: format!("http://127.0.0.1:{port}/workspace.pac"), stop })
    }
}

impl Drop for PacServer {
    fn drop(&mut self) { self.stop.store(true, Ordering::Relaxed); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_modifies_only_auto_config_and_refuses_conflicts() {
        let before = Settings { enable: Some(0), server: Some("preserve.invalid:3128".into()), ..Settings::default() };
        let expected = before.with_pac("http://127.0.0.1:42000/workspace.pac".into()).unwrap();
        assert_eq!(expected.enable, Some(0));
        assert_eq!(expected.server, before.server);
        assert_eq!(expected.bypass, before.bypass);
        assert_eq!(expected.restore(&expected, &before), before);
        assert!(expected.with_pac("another".into()).is_err());
        assert!(Settings { enable: Some(1), ..before }.with_pac("another".into()).is_err());
    }

    #[test]
    fn crash_journal_restores_pac_and_keeps_external_edits() {
        let before = Settings::default();
        let journal = Journal { expected: before.with_pac("http://127.0.0.1:42000/workspace.pac".into()).unwrap(), before };
        let decoded: Journal = serde_json::from_slice(&serde_json::to_vec(&journal).unwrap()).unwrap();
        let changed = Settings { server: Some("manual.invalid".into()), ..decoded.expected.clone() };
        let restored = changed.restore(&decoded.expected, &decoded.before);
        assert_eq!(restored.server, changed.server);
        assert_eq!(restored.pac, None);
        assert_eq!(restored.enable, None);
    }

    #[test]
    fn pac_uses_only_valid_server_domains() {
        assert!(pac_script(10081, &["domain:claude.com".into()]).unwrap().contains("PROXY 127.0.0.1:10081"));
        assert!(pac_script(10081, &["domain:bad'host".into()]).is_err());
        assert!(pac_script(10081, &[]).is_err());
    }
}
