use serde::{Deserialize, Serialize};
use std::{fs::{self, File, OpenOptions}, io::Write, path::{Path, PathBuf}, process::Command};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct Settings {
    enable: Option<u32>,
    server: Option<String>,
    bypass: Option<String>,
    pac: Option<String>,
}

impl Settings {
    fn local(port: u16) -> Self {
        Self { enable: Some(1), server: Some(format!("127.0.0.1:{port}")), bypass: Some(String::new()), pac: None }
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

fn write_settings(settings: &Settings) -> Result<(), String> {
    let script = format!(r#"{KEY}
$settings = $env:WORKSPACE_PROXY_DATA | ConvertFrom-Json
foreach ($entry in @(
    @('ProxyServer', $settings.server, 'String'),
    @('ProxyOverride', $settings.bypass, 'String'),
    @('AutoConfigURL', $settings.pac, 'String'),
    @('ProxyEnable', $settings.enable, 'DWord')
)) {{
    if ($null -eq $entry[1]) {{ $key.DeleteValue($entry[0], $false) }}
    else {{ $key.SetValue($entry[0], $entry[1], $entry[2]) }}
}}
"#);
    let data = serde_json::to_string(settings).map_err(|_| "Не удалось подготовить настройки системного прокси")?;
    let output = crate::launch::powershell(&script).env("WORKSPACE_PROXY_WRITE", "yes")
        .env("WORKSPACE_PROXY_DATA", data).output().map_err(|_| "Не удалось изменить системный прокси")?;
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
}

impl Lease {
    fn lock(directory: &Path) -> Result<Self, String> {
        fs::create_dir_all(directory).map_err(|_| "Нет каталога настроек системного прокси")?;
        let lock = OpenOptions::new().write(true).create(true).truncate(false)
            .open(directory.join("system-proxy.lock")).map_err(|_| "Нет доступа к блокировке системного прокси")?;
        lock.try_lock().map_err(|_| "Настройками системного прокси управляет другой экземпляр Workspace")?;
        Ok(Self { journal: directory.join("system-proxy.json"), _lock: lock, restored: true })
    }

    pub fn enable(directory: &Path, port: u16) -> Result<Self, String> {
        if !cfg!(windows) { return Err("Управление системным прокси доступно в Windows".into()); }
        let mut lease = Self::lock(directory)?;
        lease.restore()?;
        let journal = Journal { before: read_settings()?, expected: Settings::local(port) };
        let serialized = serde_json::to_vec(&journal).map_err(|_| "Не удалось сохранить исходный прокси")?;
        let save = || -> std::io::Result<()> {
            let mut file = OpenOptions::new().write(true).create_new(true).open(&lease.journal)?;
            file.write_all(&serialized)?;
            file.sync_all()
        };
        save().map_err(|_| "Не удалось сохранить исходный прокси")?;
        lease.restored = false;
        write_settings(&journal.expected)?;
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
        if current != restored { write_settings(&restored)?; }
        fs::remove_file(&self.journal).map_err(|_| "Не удалось завершить восстановление прокси")?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.restored { let _ = self.restore(); }
    }
}

pub fn active(port: u16) -> Option<bool> {
    if cfg!(windows) {
        let settings = read_settings().ok()?;
        return Some(settings.enable == Some(1)
            && settings.server.as_deref() == Some(&format!("127.0.0.1:{port}"))
            && settings.pac.is_none());
    }
    if cfg!(target_os = "macos") {
        let output = Command::new("/usr/sbin/scutil").arg("--proxy").output().ok()?;
        if !output.status.success() { return None; }
        let text = String::from_utf8(output.stdout).ok()?;
        let value = |key: &str| text.lines().find_map(|line| {
            let (name, value) = line.trim().split_once(" : ")?;
            (name == key).then_some(value)
        });
        return Some(["HTTP", "HTTPS", "SOCKS"].iter().any(|kind| {
            value(&format!("{kind}Enable")) == Some("1")
                && value(&format!("{kind}Proxy")) == Some("127.0.0.1")
                && value(&format!("{kind}Port")).and_then(|value| value.parse().ok()) == Some(port)
        }));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_previous_proxy_and_missing_values() {
        let before = Settings { enable: Some(0), server: Some("corp.proxy:3128".into()),
            bypass: None, pac: Some("https://example.invalid/proxy.pac".into()) };
        let expected = Settings::local(10800);
        assert_eq!(expected.restore(&expected, &before), before);
        assert_eq!(expected.restore(&expected, &Settings::default()), Settings::default());
    }

    #[test]
    fn journal_preserves_absent_and_explicit_values_after_serialization() {
        let before = Settings { enable: Some(0), server: None, bypass: Some(String::new()), pac: None };
        let journal = Journal { before: before.clone(), expected: Settings::local(49100) };
        let decoded: Journal = serde_json::from_slice(&serde_json::to_vec(&journal).unwrap()).unwrap();
        assert_eq!(decoded.expected.restore(&decoded.expected, &decoded.before), before);
    }

    #[test]
    fn restores_partial_write_without_overwriting_other_values() {
        let before = Settings { enable: Some(0), server: Some("corp.proxy:3128".into()), ..Settings::default() };
        let expected = Settings::local(10800);
        let current = Settings { enable: before.enable, bypass: Some("changed.local".into()), ..expected.clone() };
        let restored = current.restore(&expected, &before);
        assert_eq!(restored.enable, before.enable);
        assert_eq!(restored.server, before.server);
        assert_eq!(restored.bypass, current.bypass);
    }
}
