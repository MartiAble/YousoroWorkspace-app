use crate::launch::powershell;
use std::{fs, io, path::{Path, PathBuf}, sync::Mutex};

const STARTUP_VALUE: &str = "YousoroWorkspace";

fn tray_file(data: &Path) -> PathBuf { data.join("close-to-tray") }

pub fn close_to_tray(data: &Path) -> bool { tray_file(data).is_file() }

pub fn set_close_to_tray(data: &Path, enabled: bool) -> io::Result<()> {
    let file = tray_file(data);
    if enabled {
        fs::create_dir_all(data)?;
        fs::write(file, b"")?;
    } else if let Err(error) = fs::remove_file(file) {
        if error.kind() != io::ErrorKind::NotFound { return Err(error); }
    }
    Ok(())
}

fn launch_agent() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("Не удалось определить домашнюю папку")?;
    Ok(PathBuf::from(home).join("Library/LaunchAgents/ru.yousoro.workspace.plist"))
}

pub fn autostart() -> Result<bool, String> {
    if cfg!(windows) {
        let output = powershell(r#"
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Get-ItemProperty -Path $key -Name $env:WORKSPACE_STARTUP_VALUE -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }
"#).env("WORKSPACE_STARTUP_VALUE", STARTUP_VALUE).output().map_err(|_| "Не удалось проверить автозапуск")?;
        if !output.status.success() { return Err("Windows не вернула статус автозапуска".into()); }
        return Ok(String::from_utf8_lossy(&output.stdout).trim() == "yes");
    }
    if cfg!(target_os = "macos") { return Ok(launch_agent()?.is_file()); }
    Ok(false)
}

pub fn set_autostart(enabled: bool) -> Result<(), String> {
    let binary = std::env::current_exe().map_err(|_| "Не найден файл приложения")?;
    if cfg!(windows) {
        let status = powershell(r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$name = $env:WORKSPACE_STARTUP_VALUE
if ($env:WORKSPACE_STARTUP_ENABLED -eq '1') {
  if (!(Test-Path -LiteralPath $key)) { $null = New-Item -Path $key -Force }
  Set-ItemProperty -LiteralPath $key -Name $name -Value ('"' + $env:WORKSPACE_STARTUP_BINARY + '"')
} elseif (Get-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue) {
  Remove-ItemProperty -LiteralPath $key -Name $name
}
"#).env("WORKSPACE_STARTUP_VALUE", STARTUP_VALUE).env("WORKSPACE_STARTUP_BINARY", binary)
        .env("WORKSPACE_STARTUP_ENABLED", if enabled { "1" } else { "0" })
        .status().map_err(|_| "Не удалось изменить автозапуск")?;
        return if status.success() { Ok(()) } else { Err("Windows не сохранила настройки автозапуска".into()) };
    }
    if cfg!(target_os = "macos") {
        let path = launch_agent()?;
        if enabled {
            let escaped = binary.to_string_lossy().replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
            let contents = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>ru.yousoro.workspace</string>
<key>ProgramArguments</key><array><string>{escaped}</string></array><key>RunAtLoad</key><true/></dict></plist>"#);
            fs::create_dir_all(path.parent().ok_or("Нет папки автозапуска")?).and_then(|_| fs::write(&path, contents))
                .map_err(|_| "macOS не сохранила настройки автозапуска")?;
        } else if let Err(error) = fs::remove_file(path) {
            if error.kind() != io::ErrorKind::NotFound { return Err("Не удалось отключить автозапуск".into()); }
        }
        return Ok(());
    }
    Err("Автозапуск не поддерживается на этой системе".into())
}

#[derive(Default)]
pub struct UpdateNotice(Mutex<Option<String>>);

impl UpdateNotice {
    pub fn show(&self, version: &str, dismiss: bool) -> bool {
        let Ok(mut dismissed) = self.0.lock() else { return false; };
        if version.is_empty() { return false; }
        if dismiss { *dismissed = Some(version.into()); }
        dismissed.as_deref() != Some(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updater_notice_returns_only_for_a_different_version() {
        let notice = UpdateNotice::default();
        assert!(!notice.show("", false));
        assert!(notice.show("1.2.3", false));
        assert!(!notice.show("1.2.3", true));
        assert!(!notice.show("1.2.3", false));
        assert!(notice.show("1.2.4", false));
    }
}
