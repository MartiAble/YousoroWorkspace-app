use std::{fs, io, path::{Path, PathBuf}};

#[cfg(windows)]
const STARTUP_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const STARTUP_VALUE: &str = "YousoroWorkspace";

pub fn english_browser(data: &Path) -> bool { !data.join("regional-browser-language").is_file() }

pub fn set_english_browser(data: &Path, enabled: bool) -> io::Result<()> {
    let path = data.join("regional-browser-language");
    if enabled {
        match fs::remove_file(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    } else {
        fs::create_dir_all(data)?;
        fs::write(path, [])
    }
}

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

#[cfg(not(windows))]
fn launch_agent() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("Не удалось определить домашнюю папку")?;
    Ok(PathBuf::from(home).join("Library/LaunchAgents/ru.yousoro.workspace.plist"))
}

pub fn autostart() -> Result<bool, String> {
    #[cfg(windows)]
    return match crate::native_windows::Key::user(STARTUP_KEY, false) {
        Ok(key) => key.string(STARTUP_VALUE).map(|value| value.is_some()).map_err(|_| "Не удалось проверить автозапуск".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("Не удалось проверить автозапуск".into()),
    };
    #[cfg(not(windows))]
    {
    if cfg!(target_os = "macos") { return Ok(launch_agent()?.is_file()); }
    Ok(false)
    }
}

pub fn set_autostart(enabled: bool) -> Result<(), String> {
    let binary = std::env::current_exe().map_err(|_| "Не найден файл приложения")?;
    #[cfg(windows)]
    {
        let key = if enabled { crate::native_windows::Key::user_create(STARTUP_KEY) }
            else { crate::native_windows::Key::user(STARTUP_KEY, true) };
        return match key {
            Ok(key) => {
                let command = enabled.then(|| format!("\"{}\"", binary.display()));
                key.set_string(STARTUP_VALUE, command.as_deref()).map_err(|_| "Windows не сохранила настройки автозапуска".into())
            }
            Err(error) if !enabled && error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("Не удалось изменить автозапуск".into()),
        };
    }
    #[cfg(not(windows))]
    {
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
}
