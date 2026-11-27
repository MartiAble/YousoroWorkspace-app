use crate::service::{self, SubscriptionUrgency};
use std::{
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const RENEW_PATH: &str = "/checkout?plan=monthly_renewal";

pub fn show(data: &Path, urgency: SubscriptionUrgency) -> Result<(), String> {
    let text = match urgency {
        SubscriptionUrgency::Warning3d => "До окончания подписки осталось до трёх дней.",
        SubscriptionUrgency::Warning1d => "До окончания подписки остался один день.",
        SubscriptionUrgency::ExpiresToday => "Подписка на рабочий канал заканчивается сегодня.",
        SubscriptionUrgency::Ok | SubscriptionUrgency::Expired => return Ok(()),
    };
    let day = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "Не удалось определить дату")?.as_secs() / 86400;
    if !claim(data, day)? {
        return Ok(());
    }
    show_native(text, &format!("{}{RENEW_PATH}", service::ORIGIN))
}

fn claim(data: &Path, day: u64) -> Result<bool, String> {
    let path = data.join("subscription-alerts");
    fs::create_dir_all(&path).map_err(|_| "Не удалось сохранить дату уведомления")?;
    match OpenOptions::new().write(true).create_new(true).open(path.join(day.to_string())) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(_) => Err("Не удалось сохранить дату уведомления".into()),
    }
}

#[cfg(windows)]
fn show_native(text: &str, url: &str) -> Result<(), String> {
    use std::{os::windows::process::CommandExt, process::Command};
    let windows = std::env::var_os("SystemRoot").ok_or("Не найден системный каталог Windows")?;
    let powershell = std::path::PathBuf::from(windows)
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let status = Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", include_str!("subscription_toast.ps1")])
        .env("WORKSPACE_NOTICE_TEXT", text)
        .env("WORKSPACE_NOTICE_URL", url)
        .env("WORKSPACE_NOTICE_ACTION", "Продлить в браузере")
        .creation_flags(0x0800_0000)
        .status().map_err(|_| "Не удалось показать уведомление Windows")?;
    if status.success() { Ok(()) } else { Err("Не удалось показать уведомление Windows".into()) }
}

#[cfg(target_os = "macos")]
pub fn install_delegate() {
    extern "C" {
        fn workspace_install_subscription_notice_delegate();
    }
    // Called from Tauri setup on the main thread.
    unsafe { workspace_install_subscription_notice_delegate() };
}

#[cfg(target_os = "macos")]
fn show_native(text: &str, url: &str) -> Result<(), String> {
    use std::ffi::{c_char, CString};
    extern "C" {
        fn workspace_subscription_notice(text: *const c_char, url: *const c_char);
    }
    let text = CString::new(text).map_err(|_| "Некорректный текст уведомления")?;
    let url = CString::new(url).map_err(|_| "Некорректная ссылка продления")?;
    // The native function copies both strings before dispatching to the main queue.
    unsafe { workspace_subscription_notice(text.as_ptr(), url.as_ptr()) };
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn show_native(_text: &str, _url: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn one_alert_per_day_even_after_restart() {
        let path = std::env::temp_dir().join(format!("workspace-alert-test-{}-{}", std::process::id(),
            super::SystemTime::now().duration_since(super::UNIX_EPOCH).unwrap().as_nanos()));
        assert!(super::claim(&path, 18000).unwrap());
        assert!(!super::claim(&path, 18000).unwrap());
        assert!(super::claim(&path, 18001).unwrap());
        std::fs::remove_dir_all(path).unwrap();
    }
}
