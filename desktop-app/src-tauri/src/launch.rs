use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const WEBRTC_POLICY: &str = "disable_non_proxied_udp";

use crate::service::NodeEnvironment;

pub fn profile_path(app_data: &Path, region: &str) -> Result<PathBuf, String> {
    if region.is_empty() || region.len() > 16
        || !region.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-')
    {
        return Err("Некорректный регион".into());
    }

    let profiles = app_data.join("profiles");
    let profile = profiles.join(region.to_ascii_lowercase());
    for path in [&profiles, &profile] {
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err("Каталог профиля недоступен или перенаправлен".into()),
        }
    }
    Ok(profile)
}

fn prepare_preferences(profile: &Path) -> io::Result<()> {
    let directory = profile.join("Default");
    fs::create_dir_all(&directory)?;
    let path = directory.join("Preferences");
    let preferences = serde_json::json!({
        "profile": { "default_content_setting_values": { "geolocation": 2 } },
        "webrtc": { "ip_handling_policy": WEBRTC_POLICY }
    });
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            if let Err(error) = file.write_all(preferences.to_string().as_bytes()) {
                drop(file);
                let _ = fs::remove_file(path);
                return Err(error);
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn repair_preferences(profile: &Path) -> Result<(), String> {
    if browser_process(profile)?.is_some() {
        return Err("Закройте рабочий браузер и повторите исправление".into());
    }
    update_privacy_preferences(profile).map_err(|_| "Не удалось сохранить настройки профиля".into())
}

fn update_privacy_preferences(profile: &Path) -> io::Result<()> {
    let directory = profile.join("Default");
    let path = directory.join("Preferences");
    (|| -> io::Result<()> {
        for item in [&directory, &path] {
            if fs::symlink_metadata(item).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
                return Err(io::Error::other("Redirected preferences"));
            }
        }
        prepare_preferences(profile)?;
        let mut settings: serde_json::Value = serde_json::from_slice(&fs::read(&path)?).map_err(io::Error::other)?;
        let mut changed = false;
        for (keys, value) in [
            (&["profile", "default_content_setting_values", "geolocation"][..], serde_json::json!(2)),
            (&["webrtc", "ip_handling_policy"][..], serde_json::json!(WEBRTC_POLICY)),
        ] {
            let mut entry = &mut settings;
            for key in keys {
                entry = entry.as_object_mut().ok_or_else(|| io::Error::other("Invalid preferences"))?
                    .entry(*key).or_insert_with(|| serde_json::json!({}));
            }
            if *entry != value {
                *entry = value;
                changed = true;
            }
        }
        if !changed { return Ok(()); }
        let temporary = directory.join(format!(".workspace-{}-preferences", std::process::id()));
        let mut output = OpenOptions::new().create_new(true).write(true).open(&temporary)?;
        let written = output.write_all(settings.to_string().as_bytes()).and_then(|_| output.sync_all());
        drop(output);
        if let Err(error) = written.and_then(|_| fs::rename(&temporary, &path)) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        Ok(())
    })()
}

fn find_browser() -> Option<PathBuf> {
    let paths: Vec<PathBuf> = if cfg!(target_os = "macos") {
        [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ].into_iter().map(PathBuf::from).collect()
    } else {
        ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"]
            .into_iter()
            .filter_map(std::env::var_os)
            .flat_map(|root| {
                let root = PathBuf::from(root);
                [
                    r"Google\Chrome\Application\chrome.exe",
                    r"BraveSoftware\Brave-Browser\Application\brave.exe",
                    r"Microsoft\Edge\Application\msedge.exe",
                ].map(|path| root.join(path))
            })
            .collect()
    };
    paths.into_iter().find(|path| path.is_file())
}

pub fn proxied_command(executable: &Path, port: u16) -> Command {
    let mut command = Command::new(executable);
    command.arg(format!("--proxy-server=socks5://127.0.0.1:{port}"));
    command
}

fn browser_command(browser: &Path, profile: &Path, port: u16, environment: Option<&NodeEnvironment>, url: &str, probe_port: Option<u16>) -> Command {
    let mut profile_arg = OsString::from("--user-data-dir=");
    profile_arg.push(profile);

    let mut command = proxied_command(browser, port);
    let bypass = probe_port.map_or_else(|| "<-loopback>".into(), |port| format!("<-loopback>;127.0.0.1:{port}"));
    if let Some(environment) = environment {
        command.env("TZ", &environment.timezone).arg(format!("--lang={}", environment.locale));
    }
    command
        .arg(profile_arg)
        .arg(format!("--webrtc-ip-handling-policy={WEBRTC_POLICY}"))
        .arg(format!("--force-webrtc-ip-handling-policy={WEBRTC_POLICY}"))
        .arg(format!("--proxy-bypass-list={bypass}"))
        .args(["--disable-quic", "--no-first-run", "--no-default-browser-check", "--disable-background-mode", url]);
    command
}

fn profile_in_command(line: &str, path: &Path) -> bool {
    let marker = format!("--user-data-dir={}", path.display());
    let (line, marker) = if cfg!(windows) {
        (line.to_lowercase(), marker.to_lowercase())
    } else {
        (line.to_owned(), marker)
    };
    line.match_indices(&marker).any(|(index, matched)| {
        let prefix = &line[..index];
        let suffix = &line[index + matched.len()..];
        (prefix.is_empty() || prefix.ends_with([' ', '"']))
            && (suffix.is_empty() || suffix.starts_with([' ', '"']))
    })
}

pub fn browser_process(profile: &Path) -> Result<Option<String>, String> {
    let result = if cfg!(target_os = "macos") {
        Command::new("/bin/ps").args(["-axww", "-o", "command="]).output()
    } else {
        powershell(r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Get-CimInstance Win32_Process -Filter "Name = 'chrome.exe' OR Name = 'brave.exe' OR Name = 'msedge.exe'" |
    ForEach-Object { $_.CommandLine }
"#).output()
    };
    let error = "Не удалось проверить, закрыт ли рабочий браузер";
    let output = result.map_err(|_| error)?;
    if !output.status.success() {
        return Err(error.into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).lines().find(|line| profile_in_command(line, profile) && !line.contains("--type=")).map(str::to_owned))
}

pub fn launch_browser(profile: &Path, port: u16, region: &str, environment: Option<&NodeEnvironment>, url: &str, probe: &crate::radar::BrowserProbe) -> Result<(), String> {
    let browser = find_browser().ok_or("Установите Chrome, Brave или Microsoft Edge")?;
    if browser_process(profile)?.is_some() {
        return Err("Закройте рабочий браузер этого региона перед повторным запуском".into());
    }
    update_privacy_preferences(profile).map_err(|_| "Не удалось подготовить настройки рабочего профиля")?;
    let endpoint = probe.start(port, region, url, environment.map(|node| node.timezone.as_str())).ok();
    let (startup_url, probe_port) = endpoint.as_ref().map_or((url, None), |probe| (probe.url.as_str(), Some(probe.port)));
    let command = browser_command(&browser, profile, port, environment, startup_url, probe_port);
    spawn(command)
        .map_err(|_| "Не удалось запустить браузер".into())
}

pub fn clear_browser_profile(profile: &Path) -> Result<(), String> {
    if !profile.exists() {
        return Ok(());
    }
    if browser_process(profile)?.is_some() {
        return Err("Закройте рабочий браузер этого региона перед очисткой профиля".into());
    }
    fs::remove_dir_all(profile).map_err(|_| "Не удалось очистить рабочий профиль".into())
}

pub fn powershell(script: &str) -> Command {
    let mut command = Command::new(PathBuf::from(
        std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())
    ).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"));
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command
}

pub fn spawn(mut command: Command) -> io::Result<()> {
    let mut child = command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    std::thread::spawn(move || { let _ = child.wait(); });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn older_servers_keep_browser_defaults() {
        let command = browser_command(Path::new("browser"), Path::new("profile"), 10081, None, "https://example.invalid", None);
        assert!(!command.get_args().any(|arg| arg.to_string_lossy().starts_with("--lang=")));
        assert!(!command.get_envs().any(|(key, _)| key == "TZ"));
    }

    #[test]
    fn creates_preferences_once_and_preserves_existing_settings() {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("workspace-{}-{nonce}", std::process::id()));
        let profile = profile_path(&root, "DE").unwrap();
        let path = profile.join("Default/Preferences");
        assert_eq!(profile, root.join("profiles/de"));
        assert!(profile_path(&root, "../de").is_err());
        assert!(profile_path(&root, "").is_err());
        prepare_preferences(&profile).unwrap();
        let settings: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(settings["profile"]["default_content_setting_values"]["geolocation"], 2);
        assert_eq!(settings["webrtc"]["ip_handling_policy"], WEBRTC_POLICY);
        fs::write(&path, br#"{"existing":true}"#).unwrap();
        prepare_preferences(&profile).unwrap();
        assert_eq!(fs::read(&path).unwrap(), br#"{"existing":true}"#);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repairs_privacy_preferences_without_resetting_other_fields() {
        let profile = std::env::temp_dir().join(format!("workspace-privacy-test-{}", std::process::id()));
        let default = profile.join("Default");
        let path = default.join("Preferences");
        fs::create_dir_all(&default).unwrap();
        fs::write(&path, r#"{"profile":{"default_content_setting_values":{"geolocation":1,"camera":2}},"webrtc":{"ip_handling_policy":"default"},"homepage":"about:blank"}"#).unwrap();
        fs::write(default.join("Cookies"), b"existing session").unwrap();
        update_privacy_preferences(&profile).unwrap();
        assert_eq!(fs::read(default.join("Cookies")).unwrap(), b"existing session");
        let bytes = fs::read(&path).unwrap();
        update_privacy_preferences(&profile).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let updated: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(updated["profile"]["default_content_setting_values"]["geolocation"], 2);
        assert_eq!(updated["profile"]["default_content_setting_values"]["camera"], 2);
        assert_eq!(updated["webrtc"]["ip_handling_policy"], WEBRTC_POLICY);
        assert_eq!(updated["homepage"], "about:blank");
        fs::remove_dir_all(profile).unwrap();
    }

    #[test]
    fn browser_passes_regional_privacy_and_proxy_settings() {
        let environment = NodeEnvironment { timezone: "Asia/Almaty".into(), windows_timezone: "West Asia Standard Time".into(), locale: "ru-RU".into() };
        let command = browser_command(Path::new("browser"), Path::new("Profile with spaces"), 10081, Some(&environment), "https://example.invalid", None);
        let args: Vec<_> = command.get_args().collect();
        for expected in [
            "--user-data-dir=Profile with spaces",
            "--proxy-server=socks5://127.0.0.1:10081",
            "--lang=ru-RU",
            "--webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ] {
            assert!(args.iter().any(|arg| *arg == expected));
        }
        assert!(command.get_envs().any(|(key, value)| key == "TZ" && value.unwrap() == "Asia/Almaty"));
    }

    #[test]
    fn profile_check_distinguishes_regional_paths() {
        let path = Path::new("Profile with spaces/de");
        assert!(profile_in_command(r#"chrome "--user-data-dir=Profile with spaces/de" --lang=de-DE"#, path));
        assert!(profile_in_command("chrome --user-data-dir=Profile with spaces/de --lang=de-DE", path));
        assert!(!profile_in_command("chrome --user-data-dir=Profile with spaces/de-alt", path));
    }

}
