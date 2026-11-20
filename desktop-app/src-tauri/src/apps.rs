use crate::launch::{powershell, proxied_command, spawn};
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}, process::Command};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DesktopApp { Claude, Chatgpt }

impl DesktopApp {
    fn name(self) -> &'static str {
        match self { Self::Claude => "Claude", Self::Chatgpt => "ChatGPT" }
    }

    fn mac_executable(self, root: &Path) -> Option<PathBuf> {
        let name = self.name();
        let bundle = root.join(format!("{name}.app/Contents"));
        let usual = bundle.join("MacOS").join(name);
        if usual.is_file() { return Some(usual); }
        let metadata = bundle.join("Info.plist");
        if !cfg!(target_os = "macos") || !metadata.is_file() { return None; }
        let output = Command::new("/usr/libexec/PlistBuddy").args(["-c", "Print :CFBundleExecutable"])
            .arg(metadata).output().ok()?;
        let executable = std::str::from_utf8(&output.stdout).ok()?.trim();
        let path = mac_bundle_binary(&bundle, executable)?;
        (output.status.success() && path.is_file()).then_some(path)
    }
}

fn mac_bundle_binary(contents: &Path, executable: &str) -> Option<PathBuf> {
    (!executable.is_empty() && !executable.contains(['/', '\\', '\0']) && executable != "." && executable != "..")
        .then(|| contents.join("MacOS").join(executable))
}

#[derive(Deserialize)]
struct Process {
    id: u32,
    command: Option<String>,
}

#[derive(Deserialize, Default)]
struct Discovery {
    package: Option<String>,
    registered: bool,
    paths: Vec<PathBuf>,
    processes: Vec<Process>,
}

enum Target {
    Executable(PathBuf),
    Appx(String),
}

impl Discovery {
    fn target(&self) -> Option<Target> {
        self.package.as_ref().filter(|id| valid_aumid(id))
            .map(|id| Target::Appx(id.clone()))
            .or_else(|| self.paths.first().map(|p| Target::Executable(p.clone())))
    }

    fn status(&self, port: Option<u16>, system_proxy: bool) -> DesktopStatus {
        let running = !self.processes.is_empty();
        let target = self.target();
        let store = matches!(target, Some(Target::Appx(_)));
        let proxy = port.is_some_and(|port| self.processes.iter().any(|p|
            p.command.as_deref().is_some_and(|cmd| {
                let expected = format!("--proxy-server=socks5://127.0.0.1:{port}");
                cmd.split_whitespace().any(|arg| arg.trim_matches('"') == expected)
            })));
        DesktopStatus {
            installed: running || self.registered || target.is_some(),
            can_launch: target.is_some(),
            variant: self.package.as_deref().filter(|id| id.starts_with("OpenAI.Codex_")).map(|_| "Codex Desktop"),
            running,
            store,
            proxy: if proxy { "arguments" } else if running && store && system_proxy { "system" } else { "unknown" },
        }
    }
}

fn valid_aumid(id: &str) -> bool {
    id.split_once('!').is_some_and(|(family, entry)| {
        !family.is_empty() && !entry.is_empty() && family.contains('_')
            && [family, entry].iter().all(|part| part.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
    })
}

fn discover(app: DesktopApp) -> Result<Discovery, String> {
    if cfg!(windows) {
        let output = powershell(include_str!("discover_windows_apps.ps1"))
            .env("WORKSPACE_DESKTOP_APP", app.name()).output()
            .map_err(|_| "Не удалось запустить поиск приложений Windows")?;
        if !output.status.success() { return Err("Windows не завершила поиск приложений".into()); }
        return serde_json::from_slice(&output.stdout).map_err(|_| "Windows вернула некорректный список приложений".into());
    }
    if cfg!(target_os = "macos") {
        let name = app.name();
        let paths: Vec<_> = std::iter::once(PathBuf::from("/Applications"))
            .chain(std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Applications")))
            .filter_map(|root| app.mac_executable(&root)).collect();
        let output = Command::new("/bin/ps").args(["-axww", "-o", "pid=", "-o", "command="]).output()
            .map_err(|_| "Не удалось проверить процессы macOS")?;
        if !output.status.success() { return Err("macOS не вернула список процессов".into()); }
        let mut markers = vec![format!("/{name}.app/Contents/MacOS/{name}")];
        for path in &paths {
            if let Some(binary) = path.file_name().and_then(|value| value.to_str()) {
                markers.push(format!("/{name}.app/Contents/MacOS/{binary}"));
            }
        }
        let processes = String::from_utf8_lossy(&output.stdout).lines().filter_map(|line| {
            let (pid, command) = line.trim_start().split_once(' ')?;
            let command = command.trim_start();
            let (prefix, tail) = markers.iter().find_map(|marker| command.split_once(marker.as_str()))?;
            if !prefix.starts_with('/') || prefix.contains(" -") || (!tail.is_empty() && !tail.starts_with(' ')) { return None; }
            Some(Process { id: pid.parse().ok()?, command: Some(command.to_owned()) })
        }).collect();
        return Ok(Discovery { paths, processes, ..Discovery::default() });
    }
    Ok(Discovery::default())
}

#[derive(Serialize)]
pub struct DesktopStatus {
    pub installed: bool,
    pub can_launch: bool,
    pub variant: Option<&'static str>,
    pub running: bool,
    pub store: bool,
    pub proxy: &'static str,
}

#[derive(Serialize)]
pub struct InstalledApps {
    pub claude: Option<DesktopStatus>,
    pub chatgpt: Option<DesktopStatus>,
}

pub fn installed_apps(port: Option<u16>, system_proxy: bool) -> InstalledApps {
    let status = |client| discover(client).ok().map(|app| app.status(port, system_proxy));
    InstalledApps { claude: status(DesktopApp::Claude), chatgpt: status(DesktopApp::Chatgpt) }
}

fn desktop_command(executable: &Path, port: u16) -> Command {
    let mut command = proxied_command(executable, port);
    let http = format!("http://127.0.0.1:{port}");
    let socks = format!("socks5h://127.0.0.1:{port}");
    command.env("HTTP_PROXY", &http).env("HTTPS_PROXY", &http).env("ALL_PROXY", &socks)
        .env("http_proxy", &http).env("https_proxy", &http).env("all_proxy", &socks)
        .env_remove("NO_PROXY").env_remove("no_proxy");
    command
}

fn close_for_restart(app: DesktopApp, running: &[Process]) -> Result<(), String> {
    let ids = running.iter().map(|p| p.id.to_string()).collect::<Vec<_>>().join(",");
    if cfg!(windows) {
        powershell(r#"
$ids = $env:WORKSPACE_CLOSE_PIDS -split ',' | ForEach-Object { [int]$_ }
Get-Process -Id $ids -ErrorAction SilentlyContinue |
    Where-Object { $_.SessionId -eq (Get-Process -Id $PID).SessionId -and $_.MainWindowHandle -ne 0 } |
    ForEach-Object { $null = $_.CloseMainWindow() }
"#).env("WORKSPACE_CLOSE_PIDS", &ids)
            .output().map_err(|_| "Не удалось закрыть окно клиента")?;
    } else {
        for process in running {
            Command::new("/bin/kill").args(["-TERM", &process.id.to_string()]).output()
                .map_err(|_| "Не удалось закрыть клиент")?;
        }
    }
    // Wait for the main window and its helpers to leave before starting a new instance.
    if cfg!(windows) {
        let output = powershell(r#"
$session = (Get-Process -Id $PID).SessionId
$ids = $env:WORKSPACE_CLOSE_PIDS -split ',' | ForEach-Object { [int]$_ }
for ($i = 0; $i -lt 20; $i++) {
    if (!(Get-Process -Id $ids -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $session })) { exit 0 }
    Start-Sleep -Milliseconds 250
}
exit 1
"#).env("WORKSPACE_CLOSE_PIDS", &ids).status()
            .map_err(|_| "Не удалось проверить закрытие клиента")?;
        if output.success() { return Ok(()); }
    } else {
        for _ in 0..12 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            if discover(app)?.processes.is_empty() { return Ok(()); }
        }
    }
    Err(format!("Клиент {} остался запущен в фоне. Полностью закройте его и повторите запуск.", app.name()))
}

pub fn launch(app: DesktopApp, port: u16, restart: bool, enable_store_proxy: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    let discovery = discover(app)?;
    let target = discovery.target().ok_or("Не найден доступный способ запуска клиента")?;
    if !discovery.processes.is_empty() {
        if !restart { return Err("Клиент уже запущен. Выберите перезапуск через туннель.".into()); }
        close_for_restart(app, &discovery.processes)?;
    }
    let command = match target {
        Target::Executable(path) => desktop_command(&path, port),
        Target::Appx(id) => {
            enable_store_proxy()?;
            let mut command = Command::new(PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())).join("explorer.exe"));
            command.arg(format!(r"shell:AppsFolder\{id}"));
            command
        }
    };
    spawn(command).map_err(|_| format!("Не удалось запустить {}", app.name()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_package_precedes_classic_executable() {
        let found: Discovery = serde_json::from_str(r#"{
            "package":"OpenAI.ChatGPT-Desktop_abc123!ChatGPT","registered":true,
            "paths":["C:/Programs/ChatGPT.exe"],"processes":[{"id":123,"command":null}]
        }"#).unwrap();
        assert!(matches!(found.target(), Some(Target::Appx(_))));
        assert_eq!(found.status(Some(10081), true).proxy, "system");
        assert_eq!(found.status(Some(10081), false).proxy, "unknown");
        assert!(valid_aumid("OpenAI.Codex_2p2nqsd0c76g0!App"));
        assert!(!valid_aumid("bad\\path!App"));
    }

    #[test]
    fn store_launcher_does_not_require_an_executable_path_or_an_existing_proxy() {
        for package in ["OpenAI.Codex_2p2nqsd0c76g0!App", "OpenAI.ChatGPT-Desktop_abc123!ChatGPT", "Claude_abc123!App"] {
            for running in [false, true] {
                let processes = if running { vec![Process { id: 3, command: None }] } else { vec![] };
                let found = Discovery { package: Some(package.into()), registered: true, processes, ..Discovery::default() };
                let status = found.status(Some(10081), false);
                assert!(status.installed && status.can_launch && status.store);
                assert_eq!(status.running, running);
            }
        }
    }

    #[test]
    fn current_proxy_port_is_required_for_running_process() {
        let found = Discovery { processes: vec![Process { id: 1, command: Some(
            "Claude.exe --proxy-server=socks5://127.0.0.1:10081".into()) }], ..Discovery::default() };
        assert!(found.status(None, false).installed);
        assert_eq!(found.status(Some(10081), false).proxy, "arguments");
        assert_eq!(found.status(Some(10082), false).proxy, "unknown");
    }

    #[test]
    fn classic_windows_discovery_and_arguments() {
        let found: Discovery = serde_json::from_str(r#"{"package":null,"registered":false,
            "paths":["C:/Programs/Claude.exe"],"processes":[]}"#).unwrap();
        let Some(Target::Executable(exe)) = found.target() else { panic!("expected executable") };
        let command = desktop_command(&exe, 10081);
        assert_eq!(command.get_args().next().unwrap(), "--proxy-server=socks5://127.0.0.1:10081");
        assert!(command.get_envs().any(|(name, value)| name == "HTTPS_PROXY" && value == Some(std::ffi::OsStr::new("http://127.0.0.1:10081"))));
    }

    #[test]
    fn resolves_only_bundle_relative_executable_names() {
        let contents = Path::new("/Applications/ChatGPT.app/Contents");
        assert_eq!(mac_bundle_binary(contents, "OpenAI Client"), Some(contents.join("MacOS/OpenAI Client")));
        assert!(mac_bundle_binary(contents, "../../not-the-app").is_none());
        assert!(mac_bundle_binary(contents, "../..").is_none());
    }

    #[test]
    fn discovers_mac_application_bundle() {
        let root = std::env::temp_dir().join(format!("workspace-app-test-{}", std::process::id()));
        let path = root.join("Claude.app/Contents/MacOS/Claude");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "").unwrap();
        assert_eq!(DesktopApp::Claude.mac_executable(&root), Some(path));
        assert_eq!(DesktopApp::Chatgpt.mac_executable(&root), None);
        std::fs::remove_dir_all(root).unwrap();
    }
}
