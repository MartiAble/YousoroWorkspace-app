use crate::launch::spawn;
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}, process::Command};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DesktopApp { Claude, Chatgpt }

impl DesktopApp {
    fn name(self) -> &'static str {
        match self { Self::Claude => "Claude", Self::Chatgpt => "ChatGPT" }
    }

    #[cfg(any(not(windows), test))]
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

#[cfg(any(not(windows), test))]
fn mac_bundle_binary(contents: &Path, executable: &str) -> Option<PathBuf> {
    (!executable.is_empty() && !executable.contains(['/', '\\', '\0']) && executable != "." && executable != "..")
        .then(|| contents.join("MacOS").join(executable))
}

#[derive(Clone)]
struct Process {
    id: u32,
    command: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct Discovery {
    package: Option<String>,
    package_executable: Option<PathBuf>,
    registered: bool,
    paths: Vec<PathBuf>,
    #[serde(skip)]
    processes: Vec<Process>,
    #[serde(default)]
    package_root: Option<PathBuf>,
}

enum Target {
    Executable(PathBuf),
    Appx(String),
}

impl Discovery {
    fn target(&self, pac: bool) -> Option<Target> {
        let store = self.package.as_ref().filter(|id| valid_aumid(id));
        if pac {
            if let Some(id) = store { return Some(Target::Appx(id.clone())); }
        }
        self.package_executable.as_ref().or_else(|| self.paths.first()).map(|path| Target::Executable(path.clone()))
            .or_else(|| store.map(|id| Target::Appx(id.clone())))
    }

    fn status(&self, port: Option<u16>, system_proxy: bool) -> DesktopStatus {
        let running = !self.processes.is_empty();
        let target = self.target(system_proxy);
        let store = self.package.as_deref().is_some_and(valid_aumid);
        let proxy = port.is_some_and(|port| self.processes.iter().any(|p|
            p.command.as_deref().is_some_and(|cmd| {
                let expected = format!("--proxy-server=http://127.0.0.1:{port}");
                cmd.split_whitespace().any(|arg| arg.trim_matches('"') == expected)
            })));
        DesktopStatus {
            installed: running || self.registered || target.is_some(),
            can_launch: target.is_some(),
            variant: self.package.as_deref().filter(|id| id.starts_with("OpenAI.Codex_")).map(|_| "Codex Desktop"),
            running,
            store,
            proxy: if proxy { "arguments" } else if running && store && system_proxy { "pac" } else { "unknown" },
        }
    }
}

fn valid_aumid(id: &str) -> bool {
    id.split_once('!').is_some_and(|(family, entry)| {
        !family.is_empty() && !entry.is_empty() && family.contains('_')
            && [family, entry].iter().all(|part| part.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
    })
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct Installations([Discovery; 2]);

fn discover_installed_clients() -> Installations {
    #[cfg(windows)]
    {
        let [claude, openai] = crate::native_windows::discover_packages();
        Installations([claude, openai].map(|package| {
            let mut found = Discovery::default();
            if let Some(package) = package {
                found.package = Some(package.aumid);
                found.package_executable = package.executable;
                found.package_root = Some(package.root);
                found.registered = true;
            }
            found
        })).with_classic()
    }
    #[cfg(not(windows))]
    {
        Installations([DesktopApp::Claude, DesktopApp::Chatgpt].map(|client| Discovery {
            paths: std::iter::once(PathBuf::from("/Applications"))
                .chain(std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Applications")))
                .filter_map(|root| client.mac_executable(&root)).collect(),
            ..Discovery::default()
        }))
    }
}

impl Installations {
    #[cfg(windows)]
    fn with_classic(mut self) -> Self {
        for (index, app) in self.0.iter_mut().enumerate() {
            app.paths.extend(crate::native_windows::discover_classic(index == 0));
        }
        self
    }

    fn validate(mut self) -> Self {
        for found in &mut self.0 {
            found.paths.retain(|path| path.is_file());
            if found.package_executable.as_ref().is_some_and(|path| !path.is_file()) {
                found.package_executable = None;
            }
            if found.package_root.as_ref().is_some_and(|root| !root.is_dir()) {
                found.package = None;
                found.package_root = None;
                found.package_executable = None;
                found.registered = false;
            }
        }
        self
    }

    fn read(data: &Path) -> Option<Self> {
        serde_json::from_slice::<Self>(&std::fs::read(data.join("desktop-installations.json")).ok()?)
            .ok().map(Self::validate)
    }

    fn save(&self, data: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(data)?;
        let temporary = data.join("desktop-installations.tmp");
        std::fs::write(&temporary, serde_json::to_vec(self)?)?;
        std::fs::rename(temporary, data.join("desktop-installations.json"))
    }

    fn check_running_clients(mut self) -> Result<Self, String> {
        #[cfg(windows)]
        {
            let processes = crate::native_windows::processes(&["claude.exe", "chatgpt.exe", "codex.exe"])
                .map_err(|_| "Не удалось проверить процессы Windows")?;
            for process in processes {
                let index = usize::from(!process.name.eq_ignore_ascii_case("claude.exe"));
                let found = &mut self.0[index];
                let image = process.image.as_deref();
                let from_package = image.zip(found.package_root.as_deref()).is_some_and(|(image, root)| {
                    let image = image.to_string_lossy().to_ascii_lowercase();
                    let root = root.to_string_lossy().to_ascii_lowercase();
                    image.strip_prefix(&root).is_some_and(|tail| tail.starts_with(['\\', '/']))
                });
                let codex = process.name.eq_ignore_ascii_case("codex.exe");
                if codex && !from_package { continue; }
                if process.command.as_deref().is_some_and(|command| command.contains(" --type=")) { continue; }
                if !codex && !from_package && found.paths.is_empty() {
                    found.paths.extend(image.filter(|path| path.is_file()).map(Path::to_path_buf));
                }
                found.processes.push(Process { id: process.id, command: process.command });
            }
        }
        #[cfg(not(windows))]
        if cfg!(target_os = "macos") {
            let output = Command::new("/bin/ps").args(["-axww", "-o", "pid=", "-o", "command="]).output()
                .map_err(|_| "Не удалось проверить процессы macOS")?;
            if !output.status.success() { return Err("macOS не вернула список процессов".into()); }
            let list = String::from_utf8_lossy(&output.stdout);
            for (client, found) in [DesktopApp::Claude, DesktopApp::Chatgpt].into_iter().zip(self.0.iter_mut()) {
                let name = client.name();
                let entries = std::iter::once(name).chain(found.paths.iter().filter_map(|p| p.file_name()?.to_str()));
                let markers: Vec<_> = entries.map(|binary| format!("/{name}.app/Contents/MacOS/{binary}")).collect();
                found.processes = list.lines().filter_map(|line| {
                    let (pid, command) = line.trim_start().split_once(' ')?;
                    let command = command.trim_start();
                    let (prefix, tail) = markers.iter().find_map(|marker| command.split_once(marker))?;
                    if !prefix.starts_with('/') || prefix.contains(" -") || (!tail.is_empty() && !tail.starts_with(' ')) { return None; }
                    Some(Process { id: pid.parse().ok()?, command: Some(command.to_owned()) })
                }).collect();
            }
        }
        Ok(self)
    }
}

#[derive(Default)]
pub struct AppCache {
    installs: std::sync::Mutex<Option<Installations>>,
    running: std::sync::Mutex<Option<Installations>>,
    refresh: crate::SingleFlight,
    poll: crate::SingleFlight,
}

impl AppCache {
    fn cached(&self, data: &Path) -> Result<Installations, String> {
        if let Some(found) = self.installs.lock().map_err(|_| "Ошибка кэша клиентов")?.clone() {
            return Ok(found);
        }
        if let Some(found) = Installations::read(data) {
            let mut cache = self.installs.lock().map_err(|_| "Ошибка кэша клиентов")?;
            return Ok(cache.get_or_insert(found).clone());
        }
        self.refresh(data)
    }

    fn refresh(&self, data: &Path) -> Result<Installations, String> {
        let Some(_job) = self.refresh.try_enter() else {
            return self.installs.lock().ok().and_then(|result| result.clone())
                .ok_or("Обнаружение клиентов ещё выполняется".into());
        };
        let found = discover_installed_clients();
        *self.installs.lock().map_err(|_| "Ошибка кэша клиентов")? = Some(found.clone());
        let _ = found.save(data);
        Ok(found)
    }

    pub fn rediscover(&self, data: &Path) -> Result<(), String> {
        self.refresh(data).map(|_| ())
    }

    pub fn check_running_clients(&self, data: &Path, port: Option<u16>, pac: bool) -> Result<InstalledApps, String> {
        let installed = self.cached(data)?;
        let found = if let Some(_job) = self.poll.try_enter() {
            let found = installed.check_running_clients()?;
            *self.running.lock().map_err(|_| "Ошибка кэша процессов")? = Some(found.clone());
            found
        } else {
            self.running.lock().map_err(|_| "Ошибка кэша процессов")?.clone().unwrap_or(installed)
        };
        let [claude, chatgpt] = found.0;
        Ok(InstalledApps { claude: Some(claude.status(port, pac)), chatgpt: Some(chatgpt.status(port, pac)) })
    }
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

#[derive(Default, Serialize)]
pub struct InstalledApps {
    pub claude: Option<DesktopStatus>,
    pub chatgpt: Option<DesktopStatus>,
}

fn desktop_command(executable: &Path, port: u16) -> Command {
    let mut command = Command::new(executable);
    let http = format!("http://127.0.0.1:{port}");
    let socks = format!("socks5h://127.0.0.1:{port}");
    command.arg(format!("--proxy-server={http}")).arg("--proxy-bypass-list=<-loopback>")
        .env("HTTP_PROXY", &http).env("HTTPS_PROXY", &http).env("ALL_PROXY", &socks)
        .env("http_proxy", &http).env("https_proxy", &http).env("all_proxy", &socks)
        .env_remove("NO_PROXY").env_remove("no_proxy");
    command
}

fn close_for_restart(app: DesktopApp, installed: &Installations, running: &[Process]) -> Result<(), String> {
    #[cfg(windows)]
    crate::native_windows::close_windows(&running.iter().map(|process| process.id).collect::<Vec<_>>());
    #[cfg(not(windows))]
    for process in running {
        Command::new("/bin/kill").args(["-TERM", &process.id.to_string()]).output()
            .map_err(|_| "Не удалось закрыть клиент")?;
    }
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(250));
        if installed.clone().check_running_clients()?.0[app as usize].processes.is_empty() { return Ok(()); }
    }
    Err(format!("Клиент {} остался запущен в фоне. Полностью закройте его и повторите запуск.", app.name()))
}

pub fn launch(cache: &AppCache, data: &Path, app: DesktopApp, port: u16, restart: bool, pac_active: bool) -> Result<(), String> {
    let mut installations = cache.cached(data)?;
    for retry in [false, true] {
        let active = installations.clone().check_running_clients()?;
        let found = &active.0[app as usize];
        let target = found.target(pac_active);
        let missing = match target.as_ref() {
            Some(Target::Executable(path)) => !path.is_file(),
            Some(Target::Appx(_)) => found.package_root.as_ref().is_some_and(|root| !root.is_dir()),
            None => true,
        };
        if missing {
            if retry { return Err("Не найден доступный способ запуска клиента".into()); }
            installations = cache.refresh(data)?;
            continue;
        }
        let target = target.ok_or("Не найден доступный способ запуска клиента")?;
        if matches!(target, Target::Appx(_)) && !pac_active {
            return Err("Для этого клиента включите точечный маршрут Store в настройках Workspace.".into());
        }
        if !found.processes.is_empty() {
            if !restart { return Err("Клиент уже запущен. Выберите перезапуск через туннель.".into()); }
            close_for_restart(app, &installations, &found.processes)?;
        }
        let command = match target {
            Target::Executable(path) => desktop_command(&path, port),
            Target::Appx(id) => {
                let mut command = Command::new(PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())).join("explorer.exe"));
                command.arg(format!(r"shell:AppsFolder\{id}"));
                command
            }
        };
        match spawn(command) {
            Ok(()) => return Ok(()),
            Err(error) if !retry && error.kind() == std::io::ErrorKind::NotFound => installations = cache.refresh(data)?,
            Err(_) => return Err(format!("Не удалось запустить {}", app.name())),
        }
    }
    Err(format!("Не удалось запустить {}", app.name()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_and_validates_cached_installations_without_serializing_processes() {
        let data = std::env::temp_dir().join(format!("workspace-installations-{}", std::process::id()));
        std::fs::create_dir_all(&data).unwrap();
        let executable = data.join("Claude.exe");
        std::fs::write(&executable, "").unwrap();
        let package = data.join("Codex");
        std::fs::create_dir_all(&package).unwrap();
        let cached = Installations([
            Discovery { paths: vec![executable.clone()], processes: vec![Process { id: 42, command: Some("unpersisted".into()) }], ..Discovery::default() },
            Discovery { package_root: Some(package.clone()), package: Some("OpenAI.Codex_publisher!App".into()), registered: true, ..Discovery::default() },
        ]);
        cached.save(&data).unwrap();
        let cache = AppCache::default();
        let first = cache.cached(&data).unwrap();
        assert_eq!(first.0[0].paths, vec![executable.clone()]);
        assert!(first.0[0].processes.is_empty());
        assert!(first.0[1].registered);
        std::fs::remove_file(&executable).unwrap();
        std::fs::remove_dir(&package).unwrap();
        assert_eq!(cache.cached(&data).unwrap().0[0].paths, vec![executable]);
        let from_disk = AppCache::default().cached(&data).unwrap();
        assert!(from_disk.0[0].paths.is_empty());
        assert!(!from_disk.0[1].registered);
        cached.save(&data).unwrap();
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn process_launch_precedes_store_unless_pac_was_selected() {
        let mut found: Discovery = serde_json::from_str(r#"{
            "package":"OpenAI.ChatGPT-Desktop_abc123!ChatGPT","registered":true,
            "paths":["C:/Programs/ChatGPT.exe"],"processes":[{"id":123,"command":null}]
        }"#).unwrap();
        found.processes.push(Process { id: 123, command: None });
        assert!(matches!(found.target(false), Some(Target::Executable(_))));
        assert!(matches!(found.target(true), Some(Target::Appx(_))));
        assert_eq!(found.status(Some(10081), true).proxy, "pac");
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
            "Claude.exe --proxy-server=http://127.0.0.1:10081".into()) }], ..Discovery::default() };
        assert!(found.status(None, false).installed);
        assert_eq!(found.status(Some(10081), false).proxy, "arguments");
        assert_eq!(found.status(Some(10082), false).proxy, "unknown");
    }

    #[test]
    fn classic_windows_discovery_and_arguments() {
        let found: Discovery = serde_json::from_str(r#"{"package":null,"registered":false,
            "paths":["C:/Programs/Claude.exe"],"processes":[]}"#).unwrap();
        let Some(Target::Executable(exe)) = found.target(false) else { panic!("expected executable") };
        let command = desktop_command(&exe, 10081);
        assert_eq!(command.get_args().next().unwrap(), "--proxy-server=http://127.0.0.1:10081");
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
