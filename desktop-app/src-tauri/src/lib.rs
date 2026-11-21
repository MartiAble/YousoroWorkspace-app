mod apps;
mod dns_radar;
mod launch;
#[cfg(windows)]
mod native_windows;
mod preferences;
mod radar;
mod system_proxy;
mod service;
mod tunnel;
use serde::Serialize;
use serde_json::{json, Value};
use std::{process::Command, sync::{Mutex, atomic::{AtomicBool, Ordering}}};
use tauri::{AppHandle, Emitter, Manager};
use tunnel::Tunnel;

#[derive(Default)]
struct Runtime {
    connection: Mutex<Option<Connection>>,
    profile: SingleFlight,
    browser_probe: radar::BrowserProbe,
    radar_requested: AtomicBool,
    clients: apps::AppCache,
    route: SingleFlight,
    observing: SingleFlight,
    observation: Mutex<Option<RouteObservation>>,
}

type RouteObservation = (u16, std::time::Instant, std::time::Instant, Result<radar::Observation, String>);

#[derive(Default)]
struct SingleFlight(AtomicBool);

struct Flight<'a>(&'a AtomicBool);

impl SingleFlight {
    fn try_enter(&self) -> Option<Flight<'_>> {
        self.0.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).ok()?;
        Some(Flight(&self.0))
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

struct Connection {
    proxy: Option<system_proxy::Lease>,
    tunnel: Tunnel,
    device_id: Option<String>,
    started: std::time::Instant,
    environment: Option<service::NodeEnvironment>,
}

impl Connection {
    fn restore_proxy(&mut self) -> Result<(), String> {
        if let Some(proxy) = self.proxy.as_mut() { proxy.restore()?; }
        self.proxy = None;
        Ok(())
    }
}

#[derive(Serialize)]
struct Status {
    port: Option<u16>,
    region: Option<String>,
    system_proxy: bool,
    system_proxy_supported: bool,
    proxy_error: Option<String>,
    uptime_seconds: Option<u64>,
    device_id: Option<String>,
}
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T,String> + Send + 'static) -> Result<T,String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|_| "Фоновая операция остановлена".to_owned())?
}

fn status(app: &AppHandle) -> Status {
    let state = app.state::<Runtime>();
    let mut result = Status {
        port: None, region: None, system_proxy: false, system_proxy_supported: cfg!(windows), proxy_error: None, uptime_seconds: None, device_id: None,
    };
    let mut stopped = false;
    if let Ok(mut guard) = state.connection.lock() {
        if let Some(connection) = guard.as_mut() {
            if connection.tunnel.running() {
                result.port = Some(connection.tunnel.port);
                result.region = Some(connection.tunnel.region.clone());
                result.system_proxy = connection.proxy.is_some();
                result.uptime_seconds = Some(connection.started.elapsed().as_secs());
                result.device_id = connection.device_id.clone();
            } else {
                stopped = true;
                result.system_proxy = connection.proxy.is_some();
            }
        }
    }
    if stopped {
        if let Some(_route) = state.route.try_enter() {
            match remove_connection(&state, true) {
                Ok(()) => result.system_proxy = false,
                Err(error) => result.proxy_error = Some(error),
            }
        }
    }
    if let Some(tray) = app.tray_by_id("workspace") {
        let title = result.region.as_ref().map(|r| format!("Подключено • {}", r.to_uppercase())).unwrap_or_else(|| "Отключено".into());
        let _ = tray.set_tooltip(Some(title));
    }
    result
}
#[tauri::command]
async fn tunnel_status(app: AppHandle) -> Result<Status, String> { blocking(move || Ok(status(&app))).await }
#[tauri::command]
async fn sign_in(email: String, password: String) -> Result<service::Account,String> { blocking(move || { service::login(email,password) }).await }
#[tauri::command]
async fn account() -> Result<service::Account,String> { blocking(move || { service::account(&service::Session::restore()?) }).await }
#[tauri::command]
async fn regions() -> Result<Value,String> { blocking(move || {
    service::checked(service::client()?.get(format!("{}/api/regions",service::ORIGIN)).send())?.json()
        .map_err(|_| "Не удалось прочитать регионы".into())
}).await }
// Callers serialize route mutations with a flight token. No runtime lock covers
// registry restoration, filesystem operations or sidecar shutdown.
fn remove_connection(state: &Runtime, stopped_only: bool) -> Result<(), String> {
    let connection = {
        let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния")?;
        if stopped_only && guard.as_mut().is_some_and(|connection| connection.tunnel.running()) { return Ok(()); }
        guard.take()
    };
    if let Some(mut connection) = connection {
        if let Err(error) = connection.restore_proxy() {
            *state.connection.lock().map_err(|_| "Ошибка состояния")? = Some(connection);
            return Err(error);
        }
    }
    Ok(())
}

#[tauri::command]
async fn disconnect(app: AppHandle) -> Result<Status, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
        remove_connection(&state, false)?;
        Ok(status(&app))
    }).await
}
#[tauri::command]
async fn sign_out(app: AppHandle) -> Result<(),String> { blocking(move || {
    let state = app.state::<Runtime>();
    let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
    remove_connection(&state, false)?;
    if let Ok(s) = service::Session::restore() {
        let _ = s.authorize(service::client()?.post(format!("{}/api/auth/logout",service::ORIGIN))).send();
    }
    match service::key("session")?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err("Системное хранилище не удалило сессию".into()),
    }
}).await }
#[tauri::command]
async fn select_region(app: AppHandle, region: String) -> Result<service::Account,String> { blocking(move || {
    if region.is_empty() || region.len()>16 || !region.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') { return Err("Некорректный регион".into()); }
    let state = app.state::<Runtime>();
    let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
    let s = service::Session::restore()?;
    let request = s.authorize(service::client()?.post(format!("{}/api/route",service::ORIGIN))).json(&json!({ "region":region }));
    let account = service::checked(request.send())?.json().map_err(|_| "Сервис не подтвердил выбор региона")?;
    remove_connection(&state, false)?;
    Ok(account)
}).await }
#[tauri::command]
async fn connect_tunnel(app: AppHandle) -> Result<Status,String> { blocking(move || {
    let state = app.state::<Runtime>();
    let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
    if status(&app).port.is_none() {
        remove_connection(&state, false)?;
        if let Ok(data) = app.path().app_data_dir() { system_proxy::Lease::recover(&data)?; }
        let s = service::Session::restore()?;
        let account = service::account(&s)?;
        if account.access != "active" || account.profile.state != "applied" { return Err("Подписка или сетевой профиль ещё не активны".into()); }
        let region = account.profile.applied.clone().ok_or("Выберите регион")?;
        let path = app.path().resource_dir().map_err(|_| "Нет каталога ресурсов")?.join("resources");
        let executable = std::env::current_exe().map_err(|_| "Не удалось определить путь приложения")?;
        let executable_dir = executable.parent().ok_or("Нет каталога приложения")?;
        let enrollment = service::bootstrap(&s, &account)?;
        let tunnel = tunnel::start(executable_dir, &path, enrollment.config, region)?;
        *state.connection.lock().map_err(|_| "Ошибка состояния")? = Some(Connection { tunnel, proxy: None, device_id: enrollment.device_id, started: std::time::Instant::now(), environment: account.profile.node_environment });
    }
    Ok(status(&app))
}).await }
#[tauri::command]
async fn observe_tunnel(app: AppHandle) -> Result<radar::Observation, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let (port, started) = state.connection.lock().map_err(|_| "Ошибка состояния маршрута")?.as_ref()
            .map(|route| (route.tunnel.port, route.started)).ok_or("Сначала подключите туннель")?;
        let flight = state.observing.try_enter();
        if let Some((_, _, _, result)) = state.observation.lock().map_err(|_| "Ошибка кэша маршрута")?.as_ref()
            .filter(|(cached_port, cached_start, time, _)| *cached_port == port && *cached_start == started
                && (flight.is_none() || time.elapsed() < std::time::Duration::from_secs(3))) {
            return result.clone();
        }
        let _job = flight.ok_or("Проверка маршрута ещё выполняется")?;
        let result = radar::observe_tunnel(port);
        *state.observation.lock().map_err(|_| "Ошибка кэша маршрута")? = Some((port, started, std::time::Instant::now(), result.clone()));
        result
    }).await
}

#[tauri::command]
async fn run_system_radar(app: AppHandle, lookup_geo: bool, check_dns: Option<bool>) -> Result<radar::Report, String> {
    blocking(move || {
        let route = status(&app);
        let port = route.port.ok_or("Сначала подключите туннель")?;
        let region = route.region.ok_or("Регион не определён")?;
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
        let state = app.state::<Runtime>();
        let (device_id, environment, pac_url) = state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?.as_ref()
            .filter(|active| active.tunnel.port == port)
            .map(|active| (active.device_id.clone(), active.environment.clone(), active.proxy.as_ref().and_then(system_proxy::Lease::url).map(str::to_owned)))
            .ok_or("Туннель изменился во время диагностики")?;
        let pac_active = system_proxy::active(pac_url.as_deref());
        let apps = state.clients.check_running_clients(&data, Some(port), pac_active).unwrap_or_default();
        let report = radar::report(port, &region, &data, &state.browser_probe, lookup_geo, check_dns.unwrap_or(false), device_id.as_deref(), environment.as_ref(), pac_active, apps,
            |stage| { let _ = app.emit("radar-progress", stage); });
        if status(&app).port != Some(port) { return Err("Туннель изменился во время диагностики".into()); }
        Ok(report)
    }).await
}

fn pull_browser_report(
    client: &reqwest::blocking::Client,
    session: &service::Session,
    endpoint: &str,
    token: &str,
    after: u64,
) -> Result<Value, String> {
    service::checked(session.authorize(client.post(endpoint))
        .timeout(std::time::Duration::from_secs(5))
        .json(&json!({ "token": token, "after": after })).send())?
        .json().map_err(|_| "Не удалось прочитать отчёт браузера".into())
}

#[tauri::command]
async fn run_browser_probe(app: AppHandle, stun: bool, exit_ip: Option<String>, exit_country: Option<String>) -> Result<Value, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let (port, region, environment) = {
            let guard = state.connection.lock().map_err(|_| "Ошибка состояния маршрута")?;
            let connection = guard.as_ref().ok_or("Сначала подключите маршрут")?;
            (connection.tunnel.port, connection.tunnel.region.clone(), connection.environment.clone())
        };
        let session = service::Session::restore()?;
        let client = service::client()?;
        #[derive(serde::Deserialize)]
        struct Started { token: String, diagnostics_origin: String, region: Option<String> }
        let started: Started = service::checked(session.authorize(client.post(
            format!("{}/api/radar-probe/start", service::ORIGIN)
        )).send())?.json().map_err(|_| "Сервер не выдал код проверки")?;
        if started.token.len() != 48 || !started.token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Сервер выдал некорректный код проверки".into());
        }
        let mut url = reqwest::Url::parse(&format!("{}/radar-probe", service::ORIGIN))
            .map_err(|_| "Некорректный адрес проверки")?;
        let mut fragment = reqwest::Url::parse("https://example.invalid/").map_err(|_| "Некорректный адрес")?;
        {
            let mut args = fragment.query_pairs_mut();
            args.append_pair("token", &started.token).append_pair("check", &started.diagnostics_origin);
            if let Some(environment) = &environment {
                args.append_pair("timezone", &environment.timezone).append_pair("locale", &environment.locale);
            }
            if let Some(region) = &started.region { args.append_pair("region", region); }
            if let Some(ip) = &exit_ip { args.append_pair("exit_ip", ip); }
            if let Some(country) = &exit_country { args.append_pair("exit_country", country); }
            if stun { args.append_pair("stun", "1"); }
        }
        url.set_fragment(fragment.query());
        {
            let _profile = state.profile.try_enter().ok_or("Дождитесь завершения операции с профилем")?;
            if status(&app).port != Some(port) { return Err("Маршрут изменился во время проверки".into()); }
            let data = app.path().app_data_dir().map_err(|_| "Не удалось открыть каталог приложения")?;
            let profile = launch::profile_path(&data, &region)?;
            launch::open_probe(&profile, port, environment.as_ref(), url.as_str())?;
        }
        let wait_until = std::time::Instant::now() + std::time::Duration::from_secs(40);
        let endpoint = format!("{}/api/radar-probe/result", service::ORIGIN);
        while std::time::Instant::now() < wait_until {
            if status(&app).port != Some(port) { return Err("Маршрут изменился во время проверки".into()); }
            let body = pull_browser_report(&client, &session, &endpoint, &started.token, 0)?;
            if !body["report"].is_null() {
                let result = body["report"].clone();
                if let Some(mut revision) = body["revision"].as_u64() {
                    let watched_app = app.clone();
                    std::thread::spawn(move || {
                        let until = std::time::Instant::now() + std::time::Duration::from_secs(295);
                        while std::time::Instant::now() < until && status(&watched_app).port == Some(port) {
                            std::thread::sleep(std::time::Duration::from_millis(1250));
                            let body = match pull_browser_report(&client, &session, &endpoint, &started.token, revision) {
                                Ok(body) => body,
                                Err(error) if error.contains("HTTP 404") || error.contains("HTTP 401") || error.contains("HTTP 403") => break,
                                Err(_) => continue,
                            };
                            if let Some(next) = body["revision"].as_u64() {
                                if next > revision && !body["report"].is_null() && status(&app).port == Some(port) {
                                    revision = next;
                                    let _ = watched_app.emit("browser-probe-update", body["report"].clone());
                                }
                            }
                        }
                    });
                }
                return Ok(result);
            }
            std::thread::sleep(std::time::Duration::from_millis(800));
        }
        Err("Браузер не передал результат проверки. Проверьте, открылась ли вкладка Workspace.".into())
    }).await
}

#[tauri::command]
async fn set_system_proxy(app: AppHandle, enabled: bool) -> Result<Status, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
        let (port, mut lease) = {
            let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?;
            let connection = guard.as_mut().ok_or("Сначала подключите туннель")?;
            if enabled && !connection.tunnel.running() { return Err("Сначала подключите туннель".into()); }
            if enabled && connection.proxy.is_some() { drop(guard); return Ok(status(&app)); }
            (connection.tunnel.port, if enabled { None } else { connection.proxy.take() })
        };
        if enabled {
            let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
            #[derive(serde::Deserialize)]
            struct Routing { version: u32, domains: Vec<String> }
            let session = service::Session::restore()?;
            let rules: Routing = service::checked(session.authorize(service::client()?.get(
                format!("{}/api/desktop/routing", service::ORIGIN)
            )).send())?.json().map_err(|_| "Не удалось получить список доменов Workspace")?;
            if rules.version == 0 { return Err("Список маршрутов Workspace не готов".into()); }
            lease = Some(system_proxy::Lease::enable(&data, port, &rules.domains)?);
        } else if let Some(proxy) = lease.as_mut() {
            let restored = proxy.restore();
            if restored.is_ok() { lease = None; }
            state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?.as_mut().ok_or("Туннель отключён")?.proxy = lease;
            restored?;
            return Ok(status(&app));
        }
        state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?.as_mut().ok_or("Туннель отключён")?.proxy = lease;
        Ok(status(&app))
    }).await
}
#[tauri::command]
async fn launch_terminal(app: AppHandle) -> Result<(),String> {
    blocking(move || {
        let port=status(&app).port.ok_or("Сначала подключите туннель")?;
        let http=format!("http://127.0.0.1:{port}");
        let socks=format!("socks5h://127.0.0.1:{port}");
        let result=if cfg!(target_os="macos") {
            let dir=app.path().app_data_dir().map_err(|_| "Нет каталога данных")?;
            std::fs::create_dir_all(&dir).map_err(|_| "Нет доступа к каталогу данных")?;
            let file=dir.join("Workspace-Terminal.command");
            std::fs::write(&file,format!("#!/bin/bash\nexport HTTP_PROXY={http} HTTPS_PROXY={http} ALL_PROXY={socks}\nexec /bin/zsh -i\n"))
                .map_err(|_| "Не удалось создать команду Терминала")?;
            #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&file,std::fs::Permissions::from_mode(0o700)).map_err(|_| "Не удалось разрешить запуск команды")?; }
            Command::new("/usr/bin/open").args(["-a","Terminal"]).arg(file).spawn()
        } else {
            let mut c=Command::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
            c.args(["-NoLogo","-NoExit"]).env("HTTP_PROXY",&http).env("HTTPS_PROXY",&http).env("ALL_PROXY",&socks);
            #[cfg(windows)] { use std::os::windows::process::CommandExt; c.creation_flags(0x00000010); }
            c.spawn()
        };
        result.map(|_|()).map_err(|_| "Не удалось запустить Терминал".into())
    }).await
}

#[tauri::command]
async fn launch_browser(app: AppHandle, destination: String) -> Result<(),String> {
    blocking(move || {
        let url = match destination.as_str() {
            "claude" => "https://claude.ai/",
            "chatgpt" => "https://chatgpt.com/",
            "workspace" => service::ORIGIN,
            _ => return Err("Неизвестное назначение".into()),
        };
        let state = app.state::<Runtime>();
        let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
        let _profile = state.profile.try_enter().ok_or("Дождитесь завершения операции с профилем")?;
        let (port, region, environment) = {
            let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?;
            let connection = guard.as_mut().ok_or("Сначала подключите туннель")?;
            if !connection.tunnel.running() { return Err("Сначала подключите туннель".into()); }
            (connection.tunnel.port, connection.tunnel.region.clone(), connection.environment.clone())
        };
        let data = app.path().app_data_dir().map_err(|_| "Не удалось открыть каталог приложения")?;
        let profile = launch::profile_path(&data, &region)?;
        launch::launch_browser(&profile, port, &region, environment.as_ref(), url, &state.browser_probe)
    }).await
}

#[tauri::command]
async fn clear_browser_profile(app: AppHandle, region: String) -> Result<(), String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _guard = state.profile.try_enter().ok_or("Дождитесь завершения операции с профилем")?;
        let data = app.path().app_data_dir().map_err(|_| "Не удалось открыть каталог приложения")?;
        launch::clear_browser_profile(&launch::profile_path(&data, &region)?)
    }).await
}

#[tauri::command]
async fn repair_browser_profile(app: AppHandle, region: String) -> Result<(), String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _guard = state.profile.try_enter().ok_or("Дождитесь завершения операции с профилем")?;
        let data = app.path().app_data_dir().map_err(|_| "Не удалось открыть каталог приложения")?;
        launch::repair_preferences(&launch::profile_path(&data, &region)?)
    }).await
}

#[tauri::command]
async fn open_time_settings() -> Result<(), String> {
    blocking(move || {
        let mut command = if cfg!(target_os = "macos") {
            let mut command = Command::new("/usr/bin/open");
            command.arg("x-apple.systempreferences:com.apple.Date-Time-Settings.extension");
            command
        } else {
            let mut command = Command::new("explorer.exe");
            command.arg("ms-settings:dateandtime");
            command
        };
        command.spawn().map(|_| ()).map_err(|_| "Не удалось открыть настройки времени".into())
    }).await
}

#[tauri::command]
fn take_radar_link(app: AppHandle) -> bool {
    app.state::<Runtime>().radar_requested.swap(false, std::sync::atomic::Ordering::AcqRel)
}

fn radar_link(url: &str) -> bool {
    matches!(url, "yousoro://radar" | "yousoro://radar/")
}

fn show_radar(app: &AppHandle) {
    app.state::<Runtime>().radar_requested.store(true, std::sync::atomic::Ordering::Release);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        let _ = window.emit("open-radar", ());
    }
}

#[cfg(windows)]
struct WindowsInstance { _lock: std::fs::File }

#[tauri::command]
async fn discover_installed_clients(app: AppHandle) -> Result<(), String> {
    blocking(move || {
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
        app.state::<Runtime>().clients.rediscover(&data)
    }).await
}

#[tauri::command]
async fn check_running_clients(app: AppHandle) -> Result<apps::InstalledApps, String> {
    blocking(move || {
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
        let route = status(&app);
        app.state::<Runtime>().clients.check_running_clients(&data, route.port, route.system_proxy)
    }).await
}

#[tauri::command]
async fn launch_desktop_app(app: AppHandle, client: apps::DesktopApp, restart: bool) -> Result<Status, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
        let (port, pac_url) = {
            let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?;
            let connection = guard.as_mut().ok_or("Сначала подключите туннель")?;
            if !connection.tunnel.running() { return Err("Сначала подключите туннель".into()); }
            (connection.tunnel.port, connection.proxy.as_ref().and_then(system_proxy::Lease::url).map(str::to_owned))
        };
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
        apps::launch(&state.clients, &data, client, port, restart, system_proxy::active(pac_url.as_deref()))?;
        Ok(status(&app))
    }).await
}
#[tauri::command]
async fn open_official(page: String) -> Result<(),String> {
    blocking(move || {
        let phone = format!("{}/setup/rules", service::ORIGIN);
        let url=match page.as_str() { "phone"=>phone.as_str(), "claude"=>"https://claude.com/download","chatgpt"=>"https://chatgpt.com/download/","workspace"=>service::ORIGIN,_=>return Err("Неизвестная страница".into()) };
        let mut cmd=if cfg!(target_os="macos") { Command::new("/usr/bin/open") } else { let mut c=Command::new("rundll32.exe"); c.arg("url.dll,FileProtocolHandler"); c };
        cmd.arg(url).spawn().map_err(|_| "Не удалось открыть страницу".into()).map(|_| ())
    }).await
}

#[derive(Serialize)]
struct WorkSettings { close_to_tray: bool, autostart: bool }

#[tauri::command]
async fn work_settings(app: AppHandle) -> Result<WorkSettings, String> {
    blocking(move || {
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога настроек")?;
        Ok(WorkSettings { close_to_tray: preferences::close_to_tray(&data), autostart: preferences::autostart()? })
    }).await
}

#[tauri::command]
async fn set_work_setting(app: AppHandle, setting: String, enabled: bool) -> Result<(), String> {
    blocking(move || {
        match setting.as_str() {
            "autostart" => preferences::set_autostart(enabled),
            "tray" => {
                let data = app.path().app_data_dir().map_err(|_| "Нет каталога настроек")?;
                preferences::set_close_to_tray(&data, enabled).map_err(|_| "Не удалось сохранить настройку окна".into())
            }
            _ => Err("Неизвестная настройка".into()),
        }
    }).await
}

#[tauri::command]
async fn browser_profile_state(app: AppHandle, region: String) -> Result<&'static str, String> {
    blocking(move || {
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога профиля")?;
        let profile = launch::profile_path(&data, &region)?;
        if !profile.exists() { return Ok("new"); }
        Ok(if launch::browser_process(&profile)?.is_some() { "open" } else { "ready" })
    }).await
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(Runtime::default())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" && window.app_handle().path().app_data_dir().is_ok_and(|path| preferences::close_to_tray(&path)) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        }).setup(|app| {
        #[cfg(windows)]
        {
            let data = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data)?;
            let lock = std::fs::OpenOptions::new().create(true).truncate(false)
                .read(true).write(true).open(data.join("workspace.lock"))?;
            let requested = std::env::args().skip(1).any(|arg| radar_link(&arg));
            match lock.try_lock() {
                Ok(()) => { app.manage(WindowsInstance { _lock: lock }); }
                Err(std::fs::TryLockError::WouldBlock) => {
                    if requested { std::fs::write(data.join("radar-request"), [])?; }
                    std::process::exit(0);
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
            if requested { show_radar(app.handle()); }
        }
        use tauri::{menu::{Menu,MenuItem},tray::TrayIconBuilder};
        let show=MenuItem::with_id(app,"show","Открыть Workspace",true,None::<&str>)?;
        let browser=MenuItem::with_id(app,"browser","Открыть рабочий браузер",true,None::<&str>)?;
        let exit=MenuItem::with_id(app,"exit","Выход",true,None::<&str>)?;
        let menu=Menu::with_items(app,&[&show,&browser,&exit])?;
        let icon=app.default_window_icon().ok_or("Нет значка приложения")?.clone();
        TrayIconBuilder::with_id("workspace").icon(icon).menu(&menu).tooltip("Отключено")
            .on_menu_event(|app,event| match event.id().as_ref() {
                "show"=>{if let Some(w)=app.get_webview_window("main") { let _=w.show(); let _=w.set_focus(); }},
                "browser"=>{ let app=app.clone(); tauri::async_runtime::spawn(async move {
                    if launch_browser(app.clone(),"workspace".into()).await.is_err() {
                        if let Some(w)=app.get_webview_window("main") { let _=w.show(); let _=w.set_focus(); }
                    }
                }); },
                "exit"=>app.exit(0), _=>{},
            }).build(app)?;
        let background = app.handle().clone();
        tauri::async_runtime::spawn_blocking(move || {
            if let Ok(data) = background.path().app_data_dir() {
                let state = background.state::<Runtime>();
                if state.clients.rediscover(&data).is_ok() { let _ = background.emit("desktop-clients-changed", ()); }
                if let Some(_route) = state.route.try_enter() { let _ = system_proxy::Lease::recover(&data); };
            }
        });
        if cfg!(windows) {
            let handle = app.handle().clone();
            let radar_request = app.path().app_data_dir()?.join("radar-request");
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(3));
                if std::fs::remove_file(&radar_request).is_ok() { show_radar(&handle); }
                let _ = status(&handle);
            });
        }
        Ok(())
    }).invoke_handler(tauri::generate_handler![sign_in,account,regions,select_region,sign_out,tunnel_status,connect_tunnel,disconnect,set_system_proxy,observe_tunnel,run_system_radar,run_browser_probe,launch_browser,clear_browser_profile,discover_installed_clients,check_running_clients,launch_desktop_app,launch_terminal,open_official,repair_browser_profile,open_time_settings,take_radar_link,work_settings,set_work_setting,browser_profile_state])
      .build(tauri::generate_context!()).expect("Workspace setup failed")
      .run(|app,event| match event {
          tauri::RunEvent::Exit => { let _ = remove_connection(&app.state::<Runtime>(), false); }
          #[cfg(target_os = "macos")]
          tauri::RunEvent::Opened { urls } if urls.iter().any(|url| radar_link(url.as_str())) => show_radar(app),
          _ => {}
      });
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_worker_enters_and_guard_drop_releases_the_flight() {
        let flight = SingleFlight::default();
        let running = flight.try_enter().unwrap();
        std::thread::scope(|scope| {
            assert!(scope.spawn(|| flight.try_enter().is_none()).join().unwrap());
        });
        drop(running);
        assert!(flight.try_enter().is_some());
    }
}
