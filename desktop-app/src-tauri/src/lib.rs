mod apps;
#[cfg(windows)]
mod chromium_timezone;
mod dns_radar;
mod launch;
mod killswitch;
#[cfg(windows)]
mod native_windows;
mod preferences;
mod radar;
mod system_proxy;
mod service;
mod support_diagnostics;
mod subscription_alert;
mod tunnel;
mod split_tun;
pub use split_tun::run_helper as run_split_tun_helper;
use serde::Serialize;
use serde_json::{json, Value};
use std::{process::Command, sync::{Mutex, atomic::{AtomicBool, Ordering}}};
use tauri::{AppHandle, Emitter, Manager};
use killswitch::{Core, Monitor, Phase, Proxy};
use split_tun::{ActiveEngine, Fallback, Recovery, RequestedEngine};

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
    proxy_recovery_error: Mutex<Option<String>>,
    exiting: AtomicBool,
    cancel_tun_start: AtomicBool,
    support_logs: support_diagnostics::Logs,
    tun_recovery: Mutex<Recovery>,
    pass_refresh: Mutex<()>,
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
    tunnel: Proxy,
    monitor: Option<Monitor>,
    split: Option<split_tun::Session>,
    relay_endpoint: Option<std::net::SocketAddrV4>,
    engine: ActiveEngine,
    fallback_reason: Option<Fallback>,
    tun_failed: bool,
    reconnect_needed: bool,
    dedicated_hold: bool,
    route_mode: Option<String>,
    killswitch_enabled: bool,
    region: String,
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
    killswitch_enabled: bool,
    protection: Option<Phase>,
    uptime_seconds: Option<u64>,
    device_id: Option<String>,
    requested_engine: RequestedEngine,
    active_engine: Option<ActiveEngine>,
    fallback_reason: Option<Fallback>,
    tun_recovery: Recovery,
    tun_failed: bool,
    reconnect_needed: bool,
    dedicated_hold: bool,
}

impl Status {
    fn system_tun_healthy(&self) -> bool {
        self.active_engine == Some(ActiveEngine::SplitTun)
            && matches!(self.protection, Some(Phase::Active | Phase::Restored))
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T,String> + Send + 'static) -> Result<T,String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|_| "Фоновая операция остановлена".to_owned())?
}

fn status(app: &AppHandle) -> Status {
    let state = app.state::<Runtime>();
    let mut result = Status {
        port: None, region: None, system_proxy: false, system_proxy_supported: cfg!(windows),
        proxy_error: state.proxy_recovery_error.lock().ok().and_then(|error| error.clone()),
        killswitch_enabled: true, protection: None, uptime_seconds: None, device_id: None,
        requested_engine: requested_engine(app), active_engine: None, fallback_reason: None,
        tun_recovery: *state.tun_recovery.lock().expect("TUN recovery"), tun_failed: false, reconnect_needed: false, dedicated_hold: false,
    };
    if let Ok(guard) = state.connection.lock() {
        if let Some(connection) = guard.as_ref() {
            result.port = Some(connection.tunnel.port);
            result.region = Some(connection.region.clone());
            result.system_proxy = connection.proxy.is_some();
            result.killswitch_enabled = connection.killswitch_enabled;
            result.protection = Some(connection.tunnel.phase());
            result.uptime_seconds = Some(connection.started.elapsed().as_secs());
            result.device_id = connection.device_id.clone();
            result.active_engine = (!connection.tun_failed).then_some(connection.engine);
            result.fallback_reason = connection.fallback_reason;
            result.tun_failed = connection.tun_failed;
            result.reconnect_needed = connection.reconnect_needed;
            result.dedicated_hold = connection.dedicated_hold;
            if connection.engine == ActiveEngine::SplitTun { result.system_proxy_supported = false; }
        }
    }
    if let Some(tray) = app.tray_by_id("workspace") {
        let title = match result.protection {
            Some(Phase::Checking | Phase::Blocked) => "Рабочий трафик заблокирован".into(),
            Some(_) => format!("Подключено • {}", result.region.as_deref().unwrap_or("").to_uppercase()),
            None => "Отключено".into(),
        };
        let _ = tray.set_tooltip(Some(title));
    }
    result
}
#[tauri::command]
async fn tunnel_status(app: AppHandle) -> Result<Status, String> { blocking(move || Ok(status(&app))).await }
#[tauri::command]
async fn activate(code: String) -> Result<service::Account,String> { blocking(move || service::activate(code)).await }
#[tauri::command]
async fn account(app: AppHandle) -> Result<service::Account,String> { blocking(move || {
    let result = service::Session::restore().and_then(|session| service::account(&session));
    let state = app.state::<Runtime>();
    let connected = status(&app);
    let invalidate = match &result {
        Ok(account) => !account.route_ready() || account.profile.applied != connected.region,
        Err(message) => message == "DEVICE_REVOKED" || message == "ACTIVATION_REQUIRED",
    };
    if connected.port.is_some() && !invalidate
        && result.as_ref().ok().and_then(|account| account.dedicated_passes.as_ref())
            .is_some_and(|passes| passes.mode == "DEDICATED_EXPIRED_HOLD")
    {
        if let Ok(_flight) = state.pass_refresh.try_lock() {
            // HOLD needs no new bootstrap. Close the gate as soon as the account reports it.
            if let Ok(session) = service::Session::restore() {
                apply_pass_mode(&app, &session, "DEDICATED_EXPIRED_HOLD")?;
            }
        }
    }
    if connected.port.is_some() && invalidate {
        let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
        remove_connection(&state, None)?;
    }
    result
}).await }
#[tauri::command]
async fn regions() -> Result<Value,String> { blocking(move || {
    service::checked(service::client()?.get(format!("{}/api/regions",service::ORIGIN)).send())?.json()
        .map_err(|_| "Не удалось прочитать регионы".into())
}).await }
// Restore the lease before removing the route, including when the app exits mid-command.
fn remove_connection(state: &Runtime, expected_port: Option<u16>) -> Result<(), String> {
    let connection = {
        let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния")?;
        if expected_port.is_some_and(|port| guard.as_ref().is_none_or(|connection| connection.tunnel.port != port)) { return Ok(()); }
        if let Some(connection) = guard.as_mut() { connection.restore_proxy()?; }
        guard.take()
    };
    if let Some(mut connection) = connection {
        connection.tunnel.suspend();
        stop_split(state, &mut connection);
        drop(connection);
        state.support_logs.record("stopped");
    }
    Ok(())
}

#[tauri::command]
async fn disconnect(app: AppHandle) -> Result<Status, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
        remove_connection(&state, None)?;
        Ok(status(&app))
    }).await
}
#[tauri::command]
async fn sign_out(app: AppHandle) -> Result<(),String> { blocking(move || {
    let state = app.state::<Runtime>();
    let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
    remove_connection(&state, None)?;
    match service::key("activation-device")?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err("Системное хранилище не удалило сессию".into()),
    }
}).await }
fn requested_engine(app: &AppHandle) -> RequestedEngine {
    app.path().app_data_dir().ok()
        .filter(|data| data.join("prefer-split-tun").is_file())
        .map_or(RequestedEngine::Proxy, |_| RequestedEngine::SplitTun)
}

#[tauri::command]
async fn set_requested_engine(app: AppHandle, engine: RequestedEngine) -> Result<Status, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
        if status(&app).port.is_some() { return Err("Отключите маршрут перед сменой режима".into()); }
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога настроек")?;
        let file = data.join("prefer-split-tun");
        match engine {
            RequestedEngine::SplitTun => std::fs::create_dir_all(data).and_then(|_| std::fs::write(file, [])),
            RequestedEngine::Proxy => match std::fs::remove_file(file) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                result => result,
            },
        }.map_err(|_| "Не удалось сохранить режим подключения")?;
        Ok(status(&app))
    }).await
}

fn start_relay_monitor(
    app: &AppHandle, connection: &mut Connection, session: service::Session, enrollment: service::Bootstrap,
) -> Result<(), String> {
    let state = app.state::<Runtime>();
    let executable = std::env::current_exe().map_err(|_| "Не удалось определить путь приложения")?;
    let executable_dir = executable.parent().ok_or("Нет каталога приложения")?.to_path_buf();
    let resources = app.path().resource_dir().map_err(|_| "Нет каталога ресурсов")?.join("resources");
    let split = connection.engine == ActiveEngine::SplitTun;
    let mut xray = if split { None } else {
        Some(tunnel::verified(&executable_dir, &resources).map_err(|error| {
            state.support_logs.record("core_verification_failed");
            error
        })?)
    };
    let core_logs = state.support_logs.clone();
    let watchdog_logs = state.support_logs.clone();
    let mut confirmed = None;
    let config = enrollment.config;
    connection.tunnel.resume();
    let monitor = Monitor::start(
        &connection.tunnel,
        move || {
            let core: Option<Box<dyn Core + Send>> = if split {
                let binary = executable.with_file_name(if cfg!(windows) { "sing-box.exe" } else { "sing-box" });
                split_tun::start_relay(&binary, &config).map(|core| Box::new(core) as Box<dyn Core + Send>)
            } else {
                let binary = xray.take().or_else(|| {
                    tunnel::verified(&executable_dir, &resources).map_err(|_| core_logs.record("core_verification_failed")).ok()
                })?;
                tunnel::start(&binary, config.clone()).ok().map(|core| Box::new(core) as Box<dyn Core + Send>)
            };
            if core.is_none() { core_logs.record(if split { "tun_relay_start_failed" } else { "core_start_failed" }); }
            core
        },
        move |port| radar::route_alive(port, &session, &mut confirmed),
        move |phase| watchdog_logs.record(match phase {
            Phase::Checking => "checking",
            Phase::Active => "active",
            Phase::Blocked => "blocked",
            Phase::Restored => "restored",
            Phase::Unmonitored => "unmonitored",
        }),
    ).map_err(|_| {
        connection.tunnel.suspend();
        "Не удалось запустить мониторинг маршрута"
    })?;
    connection.monitor = Some(monitor);
    connection.device_id = enrollment.device_id;
    connection.killswitch_enabled = true;
    Ok(())
}

fn engine_from_start<T>(requested: RequestedEngine, start: impl FnOnce() -> Result<T, Fallback>)
    -> (ActiveEngine, Option<T>, Option<Fallback>)
{
    match requested {
        RequestedEngine::Proxy => (ActiveEngine::Proxy, None, None),
        RequestedEngine::SplitTun => match start() {
            Ok(session) => (ActiveEngine::SplitTun, Some(session), None),
            Err(reason) => (ActiveEngine::ProxyFallback, None, Some(reason)),
        },
    }
}

#[tauri::command]
async fn connect_tunnel(app: AppHandle) -> Result<Status,String> { blocking(move || {
    let state = app.state::<Runtime>();
    let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
    if status(&app).port.is_some() { return Ok(status(&app)); }
    let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
    system_proxy::Lease::recover(&data)?;
    if let Ok(mut error) = state.proxy_recovery_error.lock() { *error = None; }
    let session = service::Session::restore()?;
    let account = service::account(&session)?;
    if !account.route_ready() { return Err("Подписка или сетевой профиль ещё не активны".into()); }
    let region = account.profile.applied.clone().ok_or("Выберите регион")?;
    let requested = requested_engine(&app);
    state.cancel_tun_start.store(false, Ordering::Release);
    let mut route_mode = Some(match &account.dedicated_passes {
        Some(passes) => passes.mode.clone(),
        None => service::pass_status(&session)?.mode,
    });
    let mut dedicated_hold = route_mode.as_deref() == Some("DEDICATED_EXPIRED_HOLD");
    let mut enrollment = if dedicated_hold { None } else { Some(service::bootstrap(&session)?) };
    let relay_endpoint = enrollment.as_ref().and_then(|entry| split_tun::relay_endpoint(&entry.config));
    let mut tunnel = Proxy::bind().map_err(|_| "Нет свободного локального порта")?;
    let (engine, split, mut fallback_reason) = engine_from_start(requested, || {
        let recovery = split_tun::recover(&data);
        record_recovery(&state, recovery);
        if recovery == Recovery::Pending { return Err(Fallback::RecoveryPending); }
        if !dedicated_hold && relay_endpoint.is_none() { return Err(Fallback::TunInitFailed); }
        split_tun::Session::start(&data, tunnel.port, relay_endpoint, || {
            state.exiting.load(Ordering::Acquire) || state.cancel_tun_start.load(Ordering::Acquire)
        })
    });
    if requested == RequestedEngine::SplitTun && state.cancel_tun_start.load(Ordering::Acquire) {
        return Err("Запуск Split-TUN отменён".into());
    }
    if requested == RequestedEngine::SplitTun {
        // Authorization can outlast the pass. Recheck before permitting any new socket.
        let fresh_mode = service::pass_status(&session)?.mode;
        if route_mode.as_deref() != Some(fresh_mode.as_str()) {
            dedicated_hold = fresh_mode == "DEDICATED_EXPIRED_HOLD";
            enrollment = if dedicated_hold { None } else { Some(service::bootstrap(&session)?) };
            route_mode = Some(fresh_mode);
        }
    }
    if fallback_reason.is_some() {
        state.support_logs.record("tun_fallback");
        // Never enable Xray on a port an incompletely stopped TUN could still use.
        tunnel = Proxy::bind().map_err(|_| "Нет свободного локального порта")?;
        let recovery = split_tun::recover(&data);
        record_recovery(&state, recovery);
        if recovery == Recovery::Pending { fallback_reason = Some(Fallback::RecoveryPending); }
    }
    if split.is_some() { state.support_logs.record("tun_started"); }
    if matches!(fallback_reason, Some(Fallback::RecoveryPending)) {
        record_recovery(&state, Recovery::Pending);
    }
    let mut connection = Connection {
        tunnel, monitor: None, split, relay_endpoint, engine, fallback_reason, dedicated_hold, route_mode,
        tun_failed: false, reconnect_needed: false, killswitch_enabled: true, region, proxy: None, device_id: None,
        started: std::time::Instant::now(), environment: account.profile.node_environment,
    };
    if let Some(enrollment) = enrollment {
        if connection.engine == ActiveEngine::SplitTun && connection.relay_endpoint != split_tun::relay_endpoint(&enrollment.config) {
            connection.tunnel.suspend();
            connection.reconnect_needed = true;
            state.support_logs.record("tun_endpoint_changed");
        } else {
            start_relay_monitor(&app, &mut connection, session, enrollment)?;
        }
    } else {
        connection.tunnel.suspend();
    }
    let port = connection.tunnel.port;
    {
        let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния")?;
        if state.exiting.load(Ordering::Acquire)
            || requested == RequestedEngine::SplitTun && state.cancel_tun_start.load(Ordering::Acquire)
        { return Err("Запуск маршрута отменён".into()); }
        *guard = Some(connection);
    }
    // Let the watchdog observe the interface while the first Relay check runs.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let current = status(&app);
        if current.port != Some(port) || current.protection != Some(Phase::Checking)
            || state.exiting.load(Ordering::Acquire) || std::time::Instant::now() >= deadline
        { return Ok(current); }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}).await }

fn record_recovery(state: &Runtime, recovery: Recovery) {
    let mut current = state.tun_recovery.lock().expect("TUN recovery");
    if recovery != Recovery::None && *current != recovery {
        state.support_logs.record(match recovery {
            Recovery::Recovered => "tun_recovered",
            Recovery::Pending => "tun_recovery_pending",
            Recovery::None => unreachable!(),
        });
        *current = recovery;
    }
}

fn stop_split(state: &Runtime, connection: &mut Connection) {
    if let Some(mut session) = connection.split.take() {
        if !session.stop() { record_recovery(state, Recovery::Pending); }
    }
}

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


fn apply_pass_mode(app: &AppHandle, session: &service::Session, mode: &str) -> Result<(), String> {
    let state = app.state::<Runtime>();
    let held = mode == "DEDICATED_EXPIRED_HOLD";
    let (port, old_monitor) = {
        let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния маршрута")?;
        let Some(connection) = guard.as_mut() else { return Ok(()); };
        if connection.tun_failed || connection.route_mode.as_deref() == Some(mode)
            && (held || connection.monitor.is_some() || connection.reconnect_needed) {
            return Ok(());
        }
        connection.tunnel.suspend();
        connection.dedicated_hold = held;
        connection.reconnect_needed = false;
        connection.route_mode = Some(mode.to_owned());
        if held { state.support_logs.record("tun_hold"); }
        (connection.tunnel.port, connection.monitor.take())
    };
    drop(old_monitor);
    if held { return Ok(()); }
    let enrollment = service::bootstrap(session)?;
    let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния маршрута")?;
    let Some(connection) = guard.as_mut().filter(|connection| connection.tunnel.port == port && !connection.tun_failed) else {
        return Ok(());
    };
    if connection.engine == ActiveEngine::SplitTun && (connection.relay_endpoint.is_none()
        || connection.relay_endpoint != split_tun::relay_endpoint(&enrollment.config))
    {
        state.support_logs.record("tun_endpoint_changed");
        connection.reconnect_needed = true;
        return Ok(());
    }
    start_relay_monitor(app, connection, service::Session::restore()?, enrollment)?;
    state.support_logs.record("tun_hold_released");
    Ok(())
}

fn refresh_pass(app: &AppHandle, action: Option<(&str, Option<u64>, bool)>) -> Result<service::DedicatedPasses, String> {
    let state = app.state::<Runtime>();
    let _flight = if action.is_some() { state.pass_refresh.lock().ok() } else { state.pass_refresh.try_lock().ok() }
        .ok_or("Проверка выделенного канала уже выполняется")?;
    let session = service::Session::restore()?;
    let passes = match action {
        Some((action, pass_id, tabs_closed)) => service::pass_action(&session, action, pass_id, tabs_closed)?,
        None => service::pass_status(&session)?,
    };
    if apply_pass_mode(app, &session, &passes.mode).is_err() { state.support_logs.record("tun_mode_retry"); }
    Ok(passes)
}

#[tauri::command]
async fn dedicated_status(app: AppHandle) -> Result<service::DedicatedPasses, String> {
    blocking(move || refresh_pass(&app, None)).await
}

#[tauri::command]
async fn dedicated_action(app: AppHandle, action: String, pass_id: Option<u64>, tabs_closed: Option<bool>) -> Result<service::DedicatedPasses, String> {
    blocking(move || refresh_pass(&app, Some((&action, pass_id, tabs_closed.unwrap_or(false))))).await
}

#[tauri::command]
async fn radar_summary() -> Result<service::RadarSummary, String> {
    blocking(|| service::radar_summary(&service::Session::restore()?)).await
}

#[tauri::command]
async fn run_system_radar(app: AppHandle, check_dns: Option<bool>) -> Result<radar::Report, String> {
    blocking(move || {
        let route = status(&app);
        let port = route.port.ok_or("Сначала подключите туннель")?;
        let region = route.region.as_deref().ok_or("Регион не определён")?;
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
        let state = app.state::<Runtime>();
        let (device_id, environment, pac_url) = state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?.as_ref()
            .filter(|active| active.tunnel.port == port)
            .map(|active| (active.device_id.clone(), active.environment.clone(), active.proxy.as_ref().and_then(system_proxy::Lease::url).map(str::to_owned)))
            .ok_or("Туннель изменился во время диагностики")?;
        let pac_active = system_proxy::active(pac_url.as_deref());
        let apps = state.clients.check_running_clients(&data, Some(port), pac_active, route.system_tun_healthy()).unwrap_or_default();
        let report = radar::report(port, region, &data, &state.browser_probe, check_dns.unwrap_or(false), device_id.as_deref(), environment.as_ref(), pac_active, apps,
            |stage| { let _ = app.emit("radar-progress", stage); });
        if status(&app).port != Some(port) { return Err("Туннель изменился во время диагностики".into()); }
        if let (Some(ip), Ok(session)) = (report.network.as_ref().map(|value| value.ip), service::Session::restore()) {
            if service::desktop_ping(&session, ip).is_err() {
                let _ = app.emit("radar-device-ping-failed", ());
            }
        }
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


fn dedicated_browser_environment(
    session: &service::Session,
    mut environment: Option<service::NodeEnvironment>,
    allow_diagnostics: bool,
) -> Result<Option<service::NodeEnvironment>, String> {
    if service::pass_status(session)?.mode != "DEDICATED_ACTIVE" {
        return Ok(environment);
    }
    let summary = service::radar_summary(session)?;
    if summary.mode != "DEDICATED_ACTIVE" {
        return Ok(environment);
    }
    environment = summary.environment.or(environment);
    let Some(zone) = summary.location.timezone.or_else(|| environment.as_ref().map(|node| node.timezone.clone())) else {
        return if allow_diagnostics { Ok(environment) } else { Err("Нет подтверждённого часового пояса выделенного канала".into()) };
    };
    if let Some(node) = &mut environment {
        node.timezone = zone;
    } else {
        environment = Some(service::NodeEnvironment { timezone: zone, windows_timezone: String::new(), locale: "en-US".into() });
    }
    Ok(environment)
}

fn browser_timezone_override<'a>(local: Option<&str>, node: Option<&'a service::NodeEnvironment>) -> Option<&'a str> {
    let node = node?;
    (cfg!(windows) && radar::timezone_matches(local, Some(&node.timezone)) != Some(true)).then_some(node.timezone.as_str())
}

#[tauri::command]
async fn run_browser_probe(app: AppHandle, stun: bool, check_dns: Option<bool>, exit_ip: Option<String>, exit_country: Option<String>,
    local_timezone: Option<String>, ignore_timezone: Option<bool>) -> Result<Value, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let (port, region, environment) = {
            let guard = state.connection.lock().map_err(|_| "Ошибка состояния маршрута")?;
            let connection = guard.as_ref().ok_or("Сначала подключите маршрут")?;
            (connection.tunnel.port, connection.region.clone(), connection.environment.clone())
        };
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога профиля")?;
        let english = preferences::english_browser(&data);
        let session = service::Session::restore()?;
        let profile = launch::profile_path(&data, &region)?;
        let browser_running = launch::browser_process(&profile)?.is_some();
        let ignore_timezone = ignore_timezone.unwrap_or(false);
        let environment = dedicated_browser_environment(&session, environment, browser_running || ignore_timezone)?;
        let override_zone = browser_timezone_override(local_timezone.as_deref(), environment.as_ref())
            .filter(|_| !ignore_timezone);
        let client = service::client()?;
        #[derive(serde::Deserialize)]
        struct Started { token: String, diagnostics_origin: String, ipv6_origin: Option<String>, region: Option<String> }
        let started: Started = service::checked(session.authorize(client.post(
            format!("{}/api/radar-probe/start", service::ORIGIN)
        )).send())?.json().map_err(|_| "Сервер не выдал код проверки")?;
        if started.token.len() != 48 || !started.token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Сервер выдал некорректный код проверки".into());
        }
        let mut url = reqwest::Url::parse(&format!("{}/radar-probe", service::ORIGIN))
            .map_err(|_| "Некорректный адрес проверки")?;
        let browser_dns = if check_dns.unwrap_or(false) { dns_radar::BrowserDns::start(port) } else { None };
        let mut fragment = reqwest::Url::parse("https://example.invalid/").map_err(|_| "Некорректный адрес")?;
        {
            let mut args = fragment.query_pairs_mut();
            args.append_pair("token", &started.token).append_pair("check", &started.diagnostics_origin);
            if let Some(origin) = &started.ipv6_origin { args.append_pair("ipv6", origin); }
            if let Some(environment) = &environment {
                args.append_pair("timezone", &environment.timezone);
            }
            if let Some(locale) = launch::browser_language(environment.as_ref(), english) { args.append_pair("locale", locale); }
            if let Some(region) = &started.region { args.append_pair("region", region); }
            if let Some(ip) = &exit_ip { args.append_pair("exit_ip", ip); }
            if let Some(country) = &exit_country { args.append_pair("exit_country", country); }
            if stun { args.append_pair("stun", "1"); }
            if let Some(dns) = &browser_dns { args.append_pair("dns", &dns.id); }
        }
        url.set_fragment(fragment.query());
        {
            let _profile = state.profile.try_enter().ok_or("Дождитесь завершения операции с профилем")?;
            if status(&app).port != Some(port) { return Err("Маршрут изменился во время проверки".into()); }
            if !browser_running && override_zone.is_some() {
                let opened = launch::launch_browser(&profile, port, &region, environment.as_ref(), english, url.as_str(), &state.browser_probe, override_zone)?;
                if !opened { return Ok(json!({ "timezone_warning": override_zone })); }
            } else {
                launch::open_probe(&profile, port, environment.as_ref(), english, url.as_str())?;
            }
        }
        let ipv6_probe_available = started.ipv6_origin.is_some();
        let wait_until = std::time::Instant::now() + std::time::Duration::from_secs(40);
        let endpoint = format!("{}/api/radar-probe/result", service::ORIGIN);
        while std::time::Instant::now() < wait_until {
            if status(&app).port != Some(port) { return Err("Маршрут изменился во время проверки".into()); }
            let body = pull_browser_report(&client, &session, &endpoint, &started.token, 0)?;
            if !body["report"].is_null() {
                let mut result = body["report"].clone();
                let dns_result = browser_dns.as_ref().map_or("unmeasured", dns_radar::BrowserDns::finish);
                result["dns"] = json!(dns_result);
                result["ipv6_probe_available"] = json!(ipv6_probe_available);
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
                                    let mut report = body["report"].clone();
                                    report["dns"] = json!(dns_result);
                                    report["ipv6_probe_available"] = json!(ipv6_probe_available);
                                    let _ = watched_app.emit("browser-probe-update", report);
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
async fn set_killswitch(app: AppHandle, enabled: bool) -> Result<Status, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
        {
            let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?;
            let connection = guard.as_mut().ok_or("Сначала подключите туннель")?;
            if connection.killswitch_enabled != enabled {
                if connection.engine == ActiveEngine::SplitTun { return Err("Split-TUN всегда проверяет маршрут Relay".into()); }
                let monitor = connection.monitor.as_ref().ok_or("Маршрут приостановлен")?;
                monitor.set_enabled(enabled)?;
                connection.killswitch_enabled = enabled;
            }
        }
        Ok(status(&app))
    }).await
}

#[tauri::command]
async fn set_system_proxy(app: AppHandle, enabled: bool) -> Result<Status, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
        if enabled {
            let current = status(&app);
            if current.system_proxy { return Ok(current); }
            if !current.system_proxy_supported { return Err("Точечный прокси доступен в режиме Proxy на Windows".into()); }
            if current.port.is_none() { return Err("Сначала подключите туннель".into()); }
            let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
            #[derive(serde::Deserialize)]
            struct Routing { version: u32, domains: Vec<String> }
            let session = service::Session::restore()?;
            let rules: Routing = service::checked(session.authorize(service::client()?.get(
                format!("{}/api/desktop/routing", service::ORIGIN)
            )).send())?.json().map_err(|_| "Не удалось получить список доменов Workspace")?;
            if rules.version == 0 { return Err("Список маршрутов Workspace не готов".into()); }
            let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?;
            let connection = guard.as_mut().ok_or("Сначала подключите туннель")?;
            if state.exiting.load(Ordering::Acquire) { return Err("Workspace завершает работу".into()); }
            if !connection.tunnel.ready() { return Err("Маршрут заблокирован до восстановления шлюза".into()); }
            connection.proxy = Some(system_proxy::Lease::enable(&data, connection.tunnel.port, &rules.domains)?);
        } else {
            let mut guard = state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?;
            guard.as_mut().ok_or("Сначала подключите туннель")?.restore_proxy()?;
        }
        Ok(status(&app))
    }).await
}
#[tauri::command]
async fn launch_terminal(app: AppHandle) -> Result<(),String> {
    blocking(move || {
        let route = status(&app);
        if matches!(route.protection, Some(Phase::Blocked | Phase::Checking)) {
            return Err("Маршрут заблокирован до восстановления шлюза".into());
        }
        let port = route.port.ok_or("Сначала подключите туннель")?;
        let http=format!("http://127.0.0.1:{port}");
        let socks=format!("socks5h://127.0.0.1:{port}");
        let result=if cfg!(target_os="macos") {
            let dir=app.path().app_data_dir().map_err(|_| "Нет каталога данных")?;
            std::fs::create_dir_all(&dir).map_err(|_| "Нет доступа к каталогу данных")?;
            let file=dir.join("Workspace-Terminal.command");
            std::fs::write(&file,format!("#!/bin/bash\nunset NO_PROXY no_proxy\nexport HTTP_PROXY={http} HTTPS_PROXY={http} ALL_PROXY={socks} http_proxy={http} https_proxy={http} all_proxy={socks}\nexec /bin/zsh -i\n"))
                .map_err(|_| "Не удалось создать команду Терминала")?;
            #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&file,std::fs::Permissions::from_mode(0o700)).map_err(|_| "Не удалось разрешить запуск команды")?; }
            Command::new("/usr/bin/open").args(["-a","Terminal"]).arg(file).spawn()
        } else {
            let mut c=Command::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
            c.args(["-NoLogo","-NoExit"]).env("HTTP_PROXY",&http).env("HTTPS_PROXY",&http).env("ALL_PROXY",&socks)
                .env("http_proxy",&http).env("https_proxy",&http).env("all_proxy",&socks)
                .env_remove("NO_PROXY").env_remove("no_proxy");
            #[cfg(windows)] { use std::os::windows::process::CommandExt; c.creation_flags(0x00000010); }
            c.spawn()
        };
        result.map(|_|()).map_err(|_| "Не удалось запустить Терминал".into())
    }).await
}

#[tauri::command]
async fn launch_browser(app: AppHandle, destination: String, local_timezone: Option<String>) -> Result<Option<String>,String> {
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
            let guard = state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?;
            let connection = guard.as_ref().ok_or("Сначала подключите туннель")?;
            if !connection.tunnel.ready() { return Err("Маршрут заблокирован до восстановления шлюза".into()); }
            (connection.tunnel.port, connection.region.clone(), connection.environment.clone())
        };
        let data = app.path().app_data_dir().map_err(|_| "Не удалось открыть каталог приложения")?;
        let session = service::Session::restore()?;
        let environment = dedicated_browser_environment(&session, environment, false)?;
        let override_zone = browser_timezone_override(local_timezone.as_deref(), environment.as_ref());
        let profile = launch::profile_path(&data, &region)?;
        let english = preferences::english_browser(&data);
        let opened = launch::launch_browser(&profile, port, &region, environment.as_ref(), english, url, &state.browser_probe, override_zone)?;
        Ok(if opened { None } else { override_zone.map(str::to_owned) })
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

struct LauncherInstance { _lock: std::fs::File }

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
        running_clients(&app, &status(&app))
    }).await
}

#[tauri::command]
async fn support_report(
    app: AppHandle, signals: [Option<support_diagnostics::Signal>; 7], held: Option<bool>,
) -> Result<String, String> {
    blocking(move || {
        let route = status(&app);
        let clients = running_clients(&app, &route).ok();
        let state = app.state::<Runtime>();
        use support_diagnostics::TunSession;
        let tun_session = if route.tun_failed { TunSession::Failed }
            else if route.active_engine != Some(ActiveEngine::SplitTun) { TunSession::Inactive }
            else if route.reconnect_needed { TunSession::ReconnectNeeded }
            else if route.dedicated_hold { TunSession::Hold }
            else { TunSession::Running };
        let engine = support_diagnostics::EngineState { requested_engine: route.requested_engine, active_engine: route.active_engine,
            fallback_reason: route.fallback_reason, tun_session, tun_recovery: route.tun_recovery };
        Ok(support_diagnostics::report(route.protection, route.killswitch_enabled,
            if route.port.is_some() { Some(route.dedicated_hold) } else { held },
            engine, signals, clients.as_ref(), &state.support_logs).to_string())
    }).await
}

fn running_clients(app: &AppHandle, route: &Status) -> Result<apps::InstalledApps, String> {
    let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
    let port = (!matches!(route.protection, Some(Phase::Checking | Phase::Blocked))).then_some(route.port).flatten();
    app.state::<Runtime>().clients.check_running_clients(&data, port, route.system_proxy, route.system_tun_healthy())
}

#[tauri::command]
async fn launch_desktop_app(app: AppHandle, client: apps::DesktopApp, restart: bool, explicit: Option<bool>) -> Result<Status, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _route = state.route.try_enter().ok_or("Дождитесь завершения операции с маршрутом")?;
        let (port, pac_url) = {
            let guard = state.connection.lock().map_err(|_| "Ошибка состояния туннеля")?;
            let connection = guard.as_ref().ok_or("Сначала подключите туннель")?;
            if !connection.tunnel.ready() { return Err("Сначала подключите туннель".into()); }
            (connection.tunnel.port, connection.proxy.as_ref().and_then(system_proxy::Lease::url).map(str::to_owned))
        };
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
        apps::launch(&state.clients, &data, client, port, restart, system_proxy::active(pac_url.as_deref()), explicit.unwrap_or(false))?;
        Ok(status(&app))
    }).await
}
#[tauri::command]
async fn notify_subscription(app: AppHandle, urgency: service::SubscriptionUrgency) -> Result<(), String> {
    let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
    blocking(move || subscription_alert::show(&data, urgency)).await
}

#[tauri::command]
async fn open_official(page: String) -> Result<(),String> {
    blocking(move || {
        let phone = format!("{}/setup/rules", service::ORIGIN);
        let mobile = format!("{}/app/mobile", service::ORIGIN);
        let cabinet = format!("{}/app", service::ORIGIN);
        let desktop = format!("{}/app/desktop", service::ORIGIN);
        let checkout = format!("{}/checkout?plan=dedicated_pass_addon", service::ORIGIN);
        let billing = format!("{}/app/billing", service::ORIGIN);
        let renewal = format!("{}{}", service::ORIGIN, subscription_alert::RENEW_PATH);
        let setup = format!("{}/setup/region", service::ORIGIN);
        let url=match page.as_str() { "dedicated-checkout"=>checkout.as_str(), "billing"=>billing.as_str(), "renewal"=>renewal.as_str(), "setup"=>setup.as_str(), "phone"=>phone.as_str(), "mobile"=>mobile.as_str(), "cabinet"=>cabinet.as_str(), "desktop"=>desktop.as_str(), "claude"=>"https://claude.com/download","chatgpt"=>"https://chatgpt.com/download/","workspace"=>service::ORIGIN,_=>return Err("Неизвестная страница".into()) };
        let mut cmd=if cfg!(target_os="macos") { Command::new("/usr/bin/open") } else { let mut c=Command::new("rundll32.exe"); c.arg("url.dll,FileProtocolHandler"); c };
        cmd.arg(url).spawn().map_err(|_| "Не удалось открыть страницу".into()).map(|_| ())
    }).await
}

#[derive(Serialize)]
struct WorkSettings { close_to_tray: bool, autostart: bool, english_browser: bool }

#[tauri::command]
async fn work_settings(app: AppHandle) -> Result<WorkSettings, String> {
    blocking(move || {
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога настроек")?;
        Ok(WorkSettings { close_to_tray: preferences::close_to_tray(&data), autostart: preferences::autostart()?, english_browser: preferences::english_browser(&data) })
    }).await
}

#[tauri::command]
async fn set_work_setting(app: AppHandle, setting: String, enabled: bool) -> Result<(), String> {
    blocking(move || {
        match setting.as_str() {
            "autostart" => preferences::set_autostart(enabled),
            "browser-language" => {
                let data = app.path().app_data_dir().map_err(|_| "Нет каталога настроек")?;
                preferences::set_english_browser(&data, enabled).map_err(|_| "Не удалось сохранить язык рабочего браузера".into())
            }
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
                if window.label() != "main" { return; }
                let app = window.app_handle();
                let state = app.state::<Runtime>();
                state.cancel_tun_start.store(true, Ordering::Release);
                let split_port = state.connection.lock().ok().and_then(|guard| {
                    let connection = guard.as_ref().filter(|connection| connection.engine == ActiveEngine::SplitTun)?;
                    connection.tunnel.suspend();
                    Some(connection.tunnel.port)
                });
                if app.path().app_data_dir().is_ok_and(|path| preferences::close_to_tray(&path)) {
                    api.prevent_close();
                    let _ = window.hide();
                    if let Some(port) = split_port {
                        let app = app.clone();
                        tauri::async_runtime::spawn_blocking(move || {
                            let _ = remove_connection(&app.state::<Runtime>(), Some(port));
                            let _ = app.emit("tunnel-changed", ());
                        });
                    }
                }
            }
        }).setup(|app| {
        #[cfg(target_os = "macos")]
        subscription_alert::install_delegate();
        {
            let data = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data)?;
            let lock = std::fs::OpenOptions::new().create(true).truncate(false)
                .read(true).write(true).open(data.join("workspace.lock"))?;
            let requested = std::env::args().skip(1).any(|arg| radar_link(&arg));
            match lock.try_lock() {
                Ok(()) => { app.manage(LauncherInstance { _lock: lock }); }
                Err(std::fs::TryLockError::WouldBlock) => {
                    if requested { std::fs::write(data.join("radar-request"), [])?; }
                    std::process::exit(0);
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
            if requested { show_radar(app.handle()); }
        }
        if let Ok(data) = app.path().app_data_dir() {
            record_recovery(&app.state::<Runtime>(), split_tun::recover(&data));
            if let Ok(mut error) = app.state::<Runtime>().proxy_recovery_error.lock() {
                *error = system_proxy::Lease::recover(&data).err();
            }
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
                "browser"=>{
                    if let Some(w)=app.get_webview_window("main") {
                        let _=w.show();
                        let _=w.set_focus();
                        let _=w.emit("open-work-browser", ());
                    }
                },
                "exit"=>app.exit(0), _=>{},
            }).build(app)?;
        let guard_handle = app.handle().clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let state = guard_handle.state::<Runtime>();
            if state.exiting.load(Ordering::Acquire) { break; }
            let failed = state.connection.lock().ok().and_then(|mut guard| {
                let connection = guard.as_mut()?;
                if connection.split.as_ref()?.healthy() { return None; }
                connection.tunnel.suspend();
                connection.tun_failed = true;
                let monitor = connection.monitor.take();
                let session = connection.split.take()?;
                Some((session, monitor))
            });
            if let Some((mut session, monitor)) = failed {
                state.support_logs.record("tun_lost");
                let _ = guard_handle.emit("tunnel-changed", ());
                if !session.stop() { record_recovery(&state, Recovery::Pending); }
                drop(monitor);
                let _ = guard_handle.emit("desktop-clients-changed", ());
            }
        });
        let pass_handle = app.handle().clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let state = pass_handle.state::<Runtime>();
            if state.exiting.load(Ordering::Acquire) { break; }
            if state.connection.lock().is_ok_and(|guard| guard.is_some()) {
                let _ = refresh_pass(&pass_handle, None);
            }
        });
        let background = app.handle().clone();
        tauri::async_runtime::spawn_blocking(move || {
            if let Ok(data) = background.path().app_data_dir() {
                let state = background.state::<Runtime>();
                if state.clients.rediscover(&data).is_ok() { let _ = background.emit("desktop-clients-changed", ()); }
            }
        });
        {
            let handle = app.handle().clone();
            #[cfg(windows)]
            let radar_request = app.path().app_data_dir()?.join("radar-request");
            std::thread::spawn(move || {
              let mut previous = [false; 3];
              loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                if handle.state::<Runtime>().exiting.load(Ordering::Acquire) { break; }
                #[cfg(windows)]
                if std::fs::remove_file(&radar_request).is_ok() { show_radar(&handle); }
                let route = status(&handle);
                if let Ok(apps) = running_clients(&handle, &route) {
                    let current = apps.unprotected();
                    if current != previous {
                        if current.iter().zip(previous).any(|(current, previous)| *current && !previous) {
                            let _ = apps::notify_unprotected();
                            if let Some(window) = handle.get_webview_window("main") {
                                let _ = window.request_user_attention(Some(tauri::UserAttentionType::Informational));
                            }
                        }
                        previous = current;
                        let _ = handle.emit("desktop-clients-changed", ());
                    }
                }
              }
            });
        }
        Ok(())
    }).invoke_handler(tauri::generate_handler![activate,account,regions,sign_out,tunnel_status,connect_tunnel,disconnect,set_killswitch,set_system_proxy,observe_tunnel,dedicated_status,dedicated_action,radar_summary,run_system_radar,run_browser_probe,launch_browser,clear_browser_profile,discover_installed_clients,check_running_clients,support_report,launch_desktop_app,launch_terminal,open_official,notify_subscription,repair_browser_profile,open_time_settings,take_radar_link,work_settings,set_work_setting,set_requested_engine,browser_profile_state])
      .build(tauri::generate_context!()).expect("Workspace setup failed")
      .run(|app,event| match event {
          tauri::RunEvent::Exit => {
              let state = app.state::<Runtime>();
              state.exiting.store(true, Ordering::Release);
              let _ = remove_connection(&state, None);
          }
          #[cfg(target_os = "macos")]
          tauri::RunEvent::Opened { urls } if urls.iter().any(|url| radar_link(url.as_str())) => show_radar(app),
          _ => {}
      });
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_split_tun_reports_actual_engine_and_fallback_reason() {
        for reason in [Fallback::UacCancelled, Fallback::AuthorizationCancelled, Fallback::TunInitFailed] {
            let (engine, handle, fallback) = engine_from_start(RequestedEngine::SplitTun, || Err::<(), _>(reason));
            assert_eq!((engine, handle, fallback), (ActiveEngine::ProxyFallback, None, Some(reason)));
        }
        assert_eq!(engine_from_start(RequestedEngine::SplitTun, || Ok(())), (ActiveEngine::SplitTun, Some(()), None));
        assert_eq!(engine_from_start::<()>(RequestedEngine::Proxy, || panic!("Proxy must not ask for elevation")),
            (ActiveEngine::Proxy, None, None));
    }

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
