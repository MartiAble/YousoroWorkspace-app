mod apps;
mod dns_radar;
mod launch;
mod radar;
mod system_proxy;
mod service;
mod tunnel;
use serde::Serialize;
use serde_json::{json, Value};
use std::{process::Command, sync::Mutex};
use tauri::{AppHandle, Manager};
use tunnel::Tunnel;

#[derive(Default)]
struct Runtime(Mutex<Option<Connection>>, Mutex<()>, radar::BrowserProbe);

struct Connection {
    proxy: Option<system_proxy::Lease>,
    tunnel: Tunnel,
    device_id: Option<String>,
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
}
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T,String> + Send + 'static) -> Result<T,String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|_| "Фоновая операция остановлена".to_owned())?
}

fn status(app: &AppHandle) -> Status {
    let state = app.state::<Runtime>();
    let mut result = Status {
        port: None, region: None, system_proxy: false, system_proxy_supported: cfg!(windows), proxy_error: None,
    };
    if let Ok(mut guard) = state.0.lock() {
        if let Some(connection) = guard.as_mut() {
            if connection.tunnel.running() {
                result.port = Some(connection.tunnel.port);
                result.region = Some(connection.tunnel.region.clone());
                result.system_proxy = connection.proxy.is_some();
            } else {
                match connection.restore_proxy() {
                    Ok(()) => *guard = None,
                    Err(error) => {
                        result.proxy_error = Some(error);
                        result.system_proxy = true;
                    }
                }
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
#[tauri::command]
fn disconnect(app: AppHandle) -> Result<Status,String> {
    let state = app.state::<Runtime>();
    let mut guard = state.0.lock().map_err(|_| "Ошибка состояния")?;
    if let Some(connection) = guard.as_mut() { connection.restore_proxy()?; }
    *guard = None;
    drop(guard);
    Ok(status(&app))
}
#[tauri::command]
async fn sign_out(app: AppHandle) -> Result<(),String> { blocking(move || {
    disconnect(app)?;
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
    let s = service::Session::restore()?;
    let request = s.authorize(service::client()?.post(format!("{}/api/route",service::ORIGIN))).json(&json!({ "region":region }));
    let account = service::checked(request.send())?.json().map_err(|_| "Сервис не подтвердил выбор региона")?;
    disconnect(app)?;
    Ok(account)
}).await }
#[tauri::command]
async fn connect_tunnel(app: AppHandle) -> Result<Status,String> { blocking(move || {
    let state = app.state::<Runtime>();
    let mut guard = state.0.lock().map_err(|_| "Ошибка состояния")?;
    if !guard.as_mut().is_some_and(|state| state.tunnel.running()) {
        if let Some(connection) = guard.as_mut() { connection.restore_proxy()?; }
        let s = service::Session::restore()?;
        let account = service::account(&s)?;
        if account.access != "active" || account.profile.state != "applied" { return Err("Подписка или сетевой профиль ещё не активны".into()); }
        let region = account.profile.applied.clone().ok_or("Выберите регион")?;
        let path = app.path().resource_dir().map_err(|_| "Нет каталога ресурсов")?.join("resources");
        let executable = std::env::current_exe().map_err(|_| "Не удалось определить путь приложения")?;
        let executable_dir = executable.parent().ok_or("Нет каталога приложения")?;
        let enrollment = service::bootstrap(&s, &account)?;
        let tunnel = tunnel::start(executable_dir, &path, enrollment.config, region)?;
        *guard = Some(Connection { tunnel, proxy: None, device_id: enrollment.device_id });
    }
    drop(guard);
    Ok(status(&app))
}).await }
#[tauri::command]
async fn observe_tunnel(app: AppHandle) -> Result<radar::Observation, String> {
    blocking(move || radar::observe_tunnel(status(&app).port.ok_or("Сначала подключите туннель")?)).await
}

#[tauri::command]
async fn run_system_radar(app: AppHandle, lookup_geo: bool, check_dns: Option<bool>) -> Result<radar::Report, String> {
    blocking(move || {
        let route = status(&app);
        let port = route.port.ok_or("Сначала подключите туннель")?;
        let region = route.region.ok_or("Регион не определён")?;
        let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
        let state = app.state::<Runtime>();
        let device_id = state.0.lock().map_err(|_| "Ошибка состояния туннеля")?.as_ref()
            .filter(|active| active.tunnel.port == port).and_then(|active| active.device_id.clone());
        let report = radar::report(port, &region, &data, &state.2, lookup_geo, check_dns.unwrap_or(false), device_id.as_deref());
        if status(&app).port != Some(port) { return Err("Туннель изменился во время диагностики".into()); }
        Ok(report)
    }).await
}

#[tauri::command]
async fn set_system_proxy(app: AppHandle, enabled: bool) -> Result<Status, String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let mut guard = state.0.lock().map_err(|_| "Ошибка состояния туннеля")?;
        let connection = guard.as_mut().ok_or("Сначала подключите туннель")?;
        if enabled {
            if !connection.tunnel.running() { return Err("Сначала подключите туннель".into()); }
            if connection.proxy.is_none() {
                let data = app.path().app_data_dir().map_err(|_| "Нет каталога данных приложения")?;
                connection.proxy = Some(system_proxy::Lease::enable(&data, connection.tunnel.port)?);
            }
        } else {
            connection.restore_proxy()?;
        }
        drop(guard);
        Ok(status(&app))
    }).await
}
#[tauri::command]
fn launch_terminal(app: AppHandle) -> Result<(),String> {
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
}

#[tauri::command]
fn launch_browser(app: AppHandle, destination: String) -> Result<(),String> {
    let url = match destination.as_str() {
        "claude" => "https://claude.ai/",
        "chatgpt" => "https://chatgpt.com/",
        "workspace" => service::ORIGIN,
        _ => return Err("Неизвестное назначение".into()),
    };
    let state = app.state::<Runtime>();
    let _profile_guard = state.1.lock().map_err(|_| "Ошибка состояния профиля")?;
    let mut tunnel = state.0.lock().map_err(|_| "Ошибка состояния туннеля")?;
    let tunnel = &mut tunnel.as_mut().ok_or("Сначала подключите туннель")?.tunnel;
    if !tunnel.running() { return Err("Сначала подключите туннель".into()); }
    let data = app.path().app_data_dir().map_err(|_| "Не удалось открыть каталог приложения")?;
    let profile = launch::profile_path(&data, &tunnel.region)?;
    launch::launch_browser(&profile, tunnel.port, &tunnel.region, url, &state.2)
}

#[tauri::command]
async fn clear_browser_profile(app: AppHandle, region: String) -> Result<(), String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let _guard = state.1.lock().map_err(|_| "Ошибка состояния профиля")?;
        let data = app.path().app_data_dir().map_err(|_| "Не удалось открыть каталог приложения")?;
        launch::clear_browser_profile(&launch::profile_path(&data, &region)?)
    }).await
}

#[tauri::command]
async fn installed_desktop_apps(app: AppHandle) -> Result<apps::InstalledApps, String> {
    blocking(move || {
        let route = status(&app);
        Ok(apps::installed_apps(route.port, route.port.and_then(system_proxy::active) == Some(true)))
    }).await
}

#[tauri::command]
async fn launch_desktop_app(app: AppHandle, client: apps::DesktopApp, restart: bool) -> Result<(), String> {
    blocking(move || {
        let state = app.state::<Runtime>();
        let mut guard = state.0.lock().map_err(|_| "Ошибка состояния туннеля")?;
        let connection = guard.as_mut().ok_or("Сначала подключите туннель")?;
        if !connection.tunnel.running() { return Err("Сначала подключите туннель".into()); }
        let port = connection.tunnel.port;
        apps::launch(client, port, connection.proxy.is_some() && system_proxy::active(port) == Some(true), restart)
    }).await
}
#[tauri::command]
fn open_official(page: String) -> Result<(),String> {
    let url=match page.as_str() { "claude"=>"https://claude.com/download","chatgpt"=>"https://chatgpt.com/download/","workspace"=>service::ORIGIN,_=>return Err("Неизвестная страница".into()) };
    let mut cmd=if cfg!(target_os="macos") { Command::new("/usr/bin/open") } else { let mut c=Command::new("rundll32.exe"); c.arg("url.dll,FileProtocolHandler"); c };
    cmd.arg(url).spawn().map_err(|_| "Не удалось открыть страницу".into()).map(|_| ())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(Runtime::default()).setup(|app| {
        use tauri::{menu::{Menu,MenuItem},tray::TrayIconBuilder};
        let show=MenuItem::with_id(app,"show","Открыть Workspace",true,None::<&str>)?;
        let browser=MenuItem::with_id(app,"browser","Открыть рабочий браузер",true,None::<&str>)?;
        let exit=MenuItem::with_id(app,"exit","Выход",true,None::<&str>)?;
        let menu=Menu::with_items(app,&[&show,&browser,&exit])?;
        let icon=app.default_window_icon().ok_or("Нет значка приложения")?.clone();
        TrayIconBuilder::with_id("workspace").icon(icon).menu(&menu).tooltip("Отключено")
            .on_menu_event(|app,event| match event.id().as_ref() {
                "show"=>{if let Some(w)=app.get_webview_window("main") { let _=w.show(); let _=w.set_focus(); }},
                "browser"=>{if launch_browser(app.clone(),"workspace".into()).is_err() { if let Some(w)=app.get_webview_window("main") { let _=w.show(); let _=w.set_focus(); } }},
                "exit"=>app.exit(0), _=>{},
            }).build(app)?;
        if cfg!(windows) {
            if let Ok(data) = app.path().app_data_dir() { let _ = system_proxy::Lease::recover(&data); }
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(3));
                let _ = status(&handle);
            });
        }
        Ok(())
    }).invoke_handler(tauri::generate_handler![sign_in,account,regions,select_region,sign_out,tunnel_status,connect_tunnel,disconnect,set_system_proxy,observe_tunnel,run_system_radar,launch_browser,clear_browser_profile,installed_desktop_apps,launch_desktop_app,launch_terminal,open_official])
      .build(tauri::generate_context!()).expect("Workspace setup failed")
      .run(|app,event| { if matches!(event,tauri::RunEvent::Exit) { let _=disconnect(app.clone()); } });
}
