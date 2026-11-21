use keyring::Entry;
use reqwest::{blocking::{Client, RequestBuilder, Response}, header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::{Cursor, Read}, process::Command, time::Duration};

pub const ORIGIN: &str = env!("DESKTOP_API_ORIGIN");
pub const DIAGNOSTICS_ORIGIN: &str = env!("DESKTOP_DIAGNOSTICS_ORIGIN");
const KEYCHAIN: &str = "ru.yousoro.workspace";

#[derive(Serialize, Deserialize)]
pub struct Session { cookie: String, csrf: String }
#[derive(Serialize, Deserialize)]
pub struct Account { pub id: i64, pub email: String, pub access: String, pub profile: Profile, pub bound: Devices }
#[derive(Serialize, Deserialize)]
pub struct Devices { pub limit: u64, pub items: Vec<Device> }
#[derive(Serialize, Deserialize)]
pub struct Device { pub id: String, pub name: String, pub os: String }
#[derive(Serialize, Deserialize)]
pub struct Profile {
    pub requested: Option<String>,
    pub applied: Option<String>,
    pub state: String,
    pub node_environment: Option<NodeEnvironment>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeEnvironment {
    pub timezone: String,
    pub windows_timezone: String,
    pub locale: String,
}

pub fn client() -> Result<Client, String> {
    Client::builder().no_proxy().timeout(Duration::from_secs(25))
        .redirect(reqwest::redirect::Policy::none()).build().map_err(|_| "Не удалось настроить клиент HTTPS".into())
}
pub fn checked(result: Result<Response, reqwest::Error>) -> Result<Response, String> {
    let r = result.map_err(|_| "Сервис Workspace недоступен".to_owned())?;
    if r.status().is_success() { Ok(r) } else {
        Err(format!("Сервис Workspace ответил HTTP {}", r.status().as_u16()))
    }
}
pub fn key(name: &str) -> Result<Entry, String> {
    Entry::new(KEYCHAIN, name).map_err(|_| "Системное хранилище недоступно".into())
}
impl Session {
    pub fn restore() -> Result<Self, String> {
        let raw = key("session")?.get_password().map_err(|_| "Войдите в аккаунт Workspace".to_owned())?;
        serde_json::from_str(&raw).map_err(|_| "Не удалось прочитать сессию".into())
    }
    pub fn authorize(&self, r: RequestBuilder) -> RequestBuilder {
        r.header(header::COOKIE, format!("workspace_session={}", self.cookie))
            .header("X-CSRF-Token", self.csrf.as_str()).header(header::ORIGIN, ORIGIN)
    }
}
pub fn login(email: String, password: String) -> Result<Account, String> {
    let r = checked(client()?.post(format!("{ORIGIN}/api/auth/login")).header(header::ORIGIN, ORIGIN)
        .json(&json!({ "email": email, "password": password })).send())?;
    let cookie = r.headers().get_all(header::SET_COOKIE).iter().filter_map(|h| h.to_str().ok())
        .find_map(|h| h.split(';').next()?.strip_prefix("workspace_session="))
        .filter(|s| is_token(s)).ok_or("Сервер не выдал сессию")?.to_owned();
    let body: Value = r.json().map_err(|_| "Не удалось прочитать сессию")?;
    let csrf = body["csrf"].as_str().filter(|s| is_token(s)).ok_or("Сервер не выдал CSRF-токен")?.to_owned();
    let account = serde_json::from_value(body).map_err(|_| "Профиль Workspace недоступен")?;
    let session = serde_json::to_string(&Session { cookie, csrf }).map_err(|_| "Ошибка сохранения сессии")?;
    key("session")?.set_password(&session).map_err(|_| "Системное хранилище отклонило сессию")?;
    Ok(account)
}
pub fn account(s: &Session) -> Result<Account, String> {
    checked(s.authorize(client()?.get(format!("{ORIGIN}/api/me"))).send())?
        .json().map_err(|_| "Не удалось прочитать аккаунт".into())
}
pub fn is_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn fingerprint() -> Result<String, String> {
    let mut cmd;
    if cfg!(target_os = "macos") {
        cmd = Command::new("/usr/sbin/ioreg");
        cmd.args(["-rd1", "-c", "IOPlatformExpertDevice"]);
    } else if cfg!(target_os = "windows") {
        cmd = Command::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        cmd.args(["-NoProfile", "-NonInteractive", "-Command", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"]);
    } else { return Err("Эта система пока не поддерживается".into()); }
    let result = cmd.output().map_err(|_| "Не удалось определить идентификатор компьютера")?;
    let raw = String::from_utf8_lossy(&result.stdout);
    let os_id = if cfg!(target_os = "macos") {
        raw.lines().find(|line| line.contains("\"IOPlatformUUID\"")).and_then(|line| line.split('"').nth(3)).unwrap_or("")
    } else { raw.trim() };
    let mac_uid = if cfg!(target_os = "macos") {
        let id = Command::new("/usr/bin/id").arg("-u").output().map_err(|_| "Не удалось прочитать UID пользователя")?;
        if !id.status.success() { return Err("Не удалось прочитать UID пользователя".into()); }
        String::from_utf8_lossy(&id.stdout).trim().to_owned()
    } else { String::new() };
    if !result.status.success() || os_id.is_empty() { return Err("Не удалось определить идентификатор компьютера".into()); }
    Ok(format!("{:x}", Sha256::digest(format!("yousoro-workspace-native-v1:{os_id}:{mac_uid}"))))
}
fn enrollment(s: &Session, os: &str) -> Result<String, String> {
    let r = checked(s.authorize(client()?.post(format!("{ORIGIN}/api/launcher/download")))
        .json(&json!({"kind":os,"product":"browser"})).send())?;
    // Only the signed-in account's enrollment manifest is read. Executables in the archive are ignored.
    let mut archive_bytes = Vec::new();
    r.take(128 * 1024 * 1024).read_to_end(&mut archive_bytes).map_err(|_| "Ошибка загрузки профиля")?;
    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes)).map_err(|_| "Сервис не вернул архив подключения")?;
    let manifest = archive.by_name("launcher.json").map_err(|_| "В архиве отсутствует профиль подключения")?;
    let body: Value = serde_json::from_reader(manifest.take(8192)).map_err(|_| "Ошибка чтения профиля")?;
    body["launcher_token"].as_str().filter(|s| is_token(s)).map(str::to_owned)
        .ok_or_else(|| "Сервер не выдал код привязки".into())
}
pub struct Bootstrap {
    pub config: Value,
    pub device_id: Option<String>,
}

pub fn bootstrap(s: &Session, account: &Account) -> Result<Bootstrap, String> {
    let os = if cfg!(target_os = "macos") { "macos" } else { "windows" };
    let fingerprint = fingerprint()?;
    let slot = key(&format!("device:{}:{fingerprint}", account.id))?;
    let token = match slot.get_password() {
        Ok(token) if is_token(&token) => token,
        Err(keyring::Error::NoEntry) => enrollment(s, os)?,
        _ => return Err("Не удалось прочитать ключ устройства. Проверьте системное хранилище".into()),
    };
    let data: Value = checked(client()?.post(format!("{ORIGIN}/api/launcher/bootstrap")).bearer_auth(token)
        .json(&json!({"device_fingerprint":fingerprint,"name":"Yousoro Workspace","os":os})).send())?
        .json().map_err(|_| "Сервер не вернул конфигурацию")?;
    if let Some(token) = data["device_token"].as_str().filter(|s| is_token(s)) {
        slot.set_password(token).map_err(|_| "Не удалось сохранить ключ устройства")?;
    }
    if !data["config"].is_object() { return Err("Некорректная конфигурация Xray".into()); }
    let device_id = data["device_id"].as_str().map(str::to_owned);
    Ok(Bootstrap { config: data["config"].clone(), device_id })
}
