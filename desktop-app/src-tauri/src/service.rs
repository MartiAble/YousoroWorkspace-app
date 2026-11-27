use keyring::Entry;
use reqwest::{blocking::{Client, RequestBuilder, Response}, header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const ORIGIN: &str = env!("DESKTOP_API_ORIGIN");
pub const DIAGNOSTICS_ORIGIN: &str = env!("DESKTOP_DIAGNOSTICS_ORIGIN");
const KEYCHAIN: &str = "ru.yousoro.workspace";

pub struct Session { token: String }
#[derive(Serialize, Deserialize)]
pub struct Account {
    pub id: i64, pub email: String, pub access: String, pub profile: Profile, pub bound: Devices,
    pub has_software_license: bool,
    pub subscription_expires_at: Option<i64>,
    pub subscription_notice: Option<SubscriptionNotice>,
    pub is_suspended: bool,
    pub suspension_reason: Option<String>,
    pub dedicated_passes: Option<DedicatedPasses>,
    pub dedicated_pass_price_rub: Option<u32>,
}
impl Account {
    pub fn route_ready(&self) -> bool {
        self.has_software_license && !self.is_suspended && self.access == "active"
            && self.profile.state == "applied" && self.profile.applied.is_some()
    }
}

#[derive(Serialize, Deserialize)]
pub struct SubscriptionNotice {
    pub days_left: u32,
    pub expires_at: i64,
    pub urgency: SubscriptionUrgency,
    pub renew_url: String,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionUrgency {
    Ok,
    #[serde(rename = "warning_3d")]
    Warning3d,
    #[serde(rename = "warning_1d")]
    Warning1d,
    ExpiresToday,
    Expired,
}

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
    pub city: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeEnvironment {
    pub timezone: String,
    pub windows_timezone: String,
    pub locale: String,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct DedicatedPasses {
    pub mode: String,
    pub available_passes_count: u32,
    pub active_pass: Option<ActivePass>,
    pub held_pass: Option<HeldPass>,
    pub next_pass: Option<AvailablePass>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct HeldPass { pub id: u64, pub reason: String }

#[derive(Clone, Serialize, Deserialize)]
pub struct ActivePass {
    pub id: u64,
    pub expires_at: i64,
    pub used_bytes: u64,
    pub quota_bytes: u64,
    pub usage_percent: f64,
    pub quota_warning: bool,
    #[serde(default)]
    pub expiry_warning: bool,
    pub refresh_count: u32,
    pub max_refreshes: u32,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct AvailablePass {
    pub id: u64,
    pub duration_hours: u64,
    pub quota_bytes: u64,
}
#[derive(Serialize, Deserialize)]
pub struct RadarSummary {
    pub mode: String,
    pub dedicated_passes: DedicatedPasses,
    pub dedicated_pass_price_rub: Option<u32>,
    pub diagnostics: Option<IpDiagnostics>,
    pub location: RadarLocation,
    pub environment: Option<NodeEnvironment>,
    pub device_parity: DeviceParity,
}
#[derive(Serialize, Deserialize)]
pub struct RadarLocation {
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub timezone: Option<String>,
}
#[derive(Serialize, Deserialize)]
pub struct IpDiagnostics {
    pub asn: Option<u32>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub timezone: Option<String>,
    pub isp_name: Option<String>,
    pub network_type: String,
    pub geo_consistent: Option<bool>,
    pub risk_score: Option<u8>,
    pub audit_status: String,
    pub health_level: String,
    pub message: String,
}
#[derive(Serialize, Deserialize)]
pub struct DeviceParity {
    pub status: String,
    pub desktop_ip: Option<String>,
    pub mobile_ip: Option<String>,
    pub checked_at: Option<i64>,
    pub hint: String,
}

pub fn pass_status(s: &Session) -> Result<DedicatedPasses, String> {
    checked(s.authorize(client()?.get(format!("{ORIGIN}/api/dedicated-passes/status"))).send())?
        .json().map_err(|_| "Не удалось прочитать статус выделенного канала".into())
}

pub fn pass_action(s: &Session, action: &str, pass_id: Option<u64>, tabs_closed: bool) -> Result<DedicatedPasses, String> {
    if !matches!(action, "activate" | "complete" | "refresh-channel") {
        return Err("Неизвестное действие с выделенным каналом".into());
    }
    let response = s.authorize(client()?.post(format!("{ORIGIN}/api/dedicated-passes/{action}")))
        .json(&json!({ "pass_id": pass_id, "tabs_closed": tabs_closed })).send().map_err(|_| "Сервис Workspace недоступен")?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        return Err(response.json::<Value>().ok().and_then(|body| body["detail"].as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("Сервис Workspace ответил HTTP {status}")));
    }
    response.json().map_err(|_| "Не удалось прочитать статус выделенного канала".into())
}

pub fn radar_summary(s: &Session) -> Result<RadarSummary, String> {
    checked(s.authorize(client()?.get(format!("{ORIGIN}/api/radar/summary"))).send())?
        .json().map_err(|_| "Не удалось прочитать сводку Радара".into())
}

pub fn desktop_ping(s: &Session, ip: Option<std::net::Ipv4Addr>, passed: bool) -> Result<(), String> {
    checked(s.authorize(client()?.post(format!("{ORIGIN}/api/radar/device-ping")))
        .json(&json!({ "device_type": "desktop", "observed_ip": ip, "passed": passed })).send())?;
    Ok(())
}

pub fn client() -> Result<Client, String> {
    Client::builder().no_proxy().connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none()).build().map_err(|_| "Не удалось настроить клиент HTTPS".into())
}
pub fn checked(result: Result<Response, reqwest::Error>) -> Result<Response, String> {
    let r = result.map_err(|_| "Сервис Workspace недоступен".to_owned())?;
    if r.status().is_success() { return Ok(r); }
    let status = r.status().as_u16();
    let payload = r.json::<Value>().unwrap_or_default();
    Err(response_error(status, &payload))
}

fn response_error(status: u16, payload: &Value) -> String {
    let detail = &payload["detail"];
    if status == 401 && detail["code"] == "DEVICE_REVOKED" && detail["revoked"] == true {
        return "DEVICE_REVOKED".into();
    }
    if let Some(code @ ("INVALID_ACTIVATION_CODE" | "DEVICE_LIMIT_REACHED")) = detail["code"].as_str() {
        return code.into();
    }
    detail["message"].as_str().or_else(|| detail.as_str())
        .filter(|message| !matches!(*message, "DEVICE_REVOKED" | "ACTIVATION_REQUIRED"))
        .map(str::to_owned).unwrap_or_else(|| format!("Сервис Workspace ответил HTTP {status}"))
}
pub fn key(name: &str) -> Result<Entry, String> {
    Entry::new(KEYCHAIN, name).map_err(|_| "Системное хранилище недоступно".into())
}
impl Session {
    pub fn restore() -> Result<Self, String> {
        let token = key("activation-device")?.get_password().map_err(|error| match error {
            keyring::Error::NoEntry => "ACTIVATION_REQUIRED".to_owned(),
            _ => "Не удалось прочитать ключ устройства".to_owned(),
        })?;
        if !is_token(&token) { return Err("Не удалось прочитать ключ устройства".into()); }
        Ok(Self { token })
    }

    pub fn forget_revoked(&self) -> Result<(), String> {
        let entry = key("activation-device")?;
        match entry.get_password() {
            Ok(token) if token == self.token => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(_) => Err("Системное хранилище не удалило отозванный ключ".into()),
            },
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err("Не удалось прочитать ключ устройства".into()),
        }
    }

    pub fn authorize(&self, request: RequestBuilder) -> RequestBuilder {
        request.bearer_auth(&self.token).header(header::ORIGIN, ORIGIN)
    }
}

pub fn activate(code: String) -> Result<Account, String> {
    let mut machine = machine(true)?;
    machine["code"] = json!(code);
    let body: Value = checked(client()?.post(format!("{ORIGIN}/api/desktop/activate")).json(&machine).send())?
        .json().map_err(|_| "Сервер не подтвердил активацию")?;
    let token = body["device_token"].as_str().filter(|value| is_token(value)).ok_or("Сервер не выдал ключ устройства")?;
    let account = serde_json::from_value(body["account"].clone()).map_err(|_| "Профиль Workspace недоступен")?;
    key("activation-device")?.set_password(token).map_err(|_| "Не удалось сохранить ключ устройства")?;
    Ok(account)
}

pub fn account(session: &Session) -> Result<Account, String> {
    checked(session.authorize(client()?.get(format!("{ORIGIN}/api/desktop/account"))).send())?
        .json().map_err(|_| "Не удалось прочитать аккаунт".into())
}

fn is_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn machine(include_legacy: bool) -> Result<Value, String> {
    #[cfg(windows)]
    let os_id = crate::native_windows::machine_id().map_err(|_| "Не удалось определить идентификатор компьютера")?;
    #[cfg(not(windows))]
    let os_id = {
        if !cfg!(target_os = "macos") { return Err("Эта система пока не поддерживается".into()); }
        let result = std::process::Command::new("/usr/sbin/ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output().map_err(|_| "Не удалось определить идентификатор компьютера")?;
        let raw = String::from_utf8_lossy(&result.stdout);
        let value = raw.lines().find(|line| line.contains("\"IOPlatformUUID\""))
            .and_then(|line| line.split('"').nth(3)).unwrap_or("");
        if !result.status.success() || value.is_empty() { return Err("Не удалось определить идентификатор компьютера".into()); }
        value.to_owned()
    };
    let os = if cfg!(target_os = "macos") { "macos" } else { "windows" };
    let name = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| {
        if !cfg!(target_os = "macos") { return String::new(); }
        std::process::Command::new("/bin/hostname").output().ok().filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned()).unwrap_or_default()
    });
    let name: String = name.trim().chars().take(100).collect();
    let fingerprint = format!("{:x}", Sha256::digest(format!("yousoro-workspace-pc-v2:{os}:{os_id}")));
    let mut identity = json!({"machine_id_hash": fingerprint,
        "device_name": if name.is_empty() { "Workspace PC" } else { &name }, "os_family": os});
    if include_legacy {
        #[cfg(windows)]
        let legacy = crate::native_windows::legacy_machine_user_id(&os_id).ok().map(|id| (id, String::new()));
        #[cfg(not(windows))]
        let legacy = std::process::Command::new("/usr/bin/id").arg("-u").output().ok()
            .filter(|output| output.status.success())
            .map(|output| (os_id, String::from_utf8_lossy(&output.stdout).trim().to_owned()));
        if let Some((id, uid)) = legacy {
            identity["legacy_machine_id_hash"] = json!(format!("{:x}",
                Sha256::digest(format!("yousoro-workspace-native-v1:{id}:{uid}"))));
        }
    }
    Ok(identity)
}

pub struct Bootstrap {
    pub config: Value,
    pub device_id: Option<String>,
}

pub fn bootstrap(session: &Session) -> Result<Bootstrap, String> {
    let data: Value = checked(session.authorize(client()?.post(format!("{ORIGIN}/api/desktop/bootstrap")))
        .json(&machine(false)?).send())?.json().map_err(|_| "Сервер не вернул конфигурацию")?;
    if !data["config"].is_object() { return Err("Некорректная конфигурация Xray".into()); }
    let device_id = data["device_id"].as_str().map(str::to_owned);
    Ok(Bootstrap { config: data["config"].clone(), device_id })
}

#[cfg(test)]
mod radar_contract_tests {
    use super::*;

    #[test]
    fn only_confirmed_server_revocation_returns_the_revocation_signal() {
        let confirmed = json!({ "detail": { "code": "DEVICE_REVOKED", "revoked": true } });
        assert_eq!(response_error(401, &confirmed), "DEVICE_REVOKED");
        assert_ne!(response_error(503, &confirmed), "DEVICE_REVOKED");
        assert_ne!(response_error(401, &json!({"detail":{"code":"DEVICE_REVOKED"}})), "DEVICE_REVOKED");
        assert_ne!(response_error(503, &json!({"detail":"DEVICE_REVOKED"})), "DEVICE_REVOKED");
    }

    #[test]
    fn route_requires_license_live_subscription_and_applied_region() {
        let mut account: Account = serde_json::from_value(json!({
            "id": 1, "email": "example@example.invalid", "access": "active",
            "has_software_license": true, "subscription_expires_at": 20000, "is_suspended": false,
            "profile": {"state": "applied", "applied": "tr"}, "bound": {"limit": 2, "items": []}
        })).unwrap();
        assert!(account.route_ready());
        account.has_software_license = false;
        assert!(!account.route_ready());
        account.has_software_license = true;
        account.access = "expired".into();
        assert!(!account.route_ready());
        account.access = "active".into();
        account.is_suspended = true;
        assert!(!account.route_ready());
        account.is_suspended = false;
        account.profile.state = "pending".into();
        assert!(!account.route_ready());
    }

    #[test]
    fn parses_radar_with_active_and_queued_passes() {
        let value = json!({
            "mode": "DEDICATED_ACTIVE",
            "dedicated_passes": {
                "mode": "DEDICATED_ACTIVE", "available_passes_count": 1,
                "active_pass": {"id": 1, "expires_at": 10000, "used_bytes": 940,
                    "quota_bytes": 1024, "usage_percent": 91.8, "quota_warning": true,
                    "refresh_count": 1, "max_refreshes": 3},
                "next_pass": {"id": 2, "duration_hours": 24, "quota_bytes": 1073741824}
            },
            "dedicated_pass_price_rub": 2000,
            "diagnostics": {"country_code": "TR", "city": "Istanbul", "timezone": "Europe/Istanbul",
                "isp_name": "Fixture", "network_type": "mobile", "geo_consistent": true,
                "risk_score": 0, "audit_status": "unchecked", "health_level": "good", "message": "Маршрут проверен"},
            "location": {"country_code": "TR", "city": "Istanbul", "timezone": "Europe/Istanbul"},
            "device_parity": {"status": "single_device", "desktop_ip": null, "mobile_ip": null,
                "checked_at": null, "hint": "Запустите проверку"}
        });
        let summary: RadarSummary = serde_json::from_value(value).unwrap();
        assert_eq!(summary.location.timezone.as_deref(), Some("Europe/Istanbul"));
        assert_eq!(summary.dedicated_passes.active_pass.unwrap().refresh_count, 1);
        assert_eq!(summary.dedicated_passes.next_pass.unwrap().duration_hours, 24);
        assert_eq!(summary.diagnostics.unwrap().risk_score, Some(0));
        assert!(summary.device_parity.desktop_ip.is_none());
    }
}
